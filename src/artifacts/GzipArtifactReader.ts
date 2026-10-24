import { createGunzip } from "node:zlib";
import { PassThrough, pipeline, type Readable } from "node:stream";
import { basename } from "node:path";
import type { Stats } from "node:fs";
import type { FileHandle } from "node:fs/promises";

import {
  ArtifactReaderFailure,
  copyArtifactEntry,
  sameArtifactEntry,
  type ArtifactEntry,
  type ArtifactReader,
  type ArtifactTraversalOptions,
} from "./ArtifactReader.js";
import { normalizeArtifactPath } from "./ArtifactPaths.js";
import type { ArtifactCommand } from "../domain/artifactGraph.js";
import { OwnedFileHandle } from "../filesystem/OwnedFileHandle.js";
import {
  openRegularFile,
  type StableRegularFileDescriptor,
} from "../filesystem/RegularFile.js";

const MAX_GZIP_FNAME_BYTES = 4_096;

const normalizeSafeGzipFilename = (name: string): string | null => {
  if (name.includes("/") || name.includes("\\")) {
    return null;
  }
  try {
    return normalizeArtifactPath(name);
  } catch {
    return null;
  }
};

const deriveFallbackFilename = (fallbackPath: string): string => {
  const base = basename(fallbackPath);
  if (base.toLowerCase().endsWith(".gz")) {
    const stem = base.slice(0, -3);
    return normalizeSafeGzipFilename(stem) ?? "decompressed_payload";
  }
  const unpacked =
    base.length > 0 && base !== "." && base !== ".." ? `${base}.unpacked` : "";
  return normalizeSafeGzipFilename(unpacked) ?? "decompressed_payload";
};

/** Extract original filename from GZIP header flags (RFC 1952) if present. */
const resolveGzipOriginalFilename = async (
  handle: FileHandle,
  size: number,
  fallbackPath: string,
): Promise<{
  readonly path: string;
  readonly sourcePath?: string;
  readonly limitations: readonly string[];
}> => {
  const fallback = deriveFallbackFilename(fallbackPath);
  if (size < 10) {
    return { path: fallback, limitations: [] };
  }
  const headerBuf = Buffer.alloc(Math.min(512, size));
  const headerRead = await handle.read(headerBuf, 0, headerBuf.length, 0);
  const prefix = headerBuf.subarray(0, headerRead.bytesRead);
  if (prefix.length < 10 || prefix[0] !== 0x1f || prefix[1] !== 0x8b) {
    return { path: fallback, limitations: [] };
  }
  const flags = prefix[3] ?? 0;
  // Bit 3 is FNAME
  if ((flags & 0x08) === 0) {
    return { path: fallback, limitations: [] };
  }

  let fnameOffset = 10;
  // If FEXTRA is set, skip extra field
  if ((flags & 0x04) !== 0) {
    if (prefix.length < 12) {
      return {
        path: fallback,
        limitations: [
          "GZIP FEXTRA header is truncated before FNAME; substituted carrier-derived filename.",
        ],
      };
    }
    const xlen = prefix.readUInt16LE(10);
    fnameOffset = 12 + xlen;
  }

  if (fnameOffset >= size) {
    return {
      path: fallback,
      limitations: [
        "GZIP FNAME offset exceeds archive size; substituted carrier-derived filename.",
      ],
    };
  }

  let fnameSlice: Buffer;
  const nullInPrefix =
    fnameOffset < prefix.length ? prefix.indexOf(0, fnameOffset) : -1;
  if (nullInPrefix >= fnameOffset) {
    fnameSlice = prefix.subarray(fnameOffset, nullInPrefix + 1);
  } else {
    const readLen = Math.min(MAX_GZIP_FNAME_BYTES, size - fnameOffset);
    const fnameBuf = Buffer.alloc(readLen);
    const fnameRead = await handle.read(fnameBuf, 0, readLen, fnameOffset);
    fnameSlice = fnameBuf.subarray(0, fnameRead.bytesRead);
  }

  const nullByte = fnameSlice.indexOf(0);
  if (nullByte === -1) {
    return {
      path: fallback,
      limitations: [
        "GZIP FNAME header is unterminated or exceeds bound; substituted carrier-derived filename.",
      ],
    };
  }

  const name = fnameSlice.subarray(0, nullByte).toString("latin1");
  const normalizedName = normalizeSafeGzipFilename(name);
  if (normalizedName === null) {
    return {
      path: fallback,
      limitations: [
        "GZIP FNAME header contains an unsafe or empty path; substituted carrier-derived filename.",
      ],
    };
  }

  return {
    path: normalizedName,
    ...(normalizedName !== name ? { sourcePath: name } : {}),
    limitations: [],
  };
};

/** Single-stream decompression reader for GZIP archives. */
export class GzipArtifactReader implements ArtifactReader {
  readonly format = "gzip" as const;
  private handle: FileHandle | undefined;
  private owner: OwnedFileHandle | undefined;
  private fileSize = 0;
  private cachedEntry: ArtifactEntry | null = null;
  private closed = false;

  constructor(
    readonly path: string,
    private readonly admitted?: StableRegularFileDescriptor,
  ) {
    if (admitted !== undefined) {
      this.handle = admitted.handle;
      this.fileSize = admitted.initial.size;
    }
  }

  provenance(): readonly ArtifactCommand[] {
    return [];
  }

  private async ensureOpen(
    signal?: AbortSignal,
  ): Promise<{ handle: FileHandle; size: number }> {
    if (this.closed) {
      throw new ArtifactReaderFailure(
        "unavailable",
        "GzipArtifactReader is closed",
      );
    }
    if (this.handle !== undefined) {
      return { handle: this.handle, size: this.fileSize };
    }
    const handle = await openRegularFile(this.path, {
      symlinks: "follow",
      signal,
    });
    this.handle = handle;
    this.owner = new OwnedFileHandle(handle);
    try {
      const metadata: Stats = await handle.stat();
      this.fileSize = metadata.size;
    } catch (cause) {
      await this.close();
      throw cause;
    }
    return { handle: this.handle, size: this.fileSize };
  }

  async *entries(
    signal?: AbortSignal,
    options?: ArtifactTraversalOptions,
  ): AsyncIterable<ArtifactEntry> {
    if (this.closed) {
      throw new ArtifactReaderFailure(
        "unavailable",
        "GzipArtifactReader was already closed",
      );
    }
    if (this.cachedEntry === null) {
      const { handle, size } = await this.ensureOpen(signal);
      const {
        path: innerName,
        sourcePath,
        limitations,
      } = await resolveGzipOriginalFilename(handle, size, this.path);

      this.cachedEntry = {
        path: innerName,
        ...(sourcePath !== undefined ? { sourcePath } : {}),
        kind: "file",
        declaredSize: null,
        compressedSize: size,
        executable: false,
        encrypted: false,
        byteOffset: null,
        declaredIntegrity: null,
        unpacked: false,
        limitations,
        adapterKey: this.path,
      };
    }
    if (signal?.aborted) {
      throw new ArtifactReaderFailure("cancelled", "Gzip traversal cancelled", {
        cancellation: { reason: signal.reason },
      });
    }
    options?.onCoverage?.({
      status: "complete",
      limitations: [...this.cachedEntry.limitations],
    });
    yield copyArtifactEntry(this.cachedEntry);
  }

  async open(entry: ArtifactEntry, signal?: AbortSignal): Promise<Readable> {
    if (this.closed) {
      throw new ArtifactReaderFailure(
        "unavailable",
        "GzipArtifactReader is closed",
      );
    }
    const { handle } = await this.ensureOpen(signal);
    const current = this.cachedEntry;
    if (current === null || !sameArtifactEntry(current, entry)) {
      throw new ArtifactReaderFailure(
        "path",
        `Unknown artifact entry: ${entry.path}`,
      );
    }
    if (signal?.aborted) {
      throw new ArtifactReaderFailure("cancelled", "Decompression cancelled", {
        cancellation: { reason: signal.reason },
      });
    }

    const inputStream = handle.createReadStream({
      start: 0,
      autoClose: false,
    });
    const gunzip = createGunzip();
    const output = new PassThrough();

    let totalBytes = 0;
    const MAX_GZIP_EXPANSION = 512 * 1024 * 1024; // 512 MiB budget
    gunzip.on("data", (chunk: Buffer) => {
      totalBytes += chunk.length;
      if (totalBytes > MAX_GZIP_EXPANSION) {
        const err = new ArtifactReaderFailure(
          "limit",
          `GZIP decompression exceeded maximum expansion budget of ${MAX_GZIP_EXPANSION} bytes`,
        );
        inputStream.destroy();
        gunzip.destroy(err);
        output.destroy(err);
      }
    });

    pipeline(inputStream, gunzip, output, (err) => {
      if (err) {
        if (!inputStream.destroyed) inputStream.destroy();
        const failure =
          err instanceof ArtifactReaderFailure
            ? err
            : new ArtifactReaderFailure(
                "format",
                `GZIP decompression error: ${err.message}`,
                { cause: err },
              );
        output.destroy(failure);
      }
    });

    output.on("close", () => {
      if (!gunzip.destroyed) gunzip.destroy();
    });

    if (signal) {
      const onAbort = () => {
        const failure = new ArtifactReaderFailure(
          "cancelled",
          "Decompression cancelled",
          { cancellation: { reason: signal.reason } },
        );
        inputStream.destroy();
        gunzip.destroy();
        output.destroy(failure);
      };
      if (signal.aborted) {
        onAbort();
      } else {
        signal.addEventListener("abort", onAbort, { once: true });
        output.on("close", () => {
          signal.removeEventListener("abort", onAbort);
        });
      }
    }

    return output;
  }

  async close(): Promise<void> {
    this.closed = true;
    if (this.owner !== undefined) {
      await this.owner.close();
      this.owner = undefined;
    }
    this.handle = undefined;
  }
}
