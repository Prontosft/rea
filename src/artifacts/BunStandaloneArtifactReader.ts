import type { Stats } from "node:fs";
import type { FileHandle } from "node:fs/promises";
import { setImmediate } from "node:timers/promises";
import { Readable, Transform, pipeline } from "node:stream";

import { artifactExpansionBudgetBytes } from "../domain/artifactExpansionBudget.js";
import type {
  BunStandaloneEntryMetadata,
  BunStandaloneMetadata,
} from "../domain/artifactFormatMetadata.js";
import { artifactIntegrityDetails } from "../domain/artifactIntegrity.js";
import { jsonValueByteLength } from "../domain/jsonValueByteLength.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { OwnedFileHandle } from "../filesystem/OwnedFileHandle.js";
import { readFileHandleChunks } from "../filesystem/readFileHandleChunks.js";
import {
  NonRegularFileReadError,
  RegularFileAdmissionFailure,
  RegularFileOperationCancelled,
  openRegularFile,
  sameRegularFileState,
  type StableRegularFileDescriptor,
} from "../filesystem/RegularFile.js";
import { hashReadable } from "./ArtifactHash.js";
import { assertArtifactReadActive } from "./ArtifactFileOperation.js";
import { normalizeArtifactPath } from "./ArtifactPaths.js";
import {
  ArtifactReaderFailure,
  copyArtifactEntry,
  sameArtifactEntry,
  type ArtifactEntry,
  type ArtifactReader,
  type ArtifactTraversalOptions,
} from "./ArtifactReader.js";
import { ArtifactResourceScope } from "./ArtifactResourceScope.js";
import {
  MAX_BUN_RETAINED_BYTES,
  bunFormatFailure,
  bunRetainedBytesLimit,
  locateBunStandaloneGraph,
  type LocatedBunGraph,
} from "./bun/BunModuleGraphLayout.js";
import {
  decodeBunModuleGraph,
  type BunDecodedModule,
} from "./bun/BunModuleGraphMembers.js";

const REGIONS = ["contents", "sourcemap", "bytecode", "module-info"] as const;
type BunRegion = (typeof REGIONS)[number];

/** One descriptor and bounded reads of an embedded Bun standalone module graph. */
export class BunStandaloneArtifactReader implements ArtifactReader {
  readonly format = "bun-standalone" as const;
  readonly #scope = new ArtifactResourceScope();
  readonly #entries = new Map<string, ArtifactEntry>();
  readonly #streams = new Set<Readable>();
  #owner: OwnedFileHandle | undefined;
  #initial: Stats | undefined;
  #opening: Promise<FileHandle> | undefined;
  #prepared: Promise<void> | undefined;
  #header: BunStandaloneMetadata | undefined;
  #closing = false;
  #boundSha256: string | undefined;

  constructor(
    private readonly path: string,
    private readonly admitted?: StableRegularFileDescriptor,
  ) {}

  formatMetadata(): BunStandaloneMetadata | undefined {
    return this.#header === undefined ? undefined : { ...this.#header };
  }

  async prepareContainer(
    expectedSha256: string,
    signal?: AbortSignal,
  ): Promise<void> {
    await this.#scope.run(async () => {
      this.#assertOpen(signal);
      const handle = await this.#assertStable(signal);
      const observed =
        this.#boundSha256 ??
        (
          await hashReadable(
            readFileHandleChunks(handle, {
              signal,
              cancellationFailure: (reason) =>
                new ArtifactReaderFailure(
                  "cancelled",
                  "Bun standalone verification cancelled",
                  { cause: reason },
                ),
            }),
            signal,
          )
        ).sha256;
      await this.#assertStable(signal);
      if (observed !== expectedSha256)
        throw new ArtifactReaderFailure(
          "integrity",
          "Bun standalone carrier changed after inventory",
          undefined,
          artifactIntegrityDetails(
            ".",
            { algorithm: "sha256", digest: expectedSha256 },
            observed,
            false,
          ),
        );
      this.#boundSha256 = observed;
    });
  }

  async *entries(
    signal?: AbortSignal,
    _options?: ArtifactTraversalOptions,
  ): AsyncIterable<ArtifactEntry> {
    await this.#scope.run(async () => {
      this.#assertOpen(signal);
      this.#prepared ??= this.#prepare(signal);
      await this.#prepared;
      await this.#assertStable(signal);
    });
    let index = 0;
    for (const entry of this.#entries.values()) {
      if (index++ % 256 === 0) await setImmediate();
      this.#assertOpen(signal);
      yield copyArtifactEntry(entry);
    }
  }

  async open(entry: ArtifactEntry, signal?: AbortSignal): Promise<Readable> {
    return this.#scope.run(async () => {
      this.#assertOpen(signal);
      const stored = this.#entries.get(entry.adapterKey);
      if (stored === undefined || !sameArtifactEntry(entry, stored))
        throw new ArtifactReaderFailure(
          "integrity",
          "Bun standalone entry does not match its owning inventory",
        );
      const handle = await this.#assertStable(signal);
      this.#assertOpen(signal);
      if (stored.byteOffset === null || stored.declaredSize === null)
        throw bunFormatFailure("member has no physical byte range");
      const source =
        stored.declaredSize === 0
          ? Readable.from([])
          : readFileHandleChunks(handle, {
              start: stored.byteOffset,
              end: stored.byteOffset + stored.declaredSize - 1,
              signal,
              cancellationFailure: (reason) =>
                new ArtifactReaderFailure(
                  "cancelled",
                  "Bun standalone read cancelled",
                  { cause: reason },
                ),
            });
      const output = memberStream(stored);
      output.on("error", () => undefined);
      this.#streams.add(output);
      void this.#scope
        .run(
          () =>
            new Promise<void>((resolve) => {
              pipeline(source, output, () => {
                this.#streams.delete(output);
                resolve();
              });
            }),
        )
        .catch((cause: unknown) =>
          output.destroy(
            cause instanceof Error
              ? cause
              : new Error("Bun standalone stream ownership failed", { cause }),
          ),
        );
      return output;
    });
  }

  async close(): Promise<void> {
    this.#closing = true;
    for (const stream of this.#streams)
      stream.destroy(
        new ArtifactReaderFailure(
          "unavailable",
          "Bun standalone reader closed",
        ),
      );
    await this.#scope.close();
    if (this.#owner !== undefined) {
      await this.#owner.close();
      this.#owner = undefined;
    }
    this.#entries.clear();
  }

  provenance(): readonly [] {
    return [];
  }

  #assertOpen(signal?: AbortSignal): void {
    assertArtifactReadActive(signal);
    if (this.#closing)
      throw new ArtifactReaderFailure(
        "unavailable",
        "Bun standalone reader is closed",
      );
  }

  #open(signal?: AbortSignal): Promise<FileHandle> {
    this.#opening ??= this.#admit(signal);
    return this.#opening;
  }

  async #admit(signal?: AbortSignal): Promise<FileHandle> {
    try {
      const handle =
        this.admitted?.handle ??
        (await openRegularFile(this.path, { symlinks: "reject", signal }));
      if (this.admitted === undefined)
        this.#owner = new OwnedFileHandle(handle);
      this.#initial = this.admitted?.initial ?? (await handle.stat());
      return handle;
    } catch (cause: unknown) {
      if (cause instanceof RegularFileAdmissionFailure) {
        this.#owner = cause.owner;
        throw ArtifactReaderFailure.withCleanup(
          admissionFailure(cause.cause, this.path),
          ArtifactReaderFailure.cleanupObservation(
            cause.cleanupCause,
            this.path,
          ),
        );
      }
      throw admissionFailure(cause, this.path);
    }
  }

  async #assertStable(signal?: AbortSignal): Promise<FileHandle> {
    assertArtifactReadActive(signal);
    const handle = await this.#open(signal);
    const observed = await handle.stat();
    if (
      this.#initial === undefined ||
      !sameRegularFileState(this.#initial, observed)
    )
      throw new ArtifactReaderFailure(
        "integrity",
        `Bun standalone source identity changed: ${this.path}`,
      );
    assertArtifactReadActive(signal);
    return handle;
  }

  async #prepare(signal?: AbortSignal): Promise<void> {
    const handle = await this.#assertStable(signal);
    const initial = this.#initial;
    if (initial === undefined)
      throw bunFormatFailure("source identity was not admitted");
    const located = await locateBunStandaloneGraph(
      handle,
      initial.size,
      signal,
    );
    if (located.status === "absent")
      throw bunFormatFailure("no Bun section or trailer");
    if (located.failure !== undefined) throw located.failure;
    if (located.graph === undefined)
      throw bunFormatFailure("no Bun section or trailer");
    const decoded = decodeBunModuleGraph(located.graph);
    const entryModule = decoded.modules[decoded.entryPointId];
    const header: BunStandaloneMetadata = {
      kind: "bun-standalone",
      layout_revision: decoded.revision,
      carrier: located.graph.carrier,
      payload_offset: located.graph.payloadOffset,
      payload_length: located.graph.payloadLength,
      module_count: decoded.modules.length,
      entry_point_id: decoded.entryPointId,
      entry_point_source_name: entryModule?.nameText.text ?? null,
      compile_exec_argv: decoded.compileExecArgv.text,
      compile_exec_argv_hex: decoded.compileExecArgv.hex,
      flags: decoded.flags,
    };
    let retainedBytes = jsonValueByteLength(header, MAX_BUN_RETAINED_BYTES);
    if (retainedBytes > MAX_BUN_RETAINED_BYTES)
      throw bunRetainedBytesLimit(retainedBytes);
    let declaredPlaintext = 0n;
    const expansionBudget = BigInt(
      artifactExpansionBudgetBytes(located.graph.payloadLength),
    );
    for (const module of decoded.modules) {
      assertArtifactReadActive(signal);
      for (const region of REGIONS) {
        const range = regionRange(module, region);
        if (range === null) continue;
        declaredPlaintext += BigInt(range.length);
        if (declaredPlaintext > expansionBudget)
          throw new ArtifactReaderFailure(
            "limit",
            `Bun standalone readable entries declare ${String(declaredPlaintext)} plaintext bytes, exceeding this graph's ${String(expansionBudget)}-byte expansion budget. This release has no runtime override. Host memory and NODE_OPTIONS do not raise it.`,
            { boundary: "memory" },
          );
        const entry = moduleEntry(located.graph, module, region, range);
        retainedBytes += jsonValueByteLength(
          entryMetadataJson(entry),
          Math.max(0, MAX_BUN_RETAINED_BYTES - retainedBytes),
        );
        if (retainedBytes > MAX_BUN_RETAINED_BYTES)
          throw bunRetainedBytesLimit(retainedBytes);
        this.#entries.set(entry.adapterKey, entry);
      }
    }
    this.#header = header;
    await this.#assertStable(signal);
  }
}

const regionRange = (
  module: BunDecodedModule,
  region: BunRegion,
): { readonly offset: number; readonly length: number } | null => {
  if (region === "contents") return module.contents;
  if (region === "sourcemap") return module.sourcemap;
  if (region === "bytecode") return module.bytecode;
  return module.moduleInfo;
};

const moduleEntry = (
  graph: LocatedBunGraph,
  module: BunDecodedModule,
  region: BunRegion,
  range: { readonly offset: number; readonly length: number },
): ArtifactEntry => {
  const located = logicalModulePath(module);
  const suffix =
    region === "contents"
      ? ""
      : region === "sourcemap"
        ? ".bunmap"
        : region === "bytecode"
          ? ".bytecode"
          : ".module-info";
  const metadata: BunStandaloneEntryMetadata = {
    kind: "bun-standalone-entry",
    index: module.index,
    region,
    source_name: module.nameText.text,
    source_name_hex: module.nameText.hex,
    encoding: module.encoding,
    encoding_name: encodingName(module.encodingName),
    loader: module.loader,
    loader_name: module.loaderName,
    module_format: module.moduleFormat,
    module_format_name: formatName(module.moduleFormatName),
    side: module.side,
    side_name: sideName(module.sideName),
    entry_point: module.index === graph.entryPointId,
    sourcemap_bytes: module.sourcemap?.length ?? 0,
    bytecode_bytes: module.bytecode?.length ?? 0,
    module_info_bytes: module.moduleInfo?.length ?? 0,
    bytecode_origin: module.bytecodeOrigin?.text ?? null,
    bytecode_origin_hex: module.bytecodeOrigin?.hex ?? null,
  };
  return {
    path: `${located.path}${suffix}`,
    ...(located.sourcePath === undefined
      ? {}
      : { sourcePath: located.sourcePath }),
    kind: "file",
    declaredSize: range.length,
    compressedSize: null,
    executable: false,
    encrypted: false,
    byteOffset: graph.payloadOffset + range.offset,
    declaredIntegrity: null,
    unpacked: false,
    limitations: [],
    adapterKey: `bun:${String(module.index)}:${region}`,
    formatMetadata: metadata,
  };
};

const encodingName = (
  value: string | null,
): BunStandaloneEntryMetadata["encoding_name"] =>
  value === "binary" ||
  value === "latin1" ||
  value === "utf8" ||
  value === "utf16"
    ? value
    : null;

const formatName = (
  value: string | null,
): BunStandaloneEntryMetadata["module_format_name"] =>
  value === "none" || value === "esm" || value === "cjs" ? value : null;

const sideName = (
  value: string | null,
): BunStandaloneEntryMetadata["side_name"] =>
  value === "server" || value === "client" ? value : null;

/**
 * Bun virtual names keep a leading slash (`/$bunfs/...`). Strip one slash
 * when the remainder is a safe relative path, and keep the raw spelling on
 * `sourcePath`. Unsafe, drive, and invalid UTF-8 names fall back to
 * `bun-modules/<index>` so inventory can still retain the module.
 */
const logicalModulePath = (
  module: BunDecodedModule,
): { readonly path: string; readonly sourcePath?: string } => {
  const fallback = `bun-modules/${String(module.index)}`;
  const text = module.nameText.text;
  if (text === null || text.length === 0) return { path: fallback };
  const candidate = text.startsWith("/") ? text.slice(1) : text;
  try {
    return {
      path: normalizeArtifactPath(candidate),
      sourcePath: text,
    };
  } catch (cause: unknown) {
    if (!(cause instanceof ArtifactReaderFailure) || cause.reason !== "path")
      throw cause;
    return { path: fallback, sourcePath: text };
  }
};

const memberStream = (entry: ArtifactEntry): Transform => {
  let bytes = 0;
  return new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      bytes += chunk.length;
      callback(null, chunk);
    },
    flush(callback) {
      callback(
        bytes === entry.declaredSize
          ? null
          : bunFormatFailure(`member ended early: ${entry.path}`),
      );
    },
  });
};

const entryMetadataJson = (entry: ArtifactEntry): JsonValue =>
  entry.formatMetadata === undefined ? null : { ...entry.formatMetadata };

const admissionFailure = (
  cause: unknown,
  path: string,
): ArtifactReaderFailure => {
  if (cause instanceof ArtifactReaderFailure) return cause;
  if (cause instanceof RegularFileOperationCancelled)
    return new ArtifactReaderFailure(
      "cancelled",
      "Bun standalone admission cancelled",
      { cause: cause.reason },
    );
  if (cause instanceof NonRegularFileReadError)
    return new ArtifactReaderFailure(
      "format",
      `Bun standalone source is not a regular file: ${path}`,
      { cause },
    );
  return new ArtifactReaderFailure(
    "io",
    cause instanceof Error
      ? cause.message
      : `Cannot admit Bun standalone source: ${path}`,
    { cause },
  );
};
