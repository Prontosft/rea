import { describe, expect, it } from "vitest";
import { gzipSync } from "node:zlib";
import { mkdtemp, open, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { GzipArtifactReader } from "./GzipArtifactReader.js";

describe("GzipArtifactReader", () => {
  it("extracts and streams compressed content correctly", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "rea-gzip-test-"));
    const gzipPath = join(tempDir, "solve_me.gz");
    const payload = Buffer.from("ELF binary test payload for CTF challenge");
    const compressed = gzipSync(payload);

    await writeFile(gzipPath, compressed);

    const reader = new GzipArtifactReader(gzipPath);
    expect(reader.format).toBe("gzip");

    const entries = [];
    for await (const entry of reader.entries()) {
      entries.push(entry);
    }

    expect(entries).toHaveLength(1);
    expect(entries[0]!.path).toBe("solve_me");
    expect(entries[0]!.kind).toBe("file");
    expect(entries[0]!.executable).toBe(false);
    expect(entries[0]!.declaredSize).toBeNull();

    const stream = await reader.open(entries[0]!);
    const chunks: Buffer[] = [];
    for await (const chunk of stream) {
      chunks.push(Buffer.from(chunk));
    }
    const result = Buffer.concat(chunks);
    expect(result.toString("utf-8")).toBe(
      "ELF binary test payload for CTF challenge",
    );

    await reader.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  it("falls back to decompressed_payload when archive basename is literally .gz", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "rea-gzip-dot-test-"));
    const gzipPath = join(tempDir, ".gz");
    await writeFile(gzipPath, gzipSync(Buffer.from("payload")));

    const reader = new GzipArtifactReader(gzipPath);
    const entries = [];
    for await (const entry of reader.entries()) {
      entries.push(entry);
    }

    expect(entries).toHaveLength(1);
    expect(entries[0]!.path).toBe("decompressed_payload");

    await reader.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  it("extracts FNAME when preceded by a large FEXTRA field exceeding 512 bytes", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "rea-gzip-fextra-test-"));
    const gzipPath = join(tempDir, "carrier.gz");
    const baseCompressed = gzipSync(Buffer.from("inner payload"));
    const extraLen = 1024;
    const extraField = Buffer.alloc(2 + extraLen, 0x41);
    extraField.writeUInt16LE(extraLen, 0);
    const fname = Buffer.from("embedded_payload.bin\0", "latin1");

    const header = Buffer.from(baseCompressed.subarray(0, 10));
    header[3] = 0x04 | 0x08; // FEXTRA | FNAME
    const customGzip = Buffer.concat([
      header,
      extraField,
      fname,
      baseCompressed.subarray(10),
    ]);
    await writeFile(gzipPath, customGzip);

    const reader = new GzipArtifactReader(gzipPath);
    const entries = [];
    for await (const entry of reader.entries()) {
      entries.push(entry);
    }

    expect(entries).toHaveLength(1);
    expect(entries[0]!.path).toBe("embedded_payload.bin");
    expect(entries[0]!.limitations).toEqual([]);

    await reader.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  it("records a limitation and partial coverage when FNAME is unsafe or unterminated", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "rea-gzip-unsafe-fname-"));
    for (const badName of [
      "../evil.bin\0",
      "C:/payload.bin\0",
      "dir\\payload.bin\0",
    ]) {
      const gzipPath = join(tempDir, "archive.gz");
      const baseCompressed = gzipSync(Buffer.from("inner payload"));
      const header = Buffer.from(baseCompressed.subarray(0, 10));
      header[3] = 0x08; // FNAME
      const unsafeFname = Buffer.from(badName, "latin1");
      await writeFile(
        gzipPath,
        Buffer.concat([header, unsafeFname, baseCompressed.subarray(10)]),
      );

      const reader = new GzipArtifactReader(gzipPath);
      const coverages: unknown[] = [];
      const entries = [];
      for await (const entry of reader.entries(undefined, {
        onCoverage: (cov) => coverages.push(cov),
      })) {
        entries.push(entry);
      }

      expect(entries).toHaveLength(1);
      expect(entries[0]!.path).toBe("archive");
      expect(entries[0]!.limitations[0]).toMatch(/unsafe or empty path/);
      expect(coverages).toEqual([
        {
          status: "complete",
          limitations: entries[0]!.limitations,
        },
      ]);

      await reader.close();
    }
    await rm(tempDir, { recursive: true, force: true });
  });

  it("normalizes carrier-derived fallback names that fail artifact path validation", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "rea-gzip-carrier-fallback-"));
    const backingPath = join(tempDir, "carrier.gz");
    await writeFile(backingPath, gzipSync(Buffer.from("payload")));
    const handle = await open(backingPath, "r");
    try {
      const initial = await handle.stat();
      for (const unsafeCarrierPath of [
        "/tmp/...gz",
        "/tmp/..gz",
        "/tmp/\0bad.gz",
        "/tmp/\0bad",
      ]) {
        const reader = new GzipArtifactReader(unsafeCarrierPath, {
          handle,
          initial,
        });
        const entries = [];
        for await (const entry of reader.entries()) {
          entries.push(entry);
        }
        expect(entries).toHaveLength(1);
        expect(entries[0]!.path).toBe("decompressed_payload");
        await reader.close();
      }
    } finally {
      await handle.close();
      await rm(tempDir, { recursive: true, force: true });
    }
  });
});
