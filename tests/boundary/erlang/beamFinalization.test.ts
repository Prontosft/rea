import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it, vi } from "vitest";
import { createBeamService } from "../../../src/composition/erlang.js";
import { OwnedFileHandle } from "../../../src/filesystem/OwnedFileHandle.js";
import { projectAnalysisError } from "../../../src/domain/analysisErrorProjection.js";
import { erlangBeamFixture } from "../../../src/erlang/Beam.fixture.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

it.each(["control", "close-failure", "close-cancel", "close-both"] as const)(
  "retains completed BEAM acquisition through %s",
  async (mode) => {
    const root = await createTestTempDirectory("rea-beam-finalization-");
    const path = join(root, "selected.beam");
    const bytes = erlangBeamFixture();
    await writeFile(path, bytes);
    const controller = new AbortController();
    const reason = { request: "cancel during BEAM close" };
    const closeFailure = Object.assign(new Error("controlled BEAM close EIO"), {
      code: "EIO",
    });
    const original = OwnedFileHandle.prototype.close;
    let owner: OwnedFileHandle | undefined;
    const close = vi
      .spyOn(OwnedFileHandle.prototype, "close")
      .mockImplementationOnce(async function (this: OwnedFileHandle) {
        owner = this;
        if (mode === "close-cancel" || mode === "close-both")
          controller.abort(reason);
        if (mode === "close-failure" || mode === "close-both")
          throw closeFailure;
        await original.call(this);
      });
    const service = createBeamService();
    try {
      const result = await service.inspect(
        { path },
        { signal: controller.signal },
      );
      if (mode === "control") {
        if (!result.ok) throw result.error;
        expect(result.value.normalized_result).toMatchObject({
          artifact: { path, bytes: bytes.length },
        });
      } else {
        if (result.ok) throw new Error("Expected finalization failure");
        const acquired = {
          kind: "file-snapshot-hash",
          path,
          sha256: createHash("sha256").update(bytes).digest("hex"),
          bytes: bytes.length,
        };
        expect(result.error.partialObservation).toEqual(acquired);
        expect(
          projectAnalysisError(result.error).details?.partial_observation,
        ).toEqual(acquired);
        const failedClose = mode === "close-failure" || mode === "close-both";
        expect(result.error.cleanupIncomplete).toBe(failedClose);
        if (failedClose) expect(owner?.handle.fd).toBeGreaterThanOrEqual(0);
        if (mode !== "close-failure") {
          const primary = result.error.cleanupPrimary ?? result.error;
          expect(primary).toMatchObject({
            _tag: "AnalysisCancelledError",
            cause: reason,
          });
        }
        close.mockRestore();
        await service.close();
        expect(result.error.cleanupIncomplete).toBe(false);
      }
      expect(owner?.handle.fd).toBe(-1);
    } finally {
      close.mockRestore();
      await service.close();
    }
  },
);
