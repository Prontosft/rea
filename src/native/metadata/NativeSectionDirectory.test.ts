import { expect, it } from "vitest";
import { pe } from "../../domain/binaryTarget.fixture.js";
import { BinaryFormatFailure } from "./BinaryContainer.js";
import { readNativeDirectoryFromBuffer } from "./NativeSectionDirectory.js";

it("classifies a confirmed overlapping PE section directory as an unsupported layout", () => {
  try {
    readNativeDirectoryFromBuffer(pe(0x014c, 4), "pe");
    throw new Error("Expected an unsupported PE layout");
  } catch (cause) {
    expect(cause).toBeInstanceOf(BinaryFormatFailure);
    expect(cause).toMatchObject({ kind: "unsupported" });
    expect((cause as Error).message).toContain("overlapping PE header");
  }
});
