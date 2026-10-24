import { open, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it } from "vitest";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";
import {
  locateBunStandaloneGraph,
  MAX_BUN_MODULE_COUNT,
  BUN_GRAPH_SUFFIX_BYTES,
} from "./BunModuleGraphLayout.js";
import {
  decodeBunModuleGraph,
  admitBunModuleCount,
} from "./BunModuleGraphMembers.js";
import {
  bunModuleGraphPayload,
  bunPrefixedPayload,
  machoBunSection,
  machoBunSections,
  peBunSection,
  elfBunSection,
  elfAppendedBunPayload,
} from "./BunStandalone.fixture.js";

async function locate(bytes: Buffer) {
  const path = join(await createTestTempDirectory("rea-bun-parser-"), "app");
  await writeFile(path, bytes);
  const handle = await open(path, "r");
  try {
    return await locateBunStandaloneGraph(handle, bytes.length);
  } finally {
    await handle.close();
  }
}

it.each([
  ["Mach-O", machoBunSection],
  ["PE", peBunSection],
  ["ELF", elfBunSection],
] as const)(
  "decodes section carrier %s with preserved names and auxiliary regions",
  async (_name, carrier) => {
    const result = await locate(
      carrier(
        bunPrefixedPayload(
          bunModuleGraphPayload({
            modules: [
              {
                name: "/$bunfs/root/main.js",
                contents: Buffer.from("hello"),
                sourcemap: Buffer.from("map"),
                bytecode: Buffer.from([1]),
              },
            ],
            compileExecArgv: "--smol",
          }),
        ),
      ),
    );
    expect(result.status).toBe("present");
    if (result.status !== "present" || !result.graph)
      throw new Error("missing graph");
    const decoded = decodeBunModuleGraph(result.graph);
    expect(decoded.compileExecArgv.text).toBe("--smol");
    expect(decoded.modules[0]).toMatchObject({
      nameText: { text: "/$bunfs/root/main.js" },
      contents: { length: 5 },
      sourcemap: { length: 3 },
      bytecode: { length: 1 },
    });
  },
);

it.each([0, 16])(
  "decodes legacy Mach-O four-byte prefixes with %s padding bytes",
  async (padding) => {
    const payload = bunModuleGraphPayload({
      revision: "bun-1.3.3",
      modules: [
        { name: "/$bunfs/root/main.js", contents: Buffer.from("hello") },
      ],
    });
    const prefix = Buffer.alloc(4);
    prefix.writeUInt32LE(payload.length);
    const bytes = machoBunSection(
      Buffer.concat([prefix, payload, Buffer.alloc(padding)]),
    );
    const result = await locate(bytes);
    if (result.status !== "present" || !result.graph)
      throw new Error("missing graph");
    expect(result.graph.carrier).toBe("mach-o-section");
    expect(result.graph.payloadOffset).toBe(
      bytes.length - padding - payload.length,
    );
    expect(result.graph.payloadLength).toBe(payload.length);
    const module = decodeBunModuleGraph(result.graph).modules[0]!;
    expect(module.nameText.text).toBe("/$bunfs/root/main.js");
    expect(
      result.graph.data
        .subarray(
          module.contents.offset,
          module.contents.offset + module.contents.length,
        )
        .toString(),
    ).toBe("hello");
  },
);

it.each(["trailer", "byte_count"])(
  "rejects legacy Mach-O prefixes with invalid %s",
  async (field) => {
    const payload = bunModuleGraphPayload({
      revision: "bun-1.3.3",
      modules: [{ name: "/$bunfs/root/main.js" }],
    });
    if (field === "trailer") payload[payload.length - 1] = 0;
    else payload.writeBigUInt64LE(0n, payload.length - BUN_GRAPH_SUFFIX_BYTES);
    const prefix = Buffer.alloc(4);
    prefix.writeUInt32LE(payload.length);
    expect(
      await locate(machoBunSection(Buffer.concat([prefix, payload]))),
    ).toMatchObject({ status: "present", failure: expect.anything() });
  },
);

it.each(["bun-1.3.3", "bun-1.3.9"] as const)(
  "decodes appended %s and retains duplicate names",
  async (revision) => {
    const result = await locate(
      elfAppendedBunPayload(
        bunModuleGraphPayload({
          revision,
          modules: [{ name: "same" }, { name: "same" }],
        }),
      ),
    );
    if (result.status !== "present" || !result.graph)
      throw new Error("missing graph");
    expect(
      decodeBunModuleGraph(result.graph).modules.map((m) => m.nameText.text),
    ).toEqual(["same", "same"]);
  },
);

it.each([
  [
    { modules: [{ contentsPointer: { offset: 99999, length: 1 } }] },
    "pointer exceeds",
  ],
  [{ modules: [{}], tableLength: 53 }, "unsupported"],
  [
    { modules: [{ loader: 0, moduleFormat: 0 }], tableLength: 468 },
    "more than one known revision",
  ],
  [{ modules: [{}], entryPointId: 8 }, "entry_point_id"],
])("fails closed for invalid module declarations", async (input, reason) => {
  const result = await locate(
    elfAppendedBunPayload(bunModuleGraphPayload(input)),
  );
  if (result.status !== "present" || !result.graph)
    throw new Error("missing graph");
  const graph = result.graph;
  expect(() => decodeBunModuleGraph(graph)).toThrow(reason);
});

it("recognizes a truncated section as malformed and enforces module admission", async () => {
  const section = bunPrefixedPayload(bunModuleGraphPayload({ modules: [{}] }));
  const result = await locate(
    machoBunSection(section.subarray(0, section.length - 1)),
  );
  expect(result).toMatchObject({
    status: "present",
    failure: { reason: "format" },
  });
  expect(() => admitBunModuleCount(MAX_BUN_MODULE_COUNT + 1)).toThrow(
    "MAX_BUN_MODULE_COUNT",
  );
});

it("locates the legacy trailer before its final carrier length", async () => {
  const bytes = elfAppendedBunPayload(
    bunModuleGraphPayload({ modules: [{ name: "main.js" }] }),
  );
  const length = Buffer.alloc(8);
  length.writeBigUInt64LE(BigInt(bytes.length + 8));
  const result = await locate(Buffer.concat([bytes, length]));
  if (result.status !== "present" || !result.graph)
    throw new Error("missing graph");
  expect(decodeBunModuleGraph(result.graph).modules).toHaveLength(1);
});

it("does not admit oversized payloads or truncated length prefixes", async () => {
  const prefix = Buffer.alloc(8);
  prefix.writeBigUInt64LE(300n * 1024n * 1024n);
  expect(await locate(machoBunSection(prefix))).toMatchObject({
    status: "present",
    failure: { reason: "limit" },
  });
  expect(await locate(machoBunSection(Buffer.from([1])))).toMatchObject({
    status: "present",
    failure: { reason: "format" },
  });
  expect(await locate(machoBunSection(Buffer.alloc(8)))).toEqual({
    status: "absent",
  });
});

it("refuses multiple embedded graphs instead of selecting one", async () => {
  const section = bunPrefixedPayload(bunModuleGraphPayload({ modules: [{}] }));
  expect(await locate(machoBunSections([section, section]))).toMatchObject({
    status: "present",
    failure: { reason: "unavailable" },
  });
});
