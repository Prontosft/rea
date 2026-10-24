import { ArtifactReaderFailure } from "../ArtifactReader.js";
import {
  BUN_RECORD_BYTES_1_3_3,
  BUN_RECORD_BYTES_1_3_9,
  MAX_BUN_MODULE_COUNT,
  MAX_BUN_RETAINED_BYTES,
  bunRetainedBytesLimit,
  bunFormatFailure,
  bunModuleCountLimit,
  readPointer,
  type BunLayoutRevision,
  type BunStringPointer,
  type LocatedBunGraph,
} from "./BunModuleGraphLayout.js";

/**
 * Loader discriminants are append-only in Bun 1.4.4 `src/ast/loader.rs`.
 * Unknown ids stay raw. The stale C header value for TOML is not used.
 */
const LOADERS = [
  "jsx",
  "js",
  "ts",
  "tsx",
  "css",
  "file",
  "json",
  "jsonc",
  "toml",
  "wasm",
  "napi",
  "base64",
  "dataurl",
  "text",
  "bunsh",
  "sqlite",
  "sqlite-embedded",
  "html",
  "yaml",
  "json5",
  "md",
  "xml",
] as const;

const MODULE_FORMATS = ["none", "esm", "cjs"] as const;
const SIDES = ["server", "client"] as const;

export interface BunTextFact {
  readonly text: string | null;
  readonly hex: string | null;
}

export interface BunByteRange {
  readonly offset: number;
  readonly length: number;
}

export interface BunDecodedModule {
  readonly index: number;
  readonly name: Buffer;
  readonly nameText: BunTextFact;
  readonly contents: BunByteRange;
  readonly sourcemap: BunByteRange | null;
  readonly bytecode: BunByteRange | null;
  readonly moduleInfo: BunByteRange | null;
  readonly bytecodeOrigin: BunTextFact | null;
  readonly encoding: number;
  readonly encodingName: string | null;
  readonly loader: number;
  readonly loaderName: string | null;
  readonly moduleFormat: number;
  readonly moduleFormatName: string | null;
  readonly side: number;
  readonly sideName: string | null;
}

export interface BunDecodedGraph {
  readonly revision: BunLayoutRevision;
  readonly entryPointId: number;
  readonly flags: number;
  readonly compileExecArgv: BunTextFact;
  readonly modules: readonly BunDecodedModule[];
}

/**
 * Admit a module count. Exported so the ceiling can be checked without
 * building a graph larger than the retained-bytes budget.
 */
export const admitBunModuleCount = (count: number): void => {
  if (!Number.isSafeInteger(count) || count < 0)
    throw bunFormatFailure("module count is not a safe integer");
  if (count > MAX_BUN_MODULE_COUNT) throw bunModuleCountLimit(count);
};

/**
 * Decode one located payload. Record size is selected by which known layout
 * is structurally valid. An unknown or ambiguous size is unsupported, not a
 * malformed graph. Flag bits stay raw: Bun 1.3 and 1.4 reuse the low bits.
 */
export const decodeBunModuleGraph = (
  graph: LocatedBunGraph,
): BunDecodedGraph => {
  const { data } = graph;
  const table = graph.modules;
  if (!pointerFits(data, table))
    throw bunFormatFailure("modules pointer exceeds the Bun module graph");
  if (table.length === 0) throw unsupported("the module table is empty");
  const candidates = recordSizes(table.length);
  if (candidates.length === 0)
    throw unsupported(
      `record table length ${String(table.length)} matches no known revision`,
    );
  const assessments = candidates.map((recordBytes) => ({
    recordBytes,
    failure: assessLayout(data, table, recordBytes, graph.entryPointId),
  }));
  const valid = assessments.filter((item) => item.failure === null);
  if (valid.length > 1)
    throw unsupported(
      `record table length ${String(table.length)} matches more than one known revision`,
    );
  const selected = valid[0] ?? assessments[0];
  if (selected === undefined || selected.failure !== null)
    throw (
      selected?.failure ??
      unsupported(
        `record table length ${String(table.length)} matches no known revision`,
      )
    );
  const count = table.length / selected.recordBytes;
  admitBunModuleCount(count);
  const revision: BunLayoutRevision =
    selected.recordBytes === BUN_RECORD_BYTES_1_3_9 ? "bun-1.3.9" : "bun-1.3.3";
  if (!pointerFits(data, graph.compileExecArgv))
    throw bunFormatFailure(
      "compile_exec_argv pointer exceeds the Bun module graph",
    );
  const records = data.subarray(table.offset, table.offset + table.length);
  const modules: BunDecodedModule[] = [];
  // Bound repeated pointer expansion before decoding strings. JSON escaping and
  // UTF-16 strings can expand each source byte; aliased names count per record.
  let retained = graph.compileExecArgv.length * 6;
  if (retained > MAX_BUN_RETAINED_BYTES) throw bunRetainedBytesLimit(retained);
  for (let index = 0; index < count; index += 1) {
    const record = records.subarray(
      index * selected.recordBytes,
      (index + 1) * selected.recordBytes,
    );
    retained += 512 + readPointer(record, 0).length * 6;
    if (selected.recordBytes === BUN_RECORD_BYTES_1_3_9)
      retained += readPointer(record, 40).length * 6;
    if (retained > MAX_BUN_RETAINED_BYTES)
      throw bunRetainedBytesLimit(retained);
    modules.push(decodeRecord(data, record, index, revision));
  }
  return {
    revision,
    entryPointId: graph.entryPointId,
    flags: graph.flags,
    compileExecArgv: textFact(
      readNul(data, graph.compileExecArgv, "compile_exec_argv"),
      true,
    ),
    modules,
  };
};

const recordSizes = (length: number): readonly number[] => {
  const sizes: number[] = [];
  if (length % BUN_RECORD_BYTES_1_3_3 === 0) sizes.push(BUN_RECORD_BYTES_1_3_3);
  if (length % BUN_RECORD_BYTES_1_3_9 === 0) sizes.push(BUN_RECORD_BYTES_1_3_9);
  return sizes;
};

const assessLayout = (
  data: Buffer,
  table: BunStringPointer,
  recordBytes: number,
  entryPointId: number,
): ArtifactReaderFailure | null => {
  const count = table.length / recordBytes;
  if (count > MAX_BUN_MODULE_COUNT) return bunModuleCountLimit(count);
  const records = data.subarray(table.offset, table.offset + table.length);
  for (let index = 0; index < count; index += 1) {
    const record = records.subarray(
      index * recordBytes,
      (index + 1) * recordBytes,
    );
    const failure = recordPointerFailure(data, record, recordBytes);
    if (failure !== null) return failure;
  }
  if (entryPointId >= count)
    return bunFormatFailure(
      `entry_point_id ${String(entryPointId)} is outside the module table`,
    );
  return null;
};

const recordPointerFailure = (
  data: Buffer,
  record: Buffer,
  recordBytes: number,
): ArtifactReaderFailure | null => {
  const fields: readonly (readonly [number, boolean, string])[] =
    recordBytes === BUN_RECORD_BYTES_1_3_9
      ? [
          [0, true, "name"],
          [8, true, "contents"],
          [16, false, "sourcemap"],
          [24, false, "bytecode"],
          [32, false, "module_info"],
          [40, true, "bytecode_origin"],
        ]
      : [
          [0, true, "name"],
          [8, true, "contents"],
          [16, false, "sourcemap"],
          [24, false, "bytecode"],
        ];
  for (const [offset, nul, label] of fields) {
    const failure = pointerFailure(
      data,
      readPointer(record, offset),
      nul,
      label,
    );
    if (failure !== null) return failure;
  }
  return null;
};

const decodeRecord = (
  data: Buffer,
  record: Buffer,
  index: number,
  revision: BunLayoutRevision,
): BunDecodedModule => {
  const wide = revision === "bun-1.3.9";
  const metadataAt = wide ? 48 : 32;
  const encoding = record[metadataAt] ?? 0;
  const loader = record[metadataAt + 1] ?? 0;
  const moduleFormat = record[metadataAt + 2] ?? 0;
  const side = record[metadataAt + 3] ?? 0;
  const name = readNul(data, readPointer(record, 0), "name");
  const contents = readPointer(record, 8);
  const sourcemap = optionalRange(readPointer(record, 16));
  const bytecode = optionalRange(readPointer(record, 24));
  const moduleInfo = wide ? optionalRange(readPointer(record, 32)) : null;
  const origin = wide
    ? textFact(readNul(data, readPointer(record, 40), "bytecode_origin"), false)
    : null;
  // Discriminant 2 was an unused Utf8 slot. Bun 1.4.4 reuses it, on the
  // 52-byte record only, for little-endian UTF-16. No version discriminator
  // distinguishes these meanings, so keep the wide layout value unnamed.
  const encodingName =
    encoding === 2
      ? wide
        ? null
        : "utf8"
      : named(["binary", "latin1"], encoding);
  return {
    index,
    name,
    nameText: textFact(name, true),
    contents: { offset: contents.offset, length: contents.length },
    sourcemap,
    bytecode,
    moduleInfo,
    bytecodeOrigin:
      origin === null || (origin.text === null && origin.hex === null)
        ? null
        : origin,
    encoding,
    encodingName,
    loader,
    loaderName: named(LOADERS, loader),
    moduleFormat,
    moduleFormatName: named(MODULE_FORMATS, moduleFormat),
    side,
    sideName: named(SIDES, side),
  };
};

const optionalRange = (pointer: BunStringPointer): BunByteRange | null =>
  pointer.length === 0
    ? null
    : { offset: pointer.offset, length: pointer.length };

const named = (table: readonly string[], value: number): string | null =>
  table[value] ?? null;

const textFact = (bytes: Buffer, emptyIsText: boolean): BunTextFact => {
  if (bytes.length === 0)
    return emptyIsText ? { text: "", hex: null } : { text: null, hex: null };
  const text = bytes.toString("utf8");
  if (Buffer.from(text, "utf8").equals(bytes)) return { text, hex: null };
  return { text: null, hex: bytes.toString("hex") };
};

const readNul = (
  data: Buffer,
  pointer: BunStringPointer,
  label: string,
): Buffer => {
  const failure = pointerFailure(data, pointer, true, label);
  if (failure !== null) throw failure;
  return Buffer.from(
    data.subarray(pointer.offset, pointer.offset + pointer.length),
  );
};

const pointerFits = (data: Buffer, pointer: BunStringPointer): boolean =>
  pointer.offset <= data.length &&
  pointer.offset + pointer.length <= data.length;

const pointerFailure = (
  data: Buffer,
  pointer: BunStringPointer,
  nul: boolean,
  label: string,
): ArtifactReaderFailure | null => {
  const end = pointer.offset + pointer.length;
  if (pointer.offset > data.length || end > data.length)
    return bunFormatFailure(`${label} pointer exceeds the Bun module graph`);
  if (!nul || pointer.length === 0) return null;
  if (end >= data.length)
    return bunFormatFailure(`${label} pointer exceeds the Bun module graph`);
  if (data[end] !== 0)
    return bunFormatFailure(`${label} is missing its terminating NUL`);
  return null;
};

const unsupported = (detail: string): ArtifactReaderFailure =>
  new ArtifactReaderFailure(
    "unavailable",
    `Bun standalone module graph layout is unsupported: ${detail}`,
  );
