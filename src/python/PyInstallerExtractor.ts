import zlib from "node:zlib";
import {
  buildPythonBytecodeHeader,
  isPythonBytecode,
  resolvePythonVersion,
} from "./PythonBytecode.js";
import { readMarshalSubset } from "../artifacts/pyinstaller/MarshalSubset.js";
import {
  isCArchiveDeclaration,
  MAX_TOC_BYTES,
  MAX_TOC_ENTRIES,
  parseCArchiveCookieAt,
  PYINSTALLER_COOKIE_SEARCH_BYTES,
  PYINSTALLER_COOKIE_V20_BYTES,
  PYINSTALLER_COOKIE_V21_BYTES,
} from "../artifacts/pyinstaller/CArchiveLayout.js";
import { MAX_PYZ_TABLE_BYTES } from "../artifacts/pyinstaller/PyzArchive.js";
import { artifactExpansionBudgetBytes } from "../domain/artifactExpansionBudget.js";

/** PyInstaller standard cookie signature: b'MEI\x0c\x0b\x0a\x0b\x0e' */
export const PYINSTALLER_MAGIC = Buffer.from([
  0x4d, 0x45, 0x49, 0x0c, 0x0b, 0x0a, 0x0b, 0x0e,
]);

/** PyInstaller legacy cookie signature: b'MEI\x12\x13\x14\x13\x16' */
export const PYINSTALLER_OLD_MAGIC = Buffer.from([
  0x4d, 0x45, 0x49, 0x12, 0x13, 0x14, 0x13, 0x16,
]);

/** Embedded PYZ archive magic: b'PYZ\0' */
export const PYZ_MAGIC = Buffer.from([0x50, 0x59, 0x5a, 0x00]);

export interface PyInstallerCookie {
  readonly offset: number;
  readonly magic: Buffer;
  readonly pkgLength: number;
  readonly tocOffset: number;
  readonly tocLength: number;
  readonly pythonVersion: number;
  readonly pythonLibName: string;
  readonly layout?: "2.0" | "2.1" | undefined;
}

export interface PyInstallerTocEntry {
  readonly name: string;
  readonly typeFlag: string;
  readonly compressionFlag: number;
  readonly pkgOffset: number;
  readonly compressedLength: number;
  readonly uncompressedLength: number;
}

export interface PyzModuleEntry {
  readonly name: string;
  readonly typeCode: number;
  readonly isPackage: boolean;
  readonly dataOffset: number;
  readonly dataLength: number;
}

export interface PyzArchive {
  readonly magic: Buffer;
  readonly pycMagic: number;
  readonly pythonVersion: string;
  readonly tocOffset: number;
  readonly modules: readonly PyzModuleEntry[];
  readonly limitations?: readonly string[] | undefined;
}

export interface PyInstallerArchive {
  readonly cookie: PyInstallerCookie;
  readonly carchiveOffset: number;
  readonly tocEntries: readonly PyInstallerTocEntry[];
  readonly embeddedPyz?: PyzArchive | undefined;
}

export interface ExtractedPyInstallerFile {
  readonly name: string;
  readonly kind:
    | "script"
    | "module"
    | "package"
    | "pyz"
    | "binary"
    | "data"
    | "metadata";
  readonly data: Buffer;
  readonly decompressed: boolean;
  readonly pythonVersion?: string | undefined;
  readonly limitations: readonly string[];
}

/** Check if binary buffer contains PyInstaller cookie. */
export const isPyInstallerBinary = (buffer: Buffer): boolean => {
  return findPyInstallerCookie(buffer) !== null;
};

const scanCookieWithMagic = (
  tail: Buffer,
  tailStart: number,
  fileSize: number,
  magic: Buffer,
): PyInstallerCookie | null => {
  let from = tail.length;
  while (from >= magic.length) {
    const relative = tail.subarray(0, from).lastIndexOf(magic);
    if (relative < 0) break;
    const cookieOffset = tailStart + relative;
    const parsed = parseCArchiveCookieAt(
      tail,
      relative,
      cookieOffset,
      fileSize,
    );
    if (parsed.ok) {
      return {
        offset: cookieOffset,
        magic,
        pkgLength: parsed.value.packageLength,
        tocOffset: parsed.value.tocOffset,
        tocLength: parsed.value.tocLength,
        pythonVersion: tail.readInt32BE(relative + 20),
        pythonLibName: parsed.value.pythonLibrary ?? "",
        layout: parsed.value.layout,
      };
    }
    from = relative;
  }
  return null;
};

/** Scan binary buffer backwards to locate a structurally valid PyInstaller CArchive cookie. */
export const findPyInstallerCookie = (
  buffer: Buffer,
): PyInstallerCookie | null => {
  if (buffer.length < PYINSTALLER_COOKIE_V20_BYTES) return null;
  const tailSize = Math.min(buffer.length, PYINSTALLER_COOKIE_SEARCH_BYTES);
  const tailStart = buffer.length - tailSize;
  const tail = buffer.subarray(tailStart);

  return (
    scanCookieWithMagic(tail, tailStart, buffer.length, PYINSTALLER_MAGIC) ??
    scanCookieWithMagic(tail, tailStart, buffer.length, PYINSTALLER_OLD_MAGIC)
  );
};

/** Parse Table of Contents and structure from a PyInstaller executable buffer. */
export const parsePyInstallerArchive = (
  buffer: Buffer,
): PyInstallerArchive | null => {
  const cookie = findPyInstallerCookie(buffer);
  if (!cookie) return null;

  const cookieBytes =
    cookie.layout === "2.0"
      ? PYINSTALLER_COOKIE_V20_BYTES
      : cookie.layout === "2.1"
        ? PYINSTALLER_COOKIE_V21_BYTES
        : cookie.pkgLength ===
            cookie.tocOffset + cookie.tocLength + PYINSTALLER_COOKIE_V20_BYTES
          ? PYINSTALLER_COOKIE_V20_BYTES
          : PYINSTALLER_COOKIE_V21_BYTES;
  const carchiveOffset = cookie.offset + cookieBytes - cookie.pkgLength;
  if (carchiveOffset < 0 || carchiveOffset + cookie.pkgLength > buffer.length) {
    return null;
  }

  const absoluteTocOffset = carchiveOffset + cookie.tocOffset;
  if (
    cookie.tocLength > MAX_TOC_BYTES ||
    absoluteTocOffset < 0 ||
    absoluteTocOffset + cookie.tocLength > buffer.length
  ) {
    return null;
  }

  const tocEntries: PyInstallerTocEntry[] = [];
  let currentOffset = absoluteTocOffset;
  const endOffset = absoluteTocOffset + cookie.tocLength;

  while (
    currentOffset + 18 <= endOffset &&
    currentOffset + 18 <= buffer.length
  ) {
    if (tocEntries.length >= MAX_TOC_ENTRIES) {
      return null;
    }
    const entryStructLen = buffer.readUInt32BE(currentOffset);
    if (
      entryStructLen < 18 ||
      currentOffset + entryStructLen > endOffset ||
      currentOffset + entryStructLen > buffer.length
    ) {
      break;
    }

    const pkgOffset = buffer.readUInt32BE(currentOffset + 4);
    const compressedLength = buffer.readUInt32BE(currentOffset + 8);
    const uncompressedLength = buffer.readUInt32BE(currentOffset + 12);
    const compressionFlag = buffer.readUInt8(currentOffset + 16);
    const typeFlag = String.fromCharCode(buffer.readUInt8(currentOffset + 17));

    const nameRaw = buffer.subarray(
      currentOffset + 18,
      currentOffset + entryStructLen,
    );
    const name = nameRaw.toString("utf8").replace(/\0.*$/s, "");

    tocEntries.push({
      name,
      typeFlag,
      compressionFlag,
      pkgOffset,
      compressedLength,
      uncompressedLength,
    });

    currentOffset += entryStructLen;
  }

  // Find embedded PYZ if present
  let embeddedPyz: PyzArchive | undefined;
  const pyzEntry = tocEntries.find(
    (e) => e.typeFlag === "z" || e.name.toLowerCase().endsWith(".pyz"),
  );
  if (pyzEntry) {
    const pyzDataOffset = carchiveOffset + pyzEntry.pkgOffset;
    if (
      pyzEntry.pkgOffset >= 0 &&
      pyzEntry.compressedLength >= 0 &&
      pyzDataOffset + pyzEntry.compressedLength <= absoluteTocOffset &&
      pyzDataOffset + pyzEntry.compressedLength <= buffer.length
    ) {
      const rawPyz = buffer.subarray(
        pyzDataOffset,
        pyzDataOffset + pyzEntry.compressedLength,
      );
      const inflatedPyz = inflatePayload(
        rawPyz,
        pyzEntry.compressionFlag,
        MAX_PER_ENTRY_BYTES,
        pyzEntry.uncompressedLength,
      );
      if (inflatedPyz.decompressed) {
        embeddedPyz = parsePyzArchive(inflatedPyz.data) ?? undefined;
      }
    }
  }

  return {
    cookie,
    carchiveOffset,
    tocEntries,
    embeddedPyz,
  };
};

/** Parse embedded PYZ archive header and its marshaled module table. */
export const parsePyzArchive = (pyzBuffer: Buffer): PyzArchive | null => {
  if (pyzBuffer.length < 12) return null;
  const magic = pyzBuffer.subarray(0, 4);
  if (!magic.equals(PYZ_MAGIC)) return null;

  const pycMagic = pyzBuffer.readUInt16LE(4);
  const pythonVersion = resolvePythonVersion(pycMagic);
  const tocOffset = pyzBuffer.readUInt32BE(8);

  if (tocOffset < 12 || tocOffset > pyzBuffer.length) return null;

  const modules: PyzModuleEntry[] = [];
  const limitations: string[] = [];
  const table = pyzBuffer.subarray(tocOffset);
  if (table.length > MAX_PYZ_TABLE_BYTES) {
    limitations.push(
      `PYZ table size (${table.length} bytes) exceeds maximum in-memory table budget of ${MAX_PYZ_TABLE_BYTES} bytes; module list omitted.`,
    );
  } else {
    const marshalled = readMarshalSubset(table);
    if (marshalled.ok && Array.isArray(marshalled.value)) {
      let nameBytes = 0;
      for (const item of marshalled.value) {
        if (!Array.isArray(item) || item.length !== 2) continue;
        const [rawName, position] = item;
        if (
          typeof rawName !== "string" ||
          !Array.isArray(position) ||
          position.length !== 3
        )
          continue;
        const [typeCode, dataOffset, dataLength] = position;
        if (
          typeof typeCode !== "number" ||
          typeof dataOffset !== "number" ||
          typeof dataLength !== "number" ||
          !Number.isSafeInteger(typeCode) ||
          !Number.isSafeInteger(dataOffset) ||
          !Number.isSafeInteger(dataLength)
        )
          continue;

        nameBytes += Buffer.byteLength(rawName, "utf8");
        if (nameBytes > table.length) break;

        if (
          typeCode >= 0 &&
          typeCode <= 3 &&
          dataOffset >= 0 &&
          dataLength >= 0 &&
          dataOffset <= tocOffset &&
          dataLength <= tocOffset - dataOffset
        ) {
          modules.push({
            name: rawName,
            typeCode,
            isPackage: typeCode === 1 || typeCode === 3,
            dataOffset,
            dataLength,
          });
        }
      }
    }
  }

  return {
    magic,
    pycMagic,
    pythonVersion,
    tocOffset,
    modules,
    ...(limitations.length > 0 ? { limitations } : {}),
  };
};

export const MAX_PER_ENTRY_BYTES = 64 * 1024 * 1024; // 64 MiB per entry limit

const isExpansionLimitError = (error?: string): boolean => {
  if (!error) return false;
  return /budget|maxoutputlength|buffer too large|err_buffer_too_large/i.test(
    error,
  );
};

const inflatePayload = (
  raw: Buffer,
  flag: number,
  maxOutputBytes = MAX_PER_ENTRY_BYTES,
  expectedLength?: number,
): {
  readonly data: Buffer;
  readonly decompressed: boolean;
  readonly error?: string | undefined;
} => {
  if (flag === 0) {
    if (expectedLength !== undefined && raw.length !== expectedLength) {
      return {
        data: raw,
        decompressed: false,
        error: `Uncompressed entry size ${raw.length} contradicts declared uncompressed length ${expectedLength}`,
      };
    }
    if (raw.length > maxOutputBytes) {
      return {
        data: raw,
        decompressed: false,
        error: `Uncompressed entry size ${raw.length} exceeds output budget ${maxOutputBytes}`,
      };
    }
    return { data: raw, decompressed: true };
  }
  if (expectedLength !== undefined && expectedLength > maxOutputBytes) {
    return {
      data: raw,
      decompressed: false,
      error: `Decompression error: expansion budget exceeded: declared uncompressed length ${expectedLength} exceeds output budget ${maxOutputBytes}`,
    };
  }
  const budget =
    expectedLength !== undefined
      ? Math.min(maxOutputBytes, Math.max(1, expectedLength))
      : maxOutputBytes;
  try {
    const data = zlib.inflateSync(raw, { maxOutputLength: budget });
    if (expectedLength !== undefined && data.length !== expectedLength) {
      return {
        data: raw,
        decompressed: false,
        error: `Decompression error: inflated size ${data.length} contradicts declared uncompressed length ${expectedLength}`,
      };
    }
    return {
      data,
      decompressed: true,
    };
  } catch (err) {
    const isLimit =
      (err as { code?: string })?.code === "ERR_BUFFER_TOO_LARGE" ||
      (err instanceof Error &&
        /maxOutputLength|output budget/i.test(err.message));
    const prefix = isLimit
      ? "Decompression error: expansion budget exceeded: "
      : "Decompression error: ";
    return {
      data: raw,
      decompressed: false,
      error: `${prefix}${err instanceof Error ? err.message : String(err)}`,
    };
  }
};

const extractPyzModule = (
  pyzData: Buffer,
  pycMagic: number,
  pythonVersion: string,
  mod: PyzModuleEntry,
  maxOutputBytes = MAX_PER_ENTRY_BYTES,
): ExtractedPyInstallerFile | null => {
  // Type 3: namespace package (no payload)
  if (mod.typeCode === 3) {
    return {
      name: mod.name.replace(/\./g, "/"),
      kind: "package",
      data: Buffer.alloc(0),
      decompressed: true,
      pythonVersion,
      limitations: [],
    };
  }

  if (mod.dataOffset < 0 || mod.dataOffset + mod.dataLength > pyzData.length) {
    return null;
  }
  const raw = pyzData.subarray(mod.dataOffset, mod.dataOffset + mod.dataLength);
  const inflated = inflatePayload(raw, 1, maxOutputBytes);

  // Type 2: raw data file (no bytecode header, no .pyc extension)
  if (mod.typeCode === 2) {
    if (!inflated.decompressed) {
      return {
        name: mod.name,
        kind: "data",
        data: raw,
        decompressed: false,
        pythonVersion,
        limitations: [
          inflated.error ?? "Failed to decompress PYZ data payload",
        ],
      };
    }
    return {
      name: mod.name,
      kind: "data",
      data: inflated.data,
      decompressed: true,
      pythonVersion,
      limitations: [],
    };
  }

  const modPath = mod.isPackage
    ? `${mod.name.replace(/\./g, "/")}/__init__.pyc`
    : `${mod.name.replace(/\./g, "/")}.pyc`;

  if (!inflated.decompressed) {
    return {
      name: modPath,
      kind: mod.isPackage ? "package" : "module",
      data: raw,
      decompressed: false,
      pythonVersion,
      limitations: [
        inflated.error ?? "Failed to decompress PYZ module payload",
      ],
    };
  }

  const header = buildPythonBytecodeHeader(pycMagic);
  const pycData = Buffer.concat([header, inflated.data]);
  return {
    name: modPath,
    kind: mod.isPackage ? "package" : "module",
    data: pycData,
    decompressed: true,
    pythonVersion,
    limitations: [],
  };
};

interface ScriptEntryOptions {
  readonly entry: PyInstallerTocEntry;
  readonly data: Buffer;
  readonly decompressed: boolean;
  readonly archive: PyInstallerArchive;
  readonly limitations: readonly string[];
}

const extractScriptEntry = (
  options: ScriptEntryOptions,
): ExtractedPyInstallerFile => {
  const { entry, data, decompressed, archive, limitations } = options;
  let fileData = data;
  if (decompressed && !isPythonBytecode(fileData)) {
    const pyVer: number | string =
      archive.embeddedPyz?.pycMagic ??
      archive.embeddedPyz?.pythonVersion ??
      (archive.cookie.pythonVersion > 0
        ? archive.cookie.pythonVersion < 100
          ? `${Math.floor(archive.cookie.pythonVersion / 10)}.${archive.cookie.pythonVersion % 10}`
          : `${Math.floor(archive.cookie.pythonVersion / 100)}.${archive.cookie.pythonVersion % 100}`
        : "3.10");
    const header = buildPythonBytecodeHeader(pyVer);
    fileData = Buffer.concat([header, data]);
  }

  const outName =
    entry.name.endsWith(".pyc") || entry.name.endsWith(".py")
      ? entry.name
      : `${entry.name}.pyc`;

  return {
    name: outName,
    kind:
      entry.typeFlag === "M"
        ? "package"
        : entry.typeFlag === "m"
          ? "module"
          : "script",
    data: fileData,
    decompressed,
    pythonVersion: archive.embeddedPyz?.pythonVersion,
    limitations,
  };
};

/**
 * Extract all files, scripts, embedded modules, and libraries from a PyInstaller binary.
 * Reconstructs valid .pyc bytecode with compliant headers for decompiler compatibility.
 */
export const extractPyInstallerEntries = (
  buffer: Buffer,
): ExtractedPyInstallerFile[] => {
  const archive = parsePyInstallerArchive(buffer);
  if (!archive) return [];

  const totalBudget = artifactExpansionBudgetBytes(buffer.length);
  let remainingBudget = totalBudget;
  const payloadEndOffset = archive.carchiveOffset + archive.cookie.tocOffset;
  const results: ExtractedPyInstallerFile[] = [];

  for (const entry of archive.tocEntries) {
    if (isCArchiveDeclaration({ typeCode: entry.typeFlag })) {
      results.push({
        name: entry.name,
        kind: entry.typeFlag === "o" ? "metadata" : "binary",
        data: Buffer.alloc(0),
        decompressed: false,
        limitations:
          entry.typeFlag === "d"
            ? [
                "Multipackage dependency bytes belong to another executable and remain unresolved.",
              ]
            : [
                "Runtime option is a CArchive declaration and carries no stored file payload.",
              ],
      });
      continue;
    }

    if (remainingBudget <= 0) {
      results.push({
        name: entry.name,
        kind: entry.typeFlag === "b" ? "binary" : "data",
        data: Buffer.alloc(0),
        decompressed: false,
        limitations: [
          `Total artifact expansion budget of ${totalBudget} bytes exhausted; entry skipped`,
        ],
      });
      break;
    }

    const dataOffset = archive.carchiveOffset + entry.pkgOffset;
    if (
      entry.pkgOffset < 0 ||
      entry.compressedLength < 0 ||
      dataOffset < archive.carchiveOffset ||
      dataOffset + entry.compressedLength > payloadEndOffset ||
      dataOffset + entry.compressedLength > buffer.length
    ) {
      continue;
    }

    const rawData = buffer.subarray(
      dataOffset,
      dataOffset + entry.compressedLength,
    );
    const entryBudget = Math.min(MAX_PER_ENTRY_BYTES, remainingBudget);
    const inflated = inflatePayload(
      rawData,
      entry.compressionFlag,
      entryBudget,
      entry.uncompressedLength,
    );
    const limitations = inflated.error ? [inflated.error] : [];
    if (inflated.decompressed) {
      remainingBudget -= inflated.data.length;
    } else if (isExpansionLimitError(inflated.error)) {
      remainingBudget = 0;
    } else {
      remainingBudget -= rawData.length;
    }

    if (entry.typeFlag === "z" || entry.name.toLowerCase().endsWith(".pyz")) {
      const pyz =
        remainingBudget > 0 && inflated.decompressed
          ? parsePyzArchive(inflated.data)
          : null;
      const pyzLimitations = [...limitations, ...(pyz?.limitations ?? [])];
      results.push({
        name: entry.name,
        kind: "pyz",
        data: inflated.data,
        decompressed: inflated.decompressed,
        pythonVersion: pyz?.pythonVersion ?? archive.embeddedPyz?.pythonVersion,
        limitations: pyzLimitations,
      });

      if (pyz && remainingBudget > 0) {
        for (const mod of pyz.modules) {
          if (remainingBudget <= 0) break;
          const modBudget = Math.min(MAX_PER_ENTRY_BYTES, remainingBudget);
          const extractedMod = extractPyzModule(
            inflated.data,
            pyz.pycMagic,
            pyz.pythonVersion,
            mod,
            modBudget,
          );
          if (extractedMod) {
            if (extractedMod.decompressed) {
              remainingBudget -= extractedMod.data.length;
            } else if (isExpansionLimitError(extractedMod.limitations[0])) {
              remainingBudget = 0;
            } else {
              remainingBudget -= mod.dataLength;
            }
            results.push(extractedMod);
            if (remainingBudget <= 0) break;
          }
        }
      }
      continue;
    }

    if (["s", "m", "M"].includes(entry.typeFlag)) {
      results.push(
        extractScriptEntry({
          entry,
          data: inflated.data,
          decompressed: inflated.decompressed,
          archive,
          limitations,
        }),
      );
      continue;
    }

    results.push({
      name: entry.name,
      kind: entry.typeFlag === "b" ? "binary" : "data",
      data: inflated.data,
      decompressed: inflated.decompressed,
      limitations,
    });
  }

  return results;
};
