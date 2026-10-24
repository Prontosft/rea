/** Maximum complete class-file buffer retained for FAT/JVM disambiguation. */
export const MAX_JVM_CLASS_IDENTITY_BYTES = 16 * 1024 * 1024;

export const JVM_CLASS_IDENTITY_LIMIT_REASON =
  "FAT/JVM identity is unresolved because the class identity scan exceeds the 16 MiB limit";

/** Maximum prefix retained by the streaming JVM class signature probe. */
export const MAX_JVM_CLASS_PROBE_BYTES = 10 + 3 * (3 + 0xffff);

export type JvmClassProbeState = "pending" | "matched" | "rejected";

/** Validate JVMS Table 4.1-A major/minor version combinations. */
const isValidJvmVersion = (major: number, minor: number): boolean => {
  if (major < 45 || major > 100) return false;
  if (major === 45) return minor >= 0 && minor <= 0xffff;
  if (major < 56) return minor === 0;
  return minor === 0 || minor === 0xffff;
};

/** Class-file identity used to disambiguate JVM CAFEBABE from Mach-O FAT. */
class ClassFileCursor {
  private offset = 0;
  private readonly view: DataView;

  constructor(private readonly bytes: Uint8Array) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  get atEnd(): boolean {
    return this.offset === this.bytes.byteLength;
  }

  u1(): number | null {
    if (!this.has(1)) return null;
    return this.bytes[this.offset++]!;
  }

  u2(): number | null {
    if (!this.has(2)) return null;
    const value = this.view.getUint16(this.offset, false);
    this.offset += 2;
    return value;
  }

  u4(): number | null {
    if (!this.has(4)) return null;
    const value = this.view.getUint32(this.offset, false);
    this.offset += 4;
    return value;
  }

  skip(length: number): boolean {
    if (!Number.isSafeInteger(length) || length < 0 || !this.has(length))
      return false;
    this.offset += length;
    return true;
  }

  private has(length: number): boolean {
    return this.offset <= this.bytes.byteLength - length;
  }
}

interface ConstantPool {
  readonly tags: (number | null)[];
  readonly first: (number | null)[];
  readonly second: (number | null)[];
}

const readConstantPool = (
  cursor: ClassFileCursor,
  count: number,
): ConstantPool | null => {
  const pool: ConstantPool = {
    tags: Array.from({ length: count }, () => null),
    first: Array.from({ length: count }, () => null),
    second: Array.from({ length: count }, () => null),
  };
  for (let index = 1; index < count; index += 1) {
    const tag = cursor.u1();
    if (tag === null) return null;
    if (!readConstant(cursor, tag, index, pool)) return null;
    if (tag === 5 || tag === 6) index += 1;
  }
  return pool;
};

const readConstant = (
  cursor: ClassFileCursor,
  tag: number,
  index: number,
  pool: ConstantPool,
): boolean => {
  switch (tag) {
    case 1: {
      const length = cursor.u2();
      if (length === null || !cursor.skip(length)) return false;
      break;
    }
    case 3:
    case 4:
      if (cursor.u4() === null) return false;
      break;
    case 5:
    case 6:
      if (index + 1 >= pool.tags.length || !cursor.skip(8)) return false;
      break;
    case 7:
    case 8:
    case 16:
    case 19:
    case 20:
      pool.first[index] = cursor.u2();
      if (pool.first[index] === null) return false;
      break;
    case 9:
    case 10:
    case 11:
    case 12:
    case 17:
    case 18:
      pool.first[index] = cursor.u2();
      pool.second[index] = cursor.u2();
      if (pool.first[index] === null || pool.second[index] === null)
        return false;
      break;
    case 15:
      pool.first[index] = cursor.u1();
      pool.second[index] = cursor.u2();
      if (pool.first[index] === null || pool.second[index] === null)
        return false;
      break;
    default:
      return false;
  }
  pool.tags[index] = tag;
  return true;
};

const poolHasTag = (
  pool: ConstantPool,
  index: number,
  ...tags: number[]
): boolean =>
  Number.isInteger(index) && index > 0 && tags.includes(pool.tags[index] ?? -1);

const hasValidPoolReferences = (pool: ConstantPool, major: number): boolean => {
  for (let index = 1; index < pool.tags.length; index += 1) {
    const tag = pool.tags[index] ?? null;
    const first = pool.first[index] ?? null;
    const second = pool.second[index] ?? null;
    if ([7, 8, 16, 19, 20].includes(tag ?? -1)) {
      if (first === null || !poolHasTag(pool, first, 1)) return false;
      if (
        (tag === 16 && major < 51) ||
        ((tag === 19 || tag === 20) && major < 53)
      )
        return false;
    } else if ([9, 10, 11].includes(tag ?? -1)) {
      if (
        first === null ||
        second === null ||
        !poolHasTag(pool, first, 7) ||
        !poolHasTag(pool, second, 12)
      )
        return false;
    } else if (tag === 12) {
      if (
        first === null ||
        second === null ||
        !poolHasTag(pool, first, 1) ||
        !poolHasTag(pool, second, 1)
      )
        return false;
    } else if (tag === 15 && !validMethodHandle(pool, first, second, major)) {
      return false;
    } else if (tag === 17 || tag === 18) {
      if (
        second === null ||
        !poolHasTag(pool, second, 12) ||
        major < (tag === 17 ? 55 : 51)
      )
        return false;
    }
  }
  return true;
};

const validMethodHandle = (
  pool: ConstantPool,
  kind: number | null,
  reference: number | null,
  major: number,
): boolean => {
  if (kind === null || reference === null || kind < 1 || kind > 9 || major < 51)
    return false;
  if (kind <= 4) return poolHasTag(pool, reference, 9);
  if (kind === 5 || kind === 8) return poolHasTag(pool, reference, 10);
  if (kind === 6 || kind === 7)
    return poolHasTag(pool, reference, ...(major >= 52 ? [10, 11] : [10]));
  return poolHasTag(pool, reference, 11);
};

const readAttributes = (
  cursor: ClassFileCursor,
  pool: ConstantPool,
  count: number,
): boolean => {
  for (let index = 0; index < count; index += 1) {
    const name = cursor.u2();
    const length = cursor.u4();
    if (
      name === null ||
      !poolHasTag(pool, name, 1) ||
      length === null ||
      !cursor.skip(length)
    )
      return false;
  }
  return true;
};

const readMembers = (cursor: ClassFileCursor, pool: ConstantPool): boolean => {
  const count = cursor.u2();
  if (count === null) return false;
  for (let index = 0; index < count; index += 1) {
    if (cursor.u2() === null) return false;
    const name = cursor.u2();
    const descriptor = cursor.u2();
    const attributes = cursor.u2();
    if (
      name === null ||
      descriptor === null ||
      !poolHasTag(pool, name, 1) ||
      !poolHasTag(pool, descriptor, 1) ||
      attributes === null ||
      !readAttributes(cursor, pool, attributes)
    )
      return false;
  }
  return true;
};

/** Validate class-file framing and constant-pool references before FAT parsing. */
export const isJvmClassFile = (bytes: Uint8Array): boolean => {
  const cursor = new ClassFileCursor(bytes);
  if (cursor.u4() !== 0xcafebabe) return false;
  const minor = cursor.u2();
  const major = cursor.u2();
  const poolCount = cursor.u2();
  if (
    minor === null ||
    major === null ||
    !isValidJvmVersion(major, minor) ||
    poolCount === null ||
    poolCount === 0
  )
    return false;
  const pool = readConstantPool(cursor, poolCount);
  if (pool === null || !hasValidPoolReferences(pool, major)) return false;
  if (cursor.u2() === null) return false;
  const thisClass = cursor.u2();
  const superClass = cursor.u2();
  if (
    thisClass === null ||
    !poolHasTag(pool, thisClass, 7) ||
    superClass === null ||
    (superClass !== 0 && !poolHasTag(pool, superClass, 7))
  )
    return false;
  const interfaces = cursor.u2();
  if (interfaces === null || !cursor.skip(interfaces * 2)) return false;
  if (!readMembers(cursor, pool) || !readMembers(cursor, pool)) return false;
  const attributes = cursor.u2();
  return (
    attributes !== null &&
    readAttributes(cursor, pool, attributes) &&
    cursor.atEnd
  );
};

type ProbeConstantStep =
  | "need-more"
  | "invalid"
  | { readonly nextOffset: number; readonly extraSlots: number };

const stepProbeConstant = (
  buffered: Uint8Array,
  view: DataView,
  offset: number,
  index: number,
  poolCount: number,
): ProbeConstantStep => {
  const tag = buffered[offset]!;
  if (tag === 1) {
    if (offset + 3 > buffered.length) return "need-more";
    const len = view.getUint16(offset + 1, false);
    if (offset + 3 + len > buffered.length) return "need-more";
    return { nextOffset: offset + 3 + len, extraSlots: 0 };
  }
  if (tag === 3 || tag === 4) {
    return offset + 5 > buffered.length
      ? "need-more"
      : { nextOffset: offset + 5, extraSlots: 0 };
  }
  if (tag === 5 || tag === 6) {
    if (index + 1 >= poolCount) return "invalid";
    return offset + 9 > buffered.length
      ? "need-more"
      : { nextOffset: offset + 9, extraSlots: 1 };
  }
  if (tag === 7 || tag === 8 || tag === 16 || tag === 19 || tag === 20) {
    return offset + 3 > buffered.length
      ? "need-more"
      : { nextOffset: offset + 3, extraSlots: 0 };
  }
  if (
    tag === 9 ||
    tag === 10 ||
    tag === 11 ||
    tag === 12 ||
    tag === 17 ||
    tag === 18
  ) {
    return offset + 5 > buffered.length
      ? "need-more"
      : { nextOffset: offset + 5, extraSlots: 0 };
  }
  if (tag === 15) {
    return offset + 4 > buffered.length
      ? "need-more"
      : { nextOffset: offset + 4, extraSlots: 0 };
  }
  return "invalid";
};

/**
 * Streaming, bounded JVM class signature probe.
 * Checks magic (0xcafebabe), valid major/minor version framing, and parses
 * up to 3 constant pool entries without requiring the complete file or EOF.
 */
export const createJvmClassSignatureProbe = (): {
  write(bytes: Uint8Array): JvmClassProbeState;
  readonly state: JvmClassProbeState;
} => {
  let state: JvmClassProbeState = "pending";
  let buffered = new Uint8Array(0);

  return {
    get state() {
      return state;
    },
    write(bytes: Uint8Array): JvmClassProbeState {
      if (state !== "pending" || bytes.length === 0) return state;

      const needed = Math.min(
        MAX_JVM_CLASS_PROBE_BYTES - buffered.length,
        bytes.length,
      );
      if (needed <= 0) {
        state = "rejected";
        return state;
      }

      const next = new Uint8Array(buffered.length + needed);
      next.set(buffered);
      next.set(bytes.subarray(0, needed), buffered.length);
      buffered = next;

      if (buffered.length < 4) return state;
      const view = new DataView(
        buffered.buffer,
        buffered.byteOffset,
        buffered.byteLength,
      );
      if (view.getUint32(0, false) !== 0xcafebabe) {
        state = "rejected";
        return state;
      }
      if (buffered.length < 10) return state;

      const minor = view.getUint16(4, false);
      const major = view.getUint16(6, false);
      const poolCount = view.getUint16(8, false);
      if (!isValidJvmVersion(major, minor) || poolCount === 0) {
        state = "rejected";
        return state;
      }

      const targetEntries = Math.min(poolCount - 1, 3);
      if (targetEntries === 0) {
        state = "matched";
        return state;
      }

      let offset = 10;
      let parsed = 0;
      for (let index = 1; index < poolCount; index += 1) {
        if (offset >= buffered.length) break;
        const step = stepProbeConstant(
          buffered,
          view,
          offset,
          index,
          poolCount,
        );
        if (step === "need-more") break;
        if (step === "invalid") {
          state = "rejected";
          return state;
        }
        offset = step.nextOffset;
        index += step.extraSlots;
        parsed += 1;
        if (parsed >= targetEntries) {
          state = "matched";
          return state;
        }
      }

      if (buffered.length >= MAX_JVM_CLASS_PROBE_BYTES) {
        state = "rejected";
      }
      return state;
    },
  };
};

/** Bounded framing check that distinguishes JVM class prefixes from Mach-O FAT without requiring full file EOF. */
export const hasBoundedJvmClassFraming = (bytes: Uint8Array): boolean =>
  createJvmClassSignatureProbe().write(bytes) === "matched";
