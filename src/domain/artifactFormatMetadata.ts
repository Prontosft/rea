import { z } from "zod";

const offset = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const uint32 = z.number().int().min(0).max(0xffff_ffff);

/** Parsed source fields owned by the PCK adapter, independent of content hashes. */
export const godotPckMetadataSchema = z.strictObject({
  kind: z.literal("godot-pck"),
  format_version: uint32,
  engine_major: uint32,
  engine_minor: uint32,
  engine_patch: uint32,
  pack_start: offset,
  pack_end: offset,
  embedded: z.boolean(),
  pack_flags: uint32,
  file_base: offset,
  directory_start: offset,
  declared_file_count: uint32,
  directory_status: z.enum(["available", "encrypted", "sparse-bundle"]),
});
export type GodotPckMetadata = z.infer<typeof godotPckMetadataSchema>;

export const godotPckEntryMetadataSchema = z.strictObject({
  kind: z.literal("godot-pck-entry"),
  index: uint32,
  source_path: z.string(),
  declared_offset: offset,
  flags: uint32,
  md5_status: z.enum(["declared", "all-zero"]),
});

/** Source cookie fields and derived directory counts without Python execution. */
export const pyInstallerMetadataSchema = z.strictObject({
  kind: z.literal("pyinstaller"),
  layout_version: z.enum(["2.0", "2.1"]),
  archive_start: offset,
  archive_size: offset,
  cookie_offset: offset,
  toc_offset: offset,
  toc_size: offset,
  entry_count: offset,
  runtime_option_count: offset,
  external_dependency_count: offset,
  python_version_raw: uint32,
  python_major: uint32.nullable(),
  python_minor: uint32.nullable(),
  python_library: z.string().nullable(),
  encryption_marker_present: z.boolean(),
});
export type PyInstallerMetadata = z.infer<typeof pyInstallerMetadataSchema>;

/** Primitive facts preserve source spelling and keep metadata copies independent. */
export const pyInstallerEntryMetadataSchema = z.strictObject({
  kind: z.literal("pyinstaller-entry"),
  container: z.enum(["carchive", "pyz"]),
  container_name: z.string().nullable(),
  index: offset,
  source_name: z.string(),
  type_code: z.union([z.string().length(1), uint32]),
  relative_offset: offset,
  directory_record_offset: offset.nullable(),
  directory_record_size: offset.nullable(),
  compression_flag: z.union([z.literal(0), z.literal(1)]),
  bytecode_header: z.enum(["not-bytecode", "unknown", "derived"]),
  bytecode_magic: z
    .string()
    .regex(/^[0-9a-f]{8}$/u)
    .nullable(),
  pyz_status: z.enum(["not-pyz", "decoded", "opaque"]),
  pyz_sha256: z
    .string()
    .regex(/^[0-9a-f]{64}$/u)
    .nullable(),
  pyz_python_magic: z
    .string()
    .regex(/^[0-9a-f]{8}$/u)
    .nullable(),
  pyz_python_version: z.string().nullable(),
  pyz_entry_count: offset.nullable(),
  encryption_source: z.literal("carchive-marker").nullable(),
  dependency_status: z
    .enum(["unresolved", "invalid-reference"])
    .exactOptional(),
  dependency_archive: z.string().nullable().exactOptional(),
  dependency_member: z.string().nullable().exactOptional(),
});
export type PyInstallerEntryMetadata = z.infer<
  typeof pyInstallerEntryMetadataSchema
>;

/** Declaration identity that is stable across archive layout changes. */
export const pyInstallerEntryDeclaration = (
  metadata: PyInstallerEntryMetadata,
) => ({
  container: metadata.container,
  container_name: metadata.container_name,
  source_name: metadata.source_name,
  type_code: metadata.type_code,
});

const bunHex = z
  .string()
  .regex(/^[0-9a-f]+$/u)
  .nullable();

/**
 * Container facts for one Bun standalone module graph. `flags` stays the raw
 * u32 because Bun 1.3 and 1.4 reuse the low bits for different meanings.
 */
export const bunStandaloneMetadataSchema = z.strictObject({
  kind: z.literal("bun-standalone"),
  layout_revision: z.enum(["bun-1.3.3", "bun-1.3.9"]),
  carrier: z.enum([
    "mach-o-section",
    "pe-section",
    "elf-section",
    "appended-trailer",
  ]),
  payload_offset: offset,
  payload_length: offset,
  module_count: uint32,
  entry_point_id: uint32,
  entry_point_source_name: z.string().nullable(),
  compile_exec_argv: z.string().nullable(),
  compile_exec_argv_hex: bunHex,
  flags: uint32,
});
export type BunStandaloneMetadata = z.infer<typeof bunStandaloneMetadataSchema>;

/** One stored region of a Bun module. Siblings repeat the module's source facts. */
export const bunStandaloneEntryMetadataSchema = z.strictObject({
  kind: z.literal("bun-standalone-entry"),
  index: uint32,
  region: z.enum(["contents", "sourcemap", "bytecode", "module-info"]),
  source_name: z.string().nullable(),
  source_name_hex: bunHex,
  encoding: uint32,
  encoding_name: z.enum(["binary", "latin1", "utf8", "utf16"]).nullable(),
  loader: uint32,
  loader_name: z.string().nullable(),
  module_format: uint32,
  module_format_name: z.enum(["none", "esm", "cjs"]).nullable(),
  side: uint32,
  side_name: z.enum(["server", "client"]).nullable(),
  entry_point: z.boolean(),
  sourcemap_bytes: offset,
  bytecode_bytes: offset,
  module_info_bytes: offset,
  bytecode_origin: z.string().nullable(),
  bytecode_origin_hex: bunHex,
});
export type BunStandaloneEntryMetadata = z.infer<
  typeof bunStandaloneEntryMetadataSchema
>;

export const artifactFormatMetadataSchema = z.discriminatedUnion("kind", [
  godotPckMetadataSchema,
  godotPckEntryMetadataSchema,
  pyInstallerMetadataSchema,
  pyInstallerEntryMetadataSchema,
  bunStandaloneMetadataSchema,
  bunStandaloneEntryMetadataSchema,
]);
export type ArtifactFormatMetadata = z.infer<
  typeof artifactFormatMetadataSchema
>;
