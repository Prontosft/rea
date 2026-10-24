import {
  schemaArrays,
  schemaChildren,
  schemaMaps,
} from "../../src/contracts/jsonSchemaKeywords.js";

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

type SchemaChildEntry = readonly [suffix: string, child: unknown];

/** Enumerate schema-valued children, including array-valued tuple `items`. */
const schemaChildEntries = (
  schema: Readonly<Record<string, unknown>>,
  arrayIndexFormat: "dot" | "bracket",
): readonly SchemaChildEntry[] => {
  const entries: SchemaChildEntry[] = [];
  const formatIndex = (key: string, index: number): string =>
    arrayIndexFormat === "dot" ? `${key}.${index}` : `${key}[${index}]`;
  for (const [key, value] of Object.entries(schema)) {
    if (schemaMaps.has(key) && isRecord(value)) {
      for (const [name, child] of Object.entries(value))
        entries.push([`${key}.${name}`, child]);
    } else if (
      (schemaArrays.has(key) || schemaChildren.has(key)) &&
      Array.isArray(value)
    ) {
      value.forEach((child, index) =>
        entries.push([formatIndex(key, index), child]),
      );
    } else if (schemaChildren.has(key)) {
      entries.push([key, value]);
    }
  }
  return entries;
};

/** VS Code Copilot rejects falsy `items` for any type that admits arrays. */
export const arrayItemSchemaError = (
  schema: unknown,
  path: string,
): string | undefined => {
  if (!isRecord(schema)) return undefined;
  const admitsArrays =
    schema.type === "array" ||
    (Array.isArray(schema.type) && schema.type.includes("array"));
  if (admitsArrays && !schema.items)
    return `${path}: tool parameters array type must have items`;
  for (const [suffix, child] of schemaChildEntries(schema, "dot")) {
    const error = arrayItemSchemaError(child, `${path}.${suffix}`);
    if (error !== undefined) return error;
  }
  return undefined;
};

/** Reject Gemini-incompatible boolean and empty-string input literals. */
export const unsupportedInputLiteralSchemaError = (
  schema: unknown,
  path: string,
): string | undefined => {
  if (!isRecord(schema)) return undefined;
  if (typeof schema.const === "boolean") return `${path}.const is boolean`;
  if (schema.const === "") return `${path}.const is an empty string`;
  if (
    Array.isArray(schema.enum) &&
    schema.enum.some((value) => typeof value === "boolean")
  )
    return `${path}.enum contains a boolean`;
  if (Array.isArray(schema.enum) && schema.enum.includes(""))
    return `${path}.enum contains an empty string`;
  for (const [suffix, child] of schemaChildEntries(schema, "bracket")) {
    const error = unsupportedInputLiteralSchemaError(
      child,
      `${path}.${suffix}`,
    );
    if (error !== undefined) return error;
  }
  return undefined;
};
