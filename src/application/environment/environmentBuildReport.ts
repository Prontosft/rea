import { basename } from "node:path";
import { isIP } from "node:net";

import { readRecordedResponseBody } from "../../domain/analysisView/recordedResponseBody.js";
import type { EnvironmentBuildReport } from "../../domain/environmentBundleExport.js";
import type { WebNetworkCaptureRecord } from "../../domain/webNetworkCapture.js";

/** A note the build report carries; warnings never change what is built. */
export type EnvironmentBuildWarning =
  EnvironmentBuildReport["warnings"][number];

/** Whole name segments that name credentials; `author` is not `auth`. */
const CREDENTIAL_SEGMENTS = new Set([
  "accesstoken",
  "apikey",
  "apikeys",
  "apitoken",
  "auth",
  "authorization",
  "bearer",
  "cookie",
  "credential",
  "credentials",
  "jwt",
  "passphrase",
  "passwd",
  "password",
  "privatekey",
  "pwd",
  "secret",
  "secrets",
  "session",
  "sessionid",
  "token",
  "tokens",
]);
const CREDENTIAL_PAIRS = new Set([
  "access key",
  "api key",
  "api keys",
  "client secret",
  "private key",
  "session id",
  "ssh key",
]);

/** Split a member name into lowercase segments at case changes and separators. */
const nameSegments = (name: string): string[] =>
  name
    .replaceAll(/([a-z0-9])([A-Z])/gu, "$1 $2")
    .replaceAll(/([A-Z]+)([A-Z][a-z])/gu, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/u)
    .filter((segment) => segment.length > 0);

/** Whether a member, header or query name looks like it holds a credential. */
export const credentialNamed = (name: string): boolean => {
  const segments = nameSegments(name);
  return segments.some(
    (segment, index) =>
      CREDENTIAL_SEGMENTS.has(segment) ||
      (index > 0 && CREDENTIAL_PAIRS.has(`${segments[index - 1]} ${segment}`)),
  );
};

/** Bodies larger than this are not scanned. */
const SCAN_BODY_LIMIT_BYTES = 4 * 1024 * 1024;
/** Pointers the report lists; the count covers every match. */
const REPORTED_POINTERS = 20;

const pointerToken = (name: string): string =>
  name.replaceAll("~", "~0").replaceAll("/", "~1");

/** A held value: a non-empty string, or an array holding one. */
const holdsValue = (value: unknown): boolean =>
  (typeof value === "string" && value !== "") ||
  (Array.isArray(value) &&
    value.some((item) => typeof item === "string" && item !== ""));

const member = (value: unknown, name: string): unknown =>
  typeof value === "object" && value !== null
    ? Reflect.get(value, name)
    : undefined;

/** A recorded body: a JSON value to walk, form fields in order with every occurrence kept, as headers and query strings are, or text too large to scan. */
type ScannedBody =
  | { readonly kind: "json"; readonly value: unknown }
  | { readonly kind: "form"; readonly fields: readonly [string, string][] }
  | { readonly kind: "skipped" };

/** A recorded body as JSON or form fields, skipped when it is cut or over the limit, or undefined when it is neither. */
const parsedBody = (text: unknown, cut = false): ScannedBody | undefined => {
  if (typeof text !== "string") return undefined;
  if (cut || Buffer.byteLength(text, "utf8") > SCAN_BODY_LIMIT_BYTES)
    return { kind: "skipped" };
  const start = text.trimStart()[0];
  if (start === "{" || start === "[") {
    try {
      return { kind: "json", value: JSON.parse(text) };
    } catch {
      return undefined;
    }
  }
  if (!/^[^=&\s]+=[^&]*(?:&[^=&\s]+=[^&]*)*$/u.test(text)) return undefined;
  try {
    return { kind: "form", fields: [...new URLSearchParams(text)] };
  } catch {
    return undefined;
  }
};

/** Name/value pairs such as HAR headers and query strings. */
const namedValues = (value: unknown): (readonly [string, unknown])[] =>
  Array.isArray(value)
    ? value.flatMap((entry: unknown) => {
        const name = member(entry, "name");
        return typeof name === "string"
          ? [[name, member(entry, "value")] as const]
          : [];
      })
    : [];

/** The response text the scan reads; binary bytes hold no JSON or form text. */
const responseBody = (
  record: WebNetworkCaptureRecord,
): ScannedBody | undefined => {
  const body = readRecordedResponseBody(record, SCAN_BODY_LIMIT_BYTES);
  return body.bodyEncoding === "base64"
    ? undefined
    : parsedBody(body.bodyText, body.bodyCut === true);
};

/** A count of matches and the first of their pointers. */
interface ScanTally {
  count: number;
  readonly pointers: string[];
}

const tallied = (tally: ScanTally, pointer: string): void => {
  tally.count++;
  if (tally.pointers.length < REPORTED_POINTERS) tally.pointers.push(pointer);
};

/**
 * Credential-named members that hold a value in recorded JSON and form
 * bodies, headers and query strings: a count and the first pointers, never
 * values, and the bodies too large to scan by record and side. The walk keeps
 * its own stack, so nesting depth cannot overflow it.
 */
export const scanCredentialNames = (
  records: readonly WebNetworkCaptureRecord[],
): Readonly<ScanTally> & { readonly skipped: Readonly<ScanTally> } => {
  const matches: ScanTally = { count: 0, pointers: [] };
  const skipped: ScanTally = { count: 0, pointers: [] };
  const found = (pointer: string): void => tallied(matches, pointer);
  const walk = (root: unknown, label: string): void => {
    const stack: [unknown, string][] = [[root, ""]];
    while (stack.length > 0) {
      const [value, pointer] = stack.pop()!;
      if (typeof value !== "object" || value === null) continue;
      if (Array.isArray(value)) {
        for (let index = value.length - 1; index >= 0; index--)
          stack.push([value[index], `${pointer}/${String(index)}`]);
        continue;
      }
      const entries = Object.entries(value);
      for (let index = entries.length - 1; index >= 0; index--) {
        const [name, child] = entries[index]!;
        const path = `${pointer}/${pointerToken(name)}`;
        if (credentialNamed(name) && holdsValue(child))
          found(`${label} ${path}`);
        stack.push([child, path]);
      }
    }
  };
  const scanBody = (body: ScannedBody | undefined, label: string): void => {
    if (body?.kind === "skipped") tallied(skipped, label);
    else if (body?.kind === "json") walk(body.value, label);
    else if (body?.kind === "form")
      for (const [name, value] of body.fields)
        if (credentialNamed(name) && holdsValue(value))
          found(`${label} /${pointerToken(name)}`);
  };
  for (const record of records) {
    const ordinal = String(record.ordinal);
    const request = member(record.reported, "request");
    const response = member(record.reported, "response");
    for (const [side, message] of [
      ["request", request],
      ["response", response],
    ] as const)
      for (const [name, value] of namedValues(member(message, "headers")))
        if (credentialNamed(name) && holdsValue(value))
          found(`record ${ordinal} ${side} header ${name}`);
    for (const [name, value] of namedValues(member(request, "queryString")))
      if (credentialNamed(name) && holdsValue(value))
        found(`record ${ordinal} request query ${name}`);
    const postData = member(request, "postData");
    const text = member(postData, "text");
    // A HAR may record form fields only as structured params; each occurrence counts, as in a form body.
    scanBody(
      typeof text !== "string"
        ? {
            kind: "form",
            fields: namedValues(member(postData, "params")).flatMap(
              ([name, value]) =>
                typeof value === "string"
                  ? [[name, value] as [string, string]]
                  : [],
            ),
          }
        : parsedBody(text),
      `record ${ordinal} request`,
    );
    scanBody(responseBody(record), `record ${ordinal} response`);
  }
  return { ...matches, skipped };
};

/** The credential-name scan's warnings: what it found, and the bodies it could not scan. */
export const credentialScanWarnings = (
  records: readonly WebNetworkCaptureRecord[],
): EnvironmentBuildWarning[] => {
  const scanned = scanCredentialNames(records);
  const warnings: EnvironmentBuildWarning[] = [];
  if (scanned.count > 0)
    warnings.push({
      code: "credential-named-members",
      message: `${String(scanned.count)} recorded body members have credential-like names and a value; evidence.json ships them, so review it before sharing.`,
      pointers: scanned.pointers,
    });
  if (scanned.skipped.count > 0)
    warnings.push({
      code: "credential-scan-incomplete",
      message: `${String(scanned.skipped.count)} recorded bodies exceed the credential-name scan's 4 MiB limit and were not scanned; evidence.json ships them, so review them before sharing.`,
      pointers: scanned.skipped.pointers,
    });
  return warnings;
};

/** Whether an origin's host is a loopback name or an IP literal, which says nothing about the application. */
export const anonymousOrigin = (origin: string): boolean => {
  let host: string;
  try {
    host = new URL(origin).hostname.toLowerCase();
  } catch {
    return false;
  }
  const bracketless = host.startsWith("[") ? host.slice(1, -1) : host;
  const bare = bracketless.endsWith(".")
    ? bracketless.slice(0, -1)
    : bracketless;
  return (
    bare === "localhost" || bare.endsWith(".localhost") || isIP(bare) !== 0
  );
};

/** A kebab-case name from a capture file's name: `grafana.har` and `grafana.capture.json` become `grafana`. */
export const nameFromCaptureFile = (path: string): string =>
  basename(path)
    .replace(/\.(?:har|json)$/iu, "")
    .replace(/\.capture$/iu, "")
    .toLowerCase()
    .replaceAll(/[^a-z0-9]+/gu, "-")
    .replace(/^-+/u, "")
    .replace(/-+$/u, "");
