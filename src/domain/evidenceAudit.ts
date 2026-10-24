import { createHash } from "node:crypto";
import { z } from "zod";

import type { EvidenceBundle } from "./evidenceBundle.js";
import type { Evidence } from "./evidence.js";
import { absoluteLocalPathStringSchema } from "./localPath.js";
import { compareUnicodeCodePoints } from "./unicodeCodePointOrder.js";
import { publicInputStrictObject } from "./publicInput.js";

/**
 * Read-only secret/location audit for a serialized Evidence bundle.
 *
 * Findings report where matched values live (Evidence ID and RFC 6901 JSON
 * pointer) plus a length and a short hash prefix, but never the matched
 * value itself, so the audit output stays safe to paste into an issue.
 */

const findingSeveritySchema = z.enum(["failure", "warning"]);

/** One deterministic finding against one matched JSON location. */
export const evidenceAuditFindingSchema = z.strictObject({
  severity: findingSeveritySchema,
  rule_id: z.string().min(1),
  evidence_id: z.string().min(1),
  pointer: z.string().min(1),
  /** Matched text length in UTF-16 code units; the value is never printed. */
  matched_length: z.number().int().min(1),
  /**
   * First 8 hex characters of the SHA-256 digest of the matched value.
   * Omitted for low-entropy matches (paths, host names, header values):
   * a digest over a guessable value would let readers confirm candidate
   * guesses offline, which is not a safe redaction of a reported leak.
   */
  matched_hash_prefix: z
    .string()
    .regex(/^[0-9a-f]{8}$/)
    .exactOptional(),
});

/** Deterministic audit projection over one validated bundle. */
export const evidenceAuditResultSchema = z.strictObject({
  findings: z.array(evidenceAuditFindingSchema),
  failures: z.number().int().min(0),
  warnings: z.number().int().min(0),
  scanned_records: z.number().int().min(0),
  scanned_unknowns: z.number().int().min(0),
  limitations: z.array(z.string()),
});

/** Input accepted by the bundle audit tool; one absolute local path. */
export const evidenceAuditInputSchema = publicInputStrictObject({
  path: absoluteLocalPathStringSchema.describe(
    "Absolute local filesystem path to the Evidence bundle; relative paths are rejected",
  ),
});

export type EvidenceAuditFinding = z.infer<typeof evidenceAuditFindingSchema>;
export type EvidenceAuditResult = z.infer<typeof evidenceAuditResultSchema>;

interface FindingCandidate {
  readonly severity: "failure" | "warning";
  readonly rule_id: string;
  readonly evidence_id: string;
  readonly pointer: string;
  readonly matched: string;
}

/** Cloud and API credential shapes that establish a failure when matched. */
const CREDENTIAL_PATTERNS: readonly { rule: string; pattern: RegExp }[] = [
  // Bearer tokens in header-shaped strings. Prose such as "Bearer realm="
  // (WWW-Authenticate challenges) or "bearer of" never carries the token, so
  // the credential must start with a real token character, and challenge
  // keywords directly after "bearer" are rejected.
  {
    rule: "credential-bearer-token",
    pattern: /\bbearer\s+(?!realm\b|of\b|token\b)[A-Za-z0-9\-._~+/]+=*/gi,
  },
  // AWS access key IDs (20 uppercase alphanumerics).
  {
    rule: "credential-aws-access-key-id",
    pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  },
  // AWS secret access keys presented as 40-char base64-ish tokens after a
  // key-like label. Library and tool names ("aws-sdk-cpp", "aws-cli") label
  // builds, not secrets, so they are excluded from the label.
  {
    rule: "credential-aws-secret-key",
    pattern:
      /\baws(?:[ _-]?secret(?:[ _-]?access)?[ _-]?key)?(?![-\w]*(?:sdk|cli|toolkit|build|crt))[\s:=]+[0-9A-Za-z/+]{40}\b/gi,
  },
  // Google API keys.
  { rule: "credential-google-api-key", pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/g },
  // GitHub personal access tokens (classic and OAuth).
  {
    rule: "credential-github-token",
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b/g,
  },
  // GitHub fine-grained personal access tokens.
  {
    rule: "credential-github-fine-grained-token",
    pattern: /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/g,
  },
  // Stripe live secret and restricted keys. Test-mode keys are deliberately
  // excluded: they authorize nothing and appear in legitimate fixtures.
  {
    rule: "credential-stripe-live-key",
    pattern: /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b/g,
  },
  // Slack tokens: bot, user, app-level, refresh, and legacy workspace tokens.
  {
    rule: "credential-slack-token",
    pattern: /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g,
  },
  // PEM-encoded private key bodies.
  {
    rule: "credential-private-key",
    pattern: /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/g,
  },
];

/**
 * Rules whose matched values are low-entropy (paths, host names, header
 * values). Their findings omit the hash prefix: a digest over a guessable
 * value lets readers confirm candidate guesses offline (see finding schema).
 */
const FINGERPRINT_OMITTING_RULES = new Set([
  "local-path-posix-home",
  "local-path-windows-home",
  "local-path-artifact-location",
  "environment-host-id",
  "credential-header-value",
  "decompiled-payload",
]);

/** Credential-bearing header names whose retained values are failures. */
const CREDENTIAL_HEADER_NAMES = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
]);

/**
 * Home-directory prefixes that identify leaked absolute local paths.
 * The account segment accepts any run of non-separator characters so that
 * non-ASCII and dotted user names are matched too.
 */
const HOME_PATH_PATTERNS: readonly { rule: string; pattern: RegExp }[] = [
  // POSIX absolute home paths: /Users/<name>/... or /home/<name>/...
  {
    rule: "local-path-posix-home",
    pattern:
      /[/\\](?:Users|home)[/\\][^\s/"',;:)>\]}\\]+(?:[/\\][^\s"',;:)>\]}]*)?/g,
  },
  // Windows drive-letter home paths: C:\Users\<name>\...
  {
    rule: "local-path-windows-home",
    pattern:
      /[A-Za-z]:\\(?:Users|Documents and Settings)\\[^\s\\"',;:)>\]}]+(?:\\[^\s"',;:)>\]}]*)?/g,
  },
];

/** True when a string value came from a decompiled or pseudocode surface. */
const DECOMPILED_PREDICATES = /(?:^|\.)(?:decompile|pseudo_?code|disassembl)/i;

/**
 * Recorded operations whose results are decompiler output. Bundles record the
 * operation on the Evidence record itself, so predicate-level detection alone
 * would miss every decompilation produced by the default predicate.
 */
const DECOMPILED_OPERATIONS = /decompile|pseudo_?code|disassembl/i;

const hashPrefix = (value: string): string =>
  createHash("sha256").update(value, "utf8").digest("hex").slice(0, 8);

const toFinding = (candidate: FindingCandidate): EvidenceAuditFinding => {
  const finding: EvidenceAuditFinding = {
    severity: candidate.severity,
    rule_id: candidate.rule_id,
    evidence_id: candidate.evidence_id,
    pointer: candidate.pointer,
    matched_length: candidate.matched.length,
  };
  // Low-entropy matches (paths, host ids, header values, decompiled text)
  // omit the digest: hashing a guessable value is not a safe redaction.
  if (!FINGERPRINT_OMITTING_RULES.has(candidate.rule_id)) {
    finding.matched_hash_prefix = hashPrefix(candidate.matched);
  }
  return finding;
};

const compareFindings = (
  left: EvidenceAuditFinding,
  right: EvidenceAuditFinding,
): number => {
  const evidenceOrder = compareUnicodeCodePoints(
    left.evidence_id,
    right.evidence_id,
  );
  if (evidenceOrder !== 0) return evidenceOrder;
  const pointerOrder = compareUnicodeCodePoints(left.pointer, right.pointer);
  if (pointerOrder !== 0) return pointerOrder;
  return compareUnicodeCodePoints(left.rule_id, right.rule_id);
};

/**
 * Walk one JSON value and report string findings plus structural locations.
 * Object keys are audited as locations, not as string values, so a secret used
 * as a key is redacted rather than printed into the pointer. Keys themselves
 * are still scanned for findings: a credential-shaped key with a clean value
 * is reported at the redacted pointer instead of passing silently.
 */
const walkValue = (
  value: unknown,
  pointer: string,
  visit: (
    text: string,
    pointer: string,
    key?: string,
    parent?: unknown,
  ) => void,
  key?: string,
  parent?: unknown,
): void => {
  if (typeof value === "string") {
    visit(value, pointer, key, parent);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((member, index) => {
      walkValue(member, `${pointer}/${index}`, visit, undefined, value);
    });
    return;
  }
  if (typeof value === "object" && value !== null) {
    for (const [entryKey, member] of Object.entries(value)) {
      const token = pointerToken(entryKey);
      if (token.startsWith("<redacted-")) visit(entryKey, pointer, undefined);
      walkValue(member, `${pointer}/${token}`, visit, entryKey, value);
    }
  }
};

/** True when an object key or string carries a credential-shaped value. */
const isCredentialShaped = (value: string): boolean =>
  CREDENTIAL_PATTERNS.some(
    ({ pattern }) => (value.match(pattern) ?? []).length > 0,
  );

/** True when a string carries a home-directory-shaped local path. */
const isLocalPathShaped = (value: string): boolean =>
  HOME_PATH_PATTERNS.some(
    ({ pattern }) => (value.match(pattern) ?? []).length > 0,
  );

/**
 * Encode one pointer token, replacing credential-shaped or local-path-shaped
 * keys with a hash. A secret used as a JSON key never reaches the report
 * through the pointer, and neither does a home path such as `/Users/alice/x`:
 * the report is meant to be safe to paste into a public issue.
 */
const pointerToken = (key: string): string =>
  isCredentialShaped(key) || isLocalPathShaped(key)
    ? `<redacted-${hashPrefix(key)}>`
    : escapePointer(key);

const escapePointer = (token: string): string =>
  token.replaceAll("~", "~0").replaceAll("/", "~1");

/**
 * Apply the home-path rules after classifying the string: an http(s) URL is
 * a web route, not a filesystem path, so its `/Users/...` path segment is not
 * a local home directory. Windows-style backslash runs still match the
 * Windows rule only, preventing duplicate cross-format findings.
 */
const applyHomePathRules = (
  text: string,
  pointer: string,
  pushMatch: (
    severity: "failure" | "warning",
    ruleId: string,
    pointer: string,
    matched: string,
  ) => void,
): void => {
  if (/https?:\/\//i.test(text)) return; // web route, not a filesystem path
  const windowsPath = /[A-Za-z]:\\/.test(text);
  for (const { rule, pattern } of HOME_PATH_PATTERNS) {
    // A drive-letter string is a Windows path: report it once under the
    // Windows rule instead of also matching its backslashes as POSIX.
    if (windowsPath !== (rule === "local-path-windows-home")) continue;
    for (const matched of text.match(pattern) ?? []) {
      pushMatch("warning", rule, pointer, matched);
    }
  }
};

/** Audit one Evidence record and return unsorted finding candidates. */
const auditRecord = (record: Evidence): readonly FindingCandidate[] => {
  const candidates: FindingCandidate[] = [];
  const evidenceId = record.evidence_id;
  const decompiledSurface =
    DECOMPILED_PREDICATES.test(record.predicate_type) ||
    DECOMPILED_OPERATIONS.test(record.operation);

  const pushMatch = (
    severity: "failure" | "warning",
    ruleId: string,
    pointer: string,
    matched: string,
  ): void => {
    // The finding schema requires a positive matched_length, and a blank value
    // carries no secret, so blank matches are never reported.
    if (matched.trim() === "") return;
    candidates.push({
      severity,
      rule_id: ruleId,
      evidence_id: evidenceId,
      pointer,
      matched,
    });
  };

  /**
   * Build a text visitor. `reportDecompiled` is set only for result surfaces:
   * metadata fields are authored by the caller, not by the decompiler.
   */
  const makeVisitor =
    (reportDecompiled: boolean) =>
    (text: string, pointer: string, key?: string, parent?: unknown): void => {
      // Credential-bearing header values that escaped capture-time redaction.
      // Only the header's value holds the secret; the header name is a label,
      // and flagging it would re-report headers that were already redacted to
      // a null value.
      if (
        typeof key === "string" &&
        key.toLowerCase() === "value" &&
        typeof parent === "object" &&
        parent !== null &&
        !Array.isArray(parent) &&
        "name" in parent &&
        typeof (parent as { name?: unknown }).name === "string" &&
        CREDENTIAL_HEADER_NAMES.has(
          (parent as { name: string }).name.toLowerCase(),
        )
      ) {
        pushMatch("failure", "credential-header-value", pointer, text);
        return;
      }
      for (const { rule, pattern } of CREDENTIAL_PATTERNS) {
        for (const matched of text.match(pattern) ?? []) {
          pushMatch("failure", rule, pointer, matched);
        }
      }
      applyHomePathRules(text, pointer, pushMatch);
      if (reportDecompiled && decompiledSurface) {
        // Decompiler output embeds target-authored strings verbatim; publishing
        // it wholesale can leak proprietary source text. Only fields that own
        // decompiler text carry the warning: the typed pseudocode field, and
        // the direct-text shape of single-string results. Status strings and
        // addresses inside batch results are not decompiled payload.
        const isPseudocodeOwner =
          key === "pseudocode" || (key === undefined && parent === undefined);
        if (isPseudocodeOwner) {
          pushMatch("warning", "decompiled-payload", pointer, text);
        }
      }
    };

  const visitResultText = makeVisitor(true);
  const visitMetadataText = makeVisitor(false);

  // Locations: artifact-path entries carry absolute local paths.
  for (const [index, location] of record.locations.entries()) {
    if (location.kind === "artifact-path") {
      pushMatch(
        "warning",
        "local-path-artifact-location",
        `/locations/${index}/path`,
        location.path,
      );
    }
  }

  // Environment records can carry host identifiers.
  const environment = record.environment;
  if (environment !== null && environment.id !== "") {
    pushMatch(
      "warning",
      "environment-host-id",
      "/environment/id",
      environment.id,
    );
  }

  // Envelope fields are audited too: the subject path and the caller-supplied
  // parameters travel with the bundle and can leak just as the results can.
  if (record.subject !== null) {
    walkValue(record.subject, "/subject", visitMetadataText);
  }
  walkValue(record.parameters, "/parameters", visitMetadataText);
  walkValue(record.environment, "/environment", visitMetadataText);
  walkValue(record.raw_result, "/raw_result", visitResultText);
  walkValue(record.normalized_result, "/normalized_result", visitResultText);

  // Free-form fields travel with the bundle like every other field; a host
  // path in a limitation string is as much a leak as one in a result.
  for (const [index, text] of (record.limitations ?? []).entries()) {
    visitMetadataText(text, `/limitations/${index}`);
  }
  // Relationship coverage diagnostics and analysis-profile parameters are
  // persisted free-form fields; they can embed host paths or credentials
  // exactly like the limitations above them.
  if (record.relationship_coverage !== null) {
    walkValue(record.relationship_coverage, "/relationship_coverage", visitMetadataText);
  }
  if (record.analysis_profile !== null) {
    walkValue(record.analysis_profile, "/analysis_profile", visitMetadataText);
  }

  return candidates;
};

/** Audit every record and unknown in one validated bundle, deterministically. */
export const auditEvidenceBundle = (
  bundle: EvidenceBundle,
): EvidenceAuditResult => {
  const recordFindings = bundle.records.flatMap((record) =>
    auditRecord(record),
  );
  const seenUnknownFindingKeys = new Set<string>();
  const unknownFindings = bundle.unknowns.flatMap((unknown) => {
    const candidates: FindingCandidate[] = [];
    const unknownId = unknown.unknown_id;
    const pushMatch = (
      severity: "failure" | "warning",
      ruleId: string,
      pointer: string,
      matched: string,
    ): void => {
      if (matched.trim() === "") return;
      // Unknown histories repeat revisions; identical matches from later
      // revisions collapse instead of spamming duplicate findings.
      const dedupeKey = `${unknownId}#${pointer}#${ruleId}#${hashPrefix(matched)}`;
      if (seenUnknownFindingKeys.has(dedupeKey)) return;
      seenUnknownFindingKeys.add(dedupeKey);
      candidates.push({
        severity,
        rule_id: ruleId,
        evidence_id: unknownId,
        pointer,
        matched,
      });
    };
    const visitText = (text: string, pointer: string): void => {
      for (const { rule, pattern } of CREDENTIAL_PATTERNS) {
        for (const matched of text.match(pattern) ?? []) {
          pushMatch("failure", rule, pointer, matched);
        }
      }
      applyHomePathRules(text, pointer, pushMatch);
    };
    walkValue(unknown, "", visitText);
    return candidates;
  });

  const findings = [...recordFindings, ...unknownFindings]
    .map(toFinding)
    .sort(compareFindings);
  return {
    findings,
    failures: findings.filter((finding) => finding.severity === "failure")
      .length,
    warnings: findings.filter((finding) => finding.severity === "warning")
      .length,
    scanned_records: bundle.records.length,
    scanned_unknowns: bundle.unknowns.length,
    limitations: [
      "The audit reports pattern matches only; a clean audit does not prove a bundle is safe to publish.",
      "Matched values are never printed; findings report a length and a short hash prefix instead. That prefix is a verification aid, not a secret: combine it with a candidate guess to confirm a match offline.",
      "Heuristic rules can produce false positives; confirm each finding against the bundle before acting on it.",
    ],
  };
};
