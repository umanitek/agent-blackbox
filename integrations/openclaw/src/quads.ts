/**
 * Identifier + quad builders for the Blackbox threat graph.
 *
 * This file is a FAITHFUL port of the canonical Python `plugins/blackbox/quads.py`
 * (the tested, shipped ground truth). A hermes node and an OpenClaw node that see
 * the same threat MUST compute the same subject URI, otherwise the cross-framework
 * threat-graph flywheel breaks (first-writer-wins on SWM root entities depends on
 * byte-identical identifiers). The contract is pinned by
 * `tests/parity/identifier_fixtures.json` and asserted by `test/parity.mjs`.
 *
 * Zero runtime deps: Node built-ins for sha256 and Java MUTF-8 byte accounting.
 */
import { createHash } from "node:crypto";

export type BlackboxSeverity = "info" | "low" | "medium" | "high" | "critical";

/** Severity ladder, lowest → highest. Mirrors constants.SEVERITY_ORDER. */
export const SEVERITY_ORDER: readonly BlackboxSeverity[] = [
  "info",
  "low",
  "medium",
  "high",
  "critical",
];

export const SEVERITY_RANK: Record<BlackboxSeverity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

// --- Ontology IRIs (shared vocabulary; identical to constants.py) ----------
// The legacy IRI path and `urn:guardian:` schemes below remain byte-stable so
// the already-published corpus stays queryable.
export const BLACKBOX_ONTOLOGY = "http://umanitek.ai/ontology/guardian/";
export const BLACKBOX_THREAT_TYPE_IRI = `${BLACKBOX_ONTOLOGY}Threat`;
export const BLACKBOX_DEP_THREAT_TYPE_IRI = `${BLACKBOX_ONTOLOGY}VulnerabilityAdvisory`;
export const BLACKBOX_INJECTION_THREAT_TYPE_IRI = `${BLACKBOX_ONTOLOGY}PromptInjectionThreat`;
export const BLACKBOX_ESCALATION_THREAT_TYPE_IRI = `${BLACKBOX_ONTOLOGY}EscalationThreat`;
export const BLACKBOX_FILE_ACCESS_THREAT_TYPE_IRI = `${BLACKBOX_ONTOLOGY}FileAccessThreat`;
export const BLACKBOX_SUSPICIOUS_SKILL_THREAT_TYPE_IRI = `${BLACKBOX_ONTOLOGY}SuspiciousSkillThreat`;
export const BLACKBOX_REPORT_TYPE_IRI = `${BLACKBOX_ONTOLOGY}ThreatReport`;
export const BLACKBOX_IDENTIFIER_PRED = `${BLACKBOX_ONTOLOGY}identifier`;
export const BLACKBOX_CURATED_PRED = `${BLACKBOX_ONTOLOGY}curated`;
export const BLACKBOX_SEVERITY_PRED = `${BLACKBOX_ONTOLOGY}severity`;
export const BLACKBOX_PATTERN_PRED = `${BLACKBOX_ONTOLOGY}pattern`;
export const BLACKBOX_TOOL_NAME_PRED = `${BLACKBOX_ONTOLOGY}toolName`;
export const BLACKBOX_ARG_SHAPE_PRED = `${BLACKBOX_ONTOLOGY}argShape`;
export const BLACKBOX_OWASP_CATEGORY_PRED = `${BLACKBOX_ONTOLOGY}owaspCategory`;
export const BLACKBOX_REPORTS_THREAT_PRED = `${BLACKBOX_ONTOLOGY}reportsThreat`;
export const BLACKBOX_REPORTER_PRED = `${BLACKBOX_ONTOLOGY}reporter`;
export const BLACKBOX_FRAMEWORK_PRED = `${BLACKBOX_ONTOLOGY}framework`;
export const BLACKBOX_PACKAGE_NAME_PRED = `${BLACKBOX_ONTOLOGY}packageName`;
export const BLACKBOX_PACKAGE_VERSION_PRED = `${BLACKBOX_ONTOLOGY}packageVersion`;
export const BLACKBOX_PACKAGE_ECOSYSTEM_PRED = `${BLACKBOX_ONTOLOGY}packageEcosystem`;
// threat kind: distinguishes active malware from a mere vulnerability. Only
// `malware` blocks (at/above block_severity); `vulnerability` always flags but
// never auto-blocks, so a legit-but-vulnerable package isn't stopped.
export const BLACKBOX_KIND_PRED = `${BLACKBOX_ONTOLOGY}kind`;
export const KIND_MALWARE = "malware";
export const KIND_VULNERABILITY = "vulnerability";
// file-access predicates (g:toolName reused; category is new) ---------------
export const BLACKBOX_CATEGORY_PRED = `${BLACKBOX_ONTOLOGY}category`;
// suspicious-skill predicates -----------------------------------------------
export const BLACKBOX_SKILL_NAME_PRED = `${BLACKBOX_ONTOLOGY}skillName`;
export const BLACKBOX_SKILL_VERSION_PRED = `${BLACKBOX_ONTOLOGY}skillVersion`;
export const BLACKBOX_DANGER_SHAPE_PRED = `${BLACKBOX_ONTOLOGY}dangerShape`;
// Append-only VM correction vocabulary. Corrections suppress an exact RDF
// subject without mutating the original published knowledge asset.
export const DEFENDER_CORRECTION_TYPE_IRI = "urn:defender:CorrectionSignal";
export const DEFENDER_CORRECTION_TARGET_PRED = "urn:defender:p:targetSubject";
export const DEFENDER_CORRECTION_ACTION_PRED = "urn:defender:p:action";
export const DEFENDER_CORRECTION_SUPPRESS = "suppress";
export const IOC_TYPES = ["domain", "url", "ip", "hash", "wallet", "contract"] as const;

const RDF_TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const SCHEMA_NAME = "http://schema.org/name";
const SCHEMA_DESCRIPTION = "http://schema.org/description";
const SCHEMA_DATE_MODIFIED = "http://schema.org/dateModified";
const SCHEMA_IDENTIFIER = "http://schema.org/identifier";
const XSD_DATETIME = "http://www.w3.org/2001/XMLSchema#dateTime";

export interface Quad {
  subject: string;
  predicate: string;
  object: string;
}

// DKG validates writable RDF literal terms with a 60,000 Java Modified UTF-8
// safe limit across Oxigraph/Blazegraph-compatible paths. Keep OpenClaw's final
// quoted term under the stricter Blackbox cap.
export const DKG_RDF_LITERAL_SAFE_MUTF8_BYTES = 60000;
export const MAX_LITERAL_BYTES = 50000;
const TRUNCATION_MARKER = " ...[truncated]";

// ---------------------------------------------------------------------------
// Hashing / slugs / URIs
// ---------------------------------------------------------------------------

/**
 * SHA-256 hex digest of the RAW UTF-8 bytes of `value`, truncated to `length`.
 *
 * Port of Python `stable_hash`: it hashes the string's raw bytes, NOT a JSON
 * stringification. Do not add quotes / JSON.stringify here — that would diverge
 * from the Python identifiers.
 */
export function stableHash(value: string, length = 24): string {
  return createHash("sha256").update(value, "utf8").digest("hex").slice(0, length);
}

/** lowercase, non `[a-z0-9._-]` → `-`, trim leading/trailing dashes, ≤96 chars. */
export function slug(value: string): string {
  const lowered = String(value).toLowerCase().replace(/[^a-z0-9._-]+/g, "-");
  const trimmed = lowered.replace(/^-+|-+$/g, "").slice(0, 96);
  return trimmed || "unknown";
}

export function normalizeSeverity(value: unknown, fallback: BlackboxSeverity = "info"): BlackboxSeverity {
  const raw = String(value ?? "").trim().toLowerCase();
  if (raw === "moderate") return "medium";
  return raw in SEVERITY_RANK ? (raw as BlackboxSeverity) : fallback;
}

/** Stable curated-threat subject URI for a threat `identifier`. */
export function threatUri(identifier: string): string {
  return `urn:guardian:threat:${slug(identifier)}`;
}

/**
 * Per-submitter namespaced report subject URI:
 *   `urn:guardian:report:{addrLower}:{sha256(identifier)[:16]}`
 * where the hash is over the RAW identifier bytes (Python parity).
 */
export function reportUri(identifier: string, agentAddress: string): string {
  const addr = (agentAddress || "anonymous").toLowerCase();
  return `urn:guardian:report:${addr}:${stableHash(identifier, 16)}`;
}

// ---------------------------------------------------------------------------
// Identifier builders
// ---------------------------------------------------------------------------

/** `dep:{ecosystem}:{name}@{version}` — ecosystem + name lowercased/trimmed. */
export function dependencyIdentifier(ecosystem: string, name: string, version: string): string {
  return `dep:${ecosystem.trim().toLowerCase()}:${name.trim().toLowerCase()}@${version.trim()}`;
}

/** `injection:{sha256(pattern)[:24]}` — hashes the RAW pattern bytes. */
export function injectionIdentifier(pattern: string): string {
  return `injection:${stableHash(pattern, 24)}`;
}

/**
 * `escalation:{tool}:{argShape}` — human-readable, single colon, shape NOT hashed.
 * The shape is kept literal so the id is legible, e.g.
 * `escalation:shell:remote-script-pipe`.
 */
export function escalationIdentifier(toolName: string, argShape: string): string {
  return `escalation:${toolName.trim().toLowerCase()}:${argShape.trim()}`;
}

/**
 * `fileaccess:{tool}:{category}` — e.g. `fileaccess:read_file:ssh-private-key`.
 * Both parts kept literal (lowercased+trimmed) so the id is legible and two
 * nodes touching the same sensitive-path category converge on one threat KA.
 */
export function fileaccessIdentifierFor(toolName: string, category: string): string {
  return `fileaccess:${toolName.trim().toLowerCase()}:${category.trim().toLowerCase()}`;
}

/** `skill:{name}@{version}` — the known-bad (graph-matched) skill id. */
export function skillVersionIdentifierFor(name: string, version: string): string {
  return `skill:${name.trim().toLowerCase()}@${version.trim()}`;
}

/** `skill:{name}:{dangerShape}` — a heuristic dangerous-code/permission id. */
export function skillShapeIdentifierFor(name: string, dangerShape: string): string {
  return `skill:${name.trim().toLowerCase()}:${dangerShape.trim()}`;
}

/** Canonicalize an IOC value exactly like Python `normalize_ioc_value`. */
export function normalizeIocValue(iocType: string, value: string): string {
  const type = (iocType || "").trim().toLowerCase();
  let raw = String(value || "").trim();
  if (!raw) return "";
  if (type === "domain") return raw.replace(/\.+$/, "").toLowerCase();
  if (type === "url") {
    const parts = raw.split("://", 2);
    if (parts.length === 2) {
      const slash = parts[1].indexOf("/");
      const host = (slash >= 0 ? parts[1].slice(0, slash) : parts[1]).toLowerCase();
      const rest = slash >= 0 ? parts[1].slice(slash) : "";
      raw = `${parts[0].toLowerCase()}://${host}${rest}`;
    }
    return raw.replace(/\/+$/, "");
  }
  if (type === "ip") return raw.split(":", 1)[0];
  if (type === "hash") return raw.toLowerCase();
  if (type === "wallet" || type === "contract") {
    return /^0x[a-fA-F0-9]{40}$/.test(raw) ? raw.toLowerCase() : raw;
  }
  return raw;
}

/** `ioc:{type}:{normalized-value}` — shared by Hermes and OpenClaw. */
export function iocIdentifier(iocType: string, value: string): string {
  const type = (iocType || "").trim().toLowerCase();
  return `ioc:${type}:${normalizeIocValue(type, value)}`;
}

/**
 * The threat identifier string. Faithful to Python's identifier builders.
 *   dependency    -> `dep:{ecosystem}:{name}@{version}`   (eco+name lowercased+trimmed)
 *   injection     -> `injection:{sha256(pattern_raw)[:24]}`
 *   escalation    -> `escalation:{toolName}:{argShape}`    (tool lowercased, shape literal)
 *   fileaccess    -> `fileaccess:{toolName}:{category}`    (both lowercased+trimmed)
 *   skill_version -> `skill:{name}@{version}`              (name lowercased, version literal)
 *   skill_shape   -> `skill:{name}:{dangerShape}`          (name lowercased, shape literal)
 */
export function threatIdentifierFor(
  args:
    | { type: "dependency"; ecosystem: string; name: string; version: string }
    | { type: "injection"; pattern: string }
    | { type: "escalation"; toolName: string; argShape: string }
    | { type: "fileaccess"; toolName: string; category: string }
    | { type: "skill_version"; name: string; version: string }
    | { type: "skill_shape"; name: string; dangerShape: string },
): string {
  if (args.type === "dependency") {
    return dependencyIdentifier(args.ecosystem, args.name, args.version);
  }
  if (args.type === "injection") {
    return injectionIdentifier(args.pattern);
  }
  if (args.type === "fileaccess") {
    return fileaccessIdentifierFor(args.toolName, args.category);
  }
  if (args.type === "skill_version") {
    return skillVersionIdentifierFor(args.name, args.version);
  }
  if (args.type === "skill_shape") {
    return skillShapeIdentifierFor(args.name, args.dangerShape);
  }
  return escalationIdentifier(args.toolName, args.argShape);
}

// ---------------------------------------------------------------------------
// N-Triples term escaping
// ---------------------------------------------------------------------------

function q(subject: string, predicate: string, object: string): Quad {
  return { subject, predicate, object };
}

/** Render an IRI term (bare, per the daemon's quad object convention). */
export function iri(value: string): string {
  return value;
}

/**
 * Render a plain-string literal term with N-Triples escaping.
 * Matches Python `literal`: escapes backslash, doublequote, \n, \r, \t (all five).
 */
export function literal(value: string): string {
  return literalTermForValue(capLiteralValue(String(value)));
}

export function javaModifiedUtf8ByteLength(value: string): number {
  let bytes = 0;
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code === 0) bytes += 2;
    else if (code <= 0x7f) bytes += 1;
    else if (code <= 0x07ff) bytes += 2;
    else bytes += 3;
  }
  return bytes;
}

function escapeLiteralText(value: string): string {
  return value
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\n/g, "\\n")
    .replace(/\r/g, "\\r")
    .replace(/\t/g, "\\t");
}

function literalTermForValue(value: string): string {
  return `"${escapeLiteralText(value)}"`;
}

function literalValueTermMutf8Bytes(value: string): number {
  return javaModifiedUtf8ByteLength(literalTermForValue(value));
}

function capLiteralValue(value: string): string {
  if (literalValueTermMutf8Bytes(value) <= MAX_LITERAL_BYTES) return value;
  const chars = Array.from(value);
  let lo = 0;
  let hi = chars.length;
  let best = TRUNCATION_MARKER;
  while (lo <= hi) {
    const mid = Math.floor((lo + hi) / 2);
    const candidate = `${chars.slice(0, mid).join("")}${TRUNCATION_MARKER}`;
    if (literalValueTermMutf8Bytes(candidate) <= MAX_LITERAL_BYTES) {
      best = candidate;
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  return best;
}

/** Render an `xsd:dateTime` typed literal (UTC ISO-8601 with `Z`). */
export function datetimeLiteral(ts?: number): string {
  const iso = new Date(ts ?? Date.now()).toISOString(); // always UTC, ends in Z
  return `${literal(iso)}^^${XSD_DATETIME}`;
}

export interface ReportInput {
  identifier: string;
  category: "injection" | "escalation" | "dependency" | "fileaccess" | "skill" | "ioc";
  severity: BlackboxSeverity;
  /** Reporter agent address (node default agent). Lowercased for the URI. */
  reporter: string;
  framework: "hermes" | "openclaw";
  ts?: number;
  /** Present only for new candidates so they can be reviewed independently. */
  candidate?: {
    pattern?: string;
    toolName?: string;
    argShape?: string;
    packageName?: string;
    packageVersion?: string;
    packageEcosystem?: string;
    advisoryId?: string;
    owaspCategory?: string;
    // fileaccess
    fileCategory?: string;
    // skill
    skillName?: string;
    skillVersion?: string;
    dangerShape?: string;
    iocType?: string;
  };
}

/**
 * Build the SWM sighting/report quads for one finding. Faithful port of Python
 * `build_report_quads`. Reports NEVER carry observed prompt/command text (privacy
 * split — that stays in the private WM audit). `g:reportsThreat` links to the
 * curated threat URI; for a NEW candidate the category-conditional threat fields
 * are carried inline so the report is independently reviewable.
 *
 * IRIs (the rdf:type object and reportsThreat object) are emitted BARE — Python
 * `iri()` returns the value with no angle brackets.
 */
export function buildReportQuads(input: ReportInput): Quad[] {
  const ts = input.ts;
  const reporter = (input.reporter || "anonymous").toLowerCase();
  const subj = reportUri(input.identifier, input.reporter);
  const threat = threatUri(input.identifier);
  const out: Quad[] = [
    q(subj, RDF_TYPE, iri(BLACKBOX_REPORT_TYPE_IRI)),
    q(subj, BLACKBOX_REPORTS_THREAT_PRED, iri(threat)),
    q(subj, BLACKBOX_IDENTIFIER_PRED, literal(input.identifier)),
    q(subj, BLACKBOX_REPORTER_PRED, literal(reporter)),
    q(subj, BLACKBOX_FRAMEWORK_PRED, literal(input.framework)),
    q(subj, BLACKBOX_SEVERITY_PRED, literal(normalizeSeverity(input.severity))),
    q(subj, SCHEMA_DATE_MODIFIED, datetimeLiteral(ts)),
  ];
  const c = input.candidate ?? {};
  if (input.category === "injection" && c.pattern) {
    out.push(q(subj, BLACKBOX_PATTERN_PRED, literal(c.pattern)));
    if (c.owaspCategory) out.push(q(subj, BLACKBOX_OWASP_CATEGORY_PRED, literal(c.owaspCategory)));
  } else if (input.category === "escalation") {
    if (c.toolName) out.push(q(subj, BLACKBOX_TOOL_NAME_PRED, literal(c.toolName)));
    if (c.argShape) out.push(q(subj, BLACKBOX_ARG_SHAPE_PRED, literal(c.argShape)));
  } else if (input.category === "dependency") {
    if (c.packageName) out.push(q(subj, BLACKBOX_PACKAGE_NAME_PRED, literal(c.packageName)));
    if (c.packageVersion) out.push(q(subj, BLACKBOX_PACKAGE_VERSION_PRED, literal(c.packageVersion)));
    if (c.packageEcosystem) out.push(q(subj, BLACKBOX_PACKAGE_ECOSYSTEM_PRED, literal(c.packageEcosystem)));
    if (c.advisoryId) out.push(q(subj, SCHEMA_IDENTIFIER, literal(c.advisoryId)));
  } else if (input.category === "fileaccess") {
    if (c.toolName) out.push(q(subj, BLACKBOX_TOOL_NAME_PRED, literal(c.toolName)));
    if (c.fileCategory) out.push(q(subj, BLACKBOX_CATEGORY_PRED, literal(c.fileCategory)));
  } else if (input.category === "skill") {
    if (c.skillName) out.push(q(subj, BLACKBOX_SKILL_NAME_PRED, literal(c.skillName)));
    if (c.skillVersion) out.push(q(subj, BLACKBOX_SKILL_VERSION_PRED, literal(c.skillVersion)));
    if (c.dangerShape) out.push(q(subj, BLACKBOX_DANGER_SHAPE_PRED, literal(c.dangerShape)));
  }
  return out;
}

export { RDF_TYPE, SCHEMA_NAME, SCHEMA_DESCRIPTION, SCHEMA_DATE_MODIFIED, SCHEMA_IDENTIFIER, XSD_DATETIME };
