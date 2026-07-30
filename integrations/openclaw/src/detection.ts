/**
 * Ruleset-driven matcher — a faithful port of the canonical Python
 * `plugins/blackbox/quads.py` (arg-shape + dependency parsing) and
 * `plugins/blackbox/detection.py` (the matchers).
 *
 * Detection rules come ONLY from the synced threat graph (see ruleset.ts), in
 * two trust tiers: `source: "public"` (verifiable-memory, the curated source of
 * truth — matches are CONFIRMED and blockable) and `source: "community"` (the
 * shared community pool — matches are flagged but can never block). Built-in
 * heuristics only *nominate* candidates (`source: "heuristic"`). On an empty
 * graph the matcher detects nothing until synced — by design.
 *
 * Three pure detectors:
 *   - detectInjection(text, ruleset)         — cached regex over text
 *   - detectEscalation(toolName, args, rs)   — compares BOTH toolName AND argShape
 *   - detectDependency(toolName, args, rs)   — parses install cmds → dep lookup
 *
 * `normalizeArgShape` lives here (single source) and is reused by the reporter
 * for identifier building, so independent clients
 * shapes stay consistent. It returns the SINGLE top-priority shape (or null),
 * exactly like Python's `normalize_arg_shape`.
 */
import os from "node:os";
import path from "node:path";
import {
  BlackboxSeverity,
  escalationIdentifier,
  fileaccessIdentifierFor,
  injectionIdentifier,
  dependencyIdentifier,
  iocIdentifier,
  skillVersionIdentifierFor,
  skillShapeIdentifierFor,
} from "./quads.js";

export type ThreatCategory =
  | "injection"
  | "escalation"
  | "dependency"
  | "fileaccess"
  | "skill"
  | "ioc";

/**
 * Trust tier a graph rule came from. `"public"` = verifiable-memory (the
 * curated Umanitek public threat graph — the source of truth, blockable);
 * `"community"` = shared-working-memory (the community pool anyone can write
 * to — flag-only, never blocks). Mirrors Python ruleset `source` tagging.
 */
export type RuleSource = "public" | "community";

/**
 * Trust tier a finding was raised at: a graph tier (`RuleSource`),
 * `"heuristic"` for built-in discovery candidates, or `"custom"` for a
 * user-configured local rule (e.g. a protected path). A `"custom"` finding
 * always flags, blocks in block mode, and is NEVER shared to the community
 * graph. Mirrors Python `Finding.source`.
 */
export type FindingSource = RuleSource | "heuristic" | "custom";

/**
 * Trust tier of a graph rule. Untagged rules default to `public` — rules
 * cached before tier tagging (or handed in directly by tests) were always
 * treated as curated. Mirrors Python `_rule_source`.
 */
export function ruleSource(rule: { source?: string }): RuleSource {
  const src = String(rule.source ?? "public").toLowerCase();
  return src === "community" ? "community" : "public";
}

// --- Ruleset shape ---------------------------------------------------------
export interface InjectionRule {
  identifier: string;
  pattern: string; // regex source
  severity: BlackboxSeverity;
  name: string;
  owaspCategory?: string;
  /** Trust tier (absent = public, for pre-tier caches). */
  source?: RuleSource;
}
export interface EscalationRule {
  identifier: string;
  toolName: string; // lowercased for comparison
  argShape: string;
  severity: BlackboxSeverity;
  name: string;
  source?: RuleSource;
}
export interface DependencyRule {
  identifier: string;
  severity: BlackboxSeverity;
  advisoryId?: string;
  /** malware | vulnerability — vulnerabilities flag but never auto-block. */
  kind?: string;
  name: string;
  source?: RuleSource;
}
export interface FileAccessRule {
  identifier: string;
  toolName: string; // lowercased for comparison
  category: string; // lowercased for comparison
  severity: BlackboxSeverity;
  name: string;
  source?: RuleSource;
}
export interface SkillRule {
  identifier: string;
  skillName: string;
  skillVersion: string;
  dangerShape: string;
  severity: BlackboxSeverity;
  name: string;
  source?: RuleSource;
}
export interface IocRule {
  identifier: string;
  severity: BlackboxSeverity;
  name: string;
  iocType: string;
  value: string;
  kind?: string;
  sourceId?: string;
  source?: RuleSource;
}
export interface Ruleset {
  injection: InjectionRule[];
  escalation: EscalationRule[];
  /** Keyed by `{ecosystem}:{name}@{version}` (ecosystem+name lowercased). */
  dependency: Record<string, DependencyRule>;
  fileaccess: FileAccessRule[];
  skill: SkillRule[];
  /** Keyed by the full `ioc:{type}:{normalized-value}` identifier. */
  ioc: Record<string, IocRule>;
  fetchedAt: number;
}

export function emptyRuleset(): Ruleset {
  return {
    injection: [],
    escalation: [],
    dependency: {},
    fileaccess: [],
    skill: [],
    ioc: {},
    fetchedAt: 0,
  };
}

/**
 * Privacy-safe candidate threat attributes forwarded to `buildReportQuads` so a
 * reviewers can assess a candidate. NEVER carries raw prompts, paths, or
 * file/skill source — only signatures (pattern / category / danger shape / ...).
 * Mirrors Python `Finding.fields`.
 */
export interface FindingFields {
  pattern?: string;
  owaspCategory?: string;
  toolName?: string;
  argShape?: string;
  ecosystem?: string;
  packageName?: string;
  packageVersion?: string;
  advisoryId?: string;
  fileCategory?: string;
  skillName?: string;
  skillVersion?: string;
  dangerShape?: string;
  iocType?: string;
}

export interface Finding {
  identifier: string;
  category: ThreatCategory;
  severity: BlackboxSeverity;
  title: string;
  toolName: string | null;
  matched: string; // local match summary; may contain a bounded observed phrase
  evidence: string; // local-only redacted snippet; never forwarded to SWM
  /**
   * True ONLY when the finding matched the curated PUBLIC threat graph
   * (`source === "public"`) — the strict "public graph says so" bit; only
   * confirmed findings can block. Community and heuristic findings are never
   * confirmed. Mirrors Python `Finding.confirmed`.
   */
  confirmed: boolean;
  /**
   * Which trust tier raised the finding:
   *   - `"public"`    — curated public graph match (confirmed, blockable).
   *   - `"community"` — community-pool match (flagged + re-reported to
   *                     strengthen consensus, but NEVER blocks).
   *   - `"heuristic"` — built-in discovery candidate nominated to the
   *                     community graph.
   *   - `"custom"`    — user-configured local rule (protected path). Always
   *                     flags, blocks in block mode, NEVER shared to SWM.
   * Mirrors Python `Finding.source`.
   */
  source: FindingSource;
  /**
   * Threat handling kind (`malware` | `vulnerability` | `historical`).
   * Vulnerability and historical findings flag but never auto-block. Mirrors
   * Python `Finding.kind`.
   */
  kind?: string;
  /** Privacy-safe candidate threat fields (see `FindingFields`). */
  fields: FindingFields;
}

const MAX_TEXT = 50_000;

/**
 * Compiled-regex cache keyed by pattern source. Peer-supplied patterns are
 * untrusted: compilation and execution are guarded per-regex.
 */
const regexCache = new Map<string, RegExp | null>();

function compile(source: string): RegExp | null {
  if (regexCache.has(source)) return regexCache.get(source) ?? null;
  let re: RegExp | null = null;
  try {
    // DKG string literals carry one JSON/RDF escape layer beyond the regex
    // source. Leaving it intact can turn `<\\|endoftext\\|>` into a pattern
    // that matches any bare `>`. Python-authored patterns may also carry the
    // leading inline `(?i)` flag, which JavaScript rejects; the explicit `i`
    // flag below already provides the same semantics.
    const normalized = source.replace(/\\\\/g, "\\").replace(/^\(\?i\)/, "");
    re = new RegExp(normalized, "i");
  } catch {
    re = null;
  }
  regexCache.set(source, re);
  return re;
}

/** Run each cached injection regex over `text`. Fail-open per regex. */
export function detectInjection(text: string, ruleset: Ruleset): Finding[] {
  if (!text) return [];
  const capped = text.length > MAX_TEXT ? text.slice(0, MAX_TEXT) : text;
  const out: Finding[] = [];
  const seen = new Set<string>();
  for (const rule of ruleset.injection) {
    if (seen.has(rule.identifier)) continue;
    const re = compile(rule.pattern);
    if (!re) continue;
    try {
      if (re.test(capped)) {
        seen.add(rule.identifier);
        const src = ruleSource(rule);
        out.push({
          identifier: rule.identifier,
          category: "injection",
          severity: rule.severity,
          title: rule.name || "Prompt injection pattern matched",
          toolName: null,
          matched: rule.pattern,
          evidence: sampleAround(capped, re),
          confirmed: src === "public",
          source: src,
          // Community matches carry the promotion fields so our sighting
          // strengthens the community signal. Mirrors Python detect_injection.
          fields: src === "community" ? { pattern: rule.pattern } : {},
        });
      }
    } catch {
      // untrusted regex blew up at match time — skip it, keep going.
    }
  }
  return out;
}

/**
 * Escalation: derive the arg shape deterministically, then match a rule ONLY
 * when BOTH toolName AND argShape agree.
 */
export function detectEscalation(
  toolName: string,
  args: unknown,
  ruleset: Ruleset,
): Finding[] {
  const shape = normalizeArgShape(toolName, args);
  if (!shape) return [];
  const tool = (toolName || "").trim().toLowerCase();
  const out: Finding[] = [];
  const seen = new Set<string>();
  for (const rule of ruleset.escalation) {
    if (seen.has(rule.identifier)) continue;
    if (rule.toolName.trim().toLowerCase() !== tool) continue;
    if (rule.argShape.trim() !== shape) continue;
    seen.add(rule.identifier);
    const src = ruleSource(rule);
    out.push({
      identifier: rule.identifier,
      category: "escalation",
      severity: rule.severity,
      title: rule.name || `Dangerous ${tool} call (${shape})`,
      toolName: toolName || "",
      matched: shape,
      evidence: shape,
      confirmed: src === "public",
      source: src,
      fields: src === "community" ? { toolName: tool, argShape: shape } : {},
    });
  }
  // Discovery layer: a dangerous shape that no graph rule covers is still a
  // candidate escalation nominated to the community graph.
  if (out.length === 0) {
    out.push({
      identifier: escalationIdentifier(tool, shape),
      category: "escalation",
      severity: "high",
      title: `Suspicious ${tool} call (${shape})`,
      toolName: toolName || "",
      matched: shape,
      evidence: shape,
      confirmed: false,
      source: "heuristic",
      fields: { toolName: tool, argShape: shape },
    });
  }
  return out;
}

/**
 * Best-effort extraction of a command string for dependency parsing.
 * Port of Python `_command_text`: string args → raw; dict args → first present
 * COMMAND_KEYS value, else ALL string values joined (unconditionally — this
 * differs from `commandFromArgs`, which only joins for shell-like tools).
 */
export function commandText(args: unknown): string {
  if (typeof args === "string") return args;
  if (args == null || typeof args !== "object" || Array.isArray(args)) return "";
  const obj = args as Record<string, unknown>;
  for (const key of COMMAND_KEYS) {
    const val = obj[key];
    if (typeof val === "string" && val) return val;
  }
  return Object.values(obj)
    .filter((v): v is string => typeof v === "string")
    .join(" ");
}

/** Dependency: parse install commands → look up in ruleset.dependency. */
export function detectDependency(
  toolName: string,
  args: unknown,
  ruleset: Ruleset,
): Finding[] {
  const command = commandText(args);
  if (!command) return [];
  const dependencyRules = ruleset.dependency ?? {};
  if (Object.keys(dependencyRules).length === 0) return [];
  const installs = parseDependencyInstalls(command);
  const out: Finding[] = [];
  const seen = new Set<string>();
  for (const dep of installs) {
    const eco = dep.ecosystem.toLowerCase();
    const name = dep.name.toLowerCase();
    // Exact pinned version first, then a package-level `@*` rule — whole-package
    // malware / typosquats where every version is bad, incl. an unpinned install.
    const candidates = dep.version ? [`${eco}:${name}@${dep.version}`] : [];
    candidates.push(`${eco}:${name}@*`);
    const key = candidates.find((k) => dependencyRules[k]);
    if (!key || seen.has(key)) continue;
    seen.add(key);
    const rule = dependencyRules[key];
    const src = ruleSource(rule);
    const shown = dep.version || "*";
    out.push({
      identifier: rule.identifier || `dep:${key}`,
      category: "dependency",
      severity: rule.severity,
      title: rule.name || `Vulnerable dependency ${name}@${shown}`,
      toolName: toolName || "",
      matched: key,
      evidence: rule.advisoryId
        ? `${dep.ecosystem}:${dep.name}@${shown} (${rule.advisoryId})`
        : `${dep.ecosystem}:${dep.name}@${shown}`,
      confirmed: src === "public",
      source: src,
      kind: rule.kind,
      fields:
        src === "community"
          ? {
              ecosystem: eco,
              packageName: name,
              packageVersion: dep.version || "*",
              advisoryId: rule.advisoryId,
            }
          : {},
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Arg-shape normalization — port of quads.py
// ---------------------------------------------------------------------------

// A remote-download-piped-to-interpreter shape: `curl ... | sh`, `wget ... | bash`.
const REMOTE_SCRIPT_RE = /\b(?:curl|wget)\b[\s\S]{0,500}\|\s*(?:sh|bash|zsh|python|python3|node)\b/i;
// `rm -rf` against DANGEROUS roots only (mirrors Python RM_RF_SYSTEM_RE): system
// roots, bare `/`, whole-home wipe (~, $HOME), or a sensitive home dir. Routine
// cleanup (node_modules, ~/.cache, ~/build, /var/tmp) does NOT match.
const RM_RF_SYSTEM_RE =
  /\brm\s+(?:-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|-r\s+-f|-f\s+-r|--recursive\s+--force|--force\s+--recursive|-r\s+--force|--recursive\s+-f)\b[\s\S]{0,200}(?:\s\/(?:etc|usr|bin|sbin|opt|private|System|Library)\b|\s\/var(?!\/(?:tmp|folders))\b|\s\/\s*(?=[;&|]|$)|\s(?:~|\$HOME)\/?(?=\s|[;&|]|$)|\s(?:~|\$HOME)\/\.(?:ssh|aws|gnupg|gpg|kube|docker|password-store)\b)/i;
// `chmod 777` against a SENSITIVE target only (mirrors Python CHMOD_WORLD_RE).
const CHMOD_WORLD_RE =
  /\bchmod\s+(?:-R\s+)?0?777\b[\s\S]{0,200}(?:\s\/(?:etc|usr|bin|sbin|var|opt|private|System|Library)\b|\s\/\s*(?=[;&|]|$)|\s(?:~|\$HOME)\/?\.?(?:ssh|aws|gnupg))/i;
// Piping a fetched payload straight into eval.
const CURL_EVAL_RE = /\b(?:curl|wget)\b[\s\S]{0,300}\|\s*eval\b/i;
// Disabling TLS verification on a network fetch (mirrors Python INSECURE_FETCH_RE).
const INSECURE_FETCH_RE =
  /\bcurl\b[\s\S]{0,200}(?:--insecure|--no-check-certificate|\s-[a-z]*k[a-z]*\b)|\bwget\b[\s\S]{0,200}--no-check-certificate/i;
// A local/private/dev host — an insecure TLS fetch against one of these is
// routine, not a threat (mirrors Python _LOCAL_HOST_RE).
const LOCAL_HOST_RE =
  /(?:localhost|127\.0\.0\.\d+|0\.0\.0\.0|\[::1\]|\b10\.\d+\.\d+\.\d+|\b192\.168\.\d+\.\d+|\b172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|\.local\b|\.internal\b)/i;

/**
 * Ordered so the most specific / most dangerous shape wins for a given command.
 * Mirrors Python `_SHELL_SHAPE_RULES` exactly (priority order matters).
 */
const SHELL_SHAPE_RULES: ReadonlyArray<readonly [string, RegExp]> = [
  ["remote-script-pipe", REMOTE_SCRIPT_RE],
  ["remote-eval-pipe", CURL_EVAL_RE],
  ["rm-rf-system-paths", RM_RF_SYSTEM_RE],
  ["chmod-world-writable", CHMOD_WORLD_RE],
  ["insecure-tls-fetch", INSECURE_FETCH_RE],
];

// Tool names whose payload is treated as a shell command string.
const SHELL_TOOLS = new Set(["terminal", "shell", "bash", "run_command", "exec", "command"]);
const COMMAND_KEYS = ["command", "cmd", "shell", "script", "input"] as const;

const MAX_SHAPE_SCAN = 8000;

/**
 * Best-effort extraction of a shell command string from tool args.
 * Port of Python `_command_from_args`:
 *   - string args             → the raw string (capped)
 *   - dict args               → first present COMMAND_KEYS value
 *   - shell-like tools only    → concat of string values as fallback
 *   - anything else            → ""
 */
export function commandFromArgs(toolName: string, args: unknown): string {
  if (typeof args === "string") return args.slice(0, MAX_SHAPE_SCAN);
  if (args == null || typeof args !== "object" || Array.isArray(args)) return "";
  const obj = args as Record<string, unknown>;
  for (const key of COMMAND_KEYS) {
    const val = obj[key];
    if (typeof val === "string" && val) return val.slice(0, MAX_SHAPE_SCAN);
  }
  // Fall back to concatenating string values for shell-like tools only.
  if (SHELL_TOOLS.has((toolName || "").toLowerCase())) {
    const parts = Object.values(obj).filter((v): v is string => typeof v === "string");
    return parts.join(" ").slice(0, MAX_SHAPE_SCAN);
  }
  return "";
}

/** Whether a tool's payload is treated as a shell command. */
export function isShellTool(toolName: string): boolean {
  return SHELL_TOOLS.has((toolName || "").trim().toLowerCase());
}

/**
 * Derive a deterministic escalation `argShape` for a tool call.
 *
 * Returns the SINGLE top-priority stable slug (e.g. `remote-script-pipe`) or
 * `null` when the call matches no known dangerous shape. Deterministic and pure
 * so independent clients agree on identifiers.
 * Port of Python `normalize_arg_shape` (returns ONE shape or None).
 */
export function normalizeArgShape(toolName: string, args: unknown): string | null {
  const command = commandFromArgs(toolName, args);
  if (!command) return null;
  for (const [shape, pattern] of SHELL_SHAPE_RULES) {
    try {
      if (pattern.test(command)) {
        // Insecure TLS against a localhost / private / .local host is routine
        // dev work, not a threat — skip it (mirrors Python normalize_arg_shape).
        if (shape === "insecure-tls-fetch" && LOCAL_HOST_RE.test(command)) continue;
        return shape;
      }
    } catch {
      // static patterns; ignore any engine hiccup and keep scanning.
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Built-in injection heuristics (discovery layer — OWASP LLM01/LLM06)
// Port of quads.py `_INJECTION_HEURISTICS` / `scan_injection_heuristics`.
// ---------------------------------------------------------------------------

// Each entry is [severity, owasp, regex]. The DISCOVERY nomination layer: a
// prompt matching one NOT already in the graph is auto-submitted as a candidate.
// Privacy: the regex source is the shareable signature; observed prompt text
// stays in local evidence only and must never enter Finding.fields.
const INJECTION_HEURISTICS: ReadonlyArray<readonly [BlackboxSeverity, string, RegExp]> = [
  // OpenClaw replaces model-control delimiters in external content with this
  // marker before plugins see the result. Preserve the security signal.
  ["high", "LLM01", /\[REMOVED_SPECIAL_TOKEN\]/],
  // "ignore all previous instructions" and close variants (see quads.py).
  ["high", "LLM01", /(?:ignore|disregard|forget|skip|override)\s+(?:all\s+|any\s+|the\s+|these\s+)?(?:previous|prior|above|earlier|preceding|prior\s+)\s*(?:instruction|message|prompt|rule|context|direction|directive|command|guideline)s?/i],
  // Exfiltrate the system prompt / instructions.
  ["high", "LLM06", /(?:reveal|show|print|repeat|disclose|give|tell|share|send|output|expose|leak|what(?:'s|\s+is|\s+are)?|display)\b[\s\S]{0,40}\b(?:system\s+prompt|system\s+message|initial\s+(?:instruction|prompt)s?|your\s+(?:instructions|prompt|system\s+prompt|guidelines))/i],
  ["high", "LLM01", /you\s+are\s+now\b[\s\S]{0,40}\b(?:DAN|developer\s+mode|jailbroken|unrestricted)/i],
  ["high", "LLM01", /(?:pretend|act\s+as|roleplay|imagine)\s+(?:to\s+be\s+|you(?:'re|\s+are)\s+|as\s+)?[\s\S]{0,40}\b(?:no\s+restrictions|unrestricted|without\s+rules|no\s+rules|jailbroken|DAN\b)/i],
  ["high", "LLM06", /(?:exfiltrate|exfil|smuggle)\b[\s\S]{0,40}\b(?:api\s*key|secret|token|credentials|password|env(?:ironment)?\s+variables?|\.env)/i],
  ["high", "LLM06", /\b(?:leak|upload|steal|send|post)(?:s|ing|ed)?\s+(?:the\s+|my\s+|our\s+|your\s+|all\s+(?:the\s+)?)?(?:api\s*key|secret|token|credentials|password|env(?:ironment)?\s+variables?|\.env)/i],
];

/** Truncation cap for the matched dangerous phrase kept as local evidence. */
const INJECTION_PHRASE_CAP = 120;
const MAX_INJECTION_SCAN = 50_000;

export interface InjectionHeuristicHit {
  /** Fixed built-in regex source; safe to share and stable across users. */
  pattern: string;
  /** Observed prompt substring; local-only and never copied to Finding.fields. */
  phrase: string;
  severity: BlackboxSeverity;
  owasp: string;
}

/**
 * Return built-in injection matches as `[{pattern, phrase, severity, owasp}]`.
 * `pattern` is the fixed heuristic regex source; `phrase` is the matched prompt
 * substring (truncated ~120 chars) and remains local-only. Port of Python
 * `scan_injection_heuristics`.
 */
export function scanInjectionHeuristics(text: string): InjectionHeuristicHit[] {
  if (!text) return [];
  const scan = text.length > MAX_INJECTION_SCAN ? text.slice(0, MAX_INJECTION_SCAN) : text;
  const out: InjectionHeuristicHit[] = [];
  const seen = new Set<string>();
  for (const [severity, owasp, pattern] of INJECTION_HEURISTICS) {
    let m: RegExpMatchArray | null = null;
    try {
      m = scan.match(pattern);
    } catch {
      continue;
    }
    if (!m) continue;
    const signature = pattern.source;
    if (seen.has(signature)) continue;
    seen.add(signature);
    out.push({
      pattern: signature,
      phrase: m[0].slice(0, INJECTION_PHRASE_CAP),
      severity,
      owasp,
    });
  }
  return out;
}

/**
 * Built-in injection discovery: heuristic matches not already in the graph.
 * PRIVACY: the matched prompt substring is kept only in local
 * `matched`/`evidence`. The candidate fields sent to SWM carry only the fixed
 * heuristic regex signature. Port of Python `discover_injection`.
 */
export function discoverInjection(text: string, ruleset: Ruleset): Finding[] {
  const known = new Set<string>();
  for (const rule of ruleset.injection ?? []) {
    if (rule.identifier) known.add(rule.identifier);
  }
  const out: Finding[] = [];
  const seen = new Set<string>();
  for (const hit of scanInjectionHeuristics(text || "")) {
    const identifier = injectionIdentifier(hit.pattern);
    if (known.has(identifier) || seen.has(identifier)) continue;
    seen.add(identifier);
    out.push({
      identifier,
      category: "injection",
      severity: hit.severity,
      title: "Suspicious prompt-injection phrase",
      toolName: null,
      matched: hit.phrase,
      evidence: hit.phrase,
      confirmed: false,
      source: "heuristic",
      fields: { pattern: hit.pattern, owaspCategory: hit.owasp },
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Sensitive file-access categories (discovery layer)
// Port of quads.py `_SENSITIVE_PATH_RULES` / `file_access_arg` /
// `sensitive_path_category` + detection.py `detect_fileaccess`.
// ---------------------------------------------------------------------------

// [category, severity, path-regex]. Matched against the accessed path only; the
// candidate carries ONLY the category + tool — never the exact path.
const SENSITIVE_PATH_RULES: ReadonlyArray<readonly [string, BlackboxSeverity, RegExp]> = [
  ["ssh-private-key", "critical", /(?:^|\/)\.ssh\/(?!(?:config|known_hosts|authorized_keys)$)(?!.*\.pub$).+|(?:^|\/)id_(?:rsa|ed25519|ecdsa|dsa)\b(?!\.pub)/i],
  ["env-file", "high", /(?:^|\/)\.env(?:\.[\w.-]+)?$(?<!\.example)(?<!\.sample)(?<!\.template)(?<!\.dist)(?<!\.default)/i],
  [
    "credentials",
    "critical",
    /(?:^|\/)\.aws\/credentials$|(?:^|\/)\.netrc$|(?:^|\/)\.npmrc$|(?:^|\/)\.docker\/config\.json$|(?:^|\/)\.kube\/config$|(?:^|\/)\.config\/gcloud(?:\/|$)/i,
  ],
  ["password-store", "critical", /(?:^|\/)\.password-store(?:\/|$)|(?:^|\/)\.pgpass$/i],
  [
    "browser-cookies",
    "high",
    /(?:Chrome|Chromium|Brave|Edge|Opera|Vivaldi|BraveSoftware)[\s\S]{0,120}\/(?:Cookies|Login Data)$|(?:^|\/)cookies\.sqlite$|(?:^|\/)Cookies\.binarycookies$|(?:^|\/)Library\/Keychains(?:\/|$)|(?:^|\/)login\.keychain/i,
  ],
  ["system-shadow", "critical", /^\/etc\/(?:shadow|passwd|sudoers)$/i],
];

// Tools whose args reference a file/path. Value = mode (read | write).
const FILE_ACCESS_TOOLS: Record<string, "read" | "write"> = {
  read: "read",
  write: "write",
  read_file: "read",
  write_file: "write",
  edit_file: "write",
  edit: "write",
  patch: "write",
  apply_patch: "write",
  create_file: "write",
  delete_file: "write",
  open_file: "read",
  cat: "read",
  skill_manage: "write",
};
const PATH_KEYS = ["path", "file", "file_path", "filepath", "filename", "target", "target_file"] as const;

function npmrcHasToken(args: unknown): boolean {
  let text = typeof args === "string" ? args : "";
  if (args != null && typeof args === "object" && !Array.isArray(args)) {
    for (const v of Object.values(args as Record<string, unknown>)) {
      if (typeof v === "string") text += "\n" + v;
    }
  }
  return text.toLowerCase().includes("_authtoken");
}

export interface FileAccess {
  tool: string;
  path: string;
  mode: "read" | "write";
}

/**
 * Extract `{tool, path, mode}` for a file-access tool call, or `null`.
 * Port of Python `file_access_arg`.
 */
export function fileAccessArg(toolName: string, args: unknown): FileAccess | null {
  const tool = (toolName || "").trim().toLowerCase();
  const mode = FILE_ACCESS_TOOLS[tool];
  if (!mode || args == null || typeof args !== "object" || Array.isArray(args)) return null;
  const obj = args as Record<string, unknown>;
  let path = "";
  for (const key of PATH_KEYS) {
    const val = obj[key];
    if (typeof val === "string" && val.trim()) {
      path = val.trim();
      break;
    }
  }
  if (!path) return null;
  return { tool, path, mode };
}

export interface SensitiveCategory {
  category: string;
  severity: BlackboxSeverity;
}

/**
 * Classify `path` into a sensitive category, or `null`. The `.npmrc` file is
 * only sensitive when it carries an `_authToken` (checked via `args`).
 * Port of Python `sensitive_path_category`.
 */
export function sensitivePathCategory(path: string, args?: unknown): SensitiveCategory | null {
  if (!path) return null;
  const p = path.trim();
  if (p.endsWith(".npmrc")) {
    return npmrcHasToken(args) ? { category: "credentials", severity: "critical" } : null;
  }
  for (const [category, severity, pattern] of SENSITIVE_PATH_RULES) {
    try {
      if (pattern.test(p)) return { category, severity };
    } catch {
      continue;
    }
  }
  return null;
}

/**
 * Detect access to a sensitive-path category (graph rule or built-in).
 * PRIVACY: the finding carries ONLY the category + tool — never the exact path
 * or file contents. Port of Python `detect_fileaccess`.
 */
export function detectFileaccess(toolName: string, args: unknown, ruleset: Ruleset): Finding[] {
  const access = fileAccessArg(toolName, args);
  if (!access) return [];
  const hit = sensitivePathCategory(access.path, args);
  if (!hit) return [];
  const tool = access.tool;
  const category = hit.category;
  let identifier = fileaccessIdentifierFor(tool, category);
  let severity: BlackboxSeverity = hit.severity;
  let source: FindingSource = "heuristic";
  let name: string | undefined;
  for (const rule of ruleset.fileaccess ?? []) {
    if (
      String(rule.toolName || "").toLowerCase() === tool &&
      String(rule.category || "").toLowerCase() === category
    ) {
      source = ruleSource(rule);
      severity = rule.severity ?? severity;
      name = rule.name;
      identifier = rule.identifier || identifier;
      break;
    }
  }
  return [
    {
      identifier,
      category: "fileaccess",
      severity,
      title: name || `Sensitive file access (${category})`,
      toolName: tool,
      matched: category,
      evidence: `${access.mode} ${category}`,
      confirmed: source === "public",
      source,
      fields: { toolName: tool, fileCategory: category },
    },
  ];
}

// ---------------------------------------------------------------------------
// Suspicious-skill danger-shape scanning (discovery layer)
// Port of quads.py `_SKILL_CODE_RULES` / `_SKILL_PERMISSION_RULES` /
// `skill_install_arg` / `scan_skill_dangers` + detection.py `detect_skill`.
// ---------------------------------------------------------------------------

// [dangerShape, severity, regex] over the skill's declared code/content.
const SKILL_CODE_RULES: ReadonlyArray<readonly [string, BlackboxSeverity, RegExp]> = [
  [
    "shell-exec",
    "high",
    /\b(?:os\.system|subprocess\.(?:run|call|Popen|check_output)|child_process|exec(?:Sync)?\s*\(|spawn(?:Sync)?\s*\()/i,
  ],
  ["remote-script-pipe", "critical", REMOTE_SCRIPT_RE],
  [
    "credential-exfil",
    "critical",
    /(?:os\.environ|process\.env|getenv)\b[\s\S]{0,120}\b(?:requests\.(?:post|get)|fetch\s*\(|urlopen|http[s]?:\/\/)/i,
  ],
  [
    "obfuscation",
    "high",
    /\b(?:eval|exec)\s*\(\s*(?:base64|atob|Buffer\.from|codecs\.decode)|\bbase64\.b64decode\b[\s\S]{0,40}\b(?:eval|exec)/i,
  ],
];

// [dangerShape, severity, regex] over declared permissions/capabilities.
// No trailing \b — several of these end in `*` (a non-word char).
const SKILL_PERMISSION_RULES: ReadonlyArray<readonly [string, BlackboxSeverity, RegExp]> = [
  ["over-broad-filesystem", "high", /\b(?:filesystem[:_-]?\*|fs[:_-]?full|read[_-]?write[_-]?all|allowallpaths)/i],
  ["over-broad-shell", "high", /\b(?:arbitrary[_-]?shell|shell[:_-]?\*|exec[:_-]?any|allowshell)/i],
  ["over-broad-network", "medium", /\b(?:network[:_-]?\*|raw[_-]?socket|allowallhosts|net[:_-]?any)/i],
];

// Tools that install/modify a skill.
const SKILL_TOOLS = new Set([
  "skill_manage",
  "skill_install",
  "install_skill",
  "plugin_install",
  "install_plugin",
  "skill_workshop",
]);
const SKILL_NAME_KEYS = ["name", "skill", "skill_name", "id", "plugin"] as const;
const SKILL_VERSION_KEYS = ["version", "skill_version", "ver"] as const;
const SKILL_CODE_KEYS = ["code", "content", "source", "body", "script"] as const;
const SKILL_PERM_KEYS = ["permissions", "capabilities", "scopes", "allow", "grants"] as const;

const MAX_SKILL_SCAN = 20_000;

/** Deep-stringify a value the way Python `_stringify` does. */
function stringify(value: unknown): string {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map((v) => stringify(v)).join(" ");
  if (value != null && typeof value === "object") {
    return Object.entries(value as Record<string, unknown>)
      .map(([k, v]) => `${k} ${stringify(v)}`)
      .join(" ");
  }
  return value != null ? String(value) : "";
}

export interface SkillInstall {
  name: string;
  version: string;
  code: string;
  permissions: string;
}

/**
 * Extract a skill install/modify descriptor, or `null`. `code`/`permissions`
 * are the concatenated content to scan; they are NEVER carried off-box — only
 * matched danger-shape names are submitted. Port of Python `skill_install_arg`.
 */
export function skillInstallArg(toolName: string, args: unknown): SkillInstall | null {
  const tool = (toolName || "").trim().toLowerCase();
  if (isShellTool(tool)) {
    const tokens = tokenizeShell(commandText(args));
    for (let i = 0; i + 3 < tokens.length; i += 1) {
      if (
        tokens[i]?.toLowerCase() !== "openclaw" ||
        tokens[i + 1]?.toLowerCase() !== "skills" ||
        tokens[i + 2]?.toLowerCase() !== "install"
      ) continue;
      const name = tokens[i + 3] ?? "";
      if (!name || name.startsWith("-")) return null;
      let version = "";
      for (let j = i + 4; j < tokens.length; j += 1) {
        if (tokens[j] === "--version") version = tokens[j + 1] ?? "";
        else if (tokens[j]?.startsWith("--version=")) version = tokens[j]!.slice(10);
      }
      return { name, version, code: "", permissions: "" };
    }
    return null;
  }
  if (!SKILL_TOOLS.has(tool) || args == null || typeof args !== "object" || Array.isArray(args)) {
    return null;
  }
  const obj = args as Record<string, unknown>;
  if (
    tool === "skill_workshop" &&
    !new Set(["create", "update", "revise"]).has(String(obj.action ?? "").toLowerCase())
  ) return null;
  let name = "";
  for (const key of SKILL_NAME_KEYS) {
    const val = obj[key];
    if (typeof val === "string" && val.trim()) {
      name = val.trim();
      break;
    }
  }
  if (!name) return null;
  let version = "";
  for (const key of SKILL_VERSION_KEYS) {
    const val = obj[key];
    if (typeof val === "string" && val.trim()) {
      version = val.trim();
      break;
    }
  }
  const code = [...SKILL_CODE_KEYS, "proposal_content"].filter((k) => obj[k])
    .map((k) => stringify(obj[k]))
    .join(" ");
  const perms = SKILL_PERM_KEYS.filter((k) => obj[k])
    .map((k) => stringify(obj[k]))
    .join(" ");
  return {
    name,
    version,
    code: code.slice(0, MAX_SKILL_SCAN),
    permissions: perms.slice(0, MAX_SKILL_SCAN),
  };
}

export interface SkillDanger {
  dangerShape: string;
  severity: BlackboxSeverity;
}

/**
 * Return built-in skill danger matches as `[{dangerShape, severity}]`. Scans
 * `code` for dangerous-code shapes and `permissions` for over-broad capability
 * grants. Port of Python `scan_skill_dangers`.
 */
export function scanSkillDangers(code: string, permissions: string): SkillDanger[] {
  const out: SkillDanger[] = [];
  const seen = new Set<string>();
  const passes: ReadonlyArray<readonly [string, ReadonlyArray<readonly [string, BlackboxSeverity, RegExp]>]> = [
    [code || "", SKILL_CODE_RULES],
    [permissions || "", SKILL_PERMISSION_RULES],
  ];
  for (const [text, rules] of passes) {
    if (!text) continue;
    for (const [shape, severity, pattern] of rules) {
      if (seen.has(shape)) continue;
      try {
        if (pattern.test(text)) {
          seen.add(shape);
          out.push({ dangerShape: shape, severity });
        }
      } catch {
        continue;
      }
    }
  }
  return out;
}

/**
 * Detect a suspicious skill install/modify (graph known-bad or built-in).
 * Three signals: known-bad `skill:{name}@{version}` from the graph; dangerous-
 * code shapes; over-broad permission grants. PRIVACY: a finding carries the
 * skill name + matched danger shape — never the full skill source.
 * Port of Python `detect_skill`.
 */
export function detectSkill(toolName: string, args: unknown, ruleset: Ruleset): Finding[] {
  const skill = skillInstallArg(toolName, args);
  if (!skill) return [];
  const out: Finding[] = [];
  const seen = new Set<string>();
  const name = skill.name;
  const version = skill.version;
  // (a) known-bad from graph: match name@version or name against skill: rules.
  for (const rule of ruleset.skill ?? []) {
    const ruleName = String(rule.skillName || "").trim().toLowerCase();
    const ruleVer = String(rule.skillVersion || "").trim();
    if (ruleName && ruleName === name.toLowerCase() && (!ruleVer || ruleVer === version)) {
      const ident = rule.identifier || skillVersionIdentifierFor(name, version);
      if (seen.has(ident)) continue;
      seen.add(ident);
      const src = ruleSource(rule);
      const historical = !ruleVer;
      out.push({
        identifier: ident,
        category: "skill",
        severity: historical ? "medium" : (rule.severity ?? "high"),
        title: historical
          ? `Historical threat report for ${name} (version unspecified)`
          : (rule.name || `Known-bad skill ${name}`),
        // Python: skill.get("tool", "") or (tool_name or "").lower(); the
        // install descriptor has no `tool` key so this is always the tool name.
        toolName: (toolName || "").toLowerCase(),
        matched: name,
        evidence: historical
          ? `Skill ${name} was exploited in the past; the graph does not specify an affected version, so the issue may be fixed in newer releases.`
          : `known-bad skill ${name}`,
        confirmed: src === "public",
        source: src,
        kind: historical ? "historical" : undefined,
        fields: { skillName: name, skillVersion: version },
      });
    }
  }
  // (b)+(c) built-in dangerous-code / over-broad-permission discovery.
  for (const danger of scanSkillDangers(skill.code, skill.permissions)) {
    const shape = danger.dangerShape;
    const ident = skillShapeIdentifierFor(name, shape);
    if (seen.has(ident)) continue;
    seen.add(ident);
    out.push({
      identifier: ident,
      category: "skill",
      severity: danger.severity ?? "high",
      title: `Suspicious skill ${name} (${shape})`,
      toolName: (toolName || "").toLowerCase(),
      matched: shape,
      evidence: `skill ${name}: ${shape}`,
      confirmed: false,
      source: "heuristic",
      fields: { skillName: name, skillVersion: version, dangerShape: shape },
    });
  }
  return out;
}

// IOC extraction mirrors Python `quads.iter_ioc_candidates`. Extraction is
// deliberately broad, but a finding exists only after an exact dictionary hit
// against a known-bad graph identifier.
const IOC_URL_RE = /https?:\/\/[^\s'"<>|\\)}\]]+/gi;
const IOC_IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const IOC_DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi;
const IOC_SHA256_RE = /\b[a-fA-F0-9]{64}\b/g;
const IOC_SHA1_RE = /\b[a-fA-F0-9]{40}\b/g;
const IOC_MD5_RE = /\b[a-fA-F0-9]{32}\b/g;
const IOC_EVM_RE = /0x[a-fA-F0-9]{40}/g;
const IOC_BTC_RE = /\b(?:bc1[023-9ac-hj-np-z]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,39})\b/g;
const IOC_SOL_RE = /\b[1-9A-HJ-NP-Za-km-z]{32,44}\b/g;
const MAX_IOC_CANDIDATES = 4_000;

function hostSuffixes(host: string): string[] {
  const clean = host.replace(/^\.+|\.+$/g, "").toLowerCase();
  if (!clean) return [];
  const out = [clean];
  if (clean.startsWith("www.")) out.push(clean.slice(4));
  const labels = clean.split(".");
  for (let i = 1; i < labels.length - 1; i += 1) out.push(labels.slice(i).join("."));
  return [...new Set(out)];
}

export function iterIocCandidates(input: string): string[] {
  const text = (input || "").slice(0, MAX_TEXT);
  if (!text) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  const add = (type: string, value: string): void => {
    if (out.length >= MAX_IOC_CANDIDATES) return;
    const identifier = iocIdentifier(type, value);
    if (!seen.has(identifier)) {
      seen.add(identifier);
      out.push(identifier);
    }
  };
  for (const match of text.matchAll(IOC_URL_RE)) {
    const clean = match[0].replace(/[.,);'" ]+$/g, "");
    add("url", clean);
    const host = clean.split("://", 2).at(-1)?.split("/", 1)[0].split("@").at(-1)?.split(":", 1)[0] ?? "";
    for (const suffix of hostSuffixes(host)) add("domain", suffix);
  }
  for (const match of text.matchAll(IOC_DOMAIN_RE)) {
    for (const suffix of hostSuffixes(match[0])) add("domain", suffix);
  }
  for (const match of text.matchAll(IOC_IPV4_RE)) add("ip", match[0]);
  for (const match of text.matchAll(IOC_SHA256_RE)) add("hash", `sha256:${match[0]}`);
  for (const match of text.matchAll(IOC_SHA1_RE)) add("hash", `sha1:${match[0]}`);
  for (const match of text.matchAll(IOC_MD5_RE)) add("hash", `md5:${match[0]}`);
  for (const re of [IOC_EVM_RE, IOC_BTC_RE, IOC_SOL_RE]) {
    for (const match of text.matchAll(re)) {
      add("wallet", match[0]);
      add("contract", match[0]);
    }
  }
  return out;
}

export function detectIoc(toolName: string, args: unknown, ruleset: Ruleset): Finding[] {
  if (!ruleset.ioc) return [];
  const text = typeof args === "string" ? args : collectText(args).join("\n");
  if (!text) return [];
  const out: Finding[] = [];
  for (const identifier of iterIocCandidates(text)) {
    const rule = ruleset.ioc[identifier];
    if (!rule) continue;
    const src = ruleSource(rule);
    const parts = identifier.split(":", 3);
    const iocType = rule.iocType || parts[1] || "indicator";
    const value = identifier.slice(`ioc:${parts[1] ?? ""}:`.length);
    out.push({
      identifier,
      category: "ioc",
      severity: rule.severity ?? "high",
      title: rule.name || `Known-bad ${iocType}`,
      toolName: toolName || "",
      matched: value.slice(0, 200),
      evidence: `${iocType} ${value}`.slice(0, 200),
      confirmed: src === "public",
      source: src,
      kind: rule.kind,
      fields: src === "community" ? { iocType } : {},
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Dependency install parsing — port
// ---------------------------------------------------------------------------

const SHELL_INSTALL_PATTERNS = [
  /\b(?:python(?:3)?\s+-m\s+)?pip3?\s+install\b/i,
  /\buv\s+pip\s+install\b/i,
  /\buv\s+add\b/i,
  /\buvx\b/i,
  /\bnpm\s+(?:install|i|add)\b/i,
  /\bpnpm\s+add\b/i,
  /\byarn\s+add\b/i,
  /\bbun\s+add\b/i,
  /\bcargo\s+add\b/i,
  /\bgem\s+install\b/i,
  /\bbrew\s+install\b/i,
];

const TOKEN_RE = /"([^"]*)"|'([^']*)'|(\S+)/g;

function tokenizeShell(command: string): string[] {
  const out: string[] = [];
  for (const m of command.matchAll(TOKEN_RE)) {
    out.push(m[1] ?? m[2] ?? m[3] ?? "");
  }
  return out;
}

const SHELL_READ_COMMANDS = new Set([
  "cat",
  "less",
  "more",
  "head",
  "tail",
  "bat",
  "xxd",
  "hexdump",
  "strings",
  "od",
  "nl",
]);

function looksLikePath(token: string): boolean {
  return token.includes("/") || token.startsWith("~") || token.startsWith(".") || token.includes(".");
}

/** File paths read through cat-family shell commands (visibility only). */
export function parseShellReads(command: string): string[] {
  if (!command || ![...SHELL_READ_COMMANDS].some((name) => ` ${command} `.includes(` ${name} `))) return [];
  const tokens = tokenizeShell(command);
  const out: string[] = [];
  let i = 0;
  while (i < tokens.length) {
    if (SHELL_READ_COMMANDS.has((tokens[i] ?? "").toLowerCase())) {
      let j = i + 1;
      while (j < tokens.length && ![";", "&&", "||", "|", ">", ">>", "<"].includes(tokens[j] ?? "")) {
        const token = tokens[j] ?? "";
        if (!token.startsWith("-") && looksLikePath(token)) out.push(token);
        j += 1;
      }
      i = j;
    } else {
      i += 1;
    }
  }
  return [...new Set(out)];
}

/** HTTP(S) URLs fetched through curl/wget shell commands (visibility only). */
export function parseDownloads(command: string): string[] {
  if (!command || !/\b(?:curl|wget)\b/i.test(command)) return [];
  return [...new Set(command.match(/https?:\/\/[^\s;'"|&>]+/gi) ?? [])];
}

export interface ParsedPackage {
  ecosystem: string;
  name: string;
  version: string;
}

/**
 * Parse a single install token into `{name, version}` for `ecosystem`.
 * Port of Python `_parse_package_token`.
 */
function parsePackageToken(raw: string, ecosystem: string): { name: string; version: string } | null {
  const token = raw.replace(/,/g, "").replace(/;/g, "").trim();
  if (
    !token ||
    token.startsWith("http://") ||
    token.startsWith("https://") ||
    token.startsWith("/") ||
    token.startsWith(".") ||
    token.startsWith("@git")
  ) {
    return null;
  }
  if (ecosystem === "pypi" || ecosystem === "rubygems") {
    const exact = /^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9._+!-]+)$/.exec(token);
    if (exact) return { name: exact[1], version: exact[2] };
    const loose = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?$/.exec(token);
    if (loose) return { name: loose[1], version: "" };
    return null;
  }
  if (ecosystem === "npm") {
    const idx = token.lastIndexOf("@");
    if (idx > 0) return { name: token.slice(0, idx), version: token.slice(idx + 1) }; // scoped names start with @, require idx > 0
    if (/^(?:@[A-Za-z0-9._-]+\/)?[A-Za-z0-9._-]+$/.test(token)) return { name: token, version: "" };
    return null;
  }
  // cargo / homebrew / other: name[@version]
  const idx = token.lastIndexOf("@");
  if (idx > 0) return { name: token.slice(0, idx), version: token.slice(idx + 1) };
  if (/^[A-Za-z0-9._+/-]+$/.test(token)) return { name: token, version: "" };
  return null;
}

// manager token spec key -> [ecosystem, number of leading subcommand tokens to skip].
// The lookup order in the loop mirrors Python's `_MANAGER_SPECS` dict lookups.
type ManagerSpec = { eco: string; skip: number };

const MANAGER_SPECS_PAIR: Record<string, ManagerSpec> = {
  "pip|install": { eco: "pypi", skip: 2 },
  "pip3|install": { eco: "pypi", skip: 2 },
  "uv|pip": { eco: "pypi", skip: 3 }, // `uv pip install <pkg>`
  "uv|add": { eco: "pypi", skip: 2 },
  "pnpm|add": { eco: "npm", skip: 2 },
  "yarn|add": { eco: "npm", skip: 2 },
  "bun|add": { eco: "npm", skip: 2 },
  "cargo|add": { eco: "cargo", skip: 2 },
  "gem|install": { eco: "rubygems", skip: 2 },
  "brew|install": { eco: "homebrew", skip: 2 },
};

const MANAGER_SPECS_SINGLE: Record<string, ManagerSpec> = {
  uvx: { eco: "pypi", skip: 1 },
  // `npm install|i|add` is handled explicitly below (the Python `("npm", None)` entry).
};

/**
 * Parse install commands into `[{ecosystem, name, version}, ...]`.
 * Faithful port of Python `parse_dependency_installs`, including the `i = j`
 * advance (the outer index jumps past the packages consumed for this manager)
 * and dedup by `{ecosystem}:{name.lower()}:{version}`.
 */
export function parseDependencyInstalls(command: string): ParsedPackage[] {
  if (!command || !SHELL_INSTALL_PATTERNS.some((re) => re.test(command))) return [];
  const tokens = tokenizeShell(command);
  const out: ParsedPackage[] = [];
  const seen = new Set<string>();
  let i = 0;
  while (i < tokens.length) {
    const tok = (tokens[i] ?? "").toLowerCase();
    const nxt = i + 1 < tokens.length ? (tokens[i + 1] ?? "").toLowerCase() : null;
    let ecosystem = "";
    let start = -1;

    // Python special-cases `(tok, "pip") in _MANAGER_SPECS and nxt == "pip"`
    // ahead of the generic pair lookup so `uv pip install` resolves to skip=3.
    if (MANAGER_SPECS_PAIR[`${tok}|pip`] && nxt === "pip") {
      const spec = MANAGER_SPECS_PAIR[`${tok}|pip`];
      ecosystem = spec.eco;
      start = i + spec.skip;
    } else if (nxt !== null && MANAGER_SPECS_PAIR[`${tok}|${nxt}`]) {
      const spec = MANAGER_SPECS_PAIR[`${tok}|${nxt}`];
      ecosystem = spec.eco;
      start = i + spec.skip;
    } else if (MANAGER_SPECS_SINGLE[tok]) {
      const spec = MANAGER_SPECS_SINGLE[tok];
      ecosystem = spec.eco;
      start = i + spec.skip;
    } else if (tok === "npm" && (nxt === "install" || nxt === "i" || nxt === "add")) {
      ecosystem = "npm";
      start = i + 2;
    }

    if (start < 0 || !ecosystem) {
      i += 1;
      continue;
    }

    let j = start;
    while (j < tokens.length) {
      const raw = tokens[j] ?? "";
      if (raw === ";" || raw === "&&" || raw === "||" || raw === "|") break;
      if (raw.startsWith("-") || raw === "install" || raw === "add" || raw === "i") {
        j += 1;
        continue;
      }
      const parsed = parsePackageToken(raw, ecosystem);
      if (parsed && parsed.name) {
        const key = `${ecosystem}:${parsed.name.toLowerCase()}:${parsed.version}`;
        if (!seen.has(key)) {
          seen.add(key);
          out.push({ ecosystem, name: parsed.name, version: parsed.version });
        }
      }
      j += 1;
    }
    i = j;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Text flattening (injection scan helper) + evidence sampling
// ---------------------------------------------------------------------------

/** Flatten string-ish leaves from tool params into text (for injection scan). */
export function collectText(value: unknown, out: string[] = [], depth = 0): string[] {
  if (value == null || depth > 6) return out;
  if (typeof value === "string") {
    if (value.trim()) out.push(value);
    return out;
  }
  if (Array.isArray(value)) {
    for (const item of value.slice(0, 100)) collectText(item, out, depth + 1);
    return out;
  }
  if (typeof value === "object") {
    for (const child of Object.values(value as Record<string, unknown>)) {
      collectText(child, out, depth + 1);
    }
  }
  return out;
}

function sampleAround(text: string, re: RegExp): string {
  try {
    const m = text.match(new RegExp(re.source, "i"));
    if (m && typeof m.index === "number") {
      const start = Math.max(0, m.index - 40);
      return text.slice(start, m.index + m[0].length + 40);
    }
  } catch {
    /* ignore */
  }
  return text.slice(0, 120);
}

// ---------------------------------------------------------------------------
// OSV dependency auto-discovery (discovery layer) — port of detection.py
// `discover_dependency_candidates` + osv.py `lookup`.
// ---------------------------------------------------------------------------

/** `{advisoryId, severity}` when OSV knows a package@version vulnerable. */
export interface OsvHit {
  advisoryId: string;
  severity: BlackboxSeverity;
}

/** Async OSV lookup: (ecosystem, name, version) → OsvHit | null. */
export type OsvLookup = (
  ecosystem: string,
  name: string,
  version: string,
) => Promise<OsvHit | null> | OsvHit | null;

/**
 * Best-effort OSV auto-discovery of vulnerable installs not in the graph.
 *
 * Parses install commands, skips any pinned dep already covered by a graph
 * rule, and calls `osvLookup(ecosystem, name, version)` — which returns an
 * `OsvHit` when OSV knows it vulnerable, else null. Only OSV-VULNERABLE installs
 * become candidates; clean deps are never surfaced (privacy). Runs OFF the
 * blocking path (callers invoke this best-effort). Port of Python
 * `discover_dependency_candidates`.
 */
export async function discoverDependencyCandidates(
  toolName: string,
  args: unknown,
  ruleset: Ruleset,
  osvLookup: OsvLookup,
): Promise<Finding[]> {
  const command = commandText(args);
  if (!command) return [];
  const dependencyRules = ruleset.dependency ?? {};
  const out: Finding[] = [];
  const seen = new Set<string>();
  for (const dep of parseDependencyInstalls(command)) {
    const version = dep.version || "";
    if (!version) continue;
    const eco = dep.ecosystem.toLowerCase();
    const name = dep.name;
    const key = `${eco}:${name.toLowerCase()}@${version}`;
    if (key in dependencyRules || seen.has(key)) continue; // graph rule or dup
    seen.add(key);
    let hit: OsvHit | null = null;
    try {
      hit = await osvLookup(eco, name, version);
    } catch {
      hit = null; // fail open
    }
    if (!hit) continue;
    out.push({
      identifier: dependencyIdentifier(eco, name, version),
      category: "dependency",
      severity: hit.severity ?? "high",
      title: `OSV-vulnerable dependency ${name}@${version}`,
      toolName: toolName || "",
      matched: key,
      evidence: `${eco}:${name}@${version} (${hit.advisoryId})`,
      confirmed: false,
      source: "heuristic",
      fields: {
        ecosystem: eco,
        packageName: name,
        packageVersion: version,
        advisoryId: hit.advisoryId,
      },
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Custom (user-configured) protected-path detection
// Port of detection.py `_protected_path_match` / `detect_custom_fileaccess`.
// ---------------------------------------------------------------------------

/**
 * Expand a leading `~` / `~/` to the user's home directory, mirroring Python's
 * `os.path.expanduser` for the common cases Blackbox sees (`~`, `~/foo`). A
 * bare `~user` form is left untouched (Python would resolve it, but Blackbox's
 * patterns and paths never use it).
 */
function expandUser(p: string): string {
  if (p === "~") return os.homedir();
  if (p.startsWith("~/") || p.startsWith("~\\")) return path.join(os.homedir(), p.slice(2));
  return p;
}

/**
 * Faithful port of Python's `fnmatch.translate`: build an anchored regex that
 * matches the WHOLE string. `*` → `.*` (matches path separators too, exactly
 * like Python `fnmatch`), `?` → `.`, `[seq]`/`[!seq]` → char class. Everything
 * else is escaped literally. Case-insensitive on platforms where Python's
 * `fnmatch` normalizes case (Windows); case-sensitive elsewhere — matched here
 * by `os.platform()`.
 */
function fnmatchToRegExp(pattern: string): RegExp {
  let re = "";
  let i = 0;
  const n = pattern.length;
  while (i < n) {
    const c = pattern[i];
    i += 1;
    if (c === "*") {
      re += ".*";
    } else if (c === "?") {
      re += ".";
    } else if (c === "[") {
      let j = i;
      if (j < n && (pattern[j] === "!" || pattern[j] === "]")) j += 1;
      while (j < n && pattern[j] !== "]") j += 1;
      if (j >= n) {
        // No closing bracket — treat '[' as a literal (Python behavior).
        re += "\\[";
      } else {
        let stuff = pattern.slice(i, j);
        // Escape backslashes inside the class; leading '!' → '^' negation.
        stuff = stuff.replace(/\\/g, "\\\\");
        i = j + 1;
        if (stuff.startsWith("!")) stuff = "^" + stuff.slice(1);
        else if (stuff.startsWith("^")) stuff = "\\" + stuff;
        re += "[" + stuff + "]";
      }
    } else {
      re += c.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    }
  }
  // Anchor to the whole string, like fnmatch (translate wraps in (?s:...)\Z).
  const flags = os.platform() === "win32" ? "is" : "s";
  return new RegExp(`^(?:${re})$`, flags);
}

function fnmatch(name: string, pattern: string): boolean {
  try {
    return fnmatchToRegExp(pattern).test(name);
  } catch {
    return false;
  }
}

/**
 * True when `p` matches a user's protected-path `pattern`. Matched three ways so
 * plain paths, directories, and globs all behave intuitively: glob on the full
 * expanded path, glob on the basename (`*.pem`), and directory-prefix when the
 * pattern is glob-free (`~/secrets` protects everything under it). Both sides
 * are `~`-expanded and normalized. Port of Python `_protected_path_match`.
 */
export function protectedPathMatch(p: string, pattern: string): boolean {
  try {
    const normPath = path.normalize(expandUser(String(p ?? "")));
    const normPat = path.normalize(expandUser(String(pattern ?? "")));
    if (!normPath || !normPat) return false;
    if (fnmatch(normPath, normPat)) return true;
    if (fnmatch(path.basename(normPath), normPat)) return true;
    // Directory-prefix semantics for glob-free patterns.
    if (
      !/[*?[]/.test(normPat) &&
      (normPath === normPat ||
        normPath.startsWith(normPat.replace(/[/\\]+$/, "") + path.sep))
    ) {
      return true;
    }
  } catch {
    return false; // fail open
  }
  return false;
}

/**
 * Match file-access tool calls against the USER'S protected-path list. These are
 * personal, locally-configured rules (`source: "custom"`): they always flag,
 * they block in block mode (the user wrote the rule), and they are NEVER
 * reported to the community graph — the matched pattern is the user's own
 * configuration, not shared threat intel. Port of Python
 * `detect_custom_fileaccess`.
 */
export function detectCustomFileAccess(
  toolName: string,
  args: unknown,
  protectedPaths: Iterable<string>,
): Finding[] {
  const patterns = [...(protectedPaths ?? [])].filter((p) => String(p ?? "").trim());
  if (patterns.length === 0) return [];
  const access = fileAccessArg(toolName, args);
  if (!access) return [];
  for (const pattern of patterns) {
    if (protectedPathMatch(access.path, pattern)) {
      const tool = access.tool;
      return [
        {
          identifier: fileaccessIdentifierFor(tool, "user-protected"),
          category: "fileaccess",
          severity: "critical",
          title: "Access to a user-protected path",
          toolName: tool,
          matched: "user-protected",
          evidence: `${access.mode} path matching protected pattern ${String(pattern).slice(0, 120)}`,
          confirmed: false,
          source: "custom",
          fields: {},
        },
      ];
    }
  }
  return [];
}

// ---------------------------------------------------------------------------
// Orchestrator — port of detection.py `detect_all` / `_graph_escalation`.
// ---------------------------------------------------------------------------

/**
 * Run every detector (graph rules + built-in discovery) across categories.
 *
 * Graph-backed detection (public + community rules) ALWAYS runs for every
 * category. When `discover` is false only the built-in heuristic candidates
 * are suppressed — a curated fileaccess/skill/escalation rule keeps firing.
 * Dependency OSV auto-discovery is NOT run here — it is best-effort and runs
 * off the blocking path (see index.ts). Port of Python `detect_all`.
 */
export function detectAll(
  toolName: string,
  args: unknown,
  ruleset: Ruleset,
  discover = true,
): Finding[] {
  const findings: Finding[] = [];
  findings.push(...detectEscalation(toolName, args, ruleset));
  findings.push(...detectDependency(toolName, args, ruleset));
  // Collect raw string values (real newlines preserved) rather than
  // JSON.stringify — which escapes newlines to "\\n" and lets a multi-line
  // injection payload evade even a curated rule (mirrors Python _injection_scan_text).
  const argsText = typeof args === "string" ? args : collectText(args).join("\n");
  findings.push(...detectInjection(argsText, ruleset));
  if (discover) {
    findings.push(...discoverInjection(argsText, ruleset));
  }
  findings.push(...detectFileaccess(toolName, args, ruleset));
  findings.push(...detectSkill(toolName, args, ruleset));
  findings.push(...detectIoc(toolName, args, ruleset));
  return discover ? findings : findings.filter((f) => f.source !== "heuristic");
}
