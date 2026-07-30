/**
 * Blackbox config resolution.
 *
 * Source order (later wins): built-in defaults → `plugins.entries.blackbox.config`
 * (passed by OpenClaw as `api.pluginConfig`) → environment overrides.
 *
 * Keys mirror the hermes plugin's config table so the two frameworks stay in
 * lockstep.
 */
import { homedir } from "node:os";
import { join } from "node:path";
import { BlackboxSeverity, SEVERITY_RANK } from "./quads.js";
import type { ThreatCategory } from "./detection.js";

/**
 * The six detection categories a user can tune individually. Mirrors Python
 * `config.DETECTION_CATEGORIES`.
 */
export const DETECTION_CATEGORIES = [
  "injection",
  "escalation",
  "dependency",
  "fileaccess",
  "skill",
  "ioc",
] as const;

/**
 * Resolved per-category user policy. `enabled=false` drops the whole category;
 * `minSeverity` sets a per-category floor below which findings are dropped.
 * Mirrors Python `config.BlackboxConfig.category_setting`.
 */
export interface CategorySetting {
  enabled: boolean;
  minSeverity: BlackboxSeverity;
}

export interface BlackboxConfig {
  mode: "audit" | "block";
  contextGraphId: string;
  dkgUrl: string;
  dkgHome: string;
  syncInterval: number; // seconds
  report: boolean;
  dailyReportLimit: number;
  /**
   * Minimum severity a built-in HEURISTIC candidate must reach to be flagged /
   * reported. Graph-backed findings (public or community) always flag — this
   * only gates the discovery heuristics so low-signal candidates don't drown
   * the findings feed and the community graph. Mirrors Python
   * `report_min_severity`.
   */
  reportMinSeverity: BlackboxSeverity;
  blockSeverity: BlackboxSeverity;
  /** Run the built-in discovery nomination layer (candidate threats). */
  discover: boolean;
  /** Run OSV dependency auto-discovery off the blocking path. */
  osvLookup: boolean;
  /**
   * Per-category user policy: `{category: {enabled, minSeverity}}`. Missing
   * categories default to enabled at `info` (flag everything the graph knows).
   * Read from `plugins.entries.blackbox.detection.<category>.{enabled,min_severity}`
   * (snake_case + camelCase accepted). Mirrors Python `BlackboxConfig.categories`.
   */
  categories: Partial<Record<ThreatCategory, Partial<CategorySetting>>>;
  /**
   * User-defined protected path patterns (globs / prefixes). Access to a
   * matching path is flagged locally (source="custom", never shared) and blocks
   * in block mode. Read from `plugins.entries.blackbox.protected_paths`.
   * Mirrors Python `BlackboxConfig.protected_paths`.
   */
  protectedPaths: string[];
  /**
   * Directory where this plugin writes its local findings log
   * (`findings.openclaw.jsonl`). Set by `hermes blackbox attach` to the Hermes
   * blackbox home so the ONE dashboard surfaces OpenClaw detections too. Falls
   * back to `$OPENCLAW_STATE_DIR/blackbox`. Read from
   * `plugins.entries.blackbox.config.blackboxHome` / env `BLACKBOX_HOME`.
   */
  blackboxHome: string;
}

/** Default blackbox home when unset — mirrors ruleset.ts `resolveStateDir`. */
export function defaultBlackboxHome(): string {
  const base =
    process.env.OPENCLAW_STATE_DIR || process.env.OPENCLAW_HOME || join(homedir(), ".openclaw");
  return join(base, "blackbox");
}

/** Default isolated DKG home for a standalone OpenClaw Blackbox install. */
export function defaultBlackboxDkgHome(): string {
  const hermesHome = process.env.HERMES_HOME || join(homedir(), ".hermes");
  return join(hermesHome, "blackbox", "dkg");
}

/**
 * Sensible out-of-the-box protected paths — high-signal credential stores an
 * agent rarely has a legitimate reason to read. Applied only when the config
 * key is absent; an explicit (even empty) `protected_paths` list wins. Mirrors
 * Python `DEFAULT_PROTECTED_PATHS`.
 */
export const DEFAULT_PROTECTED_PATHS: readonly string[] = [
  "~/.ssh/*", // SSH private keys
  ".env", // environment files (any directory)
  ".env.*", // env variants (.env.local, .env.production, ...)
  "*.pem", // PEM-encoded keys / certificates
  "*.key", // private key files
  "*.p12", // PKCS#12 / PFX keystores
  "~/.aws/credentials", // cloud credential store
];

const DEFAULT_DKG_PORT = 9320;
const DEFAULT_DKG_URL = `http://127.0.0.1:${DEFAULT_DKG_PORT}`;

const DEFAULTS: BlackboxConfig = {
  mode: "audit",
  contextGraphId: "0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70/agent-blackbox-vm",
  dkgUrl: DEFAULT_DKG_URL,
  dkgHome: "",
  syncInterval: 300,
  report: false,
  dailyReportLimit: 0,
  reportMinSeverity: "high",
  blockSeverity: "critical",
  discover: true,
  osvLookup: true,
  categories: {},
  protectedPaths: [...DEFAULT_PROTECTED_PATHS],
  blackboxHome: "",
};

function str(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function num(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim()) {
    const n = Number(value);
    if (Number.isFinite(n)) return n;
  }
  return undefined;
}

function bool(value: unknown): boolean | undefined {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    const v = value.trim().toLowerCase();
    if (["true", "1", "yes", "on"].includes(v)) return true;
    if (["false", "0", "no", "off"].includes(v)) return false;
  }
  return undefined;
}

function envDkgUrl(): string | undefined {
  const explicit = str(process.env.BLACKBOX_DKG_DAEMON_URL) ?? str(process.env.BLACKBOX_DKG_URL);
  if (explicit) return explicit.replace(/\/+$/, "");
  const port = num(process.env.BLACKBOX_DKG_PORT);
  return port !== undefined ? `http://127.0.0.1:${port}` : undefined;
}

function mode(value: unknown): "audit" | "block" | undefined {
  const v = str(value)?.toLowerCase();
  return v === "audit" || v === "block" ? v : undefined;
}

function severity(value: unknown): BlackboxSeverity | undefined {
  // Strict ladder check (no "moderate" aliasing) — an invalid value falls
  // through to the key's default, matching Python's config validation.
  const v = str(value)?.toLowerCase();
  return v && v in SEVERITY_RANK ? (v as BlackboxSeverity) : undefined;
}

/**
 * Validate the `detection` config mapping into per-category policy. Only known
 * categories and valid values are kept; a bad/absent category falls back to the
 * enabled-at-`info` default at read time. Supports snake_case (`min_severity`)
 * and camelCase (`minSeverity`) keys. Mirrors Python `_normalize_categories`.
 */
function normalizeCategories(
  raw: unknown,
): Partial<Record<ThreatCategory, Partial<CategorySetting>>> {
  const out: Partial<Record<ThreatCategory, Partial<CategorySetting>>> = {};
  if (raw == null || typeof raw !== "object" || Array.isArray(raw)) return out;
  const obj = raw as Record<string, unknown>;
  for (const category of DETECTION_CATEGORIES) {
    const item = obj[category];
    if (item == null || typeof item !== "object" || Array.isArray(item)) continue;
    const rec = item as Record<string, unknown>;
    const setting: Partial<CategorySetting> = {};
    const enabled = bool(rec.enabled);
    if (enabled !== undefined) setting.enabled = enabled;
    const minSev = severity(rec.minSeverity) ?? severity(rec.min_severity);
    if (minSev !== undefined) setting.minSeverity = minSev;
    if (Object.keys(setting).length > 0) out[category] = setting;
  }
  return out;
}

/**
 * Validate `protected_paths` into a de-duplicated list of non-empty patterns
 * (capped at 100). A missing key (`null`/`undefined`) falls back to
 * `DEFAULT_PROTECTED_PATHS`; an explicit list — including an empty one — is
 * honoured verbatim. Mirrors Python `_normalize_protected_paths`.
 */
function normalizeProtectedPaths(raw: unknown): string[] {
  if (raw == null) return [...DEFAULT_PROTECTED_PATHS];
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  for (const item of raw) {
    const text = item == null ? "" : String(item).trim();
    if (text && !out.includes(text)) out.push(text);
  }
  return out.slice(0, 100);
}

/**
 * Resolved user policy for one category: `{enabled, minSeverity}`. Defaults:
 * enabled at `info` — flag everything Blackbox can detect for that category.
 * Mirrors Python `BlackboxConfig.category_setting`.
 */
export function categorySetting(cfg: BlackboxConfig, category: string): CategorySetting {
  const raw = cfg.categories[category as ThreatCategory];
  const minSeverity =
    raw && raw.minSeverity && raw.minSeverity in SEVERITY_RANK ? raw.minSeverity : "info";
  const enabled = raw && typeof raw.enabled === "boolean" ? raw.enabled : true;
  return { enabled, minSeverity };
}

/**
 * True when the user's policy lets a `category` finding at `severity` flag.
 * Mirrors Python `BlackboxConfig.category_allows`.
 */
export function categoryAllows(
  cfg: BlackboxConfig,
  category: string,
  sev: BlackboxSeverity,
): boolean {
  const setting = categorySetting(cfg, category);
  if (!setting.enabled) return false;
  const floor = SEVERITY_RANK[setting.minSeverity];
  return (SEVERITY_RANK[sev] ?? -1) >= floor;
}

/**
 * Merge plugin config + env into a resolved BlackboxConfig. `pluginConfig` is
 * the `plugins.entries.blackbox.config` object OpenClaw injects per handler.
 *
 * The per-category detection policy (`detection.<category>.{enabled,min_severity}`)
 * and protected paths (`protected_paths`) mirror the Python plugin's
 * `plugins.entries.blackbox.detection` / `.protected_paths` keys and are read
 * from the same injected config object.
 */
export function resolveConfig(pluginConfig: Record<string, unknown> = {}): BlackboxConfig {
  const env = process.env;
  return {
    mode: mode(env.BLACKBOX_MODE) ?? mode(pluginConfig.mode) ?? DEFAULTS.mode,
    contextGraphId:
      str(env.BLACKBOX_CONTEXT_GRAPH_ID) ??
      str(pluginConfig.contextGraphId) ??
      str(pluginConfig.context_graph_id) ??
      DEFAULTS.contextGraphId,
    dkgUrl:
      envDkgUrl() ??
      str(pluginConfig.dkgUrl)?.replace(/\/+$/, "") ??
      str(pluginConfig.dkg_url)?.replace(/\/+$/, "") ??
      str(pluginConfig.daemonUrl)?.replace(/\/+$/, "") ??
      DEFAULTS.dkgUrl,
    dkgHome:
      str(env.BLACKBOX_DKG_HOME) ??
      str(pluginConfig.dkgHome) ??
      str(pluginConfig.dkg_home) ??
      defaultBlackboxDkgHome(),
    syncInterval:
      num(env.BLACKBOX_SYNC_INTERVAL) ??
      num(pluginConfig.syncInterval) ??
      num(pluginConfig.sync_interval) ??
      DEFAULTS.syncInterval,
    report: false,
    dailyReportLimit: 0,
    reportMinSeverity:
      severity(env.BLACKBOX_REPORT_MIN_SEVERITY) ??
      severity(pluginConfig.reportMinSeverity) ??
      severity(pluginConfig.report_min_severity) ??
      DEFAULTS.reportMinSeverity,
    blockSeverity:
      severity(env.BLACKBOX_BLOCK_SEVERITY) ??
      severity(pluginConfig.blockSeverity) ??
      severity(pluginConfig.block_severity) ??
      DEFAULTS.blockSeverity,
    discover:
      bool(env.BLACKBOX_DISCOVER) ??
      bool(pluginConfig.discover) ??
      DEFAULTS.discover,
    osvLookup:
      bool(env.BLACKBOX_OSV_LOOKUP) ??
      bool(pluginConfig.osvLookup) ??
      bool(pluginConfig.osv_lookup) ??
      DEFAULTS.osvLookup,
    categories: normalizeCategories(pluginConfig.detection),
    protectedPaths: normalizeProtectedPaths(pluginConfig.protected_paths ?? pluginConfig.protectedPaths),
    blackboxHome:
      str(env.BLACKBOX_HOME) ??
      str(pluginConfig.blackboxHome) ??
      str(pluginConfig.blackbox_home) ??
      defaultBlackboxHome(),
  };
}

export { DEFAULTS as BLACKBOX_CONFIG_DEFAULTS };
