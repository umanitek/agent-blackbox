/**
 * Local findings log for the OpenClaw plugin.
 *
 * Writes `findings.openclaw.jsonl` into the shared blackbox home so the one
 * dashboard surfaces OpenClaw detections alongside Hermes'. Line shape matches
 * the Python `audit.record` line so `audit.read_findings` flattens it unchanged.
 * Fail-open — a logging error must never break the agent loop.
 */
import { appendFileSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import type { Finding } from "./detection.js";
import { redact, sanitizeText } from "./redact.js";

const FRAMEWORK = "openclaw" as const;
const LOG_FILE = "findings.openclaw.jsonl";
const AUDIT_LOG_FILE = "audit.openclaw.jsonl";
const LOG_MAX_BYTES = 8 * 1024 * 1024; // trim at 8 MB (matches Python)
const LOG_KEEP_BYTES = 4 * 1024 * 1024; // keep most-recent ~4 MB after trimming

/** One conversation turn shown on a finding (redacted + capped before storage). */
export interface ConvTurn {
  role: string;
  text: string;
}

/**
 * Local-only conversation snapshot attached to a finding for the dashboard modal.
 * Every field is optional and already redacted. Mirrors Python `_bounded_context`.
 */
export interface FindingContext {
  turns?: ConvTurn[];
  input?: string;
  result?: string;
  truncated?: boolean;
}

// Bounds mirror plugins/blackbox/audit/ (findings.py, log_store.py).
const CTX_MAX_TURNS = 16;
const CTX_TURN_CHARS = 3000;
const CTX_FIELD_CHARS = 6000;

function expandHome(path: string): string {
  if (path === "~") return homedir();
  if (path.startsWith("~/")) return join(homedir(), path.slice(2));
  return path;
}

/** Stable OpenClaw profile/state directory matching Python attach discovery. */
export function currentWorkspace(): string {
  const configPath = process.env.OPENCLAW_CONFIG_PATH?.trim();
  if (configPath) {
    const expanded = expandHome(configPath);
    const absolute = isAbsolute(expanded) ? expanded : resolve(expanded);
    return basename(absolute) === "openclaw.json" ? dirname(absolute) : absolute;
  }
  const stateDir = process.env.OPENCLAW_STATE_DIR?.trim();
  if (stateDir) return resolve(expandHome(stateDir));
  const openclawHome = process.env.OPENCLAW_HOME?.trim();
  if (openclawHome) return resolve(expandHome(openclawHome), ".openclaw");
  return join(homedir(), ".openclaw");
}

/**
 * Normalize, redact + bound a raw conversation context for storage. Every text
 * field runs through `sanitizeText` so this is safe even if a caller forgot to
 * redact. Returns `undefined` when empty. Mirrors Python `_bounded_context`.
 */
export function boundedContext(ctx: FindingContext | undefined): FindingContext | undefined {
  if (!ctx || typeof ctx !== "object") return undefined;
  const out: FindingContext = {};
  if (Array.isArray(ctx.turns) && ctx.turns.length) {
    const turns: ConvTurn[] = [];
    for (const t of ctx.turns.slice(-CTX_MAX_TURNS)) {
      if (!t || typeof t !== "object") continue;
      const text = sanitizeText(String(t.text ?? ""), CTX_TURN_CHARS);
      if (!text) continue;
      turns.push({ role: String(t.role ?? "user").slice(0, 32), text });
    }
    if (turns.length) out.turns = turns;
  }
  if (typeof ctx.input === "string" && ctx.input) out.input = sanitizeText(ctx.input, CTX_FIELD_CHARS);
  if (typeof ctx.result === "string" && ctx.result) out.result = sanitizeText(ctx.result, CTX_FIELD_CHARS);
  if (!out.turns && !out.input && !out.result) return undefined;
  if (ctx.truncated) out.truncated = true;
  return out;
}

/** UTC `YYYY-MM-DDTHH:MM:SSZ` — matches Python `time.strftime(...gmtime())`. */
function isoNow(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

/** Append one routine OpenClaw lifecycle/tool event to the shared audit home. */
export function recordEvent(
  home: string,
  event: string,
  detail: Record<string, unknown> = {},
): void {
  try {
    if (!home) return;
    mkdirSync(home, { recursive: true });
    const path = join(home, AUDIT_LOG_FILE);
    appendFileSync(
      path,
      JSON.stringify({
        ts: Date.now() / 1000,
        iso: isoNow(),
        event,
        framework: FRAMEWORK,
        workspace: currentWorkspace(),
        detail: redact(detail),
      }) + "\n",
      "utf8",
    );
    trimIfNeeded(path);
  } catch {
    /* fail-open — never break the agent loop over an audit write */
  }
}

/** What happened with a finding, recorded beside it: the decision, the agent and the chat. */
export interface FindingOutcome {
  decision?: string;
  agent?: string;
  sessionId?: string;
}

/** Append one finding to `<home>/findings.openclaw.jsonl`. Fail-open. */
export function recordFinding(
  home: string,
  event: string,
  finding: Finding,
  toolName?: string,
  context?: FindingContext,
  outcome: FindingOutcome = {},
): void {
  try {
    if (!home) return;
    mkdirSync(home, { recursive: true });
    const now = Date.now() / 1000;
    const tool = toolName ?? finding.toolName ?? "";
    // Local-only conversation snapshot rides in detail.context (redacted + bounded).
    const detail: Record<string, unknown> = { tool_name: tool };
    // What was DONE about it ("block" / "flag") and which agent of this profile it was — the
    // dashboard reads both from detail, as it does for a Hermes row.
    if (outcome.decision) detail.decision = outcome.decision.slice(0, 40);
    if (outcome.agent) detail.agent = sanitizeText(outcome.agent, 120);
    if (outcome.sessionId) detail.session_id = sanitizeText(outcome.sessionId, 160);
    const ctx = boundedContext(context);
    if (ctx) detail.context = ctx;
    const line = {
      ts: now,
      iso: isoNow(),
      event,
      framework: FRAMEWORK,
      workspace: currentWorkspace(),
      detail,
      // Same nested shape Python writes so read_findings lifts these fields.
      finding: {
        identifier: finding.identifier,
        category: finding.category,
        severity: finding.severity,
        title: finding.title,
        tool_name: tool,
        evidence: sanitizeText(String(finding.evidence ?? ""), 700),
        confirmed: finding.confirmed,
        candidate: !finding.confirmed,
        source: finding.source,
        framework: FRAMEWORK,
        ts: now,
      },
    };
    const path = join(home, LOG_FILE);
    appendFileSync(path, JSON.stringify(line) + "\n", "utf8");
    trimIfNeeded(path);
  } catch {
    /* fail-open — never break the agent loop over a log write */
  }
}

/** Keep the tail of the log when it grows past the cap (whole lines only). */
function trimIfNeeded(path: string): void {
  try {
    if (statSync(path).size <= LOG_MAX_BYTES) return;
    const buf = readFileSync(path);
    let tail = buf.subarray(buf.length - LOG_KEEP_BYTES);
    const nl = tail.indexOf(0x0a); // drop a possibly-partial first line
    if (nl !== -1) tail = tail.subarray(nl + 1);
    writeFileSync(path, tail);
  } catch {
    /* defensive */
  }
}
