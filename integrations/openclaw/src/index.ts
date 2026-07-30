/**
 * Agent Blackbox — OpenClaw plugin.
 *
 * Mirrors the hermes blackbox plugin's detection and reports sightings to the
 * same local DKG threat graph. Rules come ONLY from the synced graph
 * (ruleset.ts); on an empty graph nothing is detected — by design.
 *
 * Hooks:
 *   before_tool_call   — detect escalation/dependency/injection over params;
 *                        block (block mode, >= block_severity) or observe+report
 *   after_tool_call    — observe result (redacted); never blocks
 *   before_agent_run   — prompt-injection scan (needs allowConversationAccess)
 *   message_received   — observe inbound content for injection sightings
 *   session_start/end  — lifecycle observation
 *
 * Fail-open: any handler error is swallowed and the agent loop proceeds.
 */
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import type { OpenClawPluginApi } from "openclaw/plugin-sdk/plugin-entry";
import type {
  PluginHookAfterToolCallEvent,
  PluginHookBeforeAgentRunEvent,
  PluginHookBeforeAgentRunResult,
  PluginHookBeforeToolCallEvent,
  PluginHookBeforeToolCallResult,
  PluginHookMessageReceivedEvent,
  PluginHookSessionEndEvent,
  PluginHookSessionStartEvent,
} from "openclaw/plugin-sdk/types";
import {
  Finding,
  Ruleset,
  collectText,
  commandFromArgs,
  detectAll,
  detectCustomFileAccess,
  detectInjection,
  detectIoc,
  discoverInjection,
  discoverDependencyCandidates,
  fileAccessArg,
  isShellTool,
  parseDependencyInstalls,
  parseDownloads,
  parseShellReads,
} from "./detection.js";
import { DkgClient, DkgError } from "./dkgClient.js";
import { recordEvent, recordFinding, type ConvTurn, type FindingContext } from "./audit.js";
import { BlackboxConfig, categoryAllows, resolveConfig } from "./config.js";
import { RulesetCache } from "./ruleset.js";
import { BlackboxSeverity, KIND_VULNERABILITY, SEVERITY_RANK, buildReportQuads, stableHash } from "./quads.js";
import { lookup as osvLookup } from "./osv.js";
import { sanitizeText } from "./redact.js";

const PLUGIN_ID = "blackbox";
const FRAMEWORK = "openclaw" as const;

/**
 * Idempotent-registration guard. OpenClaw has NO unsubscribe primitive, so a
 * second `register(api)` for the same host API must not double-wire hooks. A
 * hot reload supplies a fresh API/registry and must register again.
 */
let registeredApis = new WeakSet<object>();

interface BlackboxRuntime {
  cfg: BlackboxConfig;
  client: DkgClient;
  ruleset: RulesetCache;
  /** Cached reporter agent address, resolved lazily from the node (never the token). */
  reporterAddress?: string;
  log: (level: "debug" | "warn", msg: string, meta?: unknown) => void;
  dailyReports: { date: string; count: number };
  /** Per-identifier cooldown stamps (identifier → epoch ms of last sighting). Mirrors Python `audit.allow_report`. */
  recentReports: Map<string, number>;
  /**
   * Per-session conversation transcript (last N turns) so a tool-call finding —
   * which has no conversation access at `before_tool_call` — can still show the
   * surrounding turns. Local-only, bounded. Mirrors Python `hooks._last_convo`.
   */
  transcript: Map<string, ConvTurn[]>;
}

// --- Conversation context capture (local-only, redacted) -------------------
//
// Attach a redacted `context` snapshot to a finding so the dashboard modal can
// render the whole turn, not just the evidence fragment. Redaction + capping
// happen in `audit.boundedContext`; this stays LOCAL-only, never in
// `Finding.fields` or an SWM sighting.

const CONTEXT_TURNS = 12;
const MAX_TRACKED_SESSIONS = 256;

/** Best-effort session id off any hook event (absent on some hooks/SDKs). */
function sessionIdOf(event: unknown): string {
  const sid = (event as { sessionId?: unknown } | null | undefined)?.sessionId;
  return typeof sid === "string" ? sid : "";
}

interface AuditHookContext {
  sessionId?: string;
  sessionKey?: string;
  runId?: string;
  modelProviderId?: string;
  modelId?: string;
  channelId?: string;
}

function sessionRefOf(event: unknown, ctx: AuditHookContext = {}): string {
  const eventSessionKey = (event as { sessionKey?: unknown } | null | undefined)?.sessionKey;
  return (
    sessionIdOf(event) ||
    ctx.sessionId ||
    (typeof eventSessionKey === "string" ? eventSessionKey : "") ||
    ctx.sessionKey ||
    ""
  );
}

/** Flatten a message's `content` (string or a list of text parts) to text. */
function messageText(content: unknown): string {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .map((it) =>
        typeof it === "string"
          ? it
          : it && typeof it === "object" && typeof (it as { text?: unknown }).text === "string"
            ? (it as { text: string }).text
            : "",
      )
      .filter(Boolean)
      .join("\n");
  }
  return "";
}

function normalizeRole(role: unknown): string {
  const r = String(role ?? "").toLowerCase();
  return r === "user" || r === "assistant" || r === "system" || r === "tool" ? r : "user";
}

/**
 * Build `[{role, text}]` from a conversation `messages` array; falls back to
 * `prompt` when messages are unavailable. Mirrors Python `hooks._conversation_turns`.
 */
function turnsFromMessages(messages: unknown, prompt?: unknown): ConvTurn[] {
  const turns: ConvTurn[] = [];
  const arr = Array.isArray(messages) ? messages : [];
  for (const m of arr.slice(-CONTEXT_TURNS * 3)) {
    if (!m || typeof m !== "object") continue;
    const text = messageText((m as { content?: unknown }).content).trim();
    if (!text) continue;
    turns.push({ role: normalizeRole((m as { role?: unknown }).role), text });
  }
  if (!turns.length) {
    const p = String(prompt ?? "").trim();
    if (p) turns.push({ role: "user", text: p });
  }
  return turns.slice(-CONTEXT_TURNS);
}

/** Replace the session transcript with the canonical conversation (bounded). */
function setTranscript(rt: BlackboxRuntime, sessionId: string, turns: ConvTurn[]): void {
  if (!sessionId || !turns.length) return;
  if (!rt.transcript.has(sessionId) && rt.transcript.size >= MAX_TRACKED_SESSIONS) rt.transcript.clear();
  rt.transcript.set(sessionId, turns.slice(-CONTEXT_TURNS));
}

/** Append one turn to the session transcript (bounded). */
function appendTranscript(rt: BlackboxRuntime, sessionId: string, turn: ConvTurn): void {
  if (!sessionId || !turn.text) return;
  let buf = rt.transcript.get(sessionId);
  if (!buf) {
    if (rt.transcript.size >= MAX_TRACKED_SESSIONS) rt.transcript.clear();
    buf = [];
    rt.transcript.set(sessionId, buf);
  }
  buf.push(turn);
  if (buf.length > CONTEXT_TURNS) buf.splice(0, buf.length - CONTEXT_TURNS);
}

function recentTranscript(rt: BlackboxRuntime, sessionId: string): ConvTurn[] {
  return sessionId ? (rt.transcript.get(sessionId) ?? []).slice() : [];
}

/** Re-report window. The KA name is stable per identifier+reporter, so a re-share
 * only refreshes dateModified — skip it. Mirrors Python audit.REPORT_COOLDOWN_SECS. */
const REPORT_COOLDOWN_MS = 6 * 3600 * 1000;

/** Drop expired cooldown stamps so the map stays small. */
function pruneRecentReports(rt: BlackboxRuntime, now: number): void {
  if (rt.recentReports.size <= 2048) return;
  for (const [identifier, ts] of rt.recentReports) {
    if (now - ts >= REPORT_COOLDOWN_MS) rt.recentReports.delete(identifier);
  }
}

/**
 * Apply the user's detection policy to raw findings. Two layers:
 *   1. Per-category policy (`detection.<category>.{enabled,minSeverity}`).
 *   2. Heuristic gate — discovery candidates additionally need `reportMinSeverity`.
 *
 * Custom rules (`source === "custom"`) bypass the category policy; graph-backed
 * findings skip the heuristic gate. Mirrors Python `hooks._flag_worthy`.
 */
function flagWorthy(cfg: BlackboxConfig, findings: Finding[]): Finding[] {
  const out: Finding[] = [];
  for (const f of findings) {
    if (f.source === "custom") {
      out.push(f);
      continue;
    }
    if (!categoryAllows(cfg, f.category, f.severity)) continue;
    if (f.source === "heuristic" && SEVERITY_RANK[f.severity] < SEVERITY_RANK[cfg.reportMinSeverity]) {
      continue;
    }
    out.push(f);
  }
  return out;
}

/**
 * Injection scan shared by `before_agent_run` and `message_received`: detect
 * graph-backed patterns, add built-in discovery candidates when enabled, then
 * apply the user's flag policy. One place so the two hooks can't drift.
 */
function scanInjection(rt: BlackboxRuntime, text: string): Finding[] {
  const ruleset = rt.ruleset.get();
  const findings = detectInjection(text, ruleset);
  if (rt.cfg.discover) findings.push(...discoverInjection(text, ruleset));
  return flagWorthy(rt.cfg, findings);
}

/**
 * Log routine file/download/package activity independently of whether it is a
 * threat. This mirrors Hermes `_record_activity` and stays fail-open.
 */
function recordToolActivity(
  rt: BlackboxRuntime,
  event: PluginHookBeforeToolCallEvent,
  ctx: AuditHookContext,
  params: Record<string, unknown>,
): void {
  try {
    const base = {
      session_id: sessionRefOf(event, ctx),
      run_id: event.runId ?? ctx.runId,
      tool_call_id: event.toolCallId,
    };
    const access = fileAccessArg(event.toolName, params);
    if (access) {
      recordEvent(rt.cfg.blackboxHome, "file_access", {
        ...base,
        tool: access.tool,
        path: access.path,
        mode: access.mode,
      });
      return;
    }
    if (!isShellTool(event.toolName)) return;
    const command = commandFromArgs(event.toolName, params);
    if (!command) return;
    for (const path of parseShellReads(command)) {
      recordEvent(rt.cfg.blackboxHome, "file_access", { ...base, tool: "shell", path, mode: "read" });
    }
    for (const url of parseDownloads(command)) {
      recordEvent(rt.cfg.blackboxHome, "file_access", { ...base, tool: "shell", path: url, mode: "download" });
    }
    for (const dep of parseDependencyInstalls(command)) {
      recordEvent(rt.cfg.blackboxHome, "dependency_install", { ...base, ...dep, tool: "shell" });
    }
  } catch {
    /* fail-open — visibility logging must never break the tool call */
  }
}

/**
 * Resolve + cache the reporter agent address via `GET /api/agent/identity`;
 * fails open to "node". NOT derived from the auth token — the node's true agent
 * address namespaces the per-submitter report URI.
 */
async function resolveReporter(rt: BlackboxRuntime): Promise<string> {
  if (rt.reporterAddress !== undefined) return rt.reporterAddress;
  try {
    rt.reporterAddress = await rt.client.reporterAddress();
  } catch {
    rt.reporterAddress = "node";
  }
  return rt.reporterAddress;
}

function today(): string {
  return new Date().toISOString().slice(0, 10);
}

function underDailyCap(rt: BlackboxRuntime): boolean {
  const d = today();
  if (rt.dailyReports.date !== d) {
    rt.dailyReports = { date: d, count: 0 };
  }
  return rt.dailyReports.count < rt.cfg.dailyReportLimit;
}

/**
 * Report a sighting to the SWM (one-shot KA share). Deterministic HTTP, fully
 * fail-open, rate-limited by daily cap + per-identifier cooldown. Reports
 * carry NO observed content.
 */
async function reportSighting(rt: BlackboxRuntime, finding: Finding): Promise<void> {
  // Custom rules stay local — NEVER shared. Mirrors Python `_report_and_audit`.
  if (finding.source === "custom") return;
  if (!rt.cfg.report) return;
  // Per-threat cooldown: skip a re-fire within the window. Mirrors Python `audit.allow_report`.
  const now = Date.now();
  const last = rt.recentReports.get(finding.identifier);
  if (last !== undefined && now - last < REPORT_COOLDOWN_MS) {
    rt.log("debug", `blackbox: report cooldown active for ${finding.identifier}`);
    return;
  }
  if (!underDailyCap(rt)) {
    rt.log("debug", "blackbox: daily report cap reached, dropping sighting");
    return;
  }
  // Stamp before the share so a burst of re-fires can't queue N shares in flight.
  rt.recentReports.set(finding.identifier, now);
  pruneRecentReports(rt, now);
  try {
    const reporter = await resolveReporter(rt);
    // Forward privacy-safe candidate fields for independent review. `fields`
    // only ever holds signatures (pattern/category/shape/...), never raw prompts,
    // paths, or file/skill source. Mirrors Python `_share_sighting`.
    const quads = buildReportQuads({
      identifier: finding.identifier,
      category: finding.category,
      severity: finding.severity,
      reporter,
      framework: FRAMEWORK,
      candidate: finding.fields,
    });
    // KA name matches Python hooks._share_sighting: hashing in the reporter keeps
    // two reporters of one threat from colliding, stable per (identifier, reporter).
    const name = `report-${stableHash(finding.identifier + reporter, 16)}`;
    await rt.client.shareKnowledgeAsset(rt.cfg.contextGraphId, name, quads);
    rt.dailyReports.count += 1;
  } catch (err) {
    if (err instanceof DkgError) {
      rt.log("debug", `blackbox: sighting report failed (node unreachable): ${err.message}`);
      return;
    }
    rt.log("debug", `blackbox: sighting report error: ${(err as Error).message}`);
  }
}

/**
 * Findings that can block at/above the block threshold: confirmed public-graph
 * matches and custom rules. Community matches and discovery candidates only
 * alert/report. A `vulnerability`-kind threat NEVER blocks — only active malware
 * is stopped. Mirrors Python's `pre_tool_call` blocking filter.
 */
function meetsBlock(finding: Finding, cfg: BlackboxConfig): boolean {
  return (
    (finding.confirmed || finding.source === "custom") &&
    finding.kind !== KIND_VULNERABILITY &&
    finding.kind !== "historical" &&
    finding.category !== "ioc" &&
    SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[cfg.blockSeverity]
  );
}

function maxSeverity(findings: Finding[]): BlackboxSeverity {
  return findings.reduce<BlackboxSeverity>(
    (best, f) => (SEVERITY_RANK[f.severity] > SEVERITY_RANK[best] ? f.severity : best),
    "info",
  );
}

function blockMessage(findings: Finding[]): string {
  const worst = maxSeverity(findings);
  const titles = [...new Set(findings.map((f) => f.title))].slice(0, 3).join("; ");
  return `Blackbox blocked this action (${worst}): ${titles}`;
}

/**
 * Surface a flagged finding: record it locally AND report the sighting. Local
 * recording covers EVERY finding; `reportSighting` skips custom rules and applies
 * the daily cap / per-identifier cooldown.
 */
function observe(
  rt: BlackboxRuntime,
  event: string,
  finding: Finding,
  toolName?: string,
  context?: FindingContext,
): void {
  try {
    recordFinding(rt.cfg.blackboxHome, event, finding, toolName, context);
  } catch {
    /* fail-open — local logging must never break the loop */
  }
  void reportSighting(rt, finding);
}

// --- Hook handlers ---------------------------------------------------------

function makeBeforeToolCall(rt: BlackboxRuntime) {
  return async (
    event: PluginHookBeforeToolCallEvent,
    hookCtx: AuditHookContext = {},
  ): Promise<PluginHookBeforeToolCallResult | void> => {
    try {
      const ruleset: Ruleset = rt.ruleset.get();
      const params = (event.params ?? {}) as Record<string, unknown>;
      recordEvent(rt.cfg.blackboxHome, "pre_tool_call", {
        session_id: sessionRefOf(event, hookCtx),
        run_id: event.runId ?? hookCtx.runId,
        tool_call_id: event.toolCallId,
        tool_name: event.toolName,
        args: params,
      });
      recordToolActivity(rt, event, hookCtx, params);
      // detectAll (+ discovery layer when enabled) + custom protected-path rules,
      // then flagWorthy applies policy. Mirrors Python detect_all +
      // detect_custom_fileaccess + _flag_worthy.
      const raw = detectAll(event.toolName, params, ruleset, rt.cfg.discover);
      raw.push(...detectCustomFileAccess(event.toolName, params, rt.cfg.protectedPaths));
      const findings: Finding[] = flagWorthy(rt.cfg, raw);

      // OSV auto-discovery runs OFF the blocking path so a network lookup never
      // delays the tool call. Fail-open.
      if (rt.cfg.discover && rt.cfg.osvLookup) {
        void discoverDependencyCandidates(event.toolName, params, ruleset, osvLookup)
          .then((candidates) => {
            for (const f of flagWorthy(rt.cfg, candidates)) observe(rt, "osv_discovery", f, event.toolName);
          })
          .catch(() => {
            /* fail-open — OSV discovery must never break the loop */
          });
      }

      if (findings.length === 0) return;

      // Conversation context: surrounding transcript turns + the scanned tool
      // input (for a `message` reply tool this input IS the agent's response).
      const ctx: FindingContext = {};
      const turns = recentTranscript(rt, sessionIdOf(event));
      if (turns.length) ctx.turns = turns;
      const inputText = collectText(params).join("\n");
      if (inputText.trim()) ctx.input = inputText;
      const context = ctx.turns || ctx.input ? ctx : undefined;

      // Record locally + report every finding (fire-and-forget; never blocks).
      for (const f of findings) observe(rt, "before_tool_call", f, event.toolName, context);

      if (rt.cfg.mode === "block") {
        const blocking = findings.filter((f) => meetsBlock(f, rt.cfg));
        if (blocking.length > 0) {
          return { block: true, blockReason: blockMessage(blocking) };
        }
      }
      return;
    } catch (err) {
      rt.log("debug", `blackbox: before_tool_call error: ${(err as Error).message}`);
      return; // fail-open
    }
  };
}

function makeAfterToolCall(rt: BlackboxRuntime) {
  return async (event: PluginHookAfterToolCallEvent, ctx: AuditHookContext = {}): Promise<void> => {
    try {
      recordEvent(rt.cfg.blackboxHome, "post_tool_call", {
        session_id: sessionRefOf(event, ctx),
        run_id: event.runId ?? ctx.runId,
        tool_call_id: event.toolCallId,
        tool_name: event.toolName,
        args: event.params,
        result: event.result,
        error: event.error,
        duration_ms: event.durationMs,
      });
      if (event.error) {
        rt.log("debug", `blackbox: tool ${event.toolName} errored`, { error: sanitizeText(event.error, 300) });
        return;
      }

      // Tool output is untrusted input to the next model call. Scan it here so
      // web pages, MCP responses, email, and RAG results appear in Blackbox even
      // when the host's next-run hook does not expose intermediate tool turns.
      const resultText = collectText(event.result).join("\n");
      if (!resultText.trim()) return;
      const findings = scanInjection(rt, resultText);
      const inputIocs = new Set(detectIoc(event.toolName, event.params, rt.ruleset.get()).map((f) => f.identifier));
      findings.push(...flagWorthy(
        rt.cfg,
        detectIoc(event.toolName, event.result, rt.ruleset.get()).filter((f) => !inputIocs.has(f.identifier)),
      ));
      const context: FindingContext = { input: resultText };
      for (const f of findings) observe(rt, "post_tool_call", f, event.toolName, context);
    } catch {
      /* fail-open */
    }
  };
}

function makeBeforeAgentRun(rt: BlackboxRuntime) {
  return async (
    event: PluginHookBeforeAgentRunEvent,
    ctx: AuditHookContext = {},
  ): Promise<PluginHookBeforeAgentRunResult> => {
    try {
      recordEvent(rt.cfg.blackboxHome, "pre_api_request", {
        session_id: sessionRefOf(event, ctx),
        run_id: ctx.runId,
        provider: ctx.modelProviderId,
        model: ctx.modelId,
        channel: event.channelId ?? ctx.channelId,
      });
      const text = [event.prompt ?? "", ...collectText(event.messages)].join("\n");
      const findings = scanInjection(rt, text);

      // Warm the per-session transcript so later tool-call findings can show it.
      const turns = turnsFromMessages(event.messages, event.prompt);
      setTranscript(rt, sessionIdOf(event), turns);
      if (findings.length === 0) return { outcome: "pass" };

      const context: FindingContext | undefined = turns.length ? { turns } : undefined;
      for (const f of findings) observe(rt, "before_agent_run", f, undefined, context);

      if (rt.cfg.mode === "block") {
        const blocking = findings.filter((f) => meetsBlock(f, rt.cfg));
        if (blocking.length > 0) {
          return {
            outcome: "block",
            reason: `blackbox:prompt-injection:${blocking.map((f) => f.identifier).join(",")}`,
            message: "This request was blocked because it contained prompt-injection content.",
          };
        }
      }
      return { outcome: "pass" };
    } catch (err) {
      rt.log("debug", `blackbox: before_agent_run error: ${(err as Error).message}`);
      return { outcome: "pass" }; // fail-open
    }
  };
}

function makeMessageReceived(rt: BlackboxRuntime) {
  return async (event: PluginHookMessageReceivedEvent, ctx: AuditHookContext = {}): Promise<void> => {
    try {
      const text = event.content ?? "";
      // Record the inbound message as a user turn so a later finding can show it.
      const sid = sessionRefOf(event, ctx);
      recordEvent(rt.cfg.blackboxHome, "message_received", {
        session_id: sid,
        run_id: event.runId ?? ctx.runId,
        message_id: event.messageId,
        channel: ctx.channelId,
        content_length: text.length,
      });
      if (text) appendTranscript(rt, sid, { role: "user", text });
      const found = scanInjection(rt, text);
      if (!found.length) return;
      const turns = recentTranscript(rt, sid);
      const context: FindingContext | undefined = turns.length
        ? { turns }
        : text
          ? { turns: [{ role: "user", text }] }
          : undefined;
      for (const f of found) observe(rt, "message_received", f, undefined, context);
    } catch {
      /* fail-open — message_received is observation-only */
    }
  };
}

function makeSessionStart(rt: BlackboxRuntime) {
  return async (event: PluginHookSessionStartEvent, ctx: AuditHookContext = {}): Promise<void> => {
    rt.log("debug", `blackbox: session_start ${event.sessionId}`);
    recordEvent(rt.cfg.blackboxHome, "session_start", {
      session_id: event.sessionId,
      session_key: event.sessionKey ?? ctx.sessionKey,
      resumed_from: event.resumedFrom,
    });
    // Warm the ruleset so the first tool call has fresh rules.
    try {
      await rt.ruleset.sync();
    } catch {
      /* fail-open */
    }
  };
}

function makeSessionEnd(rt: BlackboxRuntime) {
  return async (event: PluginHookSessionEndEvent, ctx: AuditHookContext = {}): Promise<void> => {
    rt.log("debug", `blackbox: session_end ${event.sessionId} (${event.reason ?? "unknown"})`);
    recordEvent(rt.cfg.blackboxHome, "session_end", {
      session_id: event.sessionId,
      session_key: event.sessionKey ?? ctx.sessionKey,
      message_count: event.messageCount,
      duration_ms: event.durationMs,
      reason: event.reason ?? "unknown",
      next_session_id: event.nextSessionId,
    });
    rt.transcript.delete(event.sessionId);
  };
}

// --- Registration ----------------------------------------------------------

function buildRuntime(api: OpenClawPluginApi): BlackboxRuntime {
  const cfg = resolveConfig((api.pluginConfig ?? {}) as Record<string, unknown>);
  const client = new DkgClient({ url: cfg.dkgUrl, dkgHome: cfg.dkgHome });
  const ruleset = new RulesetCache({
    client,
    contextGraphId: cfg.contextGraphId,
    ttlSeconds: cfg.syncInterval,
    seedStateDir: cfg.blackboxHome,
  });
  const log = (level: "debug" | "warn", msg: string, meta?: unknown) => {
    try {
      const logger = api.logger as unknown as Record<string, ((m: string, x?: unknown) => void) | undefined>;
      const fn = logger?.[level] ?? logger?.info;
      if (typeof fn === "function") fn(msg, meta);
    } catch {
      /* logging must never throw */
    }
  };
  return {
    cfg,
    client,
    ruleset,
    log,
    dailyReports: { date: today(), count: 0 },
    recentReports: new Map<string, number>(),
    transcript: new Map<string, ConvTurn[]>(),
  };
}

export function register(api: OpenClawPluginApi): void {
  // Idempotent guard: no unsubscribe primitive exists, so never double-wire.
  if (registeredApis.has(api)) {
    try {
      (api.logger as unknown as { debug?: (m: string) => void })?.debug?.(
        "blackbox: register() called again; skipping duplicate hook wiring",
      );
    } catch {
      /* ignore */
    }
    return;
  }
  registeredApis.add(api);

  const rt = buildRuntime(api);

  api.on("before_tool_call", makeBeforeToolCall(rt), { priority: 100 });
  api.on("after_tool_call", makeAfterToolCall(rt));
  api.on("before_agent_run", makeBeforeAgentRun(rt), { priority: 100 });
  api.on("message_received", makeMessageReceived(rt));
  api.on("session_start", makeSessionStart(rt));
  api.on("session_end", makeSessionEnd(rt));

  rt.log(
    "debug",
    `blackbox: registered (mode=${rt.cfg.mode}, cg=${rt.cfg.contextGraphId}, dkg=${rt.client.url})`,
  );
}

/** For tests: reset the process-level idempotency latch. */
export function __resetRegistrationGuardForTests(): void {
  registeredApis = new WeakSet<object>();
}

export default definePluginEntry({
  id: PLUGIN_ID,
  name: "Agent Blackbox",
  description:
    "Mirrors hermes blackbox detection in OpenClaw and reports sightings to the local DKG threat graph.",
  // No exclusive `kind` — hook-only plugin, must not claim a singleton slot
  // (memory | context-engine).
  register,
});

export { resolveConfig } from "./config.js";
export type { BlackboxConfig } from "./config.js";
