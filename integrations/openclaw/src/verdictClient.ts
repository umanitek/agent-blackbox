/**
 * Ask the Blackbox on this machine what it makes of a tool call (2026-11-20).
 *
 * WHY: this plugin carried its own copy of Blackbox's checks, and the copy fell behind — a real
 * OpenClaw agent installed a package the verified threat graph lists as malware and read a wallet
 * key while Hermes blocked both on the same machine. The verified-graph lookups, the shields
 * (wallet key stores) and the operator's local overrides live in Blackbox's Python; instead of a
 * second copy, the plugin asks Blackbox's local service (`POST /api/guard/verdict`, the SAME
 * judgement a Hermes agent's hook makes) and applies the answer.
 *
 * It is a coordination layer, never a gate on the agent: one short timeout, and ANY failure —
 * service not running, slow, an odd answer — returns null so the caller falls back to the
 * plugin's own built-in checks. After a failure it does not ask again for RETRY_AFTER_MS, so a
 * stopped service costs one timeout, not one per tool call.
 *
 * The service only answers local processes: a POST needs the session token from
 * `GET /api/session`, which a web page cannot obtain. The token is fetched once and re-fetched
 * when refused.
 *
 * No imports: Node can load this file as it is.
 *
 * Usage:
 *   const verdicts = new VerdictClient("http://127.0.0.1:9700");
 *   const verdict = await verdicts.ask("exec", { command: "npm install left-pad" });
 *   if (verdict === null) { ...use the built-in checks... }
 *   verdict.findings, verdict.blocked, verdict.decision, verdict.message
 */

/** One finding as Blackbox's Python writes it (`Finding.to_dict()`); only these fields are read. */
export interface RemoteFinding {
  identifier: string;
  category: string;
  severity: string;
  title: string;
  tool_name?: string | null;
  matched?: string;
  evidence?: string;
  confirmed?: boolean;
  source?: string;
  kind?: string | null;
  fields?: Record<string, unknown>;
}

/** Blackbox's answer for one tool call. */
export interface RemoteVerdict {
  findings: RemoteFinding[];
  /** Identifiers of the findings that block this call (empty unless Block mode applies). */
  blocked: string[];
  /** "", "flag", "flag (local override)" or "block". */
  decision: string;
  /** What the agent is told when blocked. */
  message: string;
}

type Fetch = (url: string, init?: Record<string, unknown>) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

/** How long one question may take before the built-in checks are used instead. */
export const VERDICT_TIMEOUT_MS = 1500;
/** After a failure, how long before the service is asked again. */
export const RETRY_AFTER_MS = 15_000;
const REFUSED = 403;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The answer when it has the shape promised, else null (never trust a half-formed verdict). */
export function readVerdict(body: unknown): RemoteVerdict | null {
  if (!isRecord(body) || !Array.isArray(body.findings) || !Array.isArray(body.blocked)) return null;
  const findings: RemoteFinding[] = [];
  for (const row of body.findings) {
    if (!isRecord(row)) return null;
    const { identifier, category, severity, title } = row;
    if (typeof identifier !== "string" || typeof category !== "string" || typeof severity !== "string" || typeof title !== "string") return null;
    findings.push(row as unknown as RemoteFinding);
  }
  const known = new Set(findings.map((finding) => finding.identifier));
  const blocked = body.blocked.filter((id): id is string => typeof id === "string" && known.has(id));
  if (blocked.length !== body.blocked.length) return null;   // a block must name a finding it comes with
  return {
    findings,
    blocked,
    decision: typeof body.decision === "string" ? body.decision : "",
    message: typeof body.message === "string" ? body.message : "",
  };
}

export class VerdictClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: Fetch;
  private readonly now: () => number;
  private token = "";
  private silentUntil = 0;

  /** `fetchImpl` and `now` are seams for tests; an empty `baseUrl` means "never ask". */
  constructor(baseUrl: string, fetchImpl?: Fetch, now?: () => number) {
    this.baseUrl = (baseUrl || "").replace(/\/+$/, "");
    this.fetchImpl = fetchImpl ?? (globalThis.fetch as unknown as Fetch);
    this.now = now ?? Date.now;
  }

  /** Blackbox's verdict for this call, or null when it could not be had in time. */
  async ask(toolName: string, args: unknown): Promise<RemoteVerdict | null> {
    if (!this.baseUrl || typeof this.fetchImpl !== "function" || this.now() < this.silentUntil) return null;
    try {
      const verdict = await this.askOnce(toolName, args, AbortSignal.timeout(VERDICT_TIMEOUT_MS));
      if (verdict === null) this.silentUntil = this.now() + RETRY_AFTER_MS;
      return verdict;
    } catch {
      this.silentUntil = this.now() + RETRY_AFTER_MS;
      return null;
    }
  }

  private async askOnce(toolName: string, args: unknown, signal: AbortSignal): Promise<RemoteVerdict | null> {
    for (const attempt of [1, 2]) {
      if (!this.token) this.token = await this.fetchToken(signal);
      if (!this.token) return null;
      const response = await this.fetchImpl(`${this.baseUrl}/api/guard/verdict`, {
        method: "POST",
        signal,
        headers: { "content-type": "application/json", accept: "application/json", "x-blackbox-token": this.token },
        body: JSON.stringify({ tool_name: toolName, args }),
      });
      if (response.status === REFUSED && attempt === 1) { this.token = ""; continue; }   // the service restarted
      return response.ok ? readVerdict(await response.json()) : null;
    }
    return null;
  }

  private async fetchToken(signal: AbortSignal): Promise<string> {
    const response = await this.fetchImpl(`${this.baseUrl}/api/session`, { signal, headers: { accept: "application/json" } });
    if (!response.ok) return "";
    const body = await response.json();
    return isRecord(body) && typeof body.token === "string" ? body.token : "";
  }
}
