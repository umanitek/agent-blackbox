/**
 * Minimal fetch-based client for the local DKG v10 node HTTP API.
 *
 * Zero deps — uses global `fetch` (Node ≥18) and `node:fs` for token loading.
 * Every method fails open: on any transport/HTTP error it throws `DkgError`,
 * and callers treat that as "node unreachable, carry on" (never break the
 * agent loop).
 *
 * URL/token resolution mirrors the hermes `dkg_client.py`:
 *   url   ← opts.url | $BLACKBOX_DKG_DAEMON_URL | $BLACKBOX_DKG_URL | http://127.0.0.1:9320
 *   token ← opts.token | $BLACKBOX_DKG_API_TOKEN | $BLACKBOX_DKG_AUTH_TOKEN | <Blackbox DKG home>/auth.token
 */
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { Quad } from "./quads.js";

export class DkgError extends Error {
  readonly status?: number;
  constructor(message: string, status?: number) {
    super(message);
    this.name = "DkgError";
    this.status = status;
  }
}

const DEFAULT_DKG_PORT = 9320;
const DEFAULT_URL = `http://127.0.0.1:${DEFAULT_DKG_PORT}`;
const DEFAULT_TIMEOUT_MS = 3000;
// SPARQL reads fan out across every shared-memory asset, so a large curated
// graph can take a few seconds. Only the background ruleset sync hits this, so a
// generous ceiling is safe.
const QUERY_TIMEOUT_MS = 30000;

export function resolveDkgUrl(explicit?: string): string {
  const envUrl = process.env.BLACKBOX_DKG_DAEMON_URL || process.env.BLACKBOX_DKG_URL;
  const port = Number(process.env.BLACKBOX_DKG_PORT);
  const fallback = Number.isFinite(port) && port > 0 ? `http://127.0.0.1:${port}` : DEFAULT_URL;
  return (explicit || envUrl || fallback).replace(/\/+$/, "");
}

function defaultDkgHome(): string {
  if (process.env.BLACKBOX_DKG_HOME) return process.env.BLACKBOX_DKG_HOME;
  if (process.env.BLACKBOX_HOME) return join(process.env.BLACKBOX_HOME, "dkg");
  const hermesHome = process.env.HERMES_HOME || join(homedir(), ".hermes");
  return join(hermesHome, "blackbox", "dkg");
}

export function resolveDkgToken(explicit?: string, dkgHome?: string): string | undefined {
  if (explicit) return explicit;
  const env = process.env.BLACKBOX_DKG_API_TOKEN || process.env.BLACKBOX_DKG_AUTH_TOKEN;
  if (env) return env;
  const home = dkgHome || defaultDkgHome();
  try {
    // The token file has a leading comment line (e.g. "# DKG node API token —
    // ..."); return the first non-comment, non-blank line, matching the Python
    // client. Using the whole file would put non-ASCII comment text into the
    // Authorization header and throw a ByteString error.
    for (const raw of readFileSync(join(home, "auth.token"), "utf8").split(/\r?\n/)) {
      const line = raw.trim();
      if (line && !line.startsWith("#")) return line;
    }
  } catch {
    // no token file — node may not require one on local hardhat.
  }
  return undefined;
}

export interface DkgClientOptions {
  url?: string;
  token?: string;
  dkgHome?: string;
  timeoutMs?: number;
}

export type DkgView = "working-memory" | "shared-working-memory" | "verifiable-memory";

export class DkgClient {
  readonly url: string;
  private readonly token?: string;
  private readonly timeoutMs: number;
  /** Cached reporter agent address (see `reporterAddress()`). */
  private cachedReporter?: string;

  constructor(opts: DkgClientOptions = {}) {
    this.url = resolveDkgUrl(opts.url);
    this.token = resolveDkgToken(opts.token, opts.dkgHome);
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  private async request<T = unknown>(
    path: string,
    body?: unknown,
    method = "POST",
    timeoutMs = this.timeoutMs,
  ): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const headers: Record<string, string> = { "content-type": "application/json" };
      if (this.token) headers.authorization = `Bearer ${this.token}`;
      const res = await fetch(`${this.url}${path}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
      });
      const text = await res.text();
      if (!res.ok) {
        throw new DkgError(`DKG ${method} ${path} -> ${res.status}: ${text.slice(0, 300)}`, res.status);
      }
      return (text ? JSON.parse(text) : {}) as T;
    } catch (err) {
      if (err instanceof DkgError) throw err;
      throw new DkgError(`DKG ${method} ${path} failed: ${(err as Error).message}`);
    } finally {
      clearTimeout(timer);
    }
  }

  /** Node liveness probe — public, no-auth `GET /api/status`. */
  async status(): Promise<unknown> {
    return this.request("/api/status", undefined, "GET");
  }

  /**
   * Resolve the node's reporter agent address, cached. Prefers the definitive
   * `GET /api/agent/identity` → `{agentAddress}`; falls back to `GET /api/status`
   * (which may surface an agent address). Fails open to "node" so a report URI
   * can always be namespaced. NEVER derived from the auth token string.
   */
  async reporterAddress(): Promise<string> {
    if (this.cachedReporter !== undefined) return this.cachedReporter;
    const pick = (resp: unknown): string | undefined => {
      const r = resp as Record<string, unknown> | null;
      const addr = r?.agentAddress ?? r?.agent_address ?? r?.address;
      return typeof addr === "string" && addr.trim() ? addr.trim() : undefined;
    };
    try {
      const addr = pick(await this.request("/api/agent/identity", undefined, "GET"));
      if (addr) return (this.cachedReporter = addr);
    } catch {
      // definitive route unavailable — fall through to /api/status.
    }
    try {
      const addr = pick(await this.status());
      if (addr) return (this.cachedReporter = addr);
    } catch {
      // node unreachable — fail open below.
    }
    return (this.cachedReporter = "node");
  }

  /**
   * One-shot create + write + seal (+ share to SWM). This is the report path:
   * `POST /api/knowledge-assets {contextGraphId, name, quads, alsoShareSwm:true}`.
   * Quads carry NO per-quad graph (the CG scopes them).
   */
  async shareKnowledgeAsset(
    contextGraphId: string,
    name: string,
    quads: Quad[],
  ): Promise<{ kaId?: string; ual?: string } & Record<string, unknown>> {
    return this.request("/api/knowledge-assets", {
      contextGraphId,
      name,
      quads,
      alsoShareSwm: true,
    });
  }

  /** SPARQL query against a memory view. Blackbox defaults to durable VM. */
  async query(
    sparql: string,
    contextGraphId: string,
    view: DkgView = "verifiable-memory",
  ): Promise<{ results?: unknown } & Record<string, unknown>> {
    return this.request("/api/query", { sparql, contextGraphId, view }, "POST", QUERY_TIMEOUT_MS);
  }
}
