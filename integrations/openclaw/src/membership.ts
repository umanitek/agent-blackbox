/**
 * Community membership — TypeScript mirror of `community/membership.py`.
 *
 * Since 2026-10-16 the community lives in the verified graph's shared memory (sub-graph
 * "reports"), so membership is that graph's subscription WITH shared memory. The graph is
 * registered on chain, so no owner peer is dialled first, and the node gets its definition by
 * itself, also through Cores only (DKG 10.0.25: OriginTrail/dkg#3303, #3311). It is public: no
 * join step (D-040). Subscribe with shared memory once per process — a node subscribed VM-only
 * gets its shared memory added — and believe it when the node's answer covers shared memory;
 * otherwise (a refusal, or a VM-only catch-up still running) retry after FAILED_RETRY_MS. The
 * bridge registers no sub-graph: it writes into the "reports" sub-graph the graph's owner
 * registered (DKG 10.0.25 looks that up at a member's first write, OriginTrail/dkg#3306).
 * Fail-open: errors are logged, never thrown.
 */
import type { DkgClient } from "./dkgClient.js";

export const RETRY_MS = 600_000;
export const FAILED_RETRY_MS = 60_000;

export interface MembershipState {
  confirmedAt?: number;
  lastAttemptAt?: number;
  /** The node took the subscription WITH shared memory (this process). */
  withSharedMemory?: boolean;
}

/** Whether a subscribe answer covers shared memory: an already-running catch-up keeps its own setting. */
function includesSharedMemory(reply: unknown): boolean {
  const catchup = (reply as { catchup?: Record<string, unknown> } | null)?.catchup;
  if (!catchup || typeof catchup !== "object") return true;
  return (catchup.includeSharedMemory ?? catchup.includeWorkspace) !== false;
}

export async function ensureCommunitySubscription(
  client: DkgClient,
  graph: string,
  state: MembershipState,
  log: (msg: string) => void,
  now = Date.now(),
): Promise<boolean> {
  if (!graph) return false;
  if (state.confirmedAt !== undefined && now - state.confirmedAt < RETRY_MS) return true;
  if (state.lastAttemptAt !== undefined && now - state.lastAttemptAt < FAILED_RETRY_MS) return false;
  state.lastAttemptAt = now;
  try {
    if (state.withSharedMemory) {
      const listed = (await client.contextGraphs()).find((e) => e.id === graph);
      if (listed?.subscribed) {
        state.confirmedAt = now;
        return true;
      }
    }
    const reply = await client.subscribeContextGraph(graph, true);
    if (!includesSharedMemory(reply)) return true; // subscribed; shared memory follows the running catch-up
    state.withSharedMemory = true;
    state.confirmedAt = now;
    return true;
  } catch (err) {
    log(`blackbox: subscribe with shared memory failed (retry in ${FAILED_RETRY_MS / 1000}s): ${(err as Error).message}`);
    return false;
  }
}
