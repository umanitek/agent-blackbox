/**
 * Community membership — TypeScript mirror of `community/membership.py`.
 *
 * Since 2026-10-16 the community lives in the verified graph's shared memory (sub-graph
 * "reports"), so membership is that graph's subscription WITH shared memory. The graph is public:
 * no join step (D-040). The graph's owner (`graphPeerId`, the curator) is dialled before the first
 * subscribe and re-dialled every OWNER_LINK_MS (KI-297), never by the owner's own node. Subscribe
 * with shared memory once per process — a node subscribed VM-only gets its shared memory added —
 * and confirm only once the node holds the graph's definition (its listing names an access policy;
 * "synced" can say true before that). Without it every write is refused with CONTEXT_GRAPH_NOT_FOUND:
 * an edge that reaches the graph only through relays gets it only after dialling the owner and
 * subscribing again with forceCatchup (KI-295, DKG #3264). A refusal, a VM-only catch-up still
 * running and a missing definition are retried after FAILED_RETRY_MS. Before the first write the
 * "reports" sub-graph is registered on this node. Fail-open: errors are logged, never thrown.
 */
import { COMMUNITY_SUB_GRAPH, type DkgClient } from "./dkgClient.js";

export const RETRY_MS = 600_000;
export const FAILED_RETRY_MS = 60_000;
/** How often the live link to the graph owner is re-dialled (KI-297). */
export const OWNER_LINK_MS = 120_000;

export interface MembershipState {
  confirmedAt?: number;
  lastAttemptAt?: number;
  /** The node took the subscription WITH shared memory (this process). */
  withSharedMemory?: boolean;
  /** The "reports" sub-graph is registered on this node. */
  laneReady?: boolean;
  /** When the graph owner was last dialled. */
  ownerDialledAt?: number;
  /** This node's own peer id, once known (the owner's own node never dials itself). */
  ownPeerId?: string;
}

/** Whether a subscribe answer covers shared memory: an already-running catch-up keeps its own setting. */
function includesSharedMemory(reply: unknown): boolean {
  const catchup = (reply as { catchup?: Record<string, unknown> } | null)?.catchup;
  if (!catchup || typeof catchup !== "object") return true;
  return (catchup.includeSharedMemory ?? catchup.includeWorkspace) !== false;
}

/** The node holds the graph's definition: its listing row names an access policy (KI-295). */
function hasDefinition(entry: Record<string, unknown> | undefined): boolean {
  return ["public", "private"].includes(String(entry?.accessPolicy ?? "").trim().toLowerCase());
}

async function listed(client: DkgClient, graph: string): Promise<Record<string, unknown> | undefined> {
  return (await client.contextGraphs()).find((e) => e.id === graph);
}

/** Dial the graph owner by peer id (DHT-resolved, or through a relay); never this node itself. */
async function dialOwner(client: DkgClient, owner: string, state: MembershipState, log: (msg: string) => void): Promise<void> {
  if (!state.ownPeerId) {
    try {
      state.ownPeerId = String(((await client.status()) as { peerId?: unknown } | null)?.peerId ?? "");
    } catch {
      // cannot tell yet: dial anyway (the node refuses a self-dial)
    }
  }
  if (owner === state.ownPeerId) return;
  try {
    await client.connectPeer(owner);
  } catch (err) {
    log(`blackbox: could not reach the graph owner ${owner}: ${(err as Error).message}`);
  }
}

/** Re-dial the graph owner every OWNER_LINK_MS (KI-297); true when it dialled on this call. */
async function keepOwnerLink(
  client: DkgClient,
  owner: string,
  state: MembershipState,
  log: (msg: string) => void,
  now: number,
): Promise<boolean> {
  if (!owner || (state.ownerDialledAt !== undefined && now - state.ownerDialledAt < OWNER_LINK_MS)) return false;
  state.ownerDialledAt = now;
  await dialOwner(client, owner, state, log);
  return true;
}

export async function ensureCommunitySubscription(
  client: DkgClient,
  graph: string,
  owner: string,
  state: MembershipState,
  log: (msg: string) => void,
  now = Date.now(),
): Promise<boolean> {
  if (!graph) return false;
  const dialled = await keepOwnerLink(client, owner, state, log, now);
  if (state.confirmedAt !== undefined && now - state.confirmedAt < RETRY_MS) return true;
  try {
    const entry = await listed(client, graph);
    const subscribed = Boolean(entry?.subscribed);
    const defined = !owner || hasDefinition(entry); // the owner holds it
    if (subscribed && defined && state.withSharedMemory) {
      state.confirmedAt = now;
      return true;
    }
    if (state.lastAttemptAt !== undefined && now - state.lastAttemptAt < FAILED_RETRY_MS) return subscribed;
    state.lastAttemptAt = now;
    if (owner && !dialled) await dialOwner(client, owner, state, log);
    const reply = await client.subscribeContextGraph(graph, true, subscribed && !defined);
    if (!includesSharedMemory(reply)) return true; // subscribed; shared memory follows the running catch-up
    state.withSharedMemory = true;
    if (owner && !hasDefinition(await listed(client, graph))) return true; // fetched again after FAILED_RETRY_MS
    state.confirmedAt = now;
    return true;
  } catch (err) {
    log(`blackbox: subscribe with shared memory failed (retry in ${FAILED_RETRY_MS / 1000}s): ${(err as Error).message}`);
    return false;
  }
}

/** Register the community sub-graph on this node before its first write there ("already exists" counts as ready). */
export async function ensureReportLane(
  client: DkgClient,
  graph: string,
  state: MembershipState,
  log: (msg: string) => void,
): Promise<boolean> {
  if (state.laneReady) return true;
  try {
    await client.createSubGraph(graph, COMMUNITY_SUB_GRAPH);
  } catch (err) {
    if (!String((err as Error).message).includes("already exists")) {
      log(`blackbox: could not register the community sub-graph on this node: ${(err as Error).message}`);
      return false;
    }
  }
  state.laneReady = true;
  return true;
}
