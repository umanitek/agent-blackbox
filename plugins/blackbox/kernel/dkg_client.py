"""Stdlib HTTP client for the local DKG v10 node.

Wraps the daemon's write/query API with a tiny, dependency-free ``urllib``
client. Blackbox defaults to its own daemon URL and DKG home, not the DKG CLI's
``~/.dkg``/9200 defaults. URL/token resolution is
``BLACKBOX_DKG_*`` env → Blackbox config/home → ``$BLACKBOX_DKG_HOME/auth.token``.
Every request uses a short timeout and raises
:class:`DkgError` on a non-2xx response; all callers fail open.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import constants, host_secrets
from .sparql_text import extract_binding, normalize_bindings, rows_or_fallback  # re-exported: callers import them from here

logger = logging.getLogger(__name__)

_TIMEOUT = 3.0
# Read path: a large graph can take a few seconds to evaluate. Only the
# background refresh and the dashboard hit it, never the cached hot hook path.
_QUERY_TIMEOUT = 30.0
_STORE_TIMEOUT = 150.0
Quad = dict[str, str]


class DkgError(RuntimeError):
    """Raised for any non-2xx daemon response or transport failure."""

    def __init__(self, message: str, *, status_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def _validate_quads_literal_sizes(quads: list[Quad]) -> None:
    """Mirror DKG's writable-literal preflight before sending write payloads."""
    try:
        from . import rdf_terms

        rdf_terms.assert_quads_literal_size(quads, label="quads")
    except ValueError as exc:
        raise DkgError(str(exc)) from exc


def _is_already_finalized(exc: DkgError) -> bool:
    """True when a share failed only because the KA already exists sealed.

    The daemon rejects re-finalizing an assertion with a different (or same)
    merkle root; for our deterministic threat/report names that just means the
    content is already on the graph, so the caller can treat it as success.
    """
    msg = str(exc).lower()
    return "already finalized" in msg or "already exists" in msg


def _is_wm_merkle_conflict(exc: DkgError) -> bool:
    """True when the local WM draft/finalized assertion is stale vs SWM."""
    msg = str(exc).lower()
    return (
        "wm_draft_conflict" in msg
        or "draft conflict" in msg
        or "different merkleroot" in msg
        or "different merkle root" in msg
    )


def _job_id_from_error(exc: DkgError) -> Optional[str]:
    """Extract a daemon-returned job id from an HTTP error body if present."""
    msg = str(exc)
    for key in ("existingJobId", "jobId", "id"):
        m = re.search(rf'"{key}"\s*:\s*"([^"]+)"', msg)
        if m:
            return m.group(1)
    return None


def _dkg_home(explicit: Optional[str] = None) -> Path:
    if explicit:
        return Path(explicit).expanduser()
    env = os.environ.get("BLACKBOX_DKG_HOME")
    return Path(env).expanduser() if env else constants.blackbox_dkg_home()


def load_daemon_url() -> str:
    """Resolve the Blackbox daemon URL from Blackbox-specific settings."""
    env = os.environ.get("BLACKBOX_DKG_DAEMON_URL") or os.environ.get("BLACKBOX_DKG_URL")
    if env and env.strip():
        return env.strip().rstrip("/")
    port = os.environ.get("BLACKBOX_DKG_PORT")
    if port and port.strip():
        try:
            return f"http://127.0.0.1:{int(port.strip())}"
        except ValueError:
            pass
    return constants.DEFAULT_DKG_URL


def load_token(dkg_home: Optional[str] = None) -> Optional[str]:
    """Resolve the bearer token: Blackbox variable (read through Hermes) → Blackbox's own auth.token."""
    env = host_secrets.read_host_secret("BLACKBOX_DKG_API_TOKEN") or host_secrets.read_host_secret("BLACKBOX_DKG_AUTH_TOKEN")
    if env:
        return env
    token_path = _dkg_home(dkg_home) / "auth.token"
    try:
        if token_path.exists():
            for line in token_path.read_text(encoding="utf-8-sig").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    return line
    except Exception:
        return None
    return None


def signed_request_headers(token: str, method: str, path: str, body: Optional[bytes]) -> dict[str, str]:
    """Signed-request headers required by DKG >= 10.0.19 (daemon spec §18).

    The daemon rejects any protected route without them (empty HTTP 400 —
    ``missing-fields``): a bearer token alone stopped being sufficient in
    10.0.19. The signature is ``HMAC-SHA256(token, canonical payload)`` where
    the canonical payload is exactly::

        METHOD \\n PATH(pathname+search) \\n TIMESTAMP \\n NONCE \\n sha256hex(BODY)

    *path* must be the same pathname+query string used on the wire — the HMAC
    binds it, so a signature cannot be replayed against another route. The
    nonce is single-use (replay rejection) and the timestamp is epoch-ms.

    Older daemons (<= 10.0.18) simply ignore these extra headers, so callers
    always send them whenever a token is present — one client speaks to every
    daemon generation with no version detection.
    """
    timestamp = str(int(time.time() * 1000))
    nonce = uuid.uuid4().hex
    body_hash = hashlib.sha256(body or b"").hexdigest()
    payload = "\n".join([method.upper(), path, timestamp, nonce, body_hash])
    signature = hmac.new(token.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "x-dkg-timestamp": timestamp,
        "x-dkg-nonce": nonce,
        "x-dkg-signature": signature,
    }


class DkgClient:
    """Minimal DKG v10 HTTP client. Construct with an explicit url/token or
    let :meth:`from_env` resolve them."""

    def __init__(
        self,
        url: Optional[str] = None,
        token: Optional[str] = None,
        dkg_home: Optional[str] = None,
    ) -> None:
        self.url = (url or load_daemon_url()).rstrip("/")
        self.dkg_home = str(_dkg_home(dkg_home))
        self.token = token if token is not None else load_token(self.dkg_home)

    @classmethod
    def from_env(cls) -> DkgClient:
        return cls()

    # -- transport ---------------------------------------------------------

    def request(
        self,
        method: str,
        path: str,
        body: Optional[dict[str, Any]] = None,
        timeout: Optional[float] = None,
    ) -> dict[str, Any]:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
            # DKG >= 10.0.19 requires HMAC-signed requests on protected routes
            # (older daemons ignore the extra headers). See signed_request_headers.
            headers.update(signed_request_headers(self.token, method, path, data))
        req = urllib.request.Request(f"{self.url}{path}", data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout or _TIMEOUT) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read(1024).decode("utf-8", errors="replace")
            raise DkgError(
                f"{method} {path} -> {exc.code}: {detail}",
                status_code=exc.code,
            ) from exc
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise DkgError(f"{method} {path} transport error: {exc}") from exc
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    # -- status ------------------------------------------------------------

    def status(self, timeout: Optional[float] = None) -> dict[str, Any]:
        """Return node status; raises :class:`DkgError` if unreachable.

        ``GET /api/status`` is the public (no-auth) liveness endpoint; older
        daemons are probed via ``/api/info`` as a fallback (``/api/health`` is
        not a DKG v10 route, so we don't probe it). Pass ``timeout`` for a fast
        liveness probe (e.g. the dashboard) so a dead node fails in a second or
        two rather than the default read timeout.
        """
        for route in ("/api/status", "/api/info"):
            try:
                return self.request("GET", route, timeout=timeout)
            except DkgError:
                continue
        raise DkgError("node unreachable on /api/status, /api/info")

    def agent_identity(self) -> dict[str, Any]:
        """Resolve the calling token to its agent identity.

        ``GET /api/agent/identity`` → ``{agentAddress, agentDid, name, ...}`` —
        the definitive way to learn which agent the node sees us as.
        """
        return self.request("GET", "/api/agent/identity")

    def reachable(self, timeout: Optional[float] = None) -> bool:
        try:
            self.status(timeout=timeout)
            return True
        except DkgError:
            return False

    # -- context graph -----------------------------------------------------

    def connect_peer(self, peer_id: str) -> dict[str, Any]:
        """Ask DKG to resolve and connect to one graph source peer."""
        return self.request(
            "POST", "/api/connect", {"peerId": peer_id}, timeout=15.0
        )

    def connect_multiaddr(self, multiaddr: str) -> dict[str, Any]:
        """Connect through one explicit address when cold DHT lookup is pending."""
        return self.request(
            "POST", "/api/connect", {"multiaddr": multiaddr}, timeout=15.0
        )

    def subscribe_context_graph(self, cg_id: str, *, include_shared_memory: bool = True,
                                force_catchup: bool = False) -> dict[str, Any]:
        """Subscribe the node to a context graph and catch up its VM and shared memory.

        A fresh install that only set ``context_graph_id`` never subscribes the
        daemon, so its store stays empty. Shared memory is included because the
        community's reports live there (one graph, 2026-10-16); a node subscribed
        without it gets a catch-up job that adds it, an already-ready one a no-op
        unless *force_catchup* (which also fetches a graph definition that never came).
        """
        body = {"contextGraphId": cg_id, "includeSharedMemory": include_shared_memory}
        if force_catchup:
            body["forceCatchup"] = True
        return self.request("POST", "/api/context-graph/subscribe", body, timeout=_STORE_TIMEOUT)

    def unsubscribe_context_graph(self, cg_id: str) -> dict[str, Any]:
        """Drop live gossip/sync scope without deleting local VM/SWM data."""
        return self.request(
            "POST",
            "/api/context-graph/unsubscribe",
            {"contextGraphId": cg_id},
            timeout=_STORE_TIMEOUT,
        )

    def restart_context_graph_catchup(
        self,
        cg_id: str,
        *,
        include_shared_memory: bool = True,
    ) -> dict[str, Any]:
        """Force a fresh official catch-up without deleting local graph data."""
        self.unsubscribe_context_graph(cg_id)
        return self.subscribe_context_graph(
            cg_id,
            include_shared_memory=include_shared_memory,
        )

    def catchup_status(
        self,
        cg_id: str,
        *,
        job_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Return an asynchronous catch-up job for ``cg_id``.

        The daemon applies a recovered graph snapshot atomically, so consumers
        cannot count partial rows while it is running.  This status lets UI
        callers distinguish that active transfer from a genuinely empty graph.
        Once subscribe returns a job id, pass it here so a concurrent newer job
        cannot replace the status being awaited.
        """
        if job_id:
            query = f"jobId={urllib.parse.quote(job_id, safe='')}"
        else:
            query = f"contextGraphId={urllib.parse.quote(cg_id, safe='')}"
        return self.request(
            "GET",
            f"/api/sync/catchup-status?{query}",
        )

    def context_graphs(self) -> list[dict[str, Any]]:
        """Return the daemon's native context-graph registry projection."""
        result = self.request(
            "GET",
            "/api/context-graph/list",
            timeout=_STORE_TIMEOUT,
        )
        rows = result.get("contextGraphs") if isinstance(result, dict) else None
        return [row for row in (rows or []) if isinstance(row, dict)]

    def catchup_from_peer(
        self,
        cg_id: str,
        peer_id: str,
        *,
        budget_ms: int = 300_000,
    ) -> dict[str, Any]:
        """Recover the graph's durable VM from one configured source peer.

        DKG's route retains its historical ``shared-memory`` name, but the flags
        below skip SWM: the shared memory comes with the subscription. Pinning the
        source avoids a generic peer returning a partial or stale graph. A successful
        already-current recovery legitimately inserts zero triples.
        """
        bounded_budget = max(1_000, min(300_000, int(budget_ms)))
        return self.request(
            "POST",
            "/api/shared-memory/catchup",
            {
                "contextGraphId": cg_id,
                "peerId": peer_id,
                "includeSharedMemory": False,
                "includeDurable": True,
                "hostCatchupFallback": False,
                "perPeerDurableBudgetMs": bounded_budget,
            },
            # The budget bounds network fetching, not exact-graph verification
            # and atomic store materialization. Large fresh-node batches can
            # spend many minutes settling after the fetch deadline, and the
            # route deliberately waits for that work before responding.
            timeout=max(
                (bounded_budget / 1_000) + 45,
                constants.GRAPH_SYNC_SETTLEMENT_TIMEOUT_S,
            ),
        )

    def context_graph_participants(self, cg_id: str) -> dict[str, Any]:
        encoded = urllib.parse.quote(cg_id, safe="")
        return self.request(
            "GET",
            f"/api/context-graph/{encoded}/participants",
        )

    def context_graph_has_agent(self, cg_id: str, agent_address: str) -> bool:
        if not agent_address:
            return False
        result = self.context_graph_participants(cg_id)
        allowed = result.get("allowedAgents") if isinstance(result, dict) else None
        if not isinstance(allowed, list):
            return False
        expected = agent_address.lower()
        return any(str(address).lower() == expected for address in allowed)

    def publish_agent_profile(self) -> dict[str, Any]:
        """Publish this node's default agent profile and encryption keys."""
        return self.request(
            "POST",
            "/api/agent/publish-profile",
            {},
            timeout=_STORE_TIMEOUT,
        )

    def request_join(self, cg_id: str, graph_peer_id: str,
                     agent_name: str = "agent-blackbox") -> dict[str, Any]:
        """Sign a join request and forward it to the graph's bootstrap peer.

        Publish the default profile first so the curator has the requester's
        workspace encryption key before it admits the node, then perform the
        signed join flow. Profile publication is best-effort for compatibility
        with older daemons that do not expose the endpoint; the curator keeps
        such requests pending instead of admitting a member that would break
        SWM encryption. Idempotent: a repeat request or an already-member is a
        no-op. Returns the request-join result (``delivered`` count /
        ``alreadyMember``).
        """
        try:
            self.publish_agent_profile()
        except DkgError as exc:
            logger.warning("Could not publish DKG agent profile before join: %s", exc)
        enc = urllib.parse.quote(cg_id, safe="")
        signed = self.request("POST", f"/api/context-graph/{enc}/sign-join", {}, timeout=_STORE_TIMEOUT)
        delegation = signed.get("delegation") if isinstance(signed, dict) else None
        if not delegation:
            raise DkgError("sign-join returned no delegation")
        return self.request("POST", f"/api/context-graph/{enc}/request-join",
                             {"delegation": delegation, "curatorPeerId": graph_peer_id,
                              "agentName": agent_name}, timeout=_STORE_TIMEOUT)

    # -- knowledge assets --------------------------------------------------

    def share_knowledge_asset(self, cg_id: str, name: str, quads: list[Quad],
                              create_timeout: Optional[float] = None) -> dict[str, Any]:   # community statements only
        """Create/finalize a KA, then explicitly share its sealed assertion to SWM.

        Private/agent-gated context graphs require the node's sender-key SWM
        envelope. DKG's old one-shot ``alsoShareSwm:true`` path can leave assets
        without a usable share intent, so Blackbox uses the explicit v10
        lifecycle: write/seal to WM, then enqueue ``/swm/share-async`` and poll
        the share job.

        Idempotent: threat/report KA names are deterministic (``sha256`` of the
        threat identifier), so re-sharing the same threat is expected. The node
        rejects re-finalizing an existing sealed assertion; we then share the
        already-sealed assertion instead of treating the whole operation as done.
        """
        _validate_quads_literal_sizes(quads)
        try:
            self.request(
                "POST",
                "/api/knowledge-assets",
                {"contextGraphId": cg_id, "name": name, "quads": quads, "alsoShareSwm": False,
                 "subGraphName": constants.COMMUNITY_SUB_GRAPH},
                timeout=create_timeout or _STORE_TIMEOUT,
            )
        except DkgError as exc:
            if not (_is_already_finalized(exc) or _is_wm_merkle_conflict(exc)):
                raise
        return self.share_finalized_knowledge_asset(cg_id, name, constants.COMMUNITY_SUB_GRAPH)

    def _ka_path(self, name: str, suffix: str = "") -> str:
        enc = urllib.parse.quote(name, safe="")
        return f"/api/knowledge-assets/{enc}{suffix}"

    def pull_knowledge_asset_from(
        self,
        cg_id: str,
        name: str,
        layer: str = "swm",
        *,
        on_conflict: Optional[str] = None,
        sub_graph: str = "",
    ) -> dict[str, Any]:
        """Pull the latest KA assertion from another layer into local WM (of *sub_graph*, "" = root).

        Used to repair stale local finalized state before re-sharing old assets.
        """
        body: dict[str, Any] = {"contextGraphId": cg_id, "layer": layer, **({"subGraphName": sub_graph} if sub_graph else {})}
        if on_conflict:
            body["onConflict"] = on_conflict
        return self.request("POST", self._ka_path(name, "/wm/pull-from"), body, timeout=_STORE_TIMEOUT)

    def share_async(self, cg_id: str, name: str, sub_graph: str = "") -> dict[str, Any]:
        """Queue an async SWM share job for an already-finalized WM KA (in *sub_graph*; "" = root)."""
        body = {"contextGraphId": cg_id, "entities": "all", **({"subGraphName": sub_graph} if sub_graph else {})}
        try:
            return self.request("POST", self._ka_path(name, "/swm/share-async"), body, timeout=_STORE_TIMEOUT)
        except DkgError as exc:
            job_id = _job_id_from_error(exc)
            if job_id:
                return {"jobId": job_id, "state": "existing"}
            raise

    def share_job(self, job_id: str) -> dict[str, Any]:
        """Fetch one async SWM share job by id."""
        enc = urllib.parse.quote(job_id, safe="")
        return self.request("GET", f"/api/knowledge-assets/swm/share-jobs/{enc}", timeout=_STORE_TIMEOUT)

    @staticmethod
    def _share_job_id(result: dict[str, Any]) -> Optional[str]:
        if not isinstance(result, dict):
            return None
        job = result.get("job") if isinstance(result.get("job"), dict) else result
        for key in ("jobId", "id", "job_id", "shareJobId", "existingJobId"):
            value = job.get(key)
            if value:
                return str(value)
        return None

    def wait_for_share_job(
        self,
        job_id: str,
        *,
        timeout_s: float = 600.0,
        poll_s: float = 5.0,
    ) -> dict[str, Any]:
        """Poll an async SWM share job until it succeeds or fails."""
        deadline = time.monotonic() + max(1.0, float(timeout_s))
        last_state = "unknown"
        last_job: dict[str, Any] = {}
        while True:
            job = self.share_job(job_id)
            last_job = job if isinstance(job, dict) else {}
            last_state = str(
                last_job.get("state") or last_job.get("status") or last_job.get("phase") or "unknown"
            ).lower()
            if last_state in {"succeeded", "success", "completed", "complete"}:
                return last_job
            if last_state in {"failed", "error", "cancelled", "canceled"}:
                detail = json.dumps(last_job, sort_keys=True)[:1000]
                raise DkgError(f"SWM share job {job_id} failed: {detail}")
            if time.monotonic() >= deadline:
                detail = json.dumps(last_job, sort_keys=True)[:1000]
                raise DkgError(
                    f"SWM share job {job_id} timed out after {int(timeout_s)}s "
                    f"(last state={last_state}, job={detail})"
                )
            time.sleep(max(1.0, float(poll_s)))

    def share_async_and_wait(
        self,
        cg_id: str,
        name: str,
        *,
        timeout_s: float = 600.0,
        poll_s: float = 5.0,
        sub_graph: str = "",
    ) -> dict[str, Any]:
        """Queue async SWM share (into *sub_graph*; "" = root) and poll the job to completion."""
        result = self.share_async(cg_id, name, sub_graph)
        job_id = self._share_job_id(result)
        if not job_id:
            return result
        return self.wait_for_share_job(job_id, timeout_s=timeout_s, poll_s=poll_s)

    def share_finalized_knowledge_asset(self, cg_id: str, name: str, sub_graph: str = "") -> dict[str, Any]:
        """Share an already-finalized WM KA to SWM via async job polling. *sub_graph*
        "" is the root (the verified-graph publish path); community statements pass
        ``constants.COMMUNITY_SUB_GRAPH``."""
        try:
            return self.share_async_and_wait(cg_id, name, sub_graph=sub_graph)
        except DkgError as exc:
            if _is_already_finalized(exc):
                return {"name": name, "idempotent": True}
            if _is_wm_merkle_conflict(exc):
                self.pull_knowledge_asset_from(cg_id, name, "swm", on_conflict="replace", sub_graph=sub_graph)
                return self.share_async_and_wait(cg_id, name, sub_graph=sub_graph)
            raise

    def write_private_knowledge_asset(self, cg_id: str, name: str, quads: list[Quad]) -> dict[str, Any]:
        """Create+write+seal a KA in WM WITHOUT sharing to SWM (private audit)."""
        _validate_quads_literal_sizes(quads)
        return self.request(
            "POST",
            "/api/knowledge-assets",
            {"contextGraphId": cg_id, "name": name, "quads": quads, "alsoShareSwm": False},
            timeout=_STORE_TIMEOUT,
        )

    # -- query -------------------------------------------------------------

    def query(
        self,
        sparql: str,
        cg_id: str,
        view: Optional[str] = constants.VIEW_VERIFIABLE_MEMORY,
        on_error: Any = None,
        agent_address: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> list[dict[str, Any]]:
        """Run a SPARQL SELECT and return normalized bindings.

        Each binding is a ``{var: value}`` dict of plain strings (literals and
        IRIs already unwrapped — see :func:`extract_binding`). On transport
        error or an unrecognized reply it returns *on_error* (default ``[]``),
        since read paths fail open. A caller that must tell a genuine *empty*
        result (``[]``) apart from a *failure* passes a unique sentinel.
        """
        payload = {"sparql": sparql, "contextGraphId": cg_id}
        if view:
            payload["view"] = view
        if view == constants.VIEW_SHARED_WORKING_MEMORY:   # community statements live in their subgraph
            payload["subGraphName"] = constants.COMMUNITY_SUB_GRAPH
        if agent_address:
            payload["agentAddress"] = agent_address
        try:
            result = self.request(
                "POST",
                "/api/query",
                payload,
                timeout=timeout or _QUERY_TIMEOUT,
            )
        except DkgError as exc:
            logger.debug("blackbox: query failed: %s", exc)
            result = None  # a failure, reported like a malformed reply
        return rows_or_fallback(result, on_error)

    def threat_count(self, cg_id: str) -> int:
        """Return the locally verified Blackbox threat count with one query.

        The public VM contains both the original Defender signal entities and
        newer compact ``SourceObservation`` feed records. Counting only the
        former made successful clients look stuck at the historical watermark.
        """
        sparql = """PREFIX defender: <urn:defender:>
SELECT (COUNT(DISTINCT ?threat) AS ?n) WHERE {
  ?threat a ?type .
  VALUES ?type {
    defender:DependencySignal
    defender:InjectionSignal
    defender:SkillSignal
    defender:IocSignal
    <urn:blackbox:SourceObservation>
  }
}"""
        rows = self.query(
            sparql,
            cg_id,
            view=constants.VIEW_VERIFIABLE_MEMORY,
            on_error=[],
        )
        if not rows:
            return 0
        try:
            return int(extract_binding(rows[0].get("n")) or 0)
        except (TypeError, ValueError):
            return 0

    def register_agent(self, name: str, framework: str = "hermes") -> dict[str, Any]:
        """Register a new agent on the node → ``{agentAddress, authToken, ...}``."""
        return self.request("POST", "/api/agent/register", {"name": name, "framework": framework})
