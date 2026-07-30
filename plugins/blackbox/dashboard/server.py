"""Standalone Blackbox dashboard — a tiny FastAPI app bound to loopback.

Routes:

* ``GET /``                 → the single-page ``static/index.html``.
* ``GET /fonts/{name}``     → allowlisted, self-hosted brand fonts.
* ``GET /api/findings``     → findings.jsonl, newest-first, paged.
* ``GET /api/graph-status`` → curated threat counts + last sync + ruleset counts.
* ``GET /api/reports``      → recent outbound sightings from the community graph.
* ``GET /api/agents``       → distinct threat reporters + this node's own agent.
* ``GET /api/graph``        → threat entities from the VM, SWM, or WM view.

FastAPI/uvicorn come from the hermes ``[web]`` extra, imported lazily. Loopback only.
"""

from __future__ import annotations

import logging
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

from .. import sync_state
from ..dkg_progress import read_durable_progress

logger = logging.getLogger(__name__)

_RESCAN_INTERVAL_SEC = 5.0
_RECONCILE_INTERVAL_SEC = 60.0
_RULESET_EMPTY_RETRY_SEC = 10.0
_RULESET_MIN_RETRY_SEC = 5.0
# A complete VM refresh pages through every curated rule. On a large graph it
# can take several minutes and saturate Blazegraph, so never repeat it on the
# dashboard's short status-poll interval. Manual sync remains available.
_RULESET_HEAVY_REFRESH_MIN_SEC = 15 * 60.0
_BLACKBOX_READY_PERCENT = 80.0
_BLACKBOX_MIN_OVERDUE_SEC = 10 * 60.0
_BLACKBOX_STALLED_SYNC_SEC = 10 * 60.0
_BLACKBOX_PROFILE = "agent-blackbox"
_BLACKBOX_RUNTIME_HOST = "127.0.0.1"
_BLACKBOX_RUNTIME_PORT = 9121
_BLACKBOX_RESTART_DELAY_SEC = 2.0
_join_lock = threading.Lock()
_network_sync_lock = threading.Lock()
_connection_states: Dict[str, Dict[str, Any]] = {}

_STATIC_DIR = Path(__file__).resolve().parent / "static"
_ASSETS_DIR = Path(__file__).resolve().parent / "assets"
_FONTS_DIR = _ASSETS_DIR / "fonts"
def _dkg_durable_progress(dkg_home: str, context_graph_id: str) -> Dict[str, Any]:
    """Read the latest resumable VM offset reported by the managed DKG."""
    return read_durable_progress(dkg_home, context_graph_id)


def _blackbox_runtime_argv(port: int = _BLACKBOX_RUNTIME_PORT) -> List[str]:
    """Command for the dashboard-owned, profile-isolated Agent Blackbox backend."""
    return [
        sys.executable,
        "-m",
        "hermes_cli.main",
        "--profile",
        _BLACKBOX_PROFILE,
        "serve",
        "--host",
        _BLACKBOX_RUNTIME_HOST,
        "--port",
        str(int(port)),
        "--isolated",
    ]


def _blackbox_runtime_env() -> Dict[str, str]:
    """Build a clean named-profile environment without changing the parent."""
    env = dict(os.environ)
    # The explicit --profile selector must win even when Blackbox itself was
    # launched from another Hermes profile.
    env.pop("HERMES_HOME", None)
    return env


def _port_is_listening(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=0.2):
            return True
    except OSError:
        return False


def _recent_daemon_lines(dkg_home: str, *, max_lines: int = 400) -> List[str]:
    path = Path(dkg_home).expanduser() / "daemon.log"
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return list(deque(handle, maxlen=max_lines))
    except Exception:
        return []


def _daemon_connection_hint(dkg_home: str, cg_id: str) -> Dict[str, str]:
    """Infer the freshest actionable join/sync blocker from daemon.log."""
    if not dkg_home or not cg_id:
        return {}
    for raw in reversed(_recent_daemon_lines(dkg_home)):
        line = raw.strip()
        if cg_id not in line:
            continue
        lowered = line.lower()
        if (
            "auto-approval deferred" in lowered
            and "workspace encryption profile is not available yet" in lowered
        ):
            return {
                "state": "pending-encryption-profile",
                "error": "workspace encryption profile is not available yet",
                "evidence": line,
            }
        if "denied sync request" in lowered and "malformed or mismatched envelope" in lowered:
            return {
                "state": "sync-envelope-error",
                "error": "peer sent a malformed or mismatched sync envelope",
                "evidence": line,
            }
        if "stored pending join request" in lowered:
            return {
                "state": "pending-approval",
                "error": "curator approval is still pending",
                "evidence": line,
            }
    return {}


def _ruleset_total(rs: Any) -> int:
    try:
        return sum(int(v) for v in rs.counts().values())
    except Exception:
        return 0


def _graph_source_count(rs: Any, source: str) -> int:
    counter = getattr(rs, "graph_count", None)
    if callable(counter):
        return int(counter(source) or 0)
    return int(rs.source_count(source) or 0)


def _graph_entries(rs: Any, source: str) -> List[Dict[str, Any]]:
    getter = getattr(rs, "graph_entries", None)
    if callable(getter):
        entries = getter(source) or []
        return entries if isinstance(entries, list) else list(entries)
    return [
        {
            "identifier": rule.get("identifier"),
            "category": category,
            "severity": str(rule.get("severity") or "info").lower(),
            "name": rule.get("name") or "",
            "subject": rule.get("subject") or "",
            "source": source,
        }
        for category, rule in rs.iter_rules()
        if rule.get("source") == source
    ]


def _balanced_graph_entries(
    entries: List[Dict[str, Any]], minimum_per_category: int = 24
) -> List[Dict[str, Any]]:
    """Front-load a small sample of every populated threat category."""
    category_order = (
        "dependency", "injection", "escalation", "fileaccess",
        "skill", "secret", "ioc", "other",
    )
    buckets: Dict[str, List[Dict[str, Any]]] = {key: [] for key in category_order}
    for entry in entries:
        key = str(entry.get("category") or "other").lower()
        buckets.setdefault(key, []).append(entry)

    front: List[Dict[str, Any]] = []
    skipped: Dict[str, int] = {}
    ordered_keys = category_order + tuple(k for k in buckets if k not in category_order)
    for key in ordered_keys:
        skipped[key] = min(len(buckets.get(key, [])), minimum_per_category)
    for index in range(minimum_per_category):
        for key in ordered_keys:
            bucket = buckets.get(key, [])
            if index < len(bucket):
                front.append(bucket[index])

    rest: List[Dict[str, Any]] = []
    consumed: Dict[str, int] = {}
    for entry in entries:
        key = str(entry.get("category") or "other").lower()
        used = consumed.get(key, 0)
        if used < skipped.get(key, 0):
            consumed[key] = used + 1
            continue
        rest.append(entry)
    return front + rest


def _ruleset_sync_counts(rs: Any) -> Dict[str, int]:
    public = _graph_source_count(rs, "public")
    return {
        "total": max(_ruleset_total(rs), public),
        "public": public,
        "community": 0,
    }


def _network_sync_argv(timeout: int = 3600) -> List[str]:
    """Run the canonical verified graph sync in an isolated process."""
    return [
        sys.executable,
        "-m",
        "hermes_cli.main",
        "blackbox",
        "sync",
        "--wait",
        "--timeout",
        str(max(1, int(timeout))),
        "--require-rules",
    ]


def _network_sync_once(
    load_config: Any,
    ruleset_mod: Any,
    *,
    timeout: int = 3600,
) -> Dict[str, Any]:
    """Fetch and verify the latest VM snapshot, once per dashboard process.

    The CLI owns the complete curator-pinned recovery protocol and publishes
    progress through ``sync_state``. Running it in a subprocess keeps a long
    network transfer isolated from the dashboard server while its status
    remains visible to every dashboard poll.
    """
    if not _network_sync_lock.acquire(blocking=False):
        cfg = load_config()
        return {"ok": True, "busy": True, **_ruleset_sync_counts(ruleset_mod.peek(cfg))}
    try:
        completed = subprocess.run(
            _network_sync_argv(timeout),
            capture_output=True,
            text=True,
            timeout=max(30, int(timeout) + 30),
            check=False,
        )
        output = "\n".join(
            part.strip() for part in (completed.stdout, completed.stderr) if part.strip()
        )
        if completed.returncode != 0:
            logger.warning(
                "blackbox automatic graph sync exited %d: %s",
                completed.returncode,
                output[-2000:] or "no output",
            )
        else:
            logger.info("blackbox automatic graph sync completed")
        cfg = load_config()
        counts = _ruleset_sync_counts(ruleset_mod.peek(cfg))
        return {
            "ok": completed.returncode == 0,
            "busy": False,
            "returncode": completed.returncode,
            **counts,
        }
    except subprocess.TimeoutExpired:
        logger.warning("blackbox automatic graph sync exceeded %ds", int(timeout))
        cfg = load_config()
        return {
            "ok": False,
            "busy": False,
            "error": "automatic graph sync timed out",
            **_ruleset_sync_counts(ruleset_mod.peek(cfg)),
        }
    finally:
        _network_sync_lock.release()


def _sync_ruleset_once(load_config: Any, dkg_client_cls: Any, ruleset_mod: Any) -> Dict[str, int]:
    """Ensure one public-graph subscription and refresh curated VM rules."""
    cfg = load_config()
    transfer = sync_state.read_for_graph(cfg.context_graph_id)
    if transfer.get("status") == "running":
        # A replacement snapshot is staged atomically. Keep serving the last
        # verified cache while it is received instead of replacing the UI and
        # enforcement rules with the transfer's initial zero-progress count.
        peek = getattr(ruleset_mod, "peek", None)
        if callable(peek):
            cached_counts = _ruleset_sync_counts(peek(cfg))
            if cached_counts["public"]:
                verified = max(
                    cached_counts["public"],
                    int(transfer.get("public_entries") or 0),
                )
                cached_counts["total"] += verified - cached_counts["public"]
                cached_counts["public"] = verified
                return cached_counts
        public = int(transfer.get("public_entries") or 0)
        return {"total": public, "public": public, "community": 0}
    client = dkg_client_cls(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
    try:
        catchup = client.catchup_status(cfg.context_graph_id)
    except Exception:
        catchup = {}
    catchup_state = str(catchup.get("status") or "").lower()
    catchup_job_id = str(
        catchup.get("jobId") or catchup.get("job_id") or catchup.get("id") or ""
    )
    if catchup_state in {"queued", "running"}:
        with _join_lock:
            _connection_states[cfg.context_graph_id] = {
                "state": "syncing",
                "updated_at": time.time(),
            }
    if catchup_state in {"queued", "running"}:
        # A catch-up applies complete durable snapshots atomically. Querying
        # the VM while Blazegraph is ingesting millions of triples only adds
        # store contention and cannot reveal useful partial rules. Serve the
        # last-good cache until DKG reports a terminal state.
        peek = getattr(ruleset_mod, "peek", None)
        rs = peek(cfg) if callable(peek) else ruleset_mod.refresh(cfg, client)
        return _ruleset_sync_counts(rs)
    peek = getattr(ruleset_mod, "peek", None)
    if callable(peek):
        cached = peek(cfg)
        counts = _ruleset_sync_counts(cached)
        synced_at = float(getattr(cached, "synced_at", 0.0) or 0.0)
        configured_interval = float(getattr(cfg, "sync_interval", 0.0) or 0.0)
        refresh_interval = max(_RULESET_HEAVY_REFRESH_MIN_SEC, configured_interval)
        if counts["public"] and time.time() - synced_at < refresh_interval:
            with _join_lock:
                _connection_states[cfg.context_graph_id] = {
                    "state": "subscribed",
                    "updated_at": time.time(),
                }
            return counts
    rs = ruleset_mod.refresh(cfg, client)
    counts = _ruleset_sync_counts(rs)
    if counts["public"]:
        with _join_lock:
            _connection_states[cfg.context_graph_id] = {
                "state": "subscribed",
                "updated_at": time.time(),
            }
    return counts


def _graph_sync_state(
    count: int,
    node_reachable: bool,
    catchup_status: str,
    *,
    settled: bool = False,
) -> str:
    """Map queryable rows + DKG recovery state to an honest UI state."""
    if settled:
        # An authoritative snapshot can legitimately settle a tier at zero.
        return "ready"
    if node_reachable and str(catchup_status or "").lower() in {"queued", "running"}:
        return "syncing"
    if str(catchup_status or "").lower() in {
        "failed",
        "cancelled",
        "denied",
        "unreachable",
        "deferred",
    }:
        return "incomplete"
    if int(count or 0) > 0:
        return "ready"
    if not node_reachable:
        return "unreachable"
    return "empty"


def _is_hidden_swm_catchup_error(value: Any) -> bool:
    """Temporarily suppress the known DKG SWM catch-up UI failure."""
    text = str(value or "").lower()
    return "/api/shared-memory/catchup" in text and (
        "transport error" in text or "timed out" in text or "timeout" in text
    )


def _sync_activity(
    *,
    public: int,
    community: int,
    node_reachable: bool,
    catchup: Dict[str, Any],
    connection: Dict[str, Any],
    transfer: Dict[str, Any],
) -> Dict[str, Any]:
    catchup_status = str(catchup.get("status") or "").lower()
    connection_state = str(connection.get("state") or "").lower()
    transfer_status = str(transfer.get("status") or "").lower()
    phase = str(transfer.get("phase") or "").lower()
    current = int(transfer.get("public_entries") or public or 0)
    expected = int(transfer.get("expected_public_entries") or 0)
    current_triples = int(transfer.get("current_triples") or 0)
    expected_triples = int(transfer.get("expected_triples") or 0)
    progress: Dict[str, Any] = {
        "status": "idle",
        "phase": "idle",
        "label": "Waiting for graph sync",
        "detail": "No graph transfer is active.",
        "started_at": None,
        "updated_at": connection.get("updated_at"),
        "current": None,
        "expected": None,
        "percent": None,
        "indeterminate": True,
    }

    if transfer_status == "running":
        labels = {
            "recovering-verifiable-memory": "Receiving publisher VM",
            "waiting-for-verifiable-memory": "Verifying publisher VM",
            "refreshing-verifiable-memory": "Refreshing verified threats",
            "reconciling-public-memory": "Indexing verified public threats",
        }
        progress.update(
            status="running",
            phase=phase or "authoritative-catchup",
            label=labels.get(phase, "Syncing threat graph"),
            started_at=transfer.get("started_at"),
            updated_at=transfer.get("updated_at"),
        )
        if expected_triples > 0:
            bounded_triples = max(0, min(current_triples, expected_triples))
            if phase == "refreshing-verifiable-memory":
                progress.update(
                    label="Indexing verified threats",
                    detail=(
                        "The snapshot is verified and stored. Blackbox is "
                        "rebuilding the local enforcement ruleset."
                    ),
                    current=expected_triples,
                    expected=expected_triples,
                    percent=None,
                    indeterminate=True,
                )
                return progress
            if bounded_triples >= expected_triples:
                # The durable log reaches the manifest boundary before the
                # request's verification/store tail returns. A plain 100% bar
                # falsely communicates product readiness during that tail.
                progress.update(
                    label="Finalizing verified snapshot",
                    detail=(
                        f"All {expected_triples:,} graph triples were received. "
                        "DKG is verifying and storing the final snapshot."
                    ),
                    current=expected_triples,
                    expected=expected_triples,
                    percent=None,
                    indeterminate=True,
                )
                return progress
            progress.update(
                detail=(
                    f"{bounded_triples:,} of {expected_triples:,} graph triples "
                    "received for verification."
                ),
                current=bounded_triples,
                expected=expected_triples,
                percent=round((bounded_triples / expected_triples) * 100, 1),
                indeterminate=False,
            )
        elif phase in {"reconciling-public-memory", "refreshing-verifiable-memory", "waiting-for-verifiable-memory"} and expected > 0:
            bounded = max(0, min(current, expected))
            progress.update(
                detail=f"{bounded:,} of {expected:,} verified public threats are queryable.",
                current=bounded,
                expected=expected,
                percent=round((bounded / expected) * 100, 1),
                indeterminate=False,
            )
        else:
            progress["detail"] = "The DKG node is receiving and verifying an atomic snapshot."
        return progress

    pending_labels = {
        "joining": (
            "Joining private graph",
            "The signed membership request is being delivered to the curator.",
        ),
        "pending-approval": (
            "Waiting for curator approval",
            "The node will start graph catch-up automatically after approval.",
        ),
        "pending-encryption-profile": (
            "Preparing private graph encryption",
            "The curator is preparing the workspace encryption profile needed for sync.",
        ),
    }
    if connection_state in pending_labels:
        label, detail = pending_labels[connection_state]
        progress.update(
            status="waiting",
            phase=connection_state,
            label=label,
            detail=detail,
            started_at=connection.get("updated_at"),
            updated_at=connection.get("updated_at"),
        )
        return progress

    catchup_result = catchup.get("result") if isinstance(catchup.get("result"), dict) else {}
    error = str(
        transfer.get("error")
        or connection.get("error")
        or catchup.get("error")
        or catchup_result.get("error")
        or ""
    )

    # The source-pinned transfer is the authoritative result for this graph.
    # A generic catch-up job may still retain an older failure after that
    # transfer completed successfully; do not turn verified local data into a
    # false dashboard error. A genuinely new queued/running job remains
    # visible below.
    if transfer_status == "done" and catchup_status not in {"queued", "running"}:
        progress.update(
            status="ready",
            phase=phase or "complete",
            label="Threat graphs are ready",
            detail=f"{public:,} public and {community:,} community threats are queryable.",
            started_at=transfer.get("started_at"),
            updated_at=transfer.get("updated_at") or connection.get("updated_at"),
            current=public,
            expected=int(transfer.get("expected_public_entries") or public or 0),
            percent=100.0,
            indeterminate=False,
        )
        return progress

    # DKG currently reports an SWM catch-up transport failure even while the
    # independently verified VM remains usable. Do not cover that ready graph
    # with a false failure banner; keep unrelated VM and node errors visible.
    if _is_hidden_swm_catchup_error(error):
        if public > 0:
            progress.update(
                status="ready",
                phase="verifiable-memory-ready",
                label="Verified threat graph is ready",
                detail=f"{public:,} verified public threats are queryable.",
                updated_at=transfer.get("updated_at") or connection.get("updated_at"),
                current=public,
                expected=public,
                percent=100.0,
                indeterminate=False,
            )
        return progress

    if (
        transfer_status == "failed"
        or catchup_status in {"failed", "cancelled", "denied"}
        or connection_state in {"connection-error", "sync-envelope-error"}
    ):
        progress.update(
            status="failed",
            phase=phase or catchup_status or connection_state or "failed",
            label="Graph sync needs attention",
            detail=error or "The last graph sync did not complete.",
            started_at=transfer.get("started_at") or catchup.get("startedAt"),
            updated_at=transfer.get("updated_at") or catchup.get("finishedAt"),
        )
        return progress

    if not node_reachable:
        progress.update(
            status="offline",
            phase="node-unreachable",
            label="DKG node is offline",
            detail="Graph sync will resume when this Blackbox node is reachable.",
        )
        return progress

    if catchup_status in {"queued", "running"} or connection_state == "syncing":
        queued = catchup_status == "queued"
        progress.update(
            status="running",
            phase="queued" if queued else "network-catchup",
            label="Graph catch-up queued" if queued else "Fetching graph snapshot",
            detail=(
                "Waiting for a sync-capable DKG peer."
                if queued
                else "Receiving verified graph data from available DKG peers."
            ),
            started_at=catchup.get("startedAt") or connection.get("updated_at"),
            updated_at=connection.get("updated_at") or catchup.get("startedAt"),
        )
        return progress

    if public > 0 or community > 0:
        progress.update(
            status="ready",
            phase="complete",
            label="Threat graphs are ready",
            detail=f"{public:,} public and {community:,} community threats are queryable.",
            updated_at=transfer.get("updated_at") or connection.get("updated_at"),
            indeterminate=False,
        )
    else:
        progress.update(
            status="waiting",
            phase="waiting-for-data",
            label="Waiting for threat data",
            detail="The DKG node is online and will retry graph catch-up automatically.",
        )
    return progress


def _blackbox_sync_health(
    *,
    public: int,
    sync_interval: Any,
    activity: Dict[str, Any],
    transfer: Dict[str, Any],
    node_reachable: bool = True,
    now: Any = None,
) -> Dict[str, Any]:
    """Describe whether Agent Blackbox needs a graph update.

    The DKG has no lightweight remote threat-count endpoint, so an idle node
    cannot honestly claim an exact percentage of the curator graph. During a
    transfer we can use the verified snapshot manifest progress; while idle we
    use the authoritative cross-process result and its age.
    """
    current_time = float(time.time() if now is None else now)
    interval = max(1.0, float(sync_interval or 1.0))
    overdue_after = max(_BLACKBOX_MIN_OVERDUE_SEC, interval * 2.0)
    activity_status = str(activity.get("status") or "idle").lower()
    transfer_status = str(transfer.get("status") or "").lower()
    raw_percent = activity.get("percent")
    try:
        percent = float(raw_percent) if raw_percent is not None else None
    except (TypeError, ValueError):
        percent = None

    base: Dict[str, Any] = {
        "out_of_sync": False,
        "state": "ready",
        "reason": "fresh",
        "protection_available": int(public or 0) > 0,
        "coverage_percent": percent,
        "ready_percent": _BLACKBOX_READY_PERCENT,
        "overdue_after_seconds": int(overdue_after),
        "stalled_after_seconds": int(_BLACKBOX_STALLED_SYNC_SEC),
        "last_success_at": (
            transfer.get("updated_at") if transfer_status == "done" else None
        ),
    }

    if not node_reachable:
        return {
            **base,
            "out_of_sync": int(public or 0) <= 0,
            "state": "node-offline",
            "reason": "local-node-offline",
        }

    if activity_status in {"running", "waiting"}:
        updated_at = activity.get("updated_at") or transfer.get("updated_at")
        try:
            stalled = (
                updated_at is not None
                and current_time - float(updated_at) > _BLACKBOX_STALLED_SYNC_SEC
            )
        except (TypeError, ValueError):
            stalled = False
        if stalled:
            below_threshold = percent is not None and percent < _BLACKBOX_READY_PERCENT
            return {
                **base,
                "out_of_sync": bool(below_threshold or int(public or 0) <= 0),
                "state": "sync-stalled",
                "reason": "sync-stalled",
            }
        below_threshold = percent is not None and percent < _BLACKBOX_READY_PERCENT
        no_protection_yet = int(public or 0) <= 0
        return {
            **base,
            "out_of_sync": bool(below_threshold or no_protection_yet),
            "state": "updating",
            "reason": "sync-progress",
        }

    if int(public or 0) <= 0:
        return {
            **base,
            "out_of_sync": True,
            "state": "needs-update",
            "reason": "no-local-threats",
        }

    if transfer_status == "failed" or activity_status == "failed":
        return {
            **base,
            # Keep the failure in status metadata, but do not show a prominent
            # warning while the last verified graph still protects the agent.
            "out_of_sync": False,
            "state": "update-failed",
            "reason": "last-sync-failed",
        }

    last_success = base["last_success_at"]
    if last_success is not None:
        try:
            age = max(0.0, current_time - float(last_success))
        except (TypeError, ValueError):
            age = 0.0
        if age > overdue_after:
            return {
                **base,
                # Staleness remains observable without alarming users while a
                # usable verified graph is still loaded.
                "out_of_sync": False,
                "state": "overdue",
                "reason": "last-success-overdue",
            }

    return base


def _workspace_key(value: Any) -> str:
    """Normalize a local profile path for stable cross-log matching."""
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return os.path.normcase(os.path.realpath(os.path.expanduser(text)))
    except Exception:
        return os.path.normcase(text)


def _profile_activity_state(
    attach_rows: List[Dict[str, Any]],
    audit_rows: List[Dict[str, Any]],
    finding_rows: List[Dict[str, Any]],
) -> Dict[Tuple[str, str], Dict[str, Any]]:
    """Aggregate local activity and findings by framework *and* workspace.

    Older rows predate workspace attribution. They are assigned exactly once
    to the first (canonical/default) protected workspace for that framework,
    rather than copied onto every attached profile.
    """
    states: Dict[Tuple[str, str], Dict[str, Any]] = {}
    canonical: Dict[str, Tuple[str, str]] = {}
    for row in attach_rows:
        if not row.get("target") or not row.get("protected", row.get("already")):
            continue
        framework = str(row.get("kind") or "").lower()
        workspace = _workspace_key(row.get("target"))
        if not framework or not workspace:
            continue
        key = (framework, workspace)
        states.setdefault(key, {"is_active": False, "findings": 0})
        canonical.setdefault(framework, key)

    legacy_active: Set[str] = set()
    legacy_findings: Dict[str, int] = {}

    def _identity(row: Dict[str, Any]) -> Tuple[str, str]:
        detail = row.get("detail") if isinstance(row.get("detail"), dict) else {}
        finding = row.get("finding") if isinstance(row.get("finding"), dict) else {}
        framework = str(
            row.get("framework") or finding.get("framework") or "hermes"
        ).lower()
        workspace = _workspace_key(
            row.get("workspace") or finding.get("workspace") or detail.get("workspace")
        )
        return framework, workspace

    for row in audit_rows:
        framework, workspace = _identity(row)
        key = (framework, workspace)
        if workspace and key in states:
            states[key]["is_active"] = True
        elif not workspace and framework in canonical:
            legacy_active.add(framework)

    for row in finding_rows:
        framework, workspace = _identity(row)
        key = (framework, workspace)
        if workspace and key in states:
            states[key]["is_active"] = True
            states[key]["findings"] += 1
        elif not workspace and framework in canonical:
            legacy_active.add(framework)
            legacy_findings[framework] = legacy_findings.get(framework, 0) + 1

    for framework, key in canonical.items():
        if framework in legacy_active:
            states[key]["is_active"] = True
        states[key]["findings"] += legacy_findings.get(framework, 0)
    return states


def create_app(*, manage_blackbox: bool = False):
    """Build and return the FastAPI application."""
    from fastapi import Body, FastAPI, Query
    from fastapi.responses import FileResponse, JSONResponse, HTMLResponse

    from .. import attach, audit, constants, ruleset, settings, sync_state
    from ..config import load_blackbox_config
    from ..dkg_client import DkgClient, extract_binding

    app = FastAPI(title="Agent Blackbox", docs_url=None, redoc_url=None)

    _rescan_state: Dict[str, Any] = {
        "stop": False,
        "known": set(),
        "last_reconcile": 0.0,
        "lock": threading.Lock(),
    }
    _blackbox_stop = threading.Event()
    _blackbox_state: Dict[str, Any] = {
        "process": None,
        "thread": None,
        "ready": False,
        "error": "",
        "lock": threading.Lock(),
    }

    def _blackbox_profile_dir() -> Path:
        from hermes_cli.profiles import get_profile_dir

        return get_profile_dir(_BLACKBOX_PROFILE)

    def _set_blackbox_state(**updates: Any) -> None:
        with _blackbox_state["lock"]:
            _blackbox_state.update(updates)

    def _blackbox_snapshot() -> Dict[str, Any]:
        with _blackbox_state["lock"]:
            process = _blackbox_state.get("process")
            return {
                "managed": bool(manage_blackbox),
                "ready": bool(_blackbox_state.get("ready")),
                "error": str(_blackbox_state.get("error") or ""),
                "pid": process.pid if process is not None and process.poll() is None else None,
                "profile": _BLACKBOX_PROFILE,
                "host": _BLACKBOX_RUNTIME_HOST,
                "port": _BLACKBOX_RUNTIME_PORT,
            }

    def _blackbox_runtime_loop() -> None:
        """Keep one dashboard-owned Agent Blackbox backend alive, fail-open.

        This supervisor only terminates the exact ``Popen`` child it created.
        An occupied port is treated as a conflict; it never searches for or
        stops an unrelated process.
        """
        profile_dir = _blackbox_profile_dir()
        if not profile_dir.is_dir():
            _set_blackbox_state(error="Agent Blackbox profile is not installed")
            logger.warning("agent blackbox runtime: profile not found at %s", profile_dir)
            return
        log_dir = profile_dir / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / "blackbox-dashboard-runtime.log"

        while not _blackbox_stop.is_set():
            if _port_is_listening(_BLACKBOX_RUNTIME_HOST, _BLACKBOX_RUNTIME_PORT):
                _set_blackbox_state(
                    ready=False,
                    error=f"Port {_BLACKBOX_RUNTIME_PORT} is already in use",
                )
                logger.warning(
                    "agent blackbox runtime: port %d is occupied; leaving its process untouched",
                    _BLACKBOX_RUNTIME_PORT,
                )
                _blackbox_stop.wait(_BLACKBOX_RESTART_DELAY_SEC)
                continue

            process = None
            try:
                with log_path.open("a", encoding="utf-8") as log_handle:
                    process = subprocess.Popen(
                        _blackbox_runtime_argv(),
                        cwd=str(attach._repo_root()),
                        env=_blackbox_runtime_env(),
                        stdin=subprocess.DEVNULL,
                        stdout=log_handle,
                        stderr=subprocess.STDOUT,
                    )
                    _set_blackbox_state(process=process, ready=False, error="")
                    logger.info(
                        "agent blackbox runtime: started pid %d on %s:%d",
                        process.pid,
                        _BLACKBOX_RUNTIME_HOST,
                        _BLACKBOX_RUNTIME_PORT,
                    )

                    deadline = time.monotonic() + 30.0
                    while (
                        not _blackbox_stop.is_set()
                        and process.poll() is None
                        and time.monotonic() < deadline
                    ):
                        if _port_is_listening(_BLACKBOX_RUNTIME_HOST, _BLACKBOX_RUNTIME_PORT):
                            _set_blackbox_state(ready=True, error="")
                            break
                        _blackbox_stop.wait(0.2)
                    else:
                        if process.poll() is None and not _blackbox_stop.is_set():
                            _set_blackbox_state(error="Agent Blackbox runtime did not become ready")

                    while not _blackbox_stop.is_set() and process.poll() is None:
                        _blackbox_stop.wait(0.5)
            except Exception as exc:  # pragma: no cover - fail open
                _set_blackbox_state(ready=False, error=str(exc))
                logger.warning("agent blackbox runtime: failed to start: %s", exc)
            finally:
                if process is not None and process.poll() is None and _blackbox_stop.is_set():
                    # Only the child created above is in scope for shutdown.
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=2)
                exit_code = process.poll() if process is not None else None
                _set_blackbox_state(process=None, ready=False)
                if process is not None and not _blackbox_stop.is_set():
                    _set_blackbox_state(error=f"Agent Blackbox runtime exited with code {exit_code}")
                    logger.warning(
                        "agent blackbox runtime: pid %d exited with code %s; restarting",
                        process.pid,
                        exit_code,
                    )
            if not _blackbox_stop.is_set():
                _blackbox_stop.wait(_BLACKBOX_RESTART_DELAY_SEC)

    def _rescan_once(*, force: bool = False) -> List[Dict[str, Any]]:
        """Discover local Hermes/OpenClaw workspaces and hook Blackbox into them.

        ``force`` re-attaches every discovered workspace — an idempotent
        self-heal used by the manual refresh, so a freshly installed or upgraded
        agent is (re-)protected at once. Otherwise only newly appeared
        workspaces are attached: the cheap diff the background loop runs every
        few seconds. Returns the attach-result row for each workspace it touched.
        Serialized so the loop and a manual refresh never write one config at the
        same time. Fail-open per target."""
        with _rescan_state["lock"]:
            current: Set[Tuple[str, str]] = set()
            for h in attach.discover_hermes_homes():
                current.add(("hermes", str(h)))
            for w in attach.discover_openclaw_workspaces():
                current.add(("openclaw", str(w)))
            known: Set[Tuple[str, str]] = _rescan_state["known"]
            removed = known - current
            touched: List[Dict[str, Any]] = []
            now = time.monotonic()
            reconcile = force or now - float(_rescan_state["last_reconcile"] or 0.0) >= _RECONCILE_INTERVAL_SEC
            targets = current if reconcile else current - known
            if reconcile:
                _rescan_state["last_reconcile"] = now
            for kind, target in sorted(targets):
                try:
                    if kind == "hermes":
                        row = attach.attach_hermes(Path(target))
                    else:
                        row = attach.attach_openclaw(Path(target))
                    touched.append(row)
                    if row.get("error"):
                        logger.warning("blackbox rescan: attach %s %s failed: %s", kind, target, row["error"])
                    elif not row.get("already"):
                        logger.info("blackbox rescan: auto-attached %s at %s", kind, target)
                except Exception as exc:  # pragma: no cover - fail open
                    logger.debug("blackbox rescan: attach %s %s raised: %s", kind, target, exc)
            for kind, target in removed:
                logger.info("blackbox rescan: %s workspace vanished at %s", kind, target)
            _rescan_state["known"] = current
            return touched

    def _rescan_loop() -> None:
        """Every ``_RESCAN_INTERVAL_SEC`` seconds, attach any newly appeared
        Hermes/OpenClaw workspace and log ones that vanished."""
        while not _rescan_state["stop"]:
            try:
                _rescan_once()
            except Exception as exc:  # pragma: no cover - fail open
                logger.debug("blackbox rescan: iteration failed: %s", exc)
            for _ in range(int(_RESCAN_INTERVAL_SEC * 10)):
                if _rescan_state["stop"]:
                    return
                time.sleep(0.1)

    def _ruleset_sync_loop() -> None:
        """Keep verified VM threat rows network-synced while the dashboard runs.

        ``sync_interval`` is a period, not a post-sync sleep: the sync's own
        duration is deducted from the wait so a refresh *starts* every
        ``sync_interval`` seconds even when the sync itself is slow."""
        last_total: Any = None
        # The installer performs an authoritative catch-up before it starts the
        # dashboard. Waiting one configured period avoids immediately repeating
        # that expensive transfer and keeps short-lived test/app probes inert.
        initial_interval = max(
            _RULESET_MIN_RETRY_SEC,
            float(load_blackbox_config().sync_interval or _RULESET_EMPTY_RETRY_SEC),
        )
        for _ in range(int(initial_interval * 10)):
            if _rescan_state["stop"]:
                return
            time.sleep(0.1)
        while not _rescan_state["stop"]:
            wait = _RULESET_EMPTY_RETRY_SEC
            started = time.monotonic()
            try:
                cfg = load_blackbox_config()
                result = _network_sync_once(lambda: cfg, ruleset)
                counts = result
                total = int(counts.get("total") or 0)
                public = int(counts.get("public") or 0)
                community = int(counts.get("community") or 0)
                elapsed = time.monotonic() - started
                wait = max(
                    _RULESET_MIN_RETRY_SEC,
                    float(cfg.sync_interval or _RULESET_EMPTY_RETRY_SEC) - elapsed,
                )
                if public == 0:
                    wait = min(_RULESET_EMPTY_RETRY_SEC, wait)
                if total != last_total:
                    logger.info(
                        "blackbox automatic graph sync: %d rule(s), %d public, %d community; next sync in %.0fs",
                        total,
                        public,
                        community,
                        wait,
                    )
                    last_total = total
                else:
                    logger.debug(
                        "blackbox automatic graph sync: %d rule(s), %d public, %d community; next sync in %.0fs",
                        total,
                        public,
                        community,
                        wait,
                    )
            except Exception as exc:  # pragma: no cover - fail open
                logger.debug("blackbox automatic graph sync: iteration failed: %s", exc)
                wait = _RULESET_EMPTY_RETRY_SEC
            for _ in range(int(wait * 10)):
                if _rescan_state["stop"]:
                    return
                time.sleep(0.1)

    @app.on_event("startup")
    def _start_rescanner() -> None:
        # Do NOT pre-seed ``known``: attach is idempotent, so the first
        # iteration walks every workspace and self-heals anything the
        # CLI-level attach missed.
        t = threading.Thread(target=_rescan_loop, name="blackbox-rescan", daemon=True)
        t.start()
        logger.info("blackbox rescan: background thread started (interval %.1fs)", _RESCAN_INTERVAL_SEC)
        threading.Thread(target=_ruleset_sync_loop, name="blackbox-ruleset-sync", daemon=True).start()
        logger.info("blackbox automatic graph sync: background thread started")
        if manage_blackbox:
            blackbox_thread = threading.Thread(
                target=_blackbox_runtime_loop,
                name="agent-blackbox-runtime",
                daemon=True,
            )
            _set_blackbox_state(thread=blackbox_thread)
            blackbox_thread.start()
            logger.info("agent blackbox runtime: supervisor started")

    @app.on_event("shutdown")
    def _stop_rescanner() -> None:
        _rescan_state["stop"] = True
        _blackbox_stop.set()
        with _blackbox_state["lock"]:
            blackbox_process = _blackbox_state.get("process")
            blackbox_thread = _blackbox_state.get("thread")
        if blackbox_process is not None and blackbox_process.poll() is None:
            # Wake the supervisor immediately; it still owns final reap/kill.
            blackbox_process.terminate()
        if blackbox_thread is not None:
            blackbox_thread.join(timeout=6)

    _PREFIX = "PREFIX g: <http://umanitek.ai/ontology/guardian/> "

    def _count_query(client: "DkgClient", cfg: Any, where: str, view: str) -> int:
        """Run a single-``?n``-binding COUNT query; 0 on any failure (fail-open)."""
        try:
            rows = client.query(_PREFIX + where, cfg.context_graph_id, view=view)
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("blackbox dashboard: count query failed: %s", exc)
            return 0
        if not rows:
            return 0
        try:
            return int(extract_binding(rows[0].get("n")) or "0")
        except (TypeError, ValueError):
            return 0

    # ---- non-blocking node reads -------------------------------------------
    # Node-backed reads are served stale-while-revalidate: the handler returns
    # the last good value instantly while a background thread recomputes it, and
    # every node call is gated on a cached liveness probe. A slow or dead node
    # never makes a poll wait. TTLs are generous: the poll serves from cache, so
    # the node is queried at most once per TTL per key, and graph data changes
    # slowly enough that ~20s of staleness is invisible.
    _SWR_TTL = 20.0         # refresh a cached node read at most this often
    _REACH_TTL = 15.0       # re-probe node liveness at most this often
    # Per-route liveness timeout; /api/status can take a couple seconds under
    # load, and a probe that's too tight would wrongly report a busy node as down.
    _REACH_TIMEOUT = 5.0
    _swr_lock = threading.Lock()
    _swr_state: Dict[str, Dict[str, Any]] = {}   # key -> {"val", "ts"}
    _swr_busy: Set[str] = set()
    _reach: Dict[str, Any] = {"ok": False, "ts": -1e9, "busy": False}

    def _node_reachable(cfg: Any) -> bool:
        """Cached DKG node liveness, refreshed off the request path.

        Returns the last probe result immediately (``False`` until the first
        lands) and spawns a background re-probe past ``_REACH_TTL``. Never
        blocks the caller, so gating a node query on this is free."""
        now = time.monotonic()
        with _swr_lock:
            stale = (now - _reach["ts"]) >= _REACH_TTL
            spawn = stale and not _reach["busy"]
            if spawn:
                _reach["busy"] = True
            cur = bool(_reach["ok"])
        if spawn:
            def _probe() -> None:
                ok = False
                try:
                    ok = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home).reachable(timeout=_REACH_TIMEOUT)
                except Exception:  # pragma: no cover - fail open
                    ok = False
                with _swr_lock:
                    _reach["ok"] = ok
                    _reach["ts"] = time.monotonic()
                    _reach["busy"] = False
            threading.Thread(target=_probe, name="blackbox-reach", daemon=True).start()
        return cur

    def _swr(key: str, producer: Any, default: Any, ttl: float = _SWR_TTL) -> Any:
        """Return the cached value for ``key`` instantly, refreshing in the
        background past ``ttl``; ``default`` until the first refresh lands.
        ``producer`` runs off the request path, so it may block on the node."""
        now = time.monotonic()
        with _swr_lock:
            entry = _swr_state.get(key)
            fresh = entry is not None and (now - entry["ts"]) < ttl
            cur = entry["val"] if entry is not None else default
            spawn = (not fresh) and (key not in _swr_busy)
            if spawn:
                _swr_busy.add(key)
        if spawn:
            def _run() -> None:
                try:
                    val = producer()
                except Exception as exc:  # pragma: no cover - fail open
                    logger.debug("blackbox dashboard: swr %s failed: %s", key, exc)
                    val = None
                with _swr_lock:
                    if val is not None:
                        _swr_state[key] = {"val": val, "ts": time.monotonic()}
                    _swr_busy.discard(key)
            threading.Thread(target=_run, name="blackbox-swr", daemon=True).start()
        return cur

    @app.get("/", response_class=HTMLResponse)
    def index() -> Any:
        html = _STATIC_DIR / "index.html"
        if html.exists():
            # Never cache the SPA shell; always fetch the current dashboard.
            return FileResponse(str(html), headers={"Cache-Control": "no-cache, no-store, must-revalidate"})
        return HTMLResponse("<h1>Blackbox</h1><p>dashboard assets missing</p>", status_code=200)

    @app.get("/assets/{name}")
    def asset(name: str) -> Any:
        # Serve only the two known-safe brand SVGs (no path traversal).
        allowed = {"blackbox-logo.svg", "umanitek-icon.svg"}
        if name not in allowed:
            return JSONResponse({"error": "not found"}, status_code=404)
        path = _ASSETS_DIR / name
        if not path.exists():
            return JSONResponse({"error": "not found"}, status_code=404)
        return FileResponse(str(path), media_type="image/svg+xml")

    @app.get("/fonts/{name}")
    def font(name: str) -> Any:
        # Exact allowlist keeps this static route traversal-safe and limits the
        # dashboard to the licensed brand faces shipped by this plugin.
        allowed = {
            "archivo-latin.woff2",
            "archivo-latin-ext.woff2",
            "ibm-plex-mono-400-latin.woff2",
            "ibm-plex-mono-400-latin-ext.woff2",
            "ibm-plex-mono-500-latin.woff2",
            "ibm-plex-mono-500-latin-ext.woff2",
            "ibm-plex-mono-600-latin.woff2",
            "ibm-plex-mono-600-latin-ext.woff2",
        }
        if name not in allowed:
            return JSONResponse({"error": "not found"}, status_code=404)
        path = _FONTS_DIR / name
        if not path.exists():
            return JSONResponse({"error": "not found"}, status_code=404)
        return FileResponse(
            str(path),
            media_type="font/woff2",
            headers={"Cache-Control": "public, max-age=31536000, immutable"},
        )

    @app.get("/vendor/{name}")
    def vendor(name: str) -> Any:
        # Serve only the vendored force-graph bundle (allowlist, no traversal).
        allowed = {"force-graph.min.js"}
        if name not in allowed:
            return JSONResponse({"error": "not found"}, status_code=404)
        path = _STATIC_DIR / "vendor" / name
        if not path.exists():
            return JSONResponse({"error": "not found"}, status_code=404)
        return FileResponse(str(path), media_type="application/javascript")

    @app.get("/api/settings")
    def get_settings() -> Any:
        """Current user-tunable detection policy (defaults included)."""
        try:
            return settings.read_settings()
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("blackbox dashboard: read settings failed: %s", exc)
            return JSONResponse({"error": "could not read settings"}, status_code=500)

    @app.post("/api/settings")
    def post_settings(payload: Dict[str, Any] = Body(...)) -> Any:
        """Validate + persist detection policy under plugins.entries.blackbox.*.

        Loopback-only; writes are validated server-side in :mod:`settings` so a
        malformed body can't corrupt config.
        """
        try:
            result = settings.write_settings(payload)
            return JSONResponse(result, status_code=200 if result.get("ok") else 400)
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("blackbox dashboard: write settings failed: %s", exc)
            return JSONResponse({"ok": False, "errors": ["internal error"]}, status_code=500)

    def _clean_chat_output(text: str) -> str:
        lines: List[str] = []
        for line in (text or "").splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("session_id:"):
                continue
            if "Context file AGENTS.md TRUNCATED" in stripped:
                continue
            lines.append(line.rstrip())
        return "\n".join(lines).strip()

    def _parse_chat_session_id(text: str) -> Optional[str]:
        for line in (text or "").splitlines():
            stripped = line.strip()
            if stripped.startswith("session_id:"):
                return stripped.split(":", 1)[1].strip() or None
        return None

    @app.post("/api/blackbox-chat")
    def blackbox_chat(payload: Dict[str, Any] = Body(...)) -> Any:
        """Run one scoped Blackbox assistant turn through the managed profile."""
        message = str((payload or {}).get("message") or "").strip()
        if not message:
            return JSONResponse({"ok": False, "error": "Message is required."}, status_code=400)
        if len(message) > 4000:
            return JSONResponse({"ok": False, "error": "Message is too long."}, status_code=400)
        session_id = str((payload or {}).get("session_id") or "").strip()
        hermes = shutil.which("hermes") or os.environ.get("HERMES_BIN") or "hermes"
        argv = [hermes, "blackbox", "chat", "--query", message, "--quiet", "--pass-session-id"]
        if session_id:
            argv.extend(["--resume", session_id])
        try:
            proc = subprocess.run(
                argv,
                cwd=str(attach._repo_root()),
                text=True,
                capture_output=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            return JSONResponse({"ok": False, "error": "Blackbox took too long to answer."}, status_code=504)
        except Exception as exc:
            logger.debug("blackbox dashboard: chat failed: %s", exc)
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)
        next_session_id = _parse_chat_session_id(proc.stderr) or _parse_chat_session_id(proc.stdout) or session_id
        answer = _clean_chat_output(proc.stdout)
        err = _clean_chat_output(proc.stderr)
        if proc.returncode != 0:
            return JSONResponse(
                {"ok": False, "error": err or answer or "Blackbox chat failed.", "session_id": next_session_id},
                status_code=500,
            )
        return {"ok": True, "answer": answer or "(no response)", "session_id": next_session_id}

    @app.get("/api/findings")
    def findings(limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)) -> Any:
        items = audit.read_findings(limit=limit, offset=offset)
        return {
            "mode": load_blackbox_config().mode,
            "findings": items,
            "total": audit.count_findings(),
        }

    @app.get("/api/audit")
    def audit_events(limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)) -> Any:
        """Full agent-activity trail: session lifecycle + API + tool-call events."""
        items = audit.read_audit(limit=limit, offset=offset)
        return {
            "mode": load_blackbox_config().mode,
            "entries": items,
            "total": audit.count_audit(),
        }

    @app.get("/api/local-activity")
    def local_activity(sessions: int = Query(60, ge=1, le=200)) -> Any:
        """Local threat activity as sessions -> tool calls -> threats.

        Reconstructed from this machine's event logs, never the DKG node.
        """
        data = audit.read_local_activity(max_sessions=sessions)
        return {"mode": load_blackbox_config().mode, **data}

    @app.get("/api/graph-status")
    def graph_status() -> Any:
        cfg = load_blackbox_config()
        rs = ruleset.peek(cfg)
        counts = rs.counts()
        # Community + sightings come from the synced ruleset cache, NOT the
        # shared-working-memory view, which does O(slice) trust work and times
        # out (HTTP 500) on a large pool. Public uses the cache too: current VM
        # rows are complete threats, and ruleset.refresh also promotes any
        # still-unmigrated legacy proof rows.
        public = _graph_source_count(rs, "public")
        community = 0

        # Catch-up state must stay independent from the potentially expensive
        # SWM sightings COUNT. Otherwise a busy store can hide the live
        # queued/running state (and therefore the dashboard loader) for minutes.
        def _node_sync() -> Any:
            if not _node_reachable(cfg):
                return None
            client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
            try:
                catchup = client.catchup_status(cfg.context_graph_id)
            except Exception:
                # No job is normal on an already-settled node.
                catchup = {}
            return {
                "node_reachable": True,
                "catchup": catchup,
            }

        g = _swr(
            "graph-sync-status",
            _node_sync,
            {"node_reachable": False, "catchup": {}},
            ttl=4.0,
        )
        sightings = 0
        total_rules = sum(int(v or 0) for v in counts.values())
        catchup = g.get("catchup") if isinstance(g.get("catchup"), dict) else {}
        node_catchup_state = str(catchup.get("status") or "")
        catchup_result = catchup.get("result") if isinstance(catchup.get("result"), dict) else {}
        catchup_error = catchup.get("error") or catchup_result.get("error") or ""
        public_catchup_state = (
            "" if _is_hidden_swm_catchup_error(catchup_error) else node_catchup_state
        )
        catchup_state = node_catchup_state
        authoritative_sync = sync_state.read_for_graph(cfg.context_graph_id)
        authoritative_running = authoritative_sync.get("status") == "running"
        authoritative_done = authoritative_sync.get("status") == "done"
        if authoritative_running:
            authoritative_sync = {
                **authoritative_sync,
                **_dkg_durable_progress(cfg.dkg_home, cfg.context_graph_id),
            }
        # This count is measured from locally committed rows and can advance
        # ahead of the materialized ruleset cache during a large snapshot.
        if authoritative_running:
            try:
                public = max(public, int(authoritative_sync.get("public_entries") or 0))
            except (TypeError, ValueError):
                pass
        if authoritative_running:
            # The curator-pinned durable transfer is intentionally separate
            # from DKG's generic catch-up job. Keep the loader honest while a
            # partial but usable VM snapshot is being expanded in the
            # background.
            catchup_state = "running"
        elif authoritative_done and node_catchup_state.lower() not in {"queued", "running"}:
            # The curator transfer records both tiers, including a legitimate
            # zero-entry SWM.  Prefer that completed result over a stale generic
            # catch-up probe/connection hint.
            catchup_state = "done"
        public_state = (
            "syncing"
            if authoritative_running
            else _graph_sync_state(
                public,
                g["node_reachable"],
                public_catchup_state,
                settled=(
                    authoritative_done
                    and public
                    >= int(authoritative_sync.get("expected_public_entries") or public or 0)
                ),
            )
        )
        community_state = "coming-soon"
        with _join_lock:
            connection = dict(_connection_states.get(cfg.context_graph_id) or {})
        if connection.get("state") in {"pending-approval", "pending-encryption-profile", "joining"}:
            if not public:
                public_state = connection["state"]
        activity = _sync_activity(
            public=public,
            community=community,
            node_reachable=bool(g["node_reachable"]),
            catchup=catchup,
            connection=connection,
            transfer=authoritative_sync,
        )
        blackbox_health = _blackbox_sync_health(
            public=public,
            sync_interval=cfg.sync_interval,
            activity=activity,
            transfer=authoritative_sync,
            node_reachable=bool(g["node_reachable"]),
        )
        if activity["status"] in {"running", "waiting"}:
            if public_state == "empty":
                public_state = "syncing"

        def _sync_label(tier: str, state: str) -> str:
            suffix = {
                "ready": "synced",
                "syncing": "syncing",
                "unreachable": "offline",
                "empty": "empty",
                "incomplete": "incomplete",
                "pending-approval": "curator approval pending",
                "pending-encryption-profile": "waiting for workspace encryption profile",
                "joining": "joining private graph",
                "coming-soon": "coming soon",
                "sync-envelope-error": "peer sync handshake malformed",
            }.get(state, state)
            return f"{tier} {suffix}"
        return {
            "mode": cfg.mode,
            "context_graph_id": cfg.context_graph_id,
            "dkg_url": cfg.dkg_url,
            "dkg_home": cfg.dkg_home,
            "dkg_bin": cfg.dkg_bin,
            "node_reachable": g["node_reachable"],
            "sync_interval": cfg.sync_interval,
            "last_sync": rs.synced_at or None,
            "ruleset": counts,
            "curated": public,
            "community": community,
            "sightings": sightings,
            "findings_logged": audit.count_findings(),
            "connection": connection,
            "sync_progress": {
                "public": {
                    "count": int(public or 0),
                    "state": public_state,
                    "label": _sync_label("VM", public_state),
                },
                "community": {
                    "count": int(community or 0),
                    "state": community_state,
                    "label": "Community graph coming soon",
                },
                "catchup": {
                    "status": catchup_state or "idle",
                    "started_at": (
                        authoritative_sync.get("started_at")
                        if authoritative_sync.get("status") == "running"
                        else catchup.get("startedAt")
                    ),
                    "finished_at": catchup.get("finishedAt"),
                },
                "authoritative": authoritative_sync,
                "activity": activity,
                "blackbox": blackbox_health,
                "ruleset_total": total_rules,
                "age_seconds": max(0, int(time.time() - float(rs.synced_at or 0))) if rs.synced_at else None,
            },
        }

    @app.get("/api/agents")
    def agents() -> Any:
        """Local protected agents + distinct threat reporters in SWM.

        A "protected agent" is any framework that has written findings into this
        shared blackbox home. Each is shown separately even when several share
        one node wallet, so a Hermes and an OpenClaw on one machine are two
        agents. Fail-open.
        """
        cfg = load_blackbox_config()
        # Keyed by (framework, lowercased-address) so the same wallet under two
        # frameworks shows as two agents, and the same wallet+framework folds.
        found: "Dict[tuple, Dict[str, Any]]" = {}

        # This node's wallet, shared by every local framework. Live node call,
        # so served through the SWR cache.
        def _load_identity() -> Any:
            if not _node_reachable(cfg):
                return None   # retry next poll; don't cache a "down" as empty
            try:
                ident = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home).agent_identity() or {}
                return str(ident.get("agentAddress") or ident.get("agentDid") or "")
            except Exception as exc:  # pragma: no cover - fail open
                logger.debug("blackbox dashboard: agent identity failed: %s", exc)
                return None
        local_addr = _swr("agent-identity", _load_identity, "") or ""

        attach_state: Dict[str, List[Dict[str, Any]]] = {"hermes": [], "openclaw": []}
        try:
            attach_state = attach.attach_all(dry_run=True)
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("blackbox dashboard: attach-state enumeration failed: %s", exc)
        attach_rows = attach_state.get("hermes", []) + attach_state.get("openclaw", [])
        known_local_fw = {
            str(row.get("kind") or "").lower()
            for row in attach_rows
            if row.get("target")
        }
        protected_local_fw = {
            str(row.get("kind") or "").lower()
            for row in attach_rows
            if row.get("target") and row.get("protected", row.get("already"))
        }

        # Read local evidence once, then split it by framework + workspace.
        # Legacy rows without a workspace are attributed once to the default
        # protected profile by _profile_activity_state.
        try:
            local_fw = audit.local_active_frameworks()
        except Exception:  # pragma: no cover - fail open
            local_fw = []
        try:
            audit_rows = audit.read_audit(limit=1_000_000)
        except Exception:  # pragma: no cover - fail open
            audit_rows = []
        counts_by_fw: "Dict[str, int]" = {}
        try:
            finding_rows = audit.read_findings(limit=1_000_000)
            for row in finding_rows:
                fw = (row.get("framework") or "hermes").lower()
                counts_by_fw[fw] = counts_by_fw.get(fw, 0) + 1
        except Exception:  # pragma: no cover - fail open
            finding_rows = []
        profile_state = _profile_activity_state(attach_rows, audit_rows, finding_rows)
        blackbox_runtime = _blackbox_snapshot()
        blackbox_workspace = _workspace_key(_blackbox_profile_dir())
        blackbox_host_workspace = _workspace_key(constants.hermes_home())
        if blackbox_runtime["ready"]:
            blackbox_key = ("hermes", blackbox_workspace)
            if blackbox_key in profile_state:
                # The supervised backend is direct liveness evidence for this
                # exact profile even before its next audited chat turn.
                profile_state[blackbox_key]["is_active"] = True
        for fw in local_fw:
            if fw in known_local_fw and fw not in protected_local_fw:
                continue
            key = (fw, local_addr.lower())
            found[key] = {
                "framework": fw,
                "address": local_addr or fw,
                "reports": 0,
                "findings": counts_by_fw.get(fw, 0),
                "is_local": True,
                "is_active": True,
            }

        # Distinct threat reporters from the shared graph (may include remote
        # agents). Groups over the slow shared-working-memory view, so served
        # stale-while-revalidate; rows are cached raw and merged fresh below.
        def _load_reporters() -> Any:
            if not _node_reachable(cfg):
                return None   # keep default cached briefly; retry next poll
            try:
                client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
                sparql = (
                    "PREFIX g: <http://umanitek.ai/ontology/guardian/> "
                    "SELECT ?reporter ?framework (COUNT(?r) AS ?n) WHERE { "
                    "?r a g:ThreatReport . "
                    "OPTIONAL { ?r g:reporter ?reporter } "
                    "OPTIONAL { ?r g:framework ?framework } "
                    "} GROUP BY ?reporter ?framework"
                )
                rows = client.query(
                    sparql,
                    cfg.context_graph_id,
                    view=constants.VIEW_SHARED_WORKING_MEMORY,
                    on_error=None,
                )
                if rows is None:
                    return None
            except Exception as exc:  # pragma: no cover - fail open
                logger.debug("blackbox dashboard: agents query failed: %s", exc)
                return None  # transient failure — keep the last cached reporters
            reporters: List[Dict[str, Any]] = []
            for row in rows:
                addr = extract_binding(row.get("reporter"))
                if not addr:
                    continue
                fw = (extract_binding(row.get("framework")) or "").lower() or "unknown"
                try:
                    n = int(extract_binding(row.get("n")) or "0")
                except (TypeError, ValueError):
                    n = 0
                reporters.append({"framework": fw, "address": str(addr), "count": n})
            return reporters

        # Remote SWM reporters are not part of the VM-only release.
        for rep in []:
            fw, addr, n = rep["framework"], rep["address"], rep["count"]
            key = (fw, addr.lower())
            if key in found:
                found[key]["reports"] = max(found[key].get("reports", 0), n)
            else:
                found[key] = {"framework": fw, "address": addr, "reports": n}

        # Attached local workspaces — one card per protected workspace, so two
        # OpenClaw profiles on one node wallet render as two agents. Local-wallet
        # entries are absorbed here so the same framework doesn't render twice.
        try:
            attached = [
                (str(row.get("kind") or "").lower(), str(row.get("target") or ""))
                for row in attach_rows
                if row.get("protected", row.get("already")) and row.get("target")
            ]
            fw_with_ws = {fw for fw, _ in attached}
            local_addr_lc = local_addr.lower()
            for k in list(found.keys()):
                fw_k, addr_k = k
                if fw_k in fw_with_ws and addr_k == local_addr_lc:
                    found.pop(k, None)
            for fw, ws in attached:
                ws_name = Path(ws).name or ws
                state = profile_state.get(
                    (fw, _workspace_key(ws)), {"is_active": False, "findings": 0}
                )
                key = (fw, ws.lower())
                if key in found:
                    found[key]["workspace"] = ws
                    found[key]["workspace_label"] = ws_name
                    found[key]["is_active"] = bool(state["is_active"])
                    found[key]["findings"] = int(state["findings"])
                    found[key]["blackbox_host"] = (
                        fw == "hermes" and _workspace_key(ws) == blackbox_host_workspace
                    )
                    continue
                found[key] = {
                    "framework": fw,
                    "address": local_addr or fw,
                    "reports": 0,
                    "findings": int(state["findings"]),
                    "is_local": True,
                    # Protection/attachment is persistent configuration; only
                    # activity from this exact workspace marks it active.
                    "is_active": bool(state["is_active"]),
                    "workspace": ws,
                    "workspace_label": ws_name,
                    # The Hermes home that loaded Agent Blackbox gets a distinct
                    # UI identity; other local Hermes profiles remain separate.
                    "blackbox_host": fw == "hermes" and _workspace_key(ws) == blackbox_host_workspace,
                    "dashboard_managed": fw == "hermes" and _workspace_key(ws) == blackbox_workspace,
                }
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("blackbox dashboard: attached-workspace enumeration failed: %s", exc)

        agents_out = list(found.values())
        connected_count = sum(1 for row in agents_out if row.get("is_active"))
        protected_profile_count = sum(
            1
            for row in agents_out
            if row.get("is_local") and row.get("workspace") and not row.get("is_active")
        )
        return {
            "agents": agents_out,
            "connected_count": connected_count,
            "protected_profile_count": protected_profile_count,
            "blackbox_runtime": blackbox_runtime,
        }

    @app.get("/api/attach-targets")
    def attach_targets() -> Any:
        """Discover local agent configs the dashboard can attach Blackbox to."""
        targets: List[Dict[str, Any]] = []
        returned: Set[str] = set()
        supported = {
            "hermes": "Hermes was not detected on this machine.",
            "openclaw": "OpenClaw was not detected on this machine. Start OpenClaw once so its openclaw.json workspace can be discovered.",
        }

        def _add_rows(kind: str, rows: Any) -> None:
            if not isinstance(rows, list):
                return
            saw_row = False
            for row in rows:
                if not isinstance(row, dict):
                    continue
                saw_row = True
                row["protected"] = bool(row.get("protected", row.get("already")))
                row["available"] = bool(row.get("target")) and not row.get("error")
                if not row["available"]:
                    row["disabled_reason"] = str(row.get("error") or supported[kind])
                targets.append(row)
            if saw_row:
                returned.add(kind)

        try:
            _add_rows("hermes", attach.attach_all(openclaw=False, dry_run=True).get("hermes", []))
            _add_rows("openclaw", attach.attach_all(hermes=False, dry_run=True).get("openclaw", []))
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("blackbox dashboard: attach target discovery failed: %s", exc)
        for kind, reason in supported.items():
            if kind not in returned:
                targets.append({
                    "kind": kind,
                    "target": "",
                    "protected": False,
                    "available": False,
                    "disabled_reason": reason,
                })
        return {"targets": targets}

    @app.post("/api/attach")
    def attach_selected(payload: Dict[str, Any] = Body(...)) -> Any:
        """Attach Blackbox to selected local targets."""
        rows: List[Dict[str, Any]] = []
        for item in payload.get("targets") or []:
            if not isinstance(item, dict):
                continue
            kind = str(item.get("kind") or "").lower()
            target = str(item.get("target") or "").strip()
            if not target:
                continue
            if kind == "hermes":
                rows.append(attach.attach_hermes(Path(target)))
            elif kind == "openclaw":
                rows.append(attach.attach_openclaw(Path(target)))
        ok = all(row.get("ok") for row in rows) if rows else False
        return JSONResponse({"ok": ok, "targets": rows}, status_code=200 if ok else 400)

    @app.post("/api/agents/protection")
    def save_agent_protection(payload: Dict[str, Any] = Body(...)) -> Any:
        """Apply desired Blackbox protection state for selected local targets."""
        rows: List[Dict[str, Any]] = []
        for item in payload.get("targets") or []:
            if not isinstance(item, dict):
                continue
            kind = str(item.get("kind") or "").lower()
            target = str(item.get("target") or "").strip()
            enabled = bool(item.get("enabled"))
            if not target:
                continue
            if kind == "hermes":
                rows.append(attach.attach_hermes(Path(target)) if enabled else attach.detach_hermes(Path(target)))
            elif kind == "openclaw":
                rows.append(attach.attach_openclaw(Path(target)) if enabled else attach.detach_openclaw(Path(target)))
        ok = all(row.get("ok") for row in rows) if rows else False
        return JSONResponse({"ok": ok, "targets": rows}, status_code=200 if ok else 400)

    @app.post("/api/agents/rescan")
    def rescan_agents() -> Any:
        """Force an immediate re-hook + agent-detection sweep (the manual refresh).

        Re-attaches Blackbox to every local Hermes/OpenClaw workspace
        (idempotent), so a just-installed or upgraded agent is protected and
        shown without waiting for the background rescan loop. The frontend
        re-polls ``/api/agents`` afterwards to render any new cards. Fail-open:
        never 500s the dashboard."""
        try:
            touched = _rescan_once(force=True)
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("blackbox dashboard: manual rescan failed: %s", exc)
            return JSONResponse({"ok": False, "error": str(exc), "attached": 0, "newly_attached": 0})
        newly = sum(
            1 for row in touched
            if row.get("ok") and row.get("target") and not row.get("already") and not row.get("error")
        )
        return {"ok": True, "attached": len(touched), "newly_attached": newly}

    @app.post("/api/sync")
    def sync_graphs() -> Any:
        """Start the canonical verified network sync without blocking HTTP."""
        if _network_sync_lock.locked():
            return {"ok": True, "started": False, "busy": True}

        def _manual_sync() -> None:
            try:
                _network_sync_once(load_blackbox_config, ruleset)
            except Exception as exc:  # pragma: no cover - fail open
                logger.debug("blackbox dashboard: manual sync failed: %s", exc)

        threading.Thread(
            target=_manual_sync,
            name="blackbox-manual-network-sync",
            daemon=True,
        ).start()
        return {"ok": True, "started": True, "busy": False}

    def _tier_view(tier: str, default: str = "public") -> tuple:
        """Map a UI tier name to a DKG SPARQL view.

        ``public`` → verifiable-memory (the curated source of truth),
        ``community`` → coming soon (never queried),
        ``local`` → working-memory (this node's own private graph).
        """
        tier = (tier or default).lower()
        views = {
            "public": constants.VIEW_VERIFIABLE_MEMORY,
            "community": constants.VIEW_SHARED_WORKING_MEMORY,
            "local": constants.VIEW_WORKING_MEMORY,
        }
        if tier not in views:
            tier = default
        return tier, views[tier]

    @app.get("/api/graph")
    def graph(
        tier: str = Query("public"),
        limit: int = Query(5000, ge=1, le=50000),
        offset: int = Query(0, ge=0),
        q: str = Query("", max_length=200),
        category: str = Query("", max_length=40),
        ecosystem: str = Query("", max_length=80),
    ) -> Any:
        """Threats from one graph tier: ``public`` | ``community`` | ``local``."""
        tier, view = _tier_view(tier)
        if tier == "community":
            return {
                "tier": "community", "threats": [], "total": 0,
                "offset": offset, "limit": limit, "partial": False,
                "category_totals": {}, "ecosystem_totals": {},
                "coming_soon": True,
            }
        cfg = load_blackbox_config()

        def _category(identifier: str) -> str:
            ident = str(identifier or "")
            prefix = ident.split(":", 1)[0].lower() if ":" in ident else ""
            return {
                "dep": "dependency",
                "injection": "injection",
                "escalation": "escalation",
                "fileaccess": "fileaccess",
                "skill": "skill",
                "ioc": "ioc",
            }.get(prefix, "other")

        # The ruleset merges complete public VM threats with community SWM rows
        # and retains a compatibility join for any legacy CurationProof assets.
        if tier in {"public", "community"}:
            rs = ruleset.peek(cfg)
            all_threats = [
                {
                    "identifier": item.get("identifier"),
                    "category": item.get("category") or "other",
                    "severity": str(item.get("severity") or "info").lower(),
                    "name": item.get("name") or "",
                }
                for item in _graph_entries(rs, tier)
            ]
            needle = str(q or "").strip().casefold()
            wanted_category = str(category or "").strip().casefold()
            wanted_ecosystem = str(ecosystem or "").strip().casefold()
            if wanted_category:
                all_threats = [
                    item for item in all_threats
                    if str(item.get("category") or "other").casefold() == wanted_category
                ]
            if wanted_ecosystem:
                all_threats = [
                    item for item in all_threats
                    if (str(item.get("identifier") or "").split(":")[1:2] or [""])[0].casefold()
                    == wanted_ecosystem
                ]
            if needle:
                all_threats = [
                    item for item in all_threats
                    if needle in " ".join(
                        str(item.get(key) or "")
                        for key in ("identifier", "name", "category", "severity")
                    ).casefold()
                ]
            elif not wanted_category and not wanted_ecosystem:
                all_threats = _balanced_graph_entries(all_threats)
            # Counts describe the complete filtered result, never the rendered
            # page.  The dashboard can therefore show the real threat magnitude
            # on category/ecosystem hubs while progressively loading leaves.
            category_totals: Dict[str, int] = {}
            ecosystem_totals: Dict[str, int] = {}
            for item in all_threats:
                item_category = str(item.get("category") or "other").lower()
                category_totals[item_category] = category_totals.get(item_category, 0) + 1
                if item_category == "dependency":
                    parts = str(item.get("identifier") or "").split(":")
                    ecosystem_name = (parts[1] if len(parts) > 1 else "other").lower()
                    ecosystem_totals[ecosystem_name] = ecosystem_totals.get(ecosystem_name, 0) + 1
            return {
                "tier": tier,
                "threats": all_threats[offset:offset + limit],
                "total": len(all_threats),
                "category_totals": category_totals,
                "ecosystem_totals": ecosystem_totals,
                "offset": offset,
                "limit": limit,
                "partial": offset + limit < len(all_threats),
            }

        # The local tier reads the live working-memory view and is served
        # stale-while-revalidate.
        def _load() -> Any:
            if not _node_reachable(cfg):
                return None   # keep the default (empty) cached briefly; retry next poll
            seen: "Dict[str, Dict[str, Any]]" = {}
            try:
                client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
                identity = client.agent_identity()
                agent_address = str(identity.get("agentAddress") or "")
                rows = ruleset._fetch_tier(
                    client,
                    cfg.context_graph_id,
                    view,
                    agent_address=agent_address,
                ) or []
                local_rules = ruleset.build_from_rows(rows, source="local")
                for rule in local_rules.graph_entries("local"):
                    identifier = str(rule.get("identifier") or "")
                    if identifier and identifier not in seen:
                        seen[identifier] = {
                            "identifier": identifier,
                            "category": rule.get("category") or "other",
                            "severity": str(rule.get("severity") or "info").lower(),
                            "name": rule.get("name") or "",
                        }
            except Exception as exc:  # pragma: no cover - fail open
                logger.debug("blackbox dashboard: graph query failed: %s", exc)
            return {"tier": tier, "threats": list(seen.values())}

        return _swr("graph:" + tier, _load, {"tier": tier, "threats": []})

    @app.get("/api/reports")
    def reports(limit: int = Query(50, ge=1, le=200)) -> Any:
        return {"reports": [], "coming_soon": True, "sharing_enabled": False}

        # Community reports are deliberately not queried in the VM-only release.
        cfg = load_blackbox_config()

        # Node-backed sightings list, served stale-while-revalidate.
        def _load() -> Any:
            if not _node_reachable(cfg):
                return None   # keep the default (empty) cached briefly; retry next poll
            out: List[Dict[str, Any]] = []
            try:
                client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
                sparql = (
                    "PREFIX g: <http://umanitek.ai/ontology/guardian/> "
                    "SELECT ?identifier (COUNT(DISTINCT ?reporter) AS ?reporters) "
                    "(SAMPLE(?severity) AS ?sev) WHERE { "
                    "?r a g:ThreatReport . ?r g:identifier ?identifier . ?r g:reporter ?reporter . "
                    "OPTIONAL { ?r g:severity ?severity . } } "
                    f"GROUP BY ?identifier ORDER BY DESC(?reporters) LIMIT {int(limit)}"
                )
                rows = client.query(
                    sparql,
                    cfg.context_graph_id,
                    view=constants.VIEW_SHARED_WORKING_MEMORY,
                    on_error=[],
                ) or []
                for row in rows:
                    out.append({
                        "identifier": extract_binding(row.get("identifier")),
                        "reporters": int(extract_binding(row.get("reporters")) or "0"),
                        "severity": extract_binding(row.get("sev")) or "info",
                    })
            except Exception as exc:  # pragma: no cover - fail open
                logger.debug("blackbox dashboard: reports query failed: %s", exc)
            return {"reports": out}

        return _swr(f"reports:{limit}", _load, {"reports": []})

    # Predicate IRI -> friendly detail key, for the single-threat lookup.
    _DETAIL_FIELDS = {
        constants.SEVERITY_PRED: "severity",
        constants.KIND_PRED: "kind",
        constants.SCHEMA_NAME_PRED: "name",
        constants.SCHEMA_DESCRIPTION_PRED: "description",
        constants.OWASP_CATEGORY_PRED: "owasp",
        constants.PACKAGE_ECOSYSTEM_PRED: "ecosystem",
        constants.PACKAGE_NAME_PRED: "package",
        constants.PACKAGE_VERSION_PRED: "version",
        constants.FIXED_VERSION_PRED: "fixed_version",
        constants.TOOL_NAME_PRED: "tool",
        constants.ARG_SHAPE_PRED: "arg_shape",
        constants.CATEGORY_PRED: "file_category",
        constants.SKILL_NAME_PRED: "skill",
        constants.SKILL_VERSION_PRED: "skill_version",
        constants.DANGER_SHAPE_PRED: "danger_shape",
        constants.PATTERN_PRED: "pattern",
        constants.CURATED_PRED: "curated",
        constants.SCHEMA_DATE_MODIFIED_PRED: "modified",
        constants.SCHEMA_CONTRIBUTOR_PRED: "contributor",
        "urn:defender:p:severity": "severity",
        "urn:defender:p:kind": "kind",
        "urn:defender:p:pattern": "pattern",
        "urn:defender:p:ecosystem": "ecosystem",
        "urn:defender:p:package": "package",
        "urn:defender:p:version": "version",
        "urn:defender:p:advisoryId": "advisory_id",
        "urn:defender:p:iocType": "ioc_type",
        "urn:defender:p:value": "value",
    }

    @app.get("/api/threat")
    def threat(identifier: str = Query(..., min_length=1), tier: str = Query("public")) -> Any:
        """Full detail for ONE threat via a targeted point-lookup.

        ``tier`` ∈ public | community | local. Fail-open."""
        tier, view = _tier_view(tier, default="public")
        if tier == "community":
            return {
                "identifier": identifier, "tier": "community", "found": False,
                "coming_soon": True,
            }
        cfg = load_blackbox_config()
        prefix = identifier.split(":", 1)[0].lower() if ":" in identifier else ""
        category = prefix if prefix in ("dep", "injection", "escalation", "fileaccess", "skill", "ioc") else "other"
        if category == "dep":
            category = "dependency"
        detail: Dict[str, Any] = {
            "identifier": identifier,
            "tier": tier,
            "category": category,
            "sources": [],
            "references": [],
            "found": False,
        }
        cached_rule: Dict[str, Any] = {}
        try:
            for _cat, rule in ruleset.peek(cfg).iter_rules():
                if rule.get("source") == tier and rule.get("identifier") == identifier:
                    cached_rule = rule
                    break
        except Exception:
            pass
        if not cached_rule:
            try:
                cached_rule = next(
                    item
                    for item in _graph_entries(ruleset.peek(cfg), tier)
                    if item.get("identifier") == identifier
                )
            except Exception:
                cached_rule = {}
        if cached_rule:
            detail.update({
                key: value
                for key, value in cached_rule.items()
                if key not in {"pattern", "source"} and value is not None and value != ""
            })
            detail["found"] = True
        # A threat and its ThreatReports share g:identifier; one point-lookup
        # returns both and we separate them in Python. Far cheaper than a SPARQL
        # FILTER NOT EXISTS (~3x slower, re-scans the view per row) and folds the
        # reporter count into the same round-trip.
        lit = identifier.replace("\\", "\\\\").replace('"', '\\"')
        rdf_type = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
        try:
            # Skip the point-lookup on an unreachable node so opening a threat
            # can't hang on a dead node.
            client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home) if _node_reachable(cfg) else None
            if client is None:
                rows = []
            else:
                subject = str(cached_rule.get("subject") or "")
                if subject:
                    lookup = f"SELECT ?t ?p ?o WHERE {{ VALUES ?t {{ <{subject}> }} ?t ?p ?o }}"
                else:
                    lookup = _PREFIX + f'SELECT ?t ?p ?o WHERE {{ ?t g:identifier "{lit}" . ?t ?p ?o }}'
                agent_address = None
                if tier == "local":
                    identity = client.agent_identity()
                    agent_address = str(identity.get("agentAddress") or "")
                rows = client.query(
                    lookup,
                    cfg.context_graph_id,
                    view=view,
                    agent_address=agent_address,
                )
            subjects: Dict[str, List[Any]] = {}
            for row in rows:
                subjects.setdefault(extract_binding(row.get("t")), []).append(
                    (extract_binding(row.get("p")), extract_binding(row.get("o")))
                )
            reporters = set()
            for pairs in subjects.values():
                types = {obj for (pred, obj) in pairs if pred == rdf_type}
                if constants.REPORT_TYPE_IRI in types:  # a sighting, not the threat
                    for pred, obj in pairs:
                        if pred == constants.REPORTER_PRED and obj:
                            reporters.add(obj)
                        elif pred == constants.FRAMEWORK_PRED and obj:
                            detail.setdefault("framework", obj)
                    continue
                if constants.FALSE_POSITIVE_TYPE_IRI in types:
                    continue
                detail["found"] = True  # the threat asset itself
                for pred, obj in pairs:
                    if pred in {constants.REFERENCE_PRED, "http://schema.org/citation"}:
                        if obj and obj not in detail["references"]:
                            detail["references"].append(obj)
                    elif pred in {constants.SOURCE_PRED, "urn:defender:p:source"}:
                        if obj and obj not in detail["sources"]:
                            detail["sources"].append(obj)
                    elif pred == "urn:defender:p:contributor":
                        detail["contributor"] = obj
                    elif pred in _DETAIL_FIELDS:
                        detail[_DETAIL_FIELDS[pred]] = obj
            detail["reporters"] = len(reporters)
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("blackbox dashboard: threat detail query failed: %s", exc)
        return detail

    @app.on_event("startup")
    def _warm_node_caches() -> None:
        """Prime the SWR node caches at boot so the first load shows data
        instead of a "Loading…" window. Off-thread, fail-open."""
        def _warm() -> None:
            try:
                cfg = load_blackbox_config()
                # Probe liveness synchronously first and seed the cache, so the
                # reads below see the node's true state, not the cold default.
                try:
                    ok = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home).reachable(timeout=_REACH_TIMEOUT)
                except Exception:  # pragma: no cover - fail open
                    ok = False
                with _swr_lock:
                    _reach["ok"] = ok
                    _reach["ts"] = time.monotonic()
                    _reach["busy"] = False
                # Touch each cached endpoint to warm it. Two passes: the first
                # spawns the refresh, the second lands it.
                for _ in range(2):
                    graph_status()
                    graph("public")
                    reports(50)
                    agents()
                    time.sleep(2.5)
            except Exception as exc:  # pragma: no cover - best effort
                logger.debug("blackbox dashboard: cache warm failed: %s", exc)
        threading.Thread(target=_warm, name="blackbox-warm", daemon=True).start()

    return app


def start_dashboard(port: int = 9700) -> None:
    """Run the dashboard with uvicorn on ``127.0.0.1:{port}`` (blocking)."""
    import uvicorn

    uvicorn.run(
        create_app(manage_blackbox=True),
        host="127.0.0.1",
        port=int(port),
        log_level="warning",
    )
