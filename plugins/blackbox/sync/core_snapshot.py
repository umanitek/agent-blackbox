"""One owned DKG snapshot job, with explicit configured-core or independent RPC trust.

--wait waits for fresh inventory coverage; usable rules and full coverage remain
separate facts. Detection always queries local DKG and writes no rule export.
"""
from __future__ import annotations

import http.client
import json
import time
from copy import deepcopy
from ..kernel.config import load_blackbox_config
from ..kernel.dkg_client import DkgClient, DkgError, signed_request_headers
from ..kernel.local_http import request
from .. import ruleset
from . import state

PATH = "/api/context-graph/snapshot-sync"
POLL_SECONDS = 2.0


class SnapshotSyncClient(DkgClient):
    """Bounded local operator transport, separate from the detection read client."""
    def __init__(self, cfg):
        super().__init__(url=ruleset.local_graph_url(cfg.dkg_url), dkg_home=cfg.dkg_home)

    def request(self, method, path, body=None, timeout=15):
        if (method, path) not in {("GET", PATH), ("POST", PATH)}:
            raise DkgError("SNAPSHOT_ROUTE_REFUSED")
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
            headers.update(signed_request_headers(self.token, method, path, data))
        try:
            code, raw = request(self.url, method, path, data, headers,
                                deadline=time.monotonic() + (timeout or 15), max_bytes=65536)
            if code >= 300:
                raise DkgError("DKG_UPGRADE_REQUIRED" if code == 404 else "SNAPSHOT_REQUEST_REFUSED", status_code=code)
            reply = json.loads(raw)
            if not isinstance(reply, dict):
                raise ValueError
            return reply
        except (ValueError, OSError, http.client.HTTPException) as exc:
            raise DkgError("SNAPSHOT_UNAVAILABLE") from exc


def sync(args):
    cfg = load_blackbox_config()
    return run(SnapshotSyncClient(cfg), cfg, args)


class _Progress:
    """Owned observation state; sampled rules and full coverage stay distinct."""
    def __init__(self, cfg):
        self.cfg, self.job_id, self.usable, self.cursor = cfg, None, None, {}
        self.readiness_state, self.readiness_error, self.coverage = "pending", "", {}

    def record(self, status, phase, *, error="", result=None):
        result = self.coverage if result is None else result
        state.write(status, context_graph_id=self.cfg.context_graph_id, phase=phase,
                    chain_evidence_mode=self.cfg.snapshot_sync.mode, job_id=self.job_id,
                    public_entries=self.usable, count_kind="sampled-usable-rules",
                    detection_ready=self.readiness_state == "ready", graph_complete=result.get("current") is True,
                    readiness_state=self.readiness_state, readiness_error=self.readiness_error,
                    complete=result.get("current") is True,
                    assets=result.get("assets"), committed=result.get("committed"),
                    snapshot_digest=result.get("snapshotDigest"), error=error)


def _matches_requested_scope(request, payload):
    # New daemons echo their resolved transport even when the caller omitted it.
    # Only this known selection is additive; all authority fields remain exact.
    if not isinstance(request, dict):
        return False
    if request == payload:
        return True
    return ("transport" not in payload and request.get("transport") in ("exact", "bulk")
            and request == {**payload, "transport": request["transport"]})


def _start(client, payload):
    # Check capability before starting a transfer. Never silently fall back.
    job = client.request("GET", PATH)
    if payload.get("sourcePolicy"):
        capabilities = job.get("capabilities")
        if not isinstance(capabilities, dict) or not isinstance(capabilities.get("sourcePolicies"), list):
            raise DkgError("DKG_UPGRADE_REQUIRED")
        if payload["sourcePolicy"] not in capabilities["sourcePolicies"]:
            raise DkgError("DKG_UPGRADE_REQUIRED")
    if job.get("state") not in {"idle", "running", "complete", "failed"}:
        raise DkgError("SNAPSHOT_RESPONSE_INVALID")
    if job["state"] == "running":
        if not _matches_requested_scope(job.get("request"), payload):
            raise DkgError("ANOTHER_SNAPSHOT_JOB_IS_RUNNING")
    else:
        job = client.request("POST", PATH, payload)
        if not _matches_requested_scope(job.get("request"), payload):
            raise DkgError("SNAPSHOT_JOB_CHANGED")
    if not isinstance(job.get("id"), str) or not job["id"]:
        raise DkgError("SNAPSHOT_RESPONSE_INVALID")
    return job


def _registered_sources_valid(result, payload):
    if not payload.get("sourcePolicy"):
        return True
    peers = result.get("selectedCorePeerIds")
    if (result.get("sourcePolicy") != payload["sourcePolicy"] or not isinstance(peers, list)
            or not 1 <= len(peers) <= 4
            or any(not isinstance(p, str) or not p or len(p) > 256 for p in peers)
            or len(set(peers)) != len(peers)):
        return False
    return (payload["mode"] != "core-cache" or
            all(result.get(key) in peers for key in ("sourceCore", "coverageSourceCore")))


def _observe(job, payload, progress, args):
    if job.get("id") != progress.job_id or job.get("request") != payload:
        raise DkgError("SNAPSHOT_JOB_CHANGED")
    if job.get("state") == "failed":
        raise DkgError("SNAPSHOT_RECOVERY_FAILED")
    if job.get("state") not in {"running", "complete"}:
        raise DkgError("SNAPSHOT_RESPONSE_INVALID")
    if job["state"] == "complete":
        result = job.get("result")
        if (not isinstance(result, dict) or result.get("mode") != payload["mode"]
                or result.get("completeAsOfSnapshot") is not True
                or type(result.get("assets")) is not int or result["assets"] < 0
                or result.get("committed") != result["assets"]
                or not _registered_sources_valid(result, payload)):
            raise DkgError("SNAPSHOT_RESPONSE_INVALID")
        if not progress.coverage:
            # Completion needs a fresh sample, not whichever trailing page the
            # in-flight observer happened to reach, nor an earlier positive.
            progress.cursor.clear()
        progress.coverage = result
    try:
        progress.usable = ruleset.ready_sample(progress.cfg, cursor=progress.cursor)
        progress.readiness_error = ""
        progress.readiness_state = ("ready" if progress.usable > 0 else
                                    "empty" if progress.cursor.get("exhausted", True) else "pending")
    except DkgError as exc:
        progress.usable = None
        progress.readiness_state = "unavailable"
        progress.readiness_error = getattr(exc, "code", "QUERY_UNAVAILABLE")
    if job["state"] != "complete":
        return None
    result = progress.coverage
    complete = result.get("current") is True
    if (complete and getattr(args, "require_rules", False) and getattr(args, "wait", False)
            and progress.readiness_state in {"unavailable", "pending"}):
        # Retry only local reads within the original observation deadline. The
        # owned network job remains complete; never start another transfer.
        return None
    progress.record("complete" if complete else "partial", "snapshot-coverage-checked", result=result)
    print(f"Snapshot coverage: {result['committed']}/{result['assets']} assets; "
          f"current={complete}; usable rule sample={progress.usable if progress.usable is not None else 'unavailable'}.")
    return 0 if complete and (progress.readiness_state == "ready" or not getattr(args, "require_rules", False)) else 2


def run(client, cfg, args):
    settings = cfg.snapshot_sync
    if settings is None or cfg.detection_backend != "dkg":
        raise ValueError("A snapshot sync requires configured direct DKG mode")
    payload = {"contextGraphId": cfg.context_graph_id, "onChainId": settings.on_chain_id,
               "trustedCorePeerIds": list(settings.trusted_core_peers), "mode": settings.mode}
    if settings.source_policy:
        payload["sourcePolicy"] = settings.source_policy
    deadline = time.monotonic() + max(1.0, float(getattr(args, "timeout", 3600) or 3600))
    progress = _Progress(cfg)
    try:
        job = _start(client, payload)
        progress.job_id = job["id"]
        # Pin the validated descriptor, including any selected transport, for
        # every subsequent poll. Never normalize away a mid-job change.
        payload = deepcopy(job["request"])
        while time.monotonic() < deadline:
            outcome = _observe(job, payload, progress, args)
            if outcome is not None:
                return outcome
            progress.record("partial" if progress.coverage else "running",
                            "awaiting-local-rule-readiness" if progress.coverage else "recovering-core-snapshot",
                            error=progress.readiness_error)
            if not getattr(args, "wait", False):
                progress.record("partial", "snapshot-job-running")
                print("The DKG snapshot job is running. Run sync --wait to observe its coverage result.")
                return 0
            time.sleep(min(POLL_SECONDS, max(0.0, deadline - time.monotonic())))
            job = client.request("GET", PATH)
        progress.record("partial", "rule-readiness-timeout" if progress.coverage else "snapshot-observation-timeout",
                        error=progress.readiness_error or ("Local rule readiness was not established" if progress.coverage
                                                          else "The owned DKG job may still be running"))
        return 2
    except DkgError as exc:
        # Detailed peer/endpoint errors stay in the DKG log, not user-facing status.
        progress.record("failed", "snapshot-recovery-unavailable", error=str(exc))
        print(f"Snapshot sync unavailable: {exc}")
        return 2
    except KeyboardInterrupt:
        progress.record("partial", "snapshot-observation-cancelled", error="The owned DKG job may still be running")
        return 130
