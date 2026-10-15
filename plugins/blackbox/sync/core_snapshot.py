"""One owned DKG snapshot job, with explicit configured-core or independent RPC trust.

--wait waits for fresh inventory coverage; usable rules and full coverage remain
separate facts. Detection always queries local DKG and writes no rule export.
"""
from __future__ import annotations

import http.client
import json
import time
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
        self.cfg, self.job_id, self.usable, self.cursor = cfg, None, 0, {}

    def record(self, status, phase, *, error="", result=None):
        result = result or {}
        state.write(status, context_graph_id=self.cfg.context_graph_id, phase=phase,
                    chain_evidence_mode=self.cfg.snapshot_sync.mode, job_id=self.job_id,
                    public_entries=self.usable, count_kind="sampled-usable-rules",
                    detection_ready=self.usable > 0, graph_complete=result.get("current") is True,
                    complete=result.get("current") is True,
                    assets=result.get("assets"), committed=result.get("committed"),
                    snapshot_digest=result.get("snapshotDigest"), error=error)


def _start(client, payload):
    # Check capability before starting a transfer. Never silently fall back.
    job = client.request("GET", PATH)
    if job.get("state") not in {"idle", "running", "complete", "failed"}:
        raise DkgError("SNAPSHOT_RESPONSE_INVALID")
    if job["state"] == "running":
        if job.get("request") != payload:
            raise DkgError("ANOTHER_SNAPSHOT_JOB_IS_RUNNING")
    else:
        job = client.request("POST", PATH, payload)
    if not isinstance(job.get("id"), str) or not job["id"]:
        raise DkgError("SNAPSHOT_RESPONSE_INVALID")
    return job


def _observe(job, payload, progress, args):
    if job.get("id") != progress.job_id or job.get("request") != payload:
        raise DkgError("SNAPSHOT_JOB_CHANGED")
    if job.get("state") == "failed":
        raise DkgError("SNAPSHOT_RECOVERY_FAILED")
    if job.get("state") not in {"running", "complete"}:
        raise DkgError("SNAPSHOT_RESPONSE_INVALID")
    try:
        progress.usable = ruleset.ready_sample(progress.cfg, cursor=progress.cursor)
    except DkgError:
        progress.usable = 0
    if job["state"] != "complete":
        return None
    result = job.get("result")
    if (not isinstance(result, dict) or result.get("mode") != payload["mode"]
            or result.get("completeAsOfSnapshot") is not True
            or type(result.get("assets")) is not int or result["assets"] < 0
            or result.get("committed") != result["assets"]):
        raise DkgError("SNAPSHOT_RESPONSE_INVALID")
    complete = result.get("current") is True
    progress.record("complete" if complete else "partial", "snapshot-coverage-checked", result=result)
    print(f"Snapshot coverage: {result['committed']}/{result['assets']} assets; "
          f"current={complete}; usable rule sample={progress.usable}.")
    return 0 if complete and (progress.usable > 0 or not getattr(args, "require_rules", False)) else 2


def run(client, cfg, args):
    settings = cfg.snapshot_sync
    if settings is None or cfg.detection_backend != "dkg":
        raise ValueError("A snapshot sync requires configured direct DKG mode")
    payload = {"contextGraphId": cfg.context_graph_id, "onChainId": settings.on_chain_id,
               "trustedCorePeerIds": list(settings.trusted_core_peers), "mode": settings.mode}
    deadline = time.monotonic() + max(1.0, float(getattr(args, "timeout", 3600) or 3600))
    progress = _Progress(cfg)
    try:
        job = _start(client, payload)
        progress.job_id = job["id"]
        while time.monotonic() < deadline:
            outcome = _observe(job, payload, progress, args)
            if outcome is not None:
                return outcome
            progress.record("running", "recovering-core-snapshot")
            if not getattr(args, "wait", False):
                progress.record("partial", "snapshot-job-running")
                print("The DKG snapshot job is running. Run sync --wait to observe its coverage result.")
                return 0
            time.sleep(min(POLL_SECONDS, max(0.0, deadline - time.monotonic())))
            job = client.request("GET", PATH)
        progress.record("partial", "snapshot-observation-timeout", error="The owned DKG job may still be running")
        return 2
    except DkgError as exc:
        # Detailed peer/endpoint errors stay in the DKG log, not user-facing status.
        progress.record("failed", "snapshot-recovery-unavailable", error=str(exc))
        print(f"Snapshot sync unavailable: {exc}")
        return 2
    except KeyboardInterrupt:
        progress.record("partial", "snapshot-observation-cancelled", error="The owned DKG job may still be running")
        return 130
