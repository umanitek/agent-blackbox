"""Immutable bundle creation, approval, and guarded publisher handoff."""

from __future__ import annotations

import collections
import contextlib
import datetime as dt
import fcntl
import json
import os
import re
import secrets
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterator, Mapping, Optional, Sequence

from .core import (
    AuditLog,
    Observation,
    State,
    atomic_write,
    canonical_json,
    parse_time,
    safe_summary,
    sha256,
    utc_day,
    utcnow,
)
from .graph import assert_bundle_absent_from_graph, required_sync_strategy


def _publisher_dir(config: Mapping[str, Any]) -> Path:
    return Path(str(config["paths"]["publisher_dir"])).resolve()


def _state_dir(config: Mapping[str, Any]) -> Path:
    return Path(str(config["paths"]["state_dir"])).resolve()


def _run_node(
    publisher_dir: Path,
    script: str,
    args: Sequence[str],
    *,
    env: Optional[Mapping[str, str]] = None,
    timeout: int = 7200,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        ["node", str(publisher_dir / script), *args],
        cwd=publisher_dir,
        env={**os.environ, **dict(env or {})},
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or f"{script} failed").strip()
        raise RuntimeError(detail[-4000:])
    return completed


def _counter(values: Sequence[Any]) -> Dict[str, int]:
    return dict(sorted(collections.Counter(str(value) for value in values).items()))


def _bundle_summary(observations: Sequence[Observation], asset_size: int) -> Dict[str, Any]:
    # Select a deterministic, content-distributed review sample.  Taking the
    # first rows would systematically over-represent the oldest source/file.
    samples = sorted(
        observations,
        key=lambda item: sha256(f"review-sample\0{item.observation_id}"),
    )[: min(12, len(observations))]
    return {
        "records": len(observations),
        "assets": (len(observations) + asset_size - 1) // asset_size,
        "sources": _counter([item.source_id for item in observations]),
        "categories": _counter([item.category for item in observations]),
        "canonical_types": _counter([item.canonical_type for item in observations]),
        "lifecycle": _counter([item.lifecycle_status for item in observations]),
        "licenses": _counter([item.license_id for item in observations]),
        "confidence": {
            "min": min(item.confidence for item in observations),
            "max": max(item.confidence for item in observations),
            "average": round(sum(item.confidence for item in observations) / len(observations), 2),
        },
        "samples": [
            {
                "observation_id": item.observation_id,
                "type": item.canonical_type,
                "status": item.lifecycle_status,
                "safe_value": safe_summary(item.canonical_value),
            }
            for item in samples
        ],
    }


def build_bundle(config: Mapping[str, Any], state: State, log: AuditLog) -> Optional[Dict[str, Any]]:
    limits = config["limits"]
    maximum = int(limits["approval_bundle_records"])
    minimum = int(limits["minimum_bundle_records"])
    observations = state.bundle_candidates(maximum)
    available_count = len(observations)
    # Knowledge assets are atomic 1,000-record units in production. Keep any
    # remainder queued for the next acquisition instead of minting a partial
    # asset whose semantics differ from the approval report.
    aligned_count = len(observations) - (len(observations) % int(limits["asset_records"]))
    observations = observations[:aligned_count]
    if len(observations) < minimum:
        log.emit(
            "bundle_deferred",
            candidates=available_count,
            aligned_candidates=len(observations),
            minimum=minimum,
            message=f"bundle deferred: {available_count} candidates / {len(observations)} asset-aligned (< {minimum})",
        )
        return None

    created_at = utcnow()
    content_digest = sha256(canonical_json([item.observation_id for item in observations]))
    stamp = created_at.replace("-", "").replace(":", "").replace("Z", "Z")
    bundle_id = f"bundle-{stamp}-{content_digest[:12]}"
    root = _state_dir(config) / "bundles"
    staging = root / f".{bundle_id}.staging-{os.getpid()}"
    final = root / bundle_id
    # An expired manifest may release the exact same observations within the
    # same timestamp second. Preserve that historical directory and give the
    # replacement a distinct immutable identity instead of overwriting it.
    while staging.exists() or final.exists():
        bundle_id = f"bundle-{stamp}-{content_digest[:8]}-{secrets.token_hex(4)}"
        staging = root / f".{bundle_id}.staging-{os.getpid()}"
        final = root / bundle_id
    staging.mkdir(parents=True)

    source_path = staging / "source.json"
    batches = staging / "batches"
    registry = staging / "registry.json"
    progress = staging / "progress.json"
    expected = staging / "expected-rdf.json"
    mapping = _publisher_dir(config) / "continuous" / "mapping.mjs"
    asset_size = int(limits["asset_records"])
    source = {"version": 1, "bundleId": bundle_id, "records": [item.publisher_record() for item in observations]}
    atomic_write(source_path, canonical_json(source) + b"\n")

    _run_node(
        _publisher_dir(config),
        "chunk.mjs",
        [
            str(source_path), "--size", str(asset_size), "--expect-records", str(len(observations)),
            "--out-dir", str(batches), "--mapping", str(mapping),
        ],
    )
    inline_size = json.loads(
        _run_node(
            _publisher_dir(config),
            "continuous/validate-inline-size.mjs",
            [
                "--batch-dir", str(batches),
                "--mapping", str(mapping),
                "--context-graph-id", str(config["publisher"]["context_graph_id"]),
            ],
        ).stdout
    )
    batch_manifest_bytes = (batches / "manifest.json").read_bytes()
    batch_manifest_sha = sha256(batch_manifest_bytes)
    dry_env = {
        "KC_MAPPING_PATH": str(mapping),
        "KC_BATCH_DIR": str(batches),
        "KC_EXPECT_RECORDS": str(len(observations)),
        "KC_REGISTRY_PATH": str(registry),
        "KC_PROGRESS_PATH": str(progress),
        "KC_EXPECTED_MANIFEST_PATH": str(expected),
    }
    _run_node(_publisher_dir(config), "publish.mjs", ["--dry-run"], env=dry_env)

    summary = _bundle_summary(observations, asset_size)
    expires_at = (
        parse_time(created_at) + dt.timedelta(hours=int(limits["approval_ttl_hours"]))
    ).isoformat(timespec="seconds").replace("+00:00", "Z")
    review = {
        "version": 1,
        "bundleId": bundle_id,
        "createdAt": created_at,
        "expiresAt": expires_at,
        "contentSha256": content_digest,
        "batchManifestSha256": batch_manifest_sha,
        "mappingSha256": sha256(mapping.read_bytes()),
        "inlineStorageAck": inline_size,
        "summary": summary,
        "observations": [item.observation_id for item in observations],
        "assets": [
            {
                "ordinal": index + 1,
                "batch": entry["name"],
                "records": entry["records"],
                "sha256": entry["sha256"],
            }
            for index, entry in enumerate(json.loads(batch_manifest_bytes)["batches"])
        ],
    }
    review_bytes = canonical_json(review) + b"\n"
    manifest_sha = sha256(review_bytes)
    atomic_write(staging / "approval-manifest.json", review_bytes)
    os.replace(staging, final)

    try:
        with state.transaction() as db:
            db.execute(
                """INSERT INTO bundles(
                  bundle_id,manifest_sha256,batch_manifest_sha256,state,record_count,asset_count,created_at,expires_at
                ) VALUES (?,?,?,'bundled',?,?,?,?)""",
                (
                    bundle_id, manifest_sha, batch_manifest_sha, len(observations),
                    len(review["assets"]), created_at, expires_at,
                ),
            )
            for position, observation in enumerate(observations):
                changed = db.execute(
                    "UPDATE observations SET state='bundled',bundle_id=? WHERE observation_id=? AND state='candidate'",
                    (bundle_id, observation.observation_id),
                ).rowcount
                if changed != 1:
                    raise RuntimeError(f"candidate changed while bundling: {observation.observation_id}")
                db.execute(
                    "INSERT INTO bundle_observations(bundle_id,position,observation_id) VALUES (?,?,?)",
                    (bundle_id, position, observation.observation_id),
                )
            for asset in review["assets"]:
                db.execute(
                    "INSERT INTO assets(bundle_id,ordinal,batch_name,record_count) VALUES (?,?,?,?)",
                    (bundle_id, asset["ordinal"], asset["batch"], asset["records"]),
                )
    except Exception:
        # The directory belongs only to this not-yet-committed bundle. Preserve
        # the durable database as the source of truth and leave no orphan that
        # could later be mistaken for an approvable manifest.
        shutil.rmtree(final, ignore_errors=True)
        raise
    log.emit(
        "bundle_created", bundle_id=bundle_id, manifest_sha256=manifest_sha,
        records=len(observations), assets=len(review["assets"]),
        message=f"created {bundle_id}: {len(observations)} records / {len(review['assets'])} assets",
    )
    return {"bundle_id": bundle_id, "manifest_sha256": manifest_sha, "path": str(final), "review": review}


def bundle_path(config: Mapping[str, Any], bundle_id: str) -> Path:
    if not re.fullmatch(r"bundle-[A-Za-z0-9T.+-]+", bundle_id):
        raise ValueError("invalid bundle id")
    return _state_dir(config) / "bundles" / bundle_id


def verify_bundle(config: Mapping[str, Any], row: Mapping[str, Any]) -> Dict[str, Any]:
    root = bundle_path(config, str(row["bundle_id"]))
    review_path = root / "approval-manifest.json"
    batch_path = root / "batches" / "manifest.json"
    review_bytes = review_path.read_bytes()
    batch_bytes = batch_path.read_bytes()
    if sha256(review_bytes) != row["manifest_sha256"]:
        raise RuntimeError("approval manifest checksum mismatch")
    if sha256(batch_bytes) != row["batch_manifest_sha256"]:
        raise RuntimeError("batch manifest checksum mismatch")
    review = json.loads(review_bytes)
    if review["bundleId"] != row["bundle_id"] or review["batchManifestSha256"] != row["batch_manifest_sha256"]:
        raise RuntimeError("bundle identity contract mismatch")
    return review


def bundle_export_bytes(config: Mapping[str, Any], state: State, bundle_id: str) -> bytes:
    """Return the exact checksummed threat records represented by an approval."""
    row = state.bundle_row(bundle_id)
    review = verify_bundle(config, row)
    root = bundle_path(config, bundle_id)
    manifest = json.loads((root / "batches" / "manifest.json").read_bytes())
    threats: list[Dict[str, Any]] = []
    for entry in manifest.get("batches") or []:
        path = root / "batches" / str(entry["file"])
        payload = path.read_bytes()
        if len(payload) != int(entry["bytes"]) or sha256(payload) != entry["sha256"]:
            raise RuntimeError(f"{entry['name']}: downloadable batch checksum mismatch")
        parsed = json.loads(payload)
        records = parsed.get("records") or []
        if parsed.get("name") != entry["name"] or len(records) != int(entry["records"]):
            raise RuntimeError(f"{entry['name']}: downloadable batch content mismatch")
        threats.extend(records)
    if len(threats) != int(row["record_count"]):
        raise RuntimeError("downloadable threat count does not match the approved bundle")
    return canonical_json(
        {
            "version": 1,
            "bundleId": bundle_id,
            "manifestSha256": row["manifest_sha256"],
            "summary": review["summary"],
            "threats": threats,
        }
    ) + b"\n"


def issue_approval_nonce(config: Mapping[str, Any], state: State, bundle_id: str) -> str:
    row = state.bundle_row(bundle_id)
    verify_bundle(config, row)
    if row["state"] != "bundled":
        raise RuntimeError(f"bundle {bundle_id} is {row['state']}, not bundled")
    if not row["approval_preflight_sha256"] or not row["approval_preflight_at"]:
        raise RuntimeError("bundle has no approval preflight report")
    nonce = secrets.token_urlsafe(24)
    state.db.execute(
        "UPDATE bundles SET approval_nonce_hash=?,nonce_used_at=NULL WHERE bundle_id=?",
        (sha256(nonce), bundle_id),
    )
    return nonce


def decide_bundle(
    config: Mapping[str, Any],
    state: State,
    bundle_id: str,
    action: str,
    *,
    actor: str,
    source: str,
    manifest_sha256: Optional[str] = None,
    nonce: Optional[str] = None,
    workspace: Optional[str] = None,
    channel: Optional[str] = None,
    action_timestamp: Optional[str] = None,
    approval_preflight_sha256: Optional[str] = None,
    reason: Optional[str] = None,
) -> Dict[str, Any]:
    if action not in {"approve", "decline"}:
        raise ValueError("action must be approve or decline")
    row = state.bundle_row(bundle_id)
    verify_bundle(config, row)
    if row["state"] != "bundled":
        raise RuntimeError(f"bundle {bundle_id} is {row['state']}, not bundled")
    if parse_time(row["expires_at"]) < parse_time(utcnow()):
        state.db.execute("UPDATE bundles SET state='expired' WHERE bundle_id=?", (bundle_id,))
        raise RuntimeError("approval has expired")
    if manifest_sha256 and not secrets.compare_digest(str(row["manifest_sha256"]), manifest_sha256):
        raise RuntimeError("approval manifest hash mismatch")
    slack = config.get("slack") or {}
    if source == "slack":
        try:
            action_age = abs(parse_time(utcnow()).timestamp() - float(action_timestamp or ""))
        except (TypeError, ValueError):
            raise PermissionError("Slack action timestamp is missing or invalid") from None
        if action_age > 300:
            raise PermissionError("Slack action timestamp is stale")
        if not approval_preflight_sha256 or not row["approval_preflight_sha256"] or not secrets.compare_digest(
            str(row["approval_preflight_sha256"]), approval_preflight_sha256,
        ):
            raise PermissionError("approval preflight hash is invalid")
        preflight_age = parse_time(utcnow()) - parse_time(str(row["approval_preflight_at"]))
        if preflight_age > dt.timedelta(minutes=int(config["limits"].get("approval_preflight_ttl_minutes", 30))):
            raise PermissionError("approval preflight report is stale; refresh the Slack report")
        if not actor:
            raise PermissionError("Slack action has no authenticated user")
        allow_any_member = bool(slack.get("allow_any_channel_member", False))
        if not allow_any_member and actor not in set(str(value) for value in slack.get("approver_user_ids") or []):
            raise PermissionError("Slack user is not an authorized Blackbox approver")
        expected_workspace = str(slack.get("workspace_id") or "")
        expected_channel = str(slack.get("channel_id") or "")
        if expected_workspace and workspace != expected_workspace:
            raise PermissionError("approval came from the wrong Slack workspace")
        if expected_channel and channel != expected_channel:
            raise PermissionError("approval came from the wrong Slack channel")
        if not nonce or not row["approval_nonce_hash"] or not secrets.compare_digest(sha256(nonce), row["approval_nonce_hash"]):
            raise PermissionError("approval nonce is invalid")
        if row["nonce_used_at"]:
            raise PermissionError("approval nonce has already been used")
    now = utcnow()
    next_state = "approved" if action == "approve" else "declined"
    with state.transaction() as db:
        changed = db.execute(
            """UPDATE bundles SET state=?,decision_at=?,decided_by=?,decision_reason=?,
              nonce_used_at=CASE WHEN ?='slack' THEN ? ELSE nonce_used_at END
              WHERE bundle_id=? AND state='bundled'""",
            (next_state, now, actor, reason, source, now, bundle_id),
        ).rowcount
        if changed != 1:
            raise RuntimeError("bundle state changed during decision")
        db.execute(
            """INSERT INTO decisions(
              bundle_id,action,actor,source,manifest_sha256,workspace,channel,decided_at,reason
            ) VALUES (?,?,?,?,?,?,?,?,?)""",
            (bundle_id, action, actor, source, row["manifest_sha256"], workspace, channel, now, reason),
        )
        if action == "decline":
            db.execute(
                "UPDATE observations SET state='rejected' WHERE bundle_id=? AND state='bundled'",
                (bundle_id,),
            )
    return {"bundle_id": bundle_id, "state": next_state, "decided_at": now, "actor": actor}


def _publisher_env(config: Mapping[str, Any], bundle_id: str, record_count: int) -> Dict[str, str]:
    publisher = config["publisher"]
    root = bundle_path(config, bundle_id)
    auth_path = publisher.get("dkg_auth_token_path")
    credential = publisher.get("dkg_auth_token_credential")
    credential_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if credential and credential_dir:
        auth_path = str(Path(credential_dir) / str(credential))
    if not auth_path:
        raise RuntimeError("publisher DKG auth token path/credential is not configured")
    required = ("context_graph_id", "dkg_version", "context_graph_onchain_id")
    missing = [name for name in required if not publisher.get(name)]
    if missing:
        raise RuntimeError(f"publisher configuration missing: {', '.join(missing)}")
    env = {
        "KC_MAPPING_PATH": str(_publisher_dir(config) / "continuous" / "mapping.mjs"),
        "KC_BATCH_DIR": str(root / "batches"),
        "KC_EXPECT_RECORDS": str(record_count),
        "KC_REGISTRY_PATH": str(root / "registry.json"),
        "KC_PROGRESS_PATH": str(root / "progress.json"),
        "KC_CG_ID": str(publisher["context_graph_id"]),
        "KC_CG_ONCHAIN_ID": str(publisher["context_graph_onchain_id"]),
        "KC_DKG_VERSION": str(publisher["dkg_version"]),
        "KC_LEDGER_DKG_VERSION": str(publisher["ledger_dkg_version"]),
        "KC_EPOCHS": str(publisher.get("epochs", 12)),
        "KC_KA_PREFIX": f"agent-blackbox-{bundle_id}",
        "KC_NETWORK": str(publisher["network"]),
        "KC_VM_PUBLISH_MODE": str(publisher.get("publish_mode", "sync")),
        "KC_SWM_RESTORE_MODE": str(publisher.get("swm_restore_mode", "skip")),
        "KC_PIPELINE_WIDTH": str(publisher.get("pipeline_width", 1)),
        "KC_ACCESS_POLICY": str(publisher["access_policy"]),
        "DKG_ENDPOINT": str(publisher.get("dkg_endpoint", "http://127.0.0.1")),
        "DKG_PORT": str(publisher.get("dkg_port", 8900)),
        "DKG_AUTH_TOKEN_PATH": str(auth_path),
    }
    if publisher.get("publisher_node_identity_id") is not None:
        env["KC_PUBLISHER_NODE_IDENTITY_ID"] = str(publisher["publisher_node_identity_id"])
    return env


def _verify_publisher_boundary(config: Mapping[str, Any]) -> None:
    """Pin paid execution to the exact reviewed outer publisher script."""
    publisher = config["publisher"]
    script = _publisher_dir(config) / "publish.mjs"
    script_bytes = script.read_bytes()
    actual = sha256(script_bytes)
    approved = str(publisher.get("approved_publish_script_sha256") or "")
    if not approved or not secrets.compare_digest(actual, approved):
        raise RuntimeError(
            f"publish.mjs is not the reviewed paid boundary (actual SHA-256 {actual}); "
            "leave publishing disabled and review/pin this exact file"
        )
    source = script_bytes.decode("utf-8", errors="strict")
    required_markers = ("KC_MAPPING_PATH", "--preflight", "--confirm", "KC_SWM_RESTORE_MODE")
    missing = [marker for marker in required_markers if marker not in source]
    if missing:
        raise RuntimeError(f"reviewed publisher is missing incremental safety markers: {', '.join(missing)}")
    if publisher.get("swm_restore_mode", "skip") == "skip":
        if "swmRestoreSkippedAt" not in source or "skipped-vm-only" not in source:
            raise RuntimeError("reviewed publisher has no explicit VM-only completion marker")
    elif "swmReplicatedAt" not in source and "swmVerifiedAt" not in source:
        raise RuntimeError("reviewed publisher has no verified SWM-restoration marker")
    if publisher.get("verified_incremental_support") is not True:
        raise RuntimeError("incremental publisher support has not been explicitly verified")


def _require_fresh_graph_sync(config: Mapping[str, Any], state: State) -> None:
    graph = config.get("graph_dedupe") or {}
    if not graph.get("required_for_publishing", True):
        return
    if not graph.get("enabled", False):
        raise RuntimeError("graph deduplication is disabled")
    row = state.graph_sync_row()
    if row is None:
        raise RuntimeError("no successful graph-deduplication sync is recorded")
    age = parse_time(utcnow()) - parse_time(row["synced_at"])
    if age > dt.timedelta(hours=int(graph.get("max_age_hours", 6))):
        raise RuntimeError(f"graph-deduplication sync is stale ({row['synced_at']})")
    expected_graph = str(config["publisher"].get("context_graph_id") or "")
    if str(row["context_graph_id"]) != expected_graph:
        raise RuntimeError("graph-deduplication sync belongs to a different context graph")
    try:
        strategies = json.loads(str(row["views_json"]))
    except json.JSONDecodeError as exc:
        raise RuntimeError("graph-deduplication sync has invalid strategy metadata") from exc
    if required_sync_strategy() not in strategies:
        raise RuntimeError("graph-deduplication sync used an obsolete inventory strategy")


def prepare_approval_preflight(
    config: Mapping[str, Any], state: State, bundle_id: str,
) -> Dict[str, Any]:
    """Create the read-only node snapshot shown to the human approver."""
    row = state.bundle_row(bundle_id)
    verify_bundle(config, row)
    if row["state"] != "bundled":
        raise RuntimeError(f"bundle {bundle_id} is {row['state']}, not bundled")
    if not config["publisher"].get("enabled", False):
        snapshot = {
            "mode": "rehearsal",
            "publisherEnabled": False,
            "manifestSha256": row["manifest_sha256"],
            "message": "paid publishing is disabled; no live node or wallet preflight was performed",
        }
    else:
        _verify_publisher_boundary(config)
        _require_fresh_graph_sync(config, state)
        graph_check = assert_bundle_absent_from_graph(config, state, bundle_id)
        env = _publisher_env(config, bundle_id, int(row["record_count"]))
        completed = _run_node(_publisher_dir(config), "publish.mjs", ["--preflight"], env=env)
        wallet_match = re.search(r"wallet preflight:\s*(\{[^\n]+\})", completed.stdout)
        token_match = re.search(r"paid confirmation token:\s*(\S+)", completed.stdout)
        if not wallet_match or not token_match:
            raise RuntimeError("publisher preflight did not return the required wallet/confirmation report")
        try:
            wallets = json.loads(wallet_match.group(1))
        except json.JSONDecodeError as exc:
            raise RuntimeError("publisher preflight returned an invalid wallet report") from exc
        snapshot = {
            "mode": "live-read-only",
            "publisherEnabled": True,
            "manifestSha256": row["manifest_sha256"],
            "wallets": wallets,
            "graphCheck": graph_check,
            "confirmationTokenSha256": sha256(token_match.group(1)),
            "message": "live read-only preflight passed; current DKG does not expose a pre-publication cost quote",
        }
    snapshot["createdAt"] = utcnow()
    snapshot_sha = sha256(canonical_json(snapshot))
    state.db.execute(
        """UPDATE bundles SET approval_preflight_sha256=?,approval_preflight_at=?,approval_preflight_json=?
           WHERE bundle_id=? AND state='bundled'""",
        (snapshot_sha, snapshot["createdAt"], canonical_json(snapshot).decode(), bundle_id),
    )
    return {"sha256": snapshot_sha, **snapshot}


def _require_live_approval_preflight(row: Mapping[str, Any]) -> Dict[str, Any]:
    """Reject approvals that were issued without a live read-only node preflight."""
    raw_snapshot = row["approval_preflight_json"]
    expected_sha = str(row["approval_preflight_sha256"] or "")
    if not raw_snapshot or not expected_sha:
        raise RuntimeError("approved bundle has no approval preflight report")
    try:
        snapshot = json.loads(str(raw_snapshot))
    except json.JSONDecodeError as exc:
        raise RuntimeError("approved bundle has an invalid approval preflight report") from exc
    if not secrets.compare_digest(sha256(canonical_json(snapshot)), expected_sha):
        raise RuntimeError("approved bundle approval preflight checksum mismatch")
    if snapshot.get("mode") != "live-read-only" or snapshot.get("publisherEnabled") is not True:
        raise RuntimeError(
            "approved bundle only has a rehearsal preflight; refresh the live Slack report and approve again"
        )
    if snapshot.get("manifestSha256") != row["manifest_sha256"]:
        raise RuntimeError("approved bundle preflight belongs to a different manifest")
    return snapshot


def request_publish(config: Mapping[str, Any], state: State, bundle_id: str) -> Dict[str, Any]:
    """Atomically hand one live-approved bundle to the systemd path trigger."""
    if not config["publisher"].get("enabled", False):
        raise RuntimeError("publisher.enabled is false; this was a rehearsal approval")
    row = state.bundle_row(bundle_id)
    if row["state"] != "approved":
        raise RuntimeError(f"bundle {bundle_id} is {row['state']}, not approved")
    verify_bundle(config, row)
    _require_live_approval_preflight(row)
    trigger = _state_dir(config) / "publish.trigger"
    if trigger.exists():
        raise RuntimeError("another approved bundle is already queued for immediate publishing")
    atomic_write(
        trigger,
        canonical_json(
            {
                "version": 1, "bundleId": bundle_id,
                "manifestSha256": row["manifest_sha256"], "requestedAt": utcnow(),
            }
        ) + b"\n",
    )
    return {"status": "queued", "bundle_id": bundle_id}


def reconcile_bundle(
    config: Mapping[str, Any], state: State, bundle_id: str, *, publisher_active: bool = False,
) -> Dict[str, Any]:
    root = bundle_path(config, bundle_id)
    registry_path = root / "registry.json"
    if not registry_path.is_file():
        return {"finalized": 0, "ambiguous": 0}
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    finalized = 0
    ambiguous = 0
    publisher = config["publisher"]
    require_swm = bool(publisher.get("require_swm_verification", False))
    vm_only = publisher.get("swm_restore_mode", "skip") == "skip" and not require_swm
    recoverable_vm_only = 0
    recoverable_pre_publish = 0
    with state.transaction() as db:
        for asset in db.execute("SELECT * FROM assets WHERE bundle_id=? ORDER BY ordinal", (bundle_id,)).fetchall():
            record = (registry.get("batches") or {}).get(asset["batch_name"]) or {}
            has_finalized_vm = bool(
                record.get("txHash")
                or record.get("ual")
                or record.get("dkgFinalizationMode") == "noop"
            )
            swm_verified = bool(record.get("swmReplicatedAt") or record.get("swmVerifiedAt"))
            vm_only_complete = vm_only and bool(record.get("swmRestoreSkippedAt"))
            is_finalized = (
                record.get("status") == "finalized"
                and has_finalized_vm
                and (swm_verified if require_swm else vm_only_complete)
            )
            swm_restore_error_after_vm = (
                vm_only
                and has_finalized_vm
                and record.get("finalizedAt")
                and (record.get("lastError") or {}).get("phase") == "swm-restore"
            )
            pre_publish_rejection = (
                record.get("status") == "shared"
                and not record.get("publishStartedAt")
                and not has_finalized_vm
                and (record.get("lastError") or {}).get("phase") == "publish"
            )
            if is_finalized:
                finalized += 1
                db.execute(
                    """UPDATE assets SET status='finalized',finalized_at=?,tx_hash=?,ual=?
                       WHERE bundle_id=? AND ordinal=?""",
                    (
                        record.get("swmReplicatedAt") or record.get("finalizedAt") or utcnow(),
                        record.get("txHash"), record.get("ual"), bundle_id, asset["ordinal"],
                    ),
                )
            elif swm_restore_error_after_vm:
                # The paid VM operation is definitive. In explicit VM-only mode
                # publish.mjs can safely resume, record swmRestoreSkippedAt, and
                # continue without sending this asset to the paid endpoint again.
                recoverable_vm_only += 1
                db.execute(
                    "UPDATE assets SET status='pending' WHERE bundle_id=? AND ordinal=?",
                    (bundle_id, asset["ordinal"]),
                )
            elif pre_publish_rejection:
                # The reviewed publish.mjs clears publishStartedAt and returns
                # the record to shared only for a definitive rejection before
                # blockchain submission. It will repeat its chain check before
                # making a new paid call, so this state is restart-safe.
                recoverable_pre_publish += 1
                db.execute(
                    "UPDATE assets SET status='pending' WHERE bundle_id=? AND ordinal=?",
                    (bundle_id, asset["ordinal"]),
                )
            elif record.get("publishStartedAt") and not publisher_active:
                ambiguous += 1
                db.execute(
                    "UPDATE assets SET status='ambiguous' WHERE bundle_id=? AND ordinal=?",
                    (bundle_id, asset["ordinal"]),
                )
        total = int(db.execute("SELECT COUNT(*) AS n FROM assets WHERE bundle_id=?", (bundle_id,)).fetchone()["n"])
        done = int(db.execute(
            "SELECT COUNT(*) AS n FROM assets WHERE bundle_id=? AND status='finalized'", (bundle_id,)
        ).fetchone()["n"])
        if ambiguous:
            db.execute("UPDATE bundles SET state='ambiguous' WHERE bundle_id=?", (bundle_id,))
        elif total and done == total:
            completed_at = max(
                row["finalized_at"]
                for row in db.execute("SELECT finalized_at FROM assets WHERE bundle_id=?", (bundle_id,)).fetchall()
            )
            db.execute("UPDATE bundles SET state='published',published_at=? WHERE bundle_id=?", (completed_at, bundle_id))
            db.execute("UPDATE observations SET state='published',published_at=? WHERE bundle_id=?", (completed_at, bundle_id))
        elif recoverable_vm_only or recoverable_pre_publish:
            db.execute(
                "UPDATE bundles SET state='publishing' WHERE bundle_id=? AND state IN ('ambiguous','error')",
                (bundle_id,),
            )
    return {"finalized": finalized, "ambiguous": ambiguous}


def reconcile_all(config: Mapping[str, Any], state: State) -> Dict[str, Any]:
    result = {"bundles": 0, "finalized": 0, "ambiguous": 0}
    for row in state.list_bundles(("approved", "publishing", "ambiguous", "error")):
        current = reconcile_bundle(config, state, row["bundle_id"])
        result["bundles"] += 1
        result["finalized"] += current["finalized"]
        result["ambiguous"] += current["ambiguous"]
    return result


@contextlib.contextmanager
def singleton_lock(
    config: Mapping[str, Any], name: str, *, wait: bool = False,
) -> Iterator[None]:
    path = _state_dir(config) / "locks" / f"{name}.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+", encoding="utf-8") as handle:
        try:
            flags = fcntl.LOCK_EX if wait else fcntl.LOCK_EX | fcntl.LOCK_NB
            fcntl.flock(handle.fileno(), flags)
        except BlockingIOError as exc:
            raise RuntimeError(f"{name} is already running") from exc
        handle.seek(0)
        handle.truncate()
        handle.write(json.dumps({"pid": os.getpid(), "started_at": utcnow()}) + "\n")
        handle.flush()
        yield


def publish_once(
    config: Mapping[str, Any], state: State, log: AuditLog, *, bundle_id: Optional[str] = None,
) -> Dict[str, Any]:
    if not config["publisher"].get("enabled", False):
        raise RuntimeError("publisher.enabled is false; paid publishing is disabled")
    # These checks happen before a node preflight and before any paid action.
    _verify_publisher_boundary(config)
    _require_fresh_graph_sync(config, state)
    # Graph synchronization and VM publication both put sustained load on the
    # same local Blazegraph process. Keep distinct singleton locks for duplicate
    # worker protection, then serialize only DKG-heavy work across worker types.
    with singleton_lock(config, "publisher"), singleton_lock(
        config, "dkg-workload", wait=True,
    ):
        reconciliation = reconcile_all(config, state)
        state.expire_bundles()
        rows = (
            [state.bundle_row(bundle_id)]
            if bundle_id
            else state.list_bundles(("approved", "publishing"))
        )
        if not rows:
            status = "waiting_reconciliation" if reconciliation["ambiguous"] else "idle"
            return {"status": status, "reconciliation": reconciliation}
        row = rows[0]
        if row["state"] not in {"approved", "publishing"}:
            raise RuntimeError(f"bundle {row['bundle_id']} is {row['state']}, not publishable")
        review = verify_bundle(config, row)
        _require_live_approval_preflight(row)
        unfinished = int(state.db.execute(
            "SELECT COALESCE(SUM(record_count),0) AS n FROM assets WHERE bundle_id=? AND status<>'finalized'",
            (row["bundle_id"],),
        ).fetchone()["n"])
        used = state.published_today()
        limit = int(config["limits"]["daily_publish_records"])
        if used + unfinished > limit:
            return {"status": "daily_limit", "used": used, "remaining": limit - used, "queued": unfinished}

        bundle_id = str(row["bundle_id"])
        if row["state"] == "approved":
            graph_check = assert_bundle_absent_from_graph(config, state, bundle_id)
            log.emit(
                "bundle_graph_check_complete", bundle_id=bundle_id,
                checked=graph_check["checked"], strategy=graph_check["strategy"],
                message=f"confirmed {graph_check['checked']} approved indicators are absent from the graph",
            )
        env = _publisher_env(config, bundle_id, int(row["record_count"]))
        state.db.execute("UPDATE bundles SET state='publishing',last_error=NULL WHERE bundle_id=?", (bundle_id,))
        log.emit("publisher_preflight", bundle_id=bundle_id, message=f"preflighting approved {bundle_id}")
        try:
            preflight = _run_node(_publisher_dir(config), "publish.mjs", ["--preflight"], env=env)
            match = re.search(r"paid confirmation token:\s*(\S+)", preflight.stdout)
            if not match:
                raise RuntimeError("publisher preflight did not return a confirmation token")
            token = match.group(1)
            _run_node(
                _publisher_dir(config), "publish.mjs", ["--publish", "--confirm", token],
                env=env, timeout=int(config["publisher"].get("timeout_seconds", 86400)),
            )
            result = reconcile_bundle(config, state, bundle_id)
            final_row = state.bundle_row(bundle_id)
            if final_row["state"] != "published":
                raise RuntimeError("publisher returned success but required VM verification is incomplete")
            log.emit(
                "bundle_published", bundle_id=bundle_id, records=row["record_count"],
                assets=row["asset_count"], manifest_sha256=review["batchManifestSha256"],
                message=f"published and verified {bundle_id}",
            )
            return {"status": "published", "bundle_id": bundle_id, **result}
        except Exception as exc:
            current = reconcile_bundle(config, state, bundle_id)
            # Preserve the operator-facing reason even when the conservative
            # reconciliation guard marks a started paid call ambiguous.
            # Ambiguous controls retry policy; it must not erase diagnostics.
            error_text = str(exc)[-2000:]
            if not current["ambiguous"] and state.bundle_row(bundle_id)["state"] != "published":
                state.db.execute(
                    "UPDATE bundles SET state='error',last_error=? WHERE bundle_id=?",
                    (error_text, bundle_id),
                )
            else:
                state.db.execute(
                    "UPDATE bundles SET last_error=? WHERE bundle_id=?",
                    (error_text, bundle_id),
                )
            log.emit(
                "publisher_error", bundle_id=bundle_id, error_type=type(exc).__name__,
                message=f"publisher stopped for {bundle_id}; operator review required",
            )
            raise
