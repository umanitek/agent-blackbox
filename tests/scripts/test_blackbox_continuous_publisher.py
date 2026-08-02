"""Offline contracts for the continuous Blackbox publisher pipeline."""

from __future__ import annotations

import json
import sqlite3
import sys
import time
import types
from pathlib import Path

import pytest


PUBLISHER = Path(__file__).parents[2] / "scripts" / "dkg-kc-publisher"
sys.path.insert(0, str(PUBLISHER))

from continuous.core import (  # noqa: E402
    AuditLog,
    Observation,
    State,
    canonical_json,
    canonicalize_indicator,
    load_config,
    sha256,
)
from continuous.cli import acquire  # noqa: E402
import continuous.cli as cli_module  # noqa: E402
from continuous.dkg_monitor import stabilize_issues  # noqa: E402
import continuous.graph as graph_module  # noqa: E402
import continuous.pipeline as pipeline  # noqa: E402
from continuous.graph import assert_bundle_absent_from_graph, sync_graph_entities  # noqa: E402
from continuous.pipeline import (  # noqa: E402
    build_bundle,
    bundle_export_bytes,
    decide_bundle,
    issue_approval_nonce,
    prepare_approval_preflight,
    publish_once,
    reconcile_bundle,
    request_publish,
    verify_bundle,
)
from continuous.sources import ingest_source  # noqa: E402


def config(tmp_path: Path, **overrides):
    value = {
        "paths": {"state_dir": str(tmp_path / "state"), "publisher_dir": str(PUBLISHER)},
        "limits": {
            "asset_records": 2,
            "approval_bundle_records": 4,
            "minimum_bundle_records": 2,
            "daily_publish_records": 8,
            "max_new_records_per_source_run": 10,
            "max_pending_records": 100,
            "max_source_bytes": 1_000_000,
            "max_source_files": 20,
            "max_line_bytes": 1024,
            "approval_ttl_hours": 24,
        },
        "publisher": {
            "enabled": False,
            "context_graph_id": "0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70/agent-blackbox-vm",
            "epochs": 12,
            "publish_mode": "sync",
            "require_swm_verification": True,
            "verified_incremental_support": False,
            "approved_publish_script_sha256": "",
        },
        "graph_dedupe": {
            "enabled": False,
            "required_for_publishing": True,
            "max_age_hours": 6,
            "query_batch_size": 2,
            "query_timeout_seconds": 10,
        },
        "slack": {
            "enabled": False,
            "workspace_id": "T1",
            "channel_id": "C1",
            "download_base_url": "https://review.example.ts.net/blackbox-review",
            "approver_user_ids": ["U1"],
            "allow_manual_cli_approval": True,
        },
        "ai_discovery": {"enabled": False},
        "sources": [],
    }
    for key, replacement in overrides.items():
        value[key] = replacement
    return value


def observation(source: str, value: str, *, upstream: str | None = None, status: str = "active") -> Observation:
    return Observation.build(
        source_id=source,
        upstream_id=upstream or f"row:{value}",
        source_revision="rev-1",
        original_value=value,
        category="phishing",
        lifecycle_status=status,
        confidence=80,
        severity="high",
        license_id="MIT",
        license_url="https://example.test/license",
        attribution="fixture",
        references=["https://example.test/source"],
        evidence="fixture listing",
        parser_version="fixture-v1",
    )


def test_auto_approve_is_off_by_default_and_requires_paid_mode(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("version: 1\n", encoding="utf-8")
    assert load_config(path)["publisher"]["auto_approve"] is False

    path.write_text(
        "version: 1\npublisher:\n  enabled: false\n  auto_approve: true\n"
        "slack:\n  enabled: true\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="requires publisher.enabled"):
        load_config(path)


@pytest.fixture
def state(tmp_path):
    current = State(tmp_path / "pipeline.sqlite3")
    try:
        yield current
    finally:
        current.close()


def test_state_migrates_superseded_bundle_membership_from_v1(tmp_path):
    path = tmp_path / "migration.sqlite3"
    db = sqlite3.connect(path)
    db.executescript(
        """
        CREATE TABLE schema_meta(version INTEGER NOT NULL);
        INSERT INTO schema_meta(version) VALUES (1);
        CREATE TABLE bundle_observations(
          bundle_id TEXT NOT NULL REFERENCES bundles(bundle_id),
          position INTEGER NOT NULL,
          observation_id TEXT NOT NULL UNIQUE REFERENCES observations(observation_id),
          PRIMARY KEY(bundle_id,position)
        );
        """
    )
    db.close()

    migrated = State(path)
    try:
        assert migrated.db.execute("SELECT version FROM schema_meta").fetchone()["version"] == 2
        unique_indexes = []
        for index in migrated.db.execute("PRAGMA index_list('bundle_observations')").fetchall():
            if index["unique"]:
                columns = tuple(
                    row["name"]
                    for row in migrated.db.execute(f"PRAGMA index_info('{index['name']}')").fetchall()
                )
                unique_indexes.append(columns)
        assert ("observation_id",) not in unique_indexes
        assert ("bundle_id", "observation_id") in unique_indexes
    finally:
        migrated.close()


def test_canonicalization_preserves_url_and_ipv6_semantics():
    assert canonicalize_indicator("EXAMPLE.COM.").value == "example.com"
    assert canonicalize_indicator("https://EXAMPLE.com/a/").value == "https://example.com/a/"
    assert canonicalize_indicator("https://EXAMPLE.com/a").value == "https://example.com/a"
    assert canonicalize_indicator("2001:0db8::1").value == "2001:db8::1"
    assert canonicalize_indicator("[2001:db8::1]:443").value == "[2001:db8::1]:443"
    with pytest.raises(ValueError, match="credentials"):
        canonicalize_indicator("https://user:secret@example.com/a")


def test_blazegraph_monitor_debounces_transient_timeout_and_recovery():
    state = {}
    observed = {"blazegraph": "timed out"}

    for expected_count in (1, 2):
        current, failures, recoveries = stabilize_issues(state, observed)
        assert current == {}
        assert failures == {"blazegraph": expected_count}
        assert recoveries == {}
        state = {"issues": current, "failure_counts": failures, "recovery_counts": recoveries}

    current, failures, recoveries = stabilize_issues(state, observed)
    assert current == observed
    state = {"issues": current, "failure_counts": failures, "recovery_counts": recoveries}

    current, failures, recoveries = stabilize_issues(state, {})
    assert current == observed
    assert recoveries == {"blazegraph": 1}
    state = {"issues": current, "failure_counts": failures, "recovery_counts": recoveries}

    current, failures, recoveries = stabilize_issues(state, {})
    assert current == {}
    assert failures == {}
    assert recoveries == {}


def test_monitor_keeps_service_failure_immediate():
    observed = {"service": "dkg-node.service is failed"}
    current, failures, recoveries = stabilize_issues({}, observed)

    assert current == observed
    assert failures == {"service": 1}
    assert recoveries == {}


def test_exact_event_dedupe_preserves_cross_source_corroboration(state):
    first = observation("source-a", "evil.example")
    corroborating = observation("source-b", "EVIL.EXAMPLE.")

    assert state.insert_observation(first) == "inserted"
    assert state.insert_observation(first) == "duplicate"
    assert state.insert_observation(corroborating) == "canonical_match"
    rows = state.db.execute("SELECT * FROM observations ORDER BY source_id").fetchall()

    assert len(rows) == 2
    assert rows[0]["canonical_id"] == rows[1]["canonical_id"]
    assert rows[0]["observation_id"] != rows[1]["observation_id"]


def test_bundle_is_immutable_checksummed_and_split_into_assets(tmp_path, state):
    cfg = config(tmp_path)
    for index in range(4):
        state.insert_observation(observation("source-a", f"evil-{index}.example"))

    bundle = build_bundle(cfg, state, AuditLog(tmp_path, "bundle-test"))
    assert bundle is not None
    row = state.bundle_row(bundle["bundle_id"])
    review = verify_bundle(cfg, row)

    assert [asset["records"] for asset in review["assets"]] == [2, 2]
    assert row["record_count"] == 4
    assert row["asset_count"] == 2
    assert state.pending_count() == 0
    progress = json.loads((Path(bundle["path"]) / "progress.json").read_text())
    assert progress["phase"] == "dry-run-complete"

    manifest = Path(bundle["path"]) / "approval-manifest.json"
    manifest.write_text(manifest.read_text() + " ", encoding="utf-8")
    with pytest.raises(RuntimeError, match="checksum mismatch"):
        verify_bundle(cfg, row)


def test_sequential_bundles_never_repeat_a_canonical_indicator(tmp_path, state):
    cfg = config(tmp_path)
    cfg["limits"].update(approval_bundle_records=2, minimum_bundle_records=2, asset_records=1)
    for source, value in (
        ("source-a", "duplicate.example"),
        ("source-b", "DUPLICATE.EXAMPLE."),
        ("source-a", "first.example"),
        ("source-a", "second.example"),
        ("source-a", "third.example"),
    ):
        state.insert_observation(observation(source, value))

    first = build_bundle(cfg, state, AuditLog(tmp_path, "bundle-first"))
    second = build_bundle(cfg, state, AuditLog(tmp_path, "bundle-second"))

    assert first is not None
    assert second is not None
    bundled_values = [
        row["canonical_value"]
        for row in state.db.execute(
            """SELECT o.canonical_value
               FROM bundle_observations bo
               JOIN observations o ON o.observation_id=bo.observation_id
               JOIN bundles b ON b.bundle_id=bo.bundle_id
               WHERE b.bundle_id IN (?,?)""",
            (first["bundle_id"], second["bundle_id"]),
        ).fetchall()
    ]
    assert len(bundled_values) == 4
    assert len(set(bundled_values)) == 4


def test_slack_approval_binds_user_channel_timestamp_nonce_and_manifest(tmp_path, state):
    cfg = config(tmp_path)
    state.insert_observation(observation("source-a", "evil.example"))
    state.insert_observation(observation("source-a", "second.example"))
    bundle = build_bundle(cfg, state, AuditLog(tmp_path, "approval-test"))
    assert bundle is not None
    preflight = prepare_approval_preflight(cfg, state, bundle["bundle_id"])
    nonce = issue_approval_nonce(cfg, state, bundle["bundle_id"])

    with pytest.raises(PermissionError, match="authorized"):
        decide_bundle(
            cfg, state, bundle["bundle_id"], "approve", actor="U2", source="slack",
            manifest_sha256=bundle["manifest_sha256"], nonce=nonce, workspace="T1", channel="C1",
            action_timestamp=str(time.time()), approval_preflight_sha256=preflight["sha256"],
        )
    with pytest.raises(PermissionError, match="stale"):
        decide_bundle(
            cfg, state, bundle["bundle_id"], "approve", actor="U1", source="slack",
            manifest_sha256=bundle["manifest_sha256"], nonce=nonce, workspace="T1", channel="C1",
            action_timestamp=str(time.time() - 600), approval_preflight_sha256=preflight["sha256"],
        )
    result = decide_bundle(
        cfg, state, bundle["bundle_id"], "approve", actor="U1", source="slack",
        manifest_sha256=bundle["manifest_sha256"], nonce=nonce, workspace="T1", channel="C1",
        action_timestamp=str(time.time()), approval_preflight_sha256=preflight["sha256"],
    )
    assert result["state"] == "approved"
    assert state.bundle_row(bundle["bundle_id"])["nonce_used_at"]
    with pytest.raises(RuntimeError, match="not bundled"):
        decide_bundle(
            cfg, state, bundle["bundle_id"], "approve", actor="U1", source="slack",
            manifest_sha256=bundle["manifest_sha256"], nonce=nonce, workspace="T1", channel="C1",
            action_timestamp=str(time.time()), approval_preflight_sha256=preflight["sha256"],
        )


def test_slack_can_allow_any_authenticated_member_of_configured_channel(tmp_path, state):
    cfg = config(tmp_path)
    cfg["slack"]["allow_any_channel_member"] = True
    state.insert_observation(observation("source-a", "member-one.example"))
    state.insert_observation(observation("source-a", "member-two.example"))
    bundle = build_bundle(cfg, state, AuditLog(tmp_path, "channel-member-test"))
    assert bundle is not None
    preflight = prepare_approval_preflight(cfg, state, bundle["bundle_id"])
    nonce = issue_approval_nonce(cfg, state, bundle["bundle_id"])

    result = decide_bundle(
        cfg, state, bundle["bundle_id"], "approve", actor="U-ANY-MEMBER", source="slack",
        manifest_sha256=bundle["manifest_sha256"], nonce=nonce, workspace="T1", channel="C1",
        action_timestamp=str(time.time()), approval_preflight_sha256=preflight["sha256"],
    )
    assert result["state"] == "approved"


def test_rehearsal_approval_cannot_become_a_paid_publish(tmp_path, state, monkeypatch):
    cfg = config(tmp_path)
    state.insert_observation(observation("source-a", "rehearsal-one.example"))
    state.insert_observation(observation("source-a", "rehearsal-two.example"))
    bundle = build_bundle(cfg, state, AuditLog(tmp_path, "rehearsal-test"))
    assert bundle is not None
    preflight = prepare_approval_preflight(cfg, state, bundle["bundle_id"])
    assert preflight["mode"] == "rehearsal"
    decide_bundle(
        cfg, state, bundle["bundle_id"], "approve", actor="operator", source="cli",
        manifest_sha256=bundle["manifest_sha256"],
    )

    cfg["publisher"]["enabled"] = True
    monkeypatch.setattr(pipeline, "_verify_publisher_boundary", lambda _cfg: None)
    monkeypatch.setattr(pipeline, "_require_fresh_graph_sync", lambda _cfg, _state: None)
    with pytest.raises(RuntimeError, match="rehearsal preflight"):
        publish_once(cfg, state, AuditLog(tmp_path, "rehearsal-publish-test"))


def test_acquisition_survives_slack_reporting_failure(tmp_path, state, monkeypatch):
    cfg = config(tmp_path)
    cfg["slack"]["enabled"] = True
    monkeypatch.setattr("continuous.cli.sync_graph_entities", lambda *_args: {"status": "disabled"})
    monkeypatch.setattr(
        "continuous.cli.ingest_all",
        lambda *_args: {"sources": 1, "inserted": 10_000, "errors": 0},
    )
    monkeypatch.setattr(
        "continuous.cli.build_bundle",
        lambda *_args: {"bundle_id": "bundle-test"},
    )

    def slack_failure(*_args):
        raise RuntimeError("fixture Slack outage")

    monkeypatch.setattr("continuous.cli.post_bundle", slack_failure)
    monkeypatch.setattr("continuous.cli.post_run_summary", slack_failure)

    result = acquire(cfg, state)

    assert result["status"] == "partial"
    assert result["bundles"] == ["bundle-test"]
    assert result["slack_reports"] == [
        {"bundle_id": "bundle-test", "status": "error", "error_type": "RuntimeError"}
    ]
    assert result["slack_summary"] == {"status": "error", "error_type": "RuntimeError"}
    run = state.db.execute("SELECT status,error FROM runs WHERE run_id=?", (result["run_id"],)).fetchone()
    assert dict(run) == {"status": "partial", "error": None}


def test_slack_report_uploads_json_before_enabling_socket_mode_approvals(tmp_path, state, monkeypatch):
    import continuous.slack as slack_module

    cfg = config(tmp_path)
    cfg["slack"].update({"enabled": True, "webhook_url_credential": "slack_webhook_url"})
    state.insert_observation(observation("source-a", "webhook-one.example"))
    state.insert_observation(observation("source-a", "webhook-two.example"))
    state.insert_observation(observation("source-a", "webhook-three.example"))
    state.insert_observation(observation("source-a", "webhook-four.example"))
    bundle = build_bundle(cfg, state, AuditLog(tmp_path, "webhook-test"))
    assert bundle is not None
    api_calls = []
    attachment = {}

    monkeypatch.setattr(slack_module, "read_secret", lambda *_args: "fixture-token")

    def fake_api(_token, method, payload):
        api_calls.append((method, payload))
        return {"ok": True, "channel": "C1", "ts": "123.456"}

    def fake_upload(_slack, bundle_id, title, payload, thread_ts):
        attachment.update(
            bundle_id=bundle_id, title=title, payload=payload, thread_ts=thread_ts,
        )
        return {"ok": True, "files": [{"id": "F1"}]}

    monkeypatch.setattr(slack_module, "_slack_api", fake_api)
    monkeypatch.setattr(slack_module, "_upload_bundle_json", fake_upload)
    result = slack_module.post_bundle(cfg, state, bundle["bundle_id"])

    assert result == {
        "status": "posted", "channel": "C1", "ts": "123.456",
        "transport": "web_api", "attachment_ids": ["F1"],
    }
    assert [method for method, _payload in api_calls] == ["chat.postMessage", "chat.update"]
    pending = api_calls[0][1]
    ready = api_calls[1][1]
    assert pending["channel"] == "C1"
    assert "Uploading approval JSON" in json.dumps(pending["blocks"])
    rendered = json.dumps(ready["blocks"])
    assert "4 phishing threats" in rendered
    assert "4 active phishing indicators: 4 domains from Source-A." in rendered
    assert "Preview:" in rendered
    assert rendered.count("[.]example") == 3
    assert "Manifest SHA-256" not in rendered
    assert "JSON attached in thread" in rendered
    actions = next(block for block in ready["blocks"] if block.get("type") == "actions")
    assert [element["text"]["text"] for element in actions["elements"]] == [
        "Approve", "Decline",
    ]
    exported = json.loads(attachment["payload"])
    assert attachment["bundle_id"] == bundle["bundle_id"]
    assert attachment["thread_ts"] == "123.456"
    assert exported["manifestSha256"] == bundle["manifest_sha256"]
    assert len(exported["threats"]) == 4


def test_auto_publish_slack_report_is_informational_without_actions(tmp_path, state, monkeypatch):
    import continuous.slack as slack_module

    cfg = config(tmp_path)
    cfg["slack"]["enabled"] = True
    for index in range(4):
        state.insert_observation(observation("source-a", f"auto-info-{index}.example"))
    bundle = build_bundle(cfg, state, AuditLog(tmp_path, "auto-info-test"))
    api_calls = []
    monkeypatch.setattr(slack_module, "read_secret", lambda *_args: "fixture-token")
    monkeypatch.setattr(
        slack_module, "_slack_api",
        lambda _token, method, payload: api_calls.append((method, payload))
        or {"ok": True, "channel": "C1", "ts": "123.456"},
    )
    monkeypatch.setattr(
        slack_module, "_upload_bundle_json",
        lambda *_args: {"ok": True, "files": [{"id": "F1"}]},
    )

    result = slack_module.post_bundle(
        cfg, state, bundle["bundle_id"], approval_required=False,
    )

    assert result["status"] == "posted"
    ready_blocks = api_calls[-1][1]["blocks"]
    assert all(block.get("type") != "actions" for block in ready_blocks)
    assert "no manual approval required" in json.dumps(ready_blocks)
    assert state.bundle_row(bundle["bundle_id"])["approval_nonce_hash"] is None


def test_auto_approve_records_audited_decision_after_slack_report(tmp_path, state, monkeypatch):
    cfg = config(tmp_path)
    cfg["publisher"].update({"enabled": True, "auto_approve": True})
    cfg["slack"]["enabled"] = True
    state.insert_observation(observation("source-a", "auto-one.example"))
    state.insert_observation(observation("source-a", "auto-two.example"))
    bundle = build_bundle(cfg, state, AuditLog(tmp_path, "auto-decision-test"))

    def fake_post(_config, current, bundle_id, *, approval_required):
        assert approval_required is False
        row = current.bundle_row(bundle_id)
        snapshot = {
            "mode": "live-read-only", "publisherEnabled": True,
            "manifestSha256": row["manifest_sha256"], "createdAt": "2026-07-28T12:00:00Z",
        }
        current.db.execute(
            """UPDATE bundles SET approval_preflight_sha256=?,approval_preflight_at=?,
               approval_preflight_json=? WHERE bundle_id=?""",
            (
                sha256(canonical_json(snapshot)), snapshot["createdAt"],
                canonical_json(snapshot).decode(), bundle_id,
            ),
        )
        return {"status": "posted"}

    monkeypatch.setattr(cli_module, "post_bundle", fake_post)
    selected = cli_module._auto_approve_next(
        cfg, state, AuditLog(tmp_path, "auto-approve-test"),
    )

    assert selected == bundle["bundle_id"]
    assert state.bundle_row(selected)["state"] == "approved"
    decision = state.db.execute(
        "SELECT actor,source,reason FROM decisions WHERE bundle_id=?", (selected,),
    ).fetchone()
    assert dict(decision) == {
        "actor": "publisher-cron", "source": "auto-publisher",
        "reason": "explicit publisher.auto_approve mode",
    }


def test_auto_approve_quarantines_operator_review_bundle_and_continues(tmp_path, state, monkeypatch):
    cfg = config(tmp_path)
    cfg["publisher"].update({"enabled": True, "auto_approve": True})
    cfg["slack"]["enabled"] = True
    for value in (
        "blocked-one.example", "blocked-two.example",
        "blocked-three.example", "blocked-four.example",
    ):
        state.insert_observation(observation("source-a", value))
    blocked = build_bundle(cfg, state, AuditLog(tmp_path, "blocked-auto-test"))
    state.db.execute(
        "UPDATE bundles SET state='ambiguous' WHERE bundle_id=?", (blocked["bundle_id"],),
    )
    state.insert_observation(observation("source-a", "next-one.example"))
    state.insert_observation(observation("source-a", "next-two.example"))
    queued = build_bundle(cfg, state, AuditLog(tmp_path, "next-auto-test"))

    def fake_post(_config, current, bundle_id, *, approval_required):
        assert approval_required is False
        row = current.bundle_row(bundle_id)
        snapshot = {
            "mode": "live-read-only", "publisherEnabled": True,
            "manifestSha256": row["manifest_sha256"], "createdAt": "2026-07-30T12:00:00Z",
        }
        current.db.execute(
            """UPDATE bundles SET approval_preflight_sha256=?,approval_preflight_at=?,
               approval_preflight_json=? WHERE bundle_id=?""",
            (
                sha256(canonical_json(snapshot)), snapshot["createdAt"],
                canonical_json(snapshot).decode(), bundle_id,
            ),
        )
        return {"status": "posted"}

    monkeypatch.setattr(cli_module, "post_bundle", fake_post)

    selected = cli_module._auto_approve_next(
        cfg, state, AuditLog(tmp_path, "blocked-auto-run"),
    )

    assert selected == queued["bundle_id"]
    assert state.bundle_row(blocked["bundle_id"])["state"] == "ambiguous"
    assert state.bundle_row(queued["bundle_id"])["state"] == "approved"


def test_auto_approve_builds_next_bundle_when_only_candidates_remain(tmp_path, state, monkeypatch):
    cfg = config(tmp_path)
    cfg["publisher"].update({"enabled": True, "auto_approve": True})
    cfg["slack"]["enabled"] = True
    state.insert_observation(observation("source-a", "ambiguous-one.example"))
    state.insert_observation(observation("source-a", "ambiguous-two.example"))
    blocked = build_bundle(cfg, state, AuditLog(tmp_path, "candidate-auto-blocked"))
    state.db.execute(
        "UPDATE bundles SET state='ambiguous' WHERE bundle_id=?", (blocked["bundle_id"],),
    )
    state.insert_observation(observation("source-a", "candidate-one.example"))
    state.insert_observation(observation("source-a", "candidate-two.example"))

    def fake_post(_config, current, bundle_id, *, approval_required):
        assert approval_required is False
        row = current.bundle_row(bundle_id)
        snapshot = {
            "mode": "live-read-only", "publisherEnabled": True,
            "manifestSha256": row["manifest_sha256"], "createdAt": "2026-07-31T06:00:00Z",
        }
        current.db.execute(
            """UPDATE bundles SET approval_preflight_sha256=?,approval_preflight_at=?,
               approval_preflight_json=? WHERE bundle_id=?""",
            (
                sha256(canonical_json(snapshot)), snapshot["createdAt"],
                canonical_json(snapshot).decode(), bundle_id,
            ),
        )
        return {"status": "posted"}

    monkeypatch.setattr(cli_module, "post_bundle", fake_post)

    selected = cli_module._auto_approve_next(
        cfg, state, AuditLog(tmp_path, "candidate-auto-run"),
    )

    assert selected != blocked["bundle_id"]
    assert state.bundle_row(blocked["bundle_id"])["state"] == "ambiguous"
    assert state.bundle_row(selected)["state"] == "approved"
    assert state.db.execute(
        "SELECT COUNT(*) AS n FROM observations WHERE bundle_id=? AND state='bundled'",
        (selected,),
    ).fetchone()["n"] == 2


def test_paid_worker_waits_successfully_when_only_ambiguous_work_remains(tmp_path, state, monkeypatch):
    cfg = config(tmp_path)
    cfg["publisher"].update({"enabled": True, "swm_restore_mode": "skip"})
    state.insert_observation(observation("source-a", "ambiguous-one.example"))
    state.insert_observation(observation("source-a", "ambiguous-two.example"))
    bundle = build_bundle(cfg, state, AuditLog(tmp_path, "ambiguous-wait-test"))
    root = Path(bundle["path"])
    (root / "registry.json").write_text(json.dumps({
        "batches": {
            "batch-001": {
                "status": "error",
                "publishStartedAt": "2026-07-30T10:00:00Z",
                "lastError": {"phase": "publish", "message": "unknown terminal result"},
            },
        },
    }), encoding="utf-8")
    state.db.execute(
        "UPDATE bundles SET state='ambiguous' WHERE bundle_id=?", (bundle["bundle_id"],),
    )
    monkeypatch.setattr(pipeline, "_verify_publisher_boundary", lambda _cfg: None)
    monkeypatch.setattr(pipeline, "_require_fresh_graph_sync", lambda _cfg, _state: None)

    result = publish_once(cfg, state, AuditLog(tmp_path, "ambiguous-wait-run"))

    assert result == {
        "status": "waiting_reconciliation",
        "reconciliation": {"bundles": 1, "finalized": 0, "ambiguous": 1},
    }
    assert state.bundle_row(bundle["bundle_id"])["state"] == "ambiguous"


def test_auto_approve_rebundles_expired_never_published_observations(tmp_path, state, monkeypatch):
    cfg = config(tmp_path)
    cfg["publisher"].update({"enabled": True, "auto_approve": True})
    cfg["slack"]["enabled"] = True
    state.insert_observation(observation("source-a", "expired-one.example"))
    state.insert_observation(observation("source-a", "expired-two.example"))
    expired = build_bundle(cfg, state, AuditLog(tmp_path, "expired-auto-test"))
    state.db.execute(
        "UPDATE bundles SET expires_at='2026-07-29T00:00:00Z' WHERE bundle_id=?",
        (expired["bundle_id"],),
    )

    def fake_post(_config, current, bundle_id, *, approval_required):
        assert approval_required is False
        row = current.bundle_row(bundle_id)
        snapshot = {
            "mode": "live-read-only", "publisherEnabled": True,
            "manifestSha256": row["manifest_sha256"], "createdAt": "2026-07-30T12:00:00Z",
        }
        current.db.execute(
            """UPDATE bundles SET approval_preflight_sha256=?,approval_preflight_at=?,
               approval_preflight_json=? WHERE bundle_id=?""",
            (
                sha256(canonical_json(snapshot)), snapshot["createdAt"],
                canonical_json(snapshot).decode(), bundle_id,
            ),
        )
        return {"status": "posted"}

    monkeypatch.setattr(cli_module, "post_bundle", fake_post)

    selected = cli_module._auto_approve_next(
        cfg, state, AuditLog(tmp_path, "expired-auto-run"),
    )

    assert selected != expired["bundle_id"]
    assert state.bundle_row(expired["bundle_id"])["state"] == "expired"
    assert state.bundle_row(selected)["state"] == "approved"
    assert state.db.execute(
        "SELECT COUNT(*) AS n FROM bundle_observations WHERE bundle_id=?",
        (expired["bundle_id"],),
    ).fetchone()["n"] == 2
    assert state.db.execute(
        "SELECT COUNT(*) AS n FROM observations WHERE bundle_id=? AND state='bundled'",
        (selected,),
    ).fetchone()["n"] == 2


def test_auto_publish_refreshes_a_missing_graph_sync_only_when_work_exists(tmp_path, state, monkeypatch):
    cfg = config(tmp_path)
    cfg["publisher"].update({"enabled": True, "auto_approve": True})
    cfg["graph_dedupe"].update({"enabled": True, "required_for_publishing": True})
    cfg["slack"]["enabled"] = True
    calls = []
    monkeypatch.setattr(
        cli_module, "sync_graph_entities",
        lambda *_args: calls.append("sync") or {
            "status": "complete", "candidates_checked": 2, "existing_entities": 0,
        },
    )

    assert cli_module._refresh_graph_sync_for_auto_publish(
        cfg, state, AuditLog(tmp_path, "no-work-sync"),
    ) is None
    assert calls == []

    state.insert_observation(observation("source-a", "refresh-one.example"))
    state.insert_observation(observation("source-a", "refresh-two.example"))
    build_bundle(cfg, state, AuditLog(tmp_path, "refresh-bundle"))

    result = cli_module._refresh_graph_sync_for_auto_publish(
        cfg, state, AuditLog(tmp_path, "refresh-sync"),
    )

    assert result["status"] == "complete"
    assert calls == ["sync"]


def test_auto_publish_keeps_a_fresh_matching_graph_sync(tmp_path, state, monkeypatch):
    cfg = config(tmp_path)
    cfg["publisher"].update({"enabled": True, "auto_approve": True})
    cfg["graph_dedupe"].update({"enabled": True, "required_for_publishing": True})
    cfg["slack"]["enabled"] = True
    state.insert_observation(observation("source-a", "fresh-one.example"))
    state.insert_observation(observation("source-a", "fresh-two.example"))
    build_bundle(cfg, state, AuditLog(tmp_path, "fresh-bundle"))
    state.db.execute(
        """INSERT INTO graph_sync(
             singleton,synced_at,context_graph_id,rows_seen,entities_seen,views_json
           ) VALUES (1,?,?,?,?,?)""",
        (
            cli_module.utcnow(), cfg["publisher"]["context_graph_id"], 2, 0,
            json.dumps(["confirmed-context-partition"]),
        ),
    )
    monkeypatch.setattr(
        cli_module, "sync_graph_entities",
        lambda *_args: (_ for _ in ()).throw(AssertionError("fresh sync must be reused")),
    )

    assert cli_module._refresh_graph_sync_for_auto_publish(
        cfg, state, AuditLog(tmp_path, "fresh-sync"),
    ) is None


def test_slack_report_never_exposes_actions_when_json_upload_fails(tmp_path, state, monkeypatch):
    import continuous.slack as slack_module

    cfg = config(tmp_path)
    cfg["slack"].update({"enabled": True, "webhook_url_credential": "slack_webhook_url"})
    state.insert_observation(observation("source-a", "upload-one.example"))
    state.insert_observation(observation("source-a", "upload-two.example"))
    bundle = build_bundle(cfg, state, AuditLog(tmp_path, "upload-failure-test"))
    api_calls = []
    monkeypatch.setattr(slack_module, "read_secret", lambda *_args: "fixture-token")

    def fake_api(_token, method, payload):
        api_calls.append((method, payload))
        return {"ok": True, "channel": "C1", "ts": "123.456"}

    monkeypatch.setattr(slack_module, "_slack_api", fake_api)
    monkeypatch.setattr(
        slack_module, "_upload_bundle_json",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("fixture upload failure")),
    )

    with pytest.raises(RuntimeError, match="fixture upload failure"):
        slack_module.post_bundle(cfg, state, bundle["bundle_id"])

    assert [method for method, _payload in api_calls] == ["chat.postMessage", "chat.update"]
    failed_blocks = api_calls[-1][1]["blocks"]
    assert all(block.get("type") != "actions" for block in failed_blocks)
    assert "cannot be approved" in json.dumps(failed_blocks)


def test_slack_json_upload_reads_decoded_slack_response_data(monkeypatch):
    import continuous.slack as slack_module

    class FakeSlackResponse:
        data = {"ok": True, "files": [{"id": "F1"}]}

        def __iter__(self):
            # Matches SDK releases where iterating SlackResponse yields names,
            # which makes dict(response) fail even though the upload succeeded.
            return iter(("ok", "files"))

    class FakeWebClient:
        def __init__(self, **_kwargs):
            pass

        def files_upload_v2(self, **_kwargs):
            return FakeSlackResponse()

    fake_sdk = types.ModuleType("slack_sdk")
    fake_sdk.WebClient = FakeWebClient
    monkeypatch.setitem(sys.modules, "slack_sdk", fake_sdk)
    monkeypatch.setattr(slack_module, "read_secret", lambda *_args: "fixture-token")

    result = slack_module._upload_bundle_json(
        {"channel_id": "C1"}, "bundle-test", "4 phishing threats", b"{}", "123.456",
    )

    assert result == {"ok": True, "files": [{"id": "F1"}]}


def test_publish_completion_posts_short_slack_confirmation(tmp_path, state, monkeypatch):
    import continuous.slack as slack_module

    cfg = config(tmp_path)
    cfg["slack"].update({"enabled": True, "webhook_url_credential": "slack_webhook_url"})
    state.insert_observation(observation("source-a", "published-one.example"))
    state.insert_observation(observation("source-a", "published-two.example"))
    bundle = build_bundle(cfg, state, AuditLog(tmp_path, "publish-message-test"))
    state.db.execute(
        "UPDATE bundles SET state='published',published_at=? WHERE bundle_id=?",
        ("2026-07-26T10:00:00Z", bundle["bundle_id"]),
    )
    captured = {}
    monkeypatch.setattr(slack_module, "read_secret", lambda *_args: "https://example.test/hook")
    monkeypatch.setattr(
        slack_module, "_slack_webhook",
        lambda _url, payload: captured.update(payload) or {"ok": True, "transport": "incoming_webhook"},
    )

    result = slack_module.post_publish_success(cfg, state, bundle["bundle_id"])

    assert result["status"] == "posted"
    assert captured["text"] == "✅ Published 2 phishing threats as 1 knowledge asset."


def test_publish_progress_posts_short_verified_asset_count(tmp_path, state, monkeypatch):
    import continuous.slack as slack_module

    cfg = config(tmp_path)
    cfg["slack"].update({"enabled": True, "webhook_url_credential": "slack_webhook_url"})
    state.insert_observation(observation("source-a", "progress-one.example"))
    state.insert_observation(observation("source-a", "progress-two.example"))
    bundle = build_bundle(cfg, state, AuditLog(tmp_path, "progress-message-test"))
    captured = {}
    monkeypatch.setattr(slack_module, "read_secret", lambda *_args: "https://example.test/hook")
    monkeypatch.setattr(
        slack_module, "_slack_webhook",
        lambda _url, payload: captured.update(payload) or {"ok": True, "transport": "incoming_webhook"},
    )

    slack_module.post_publish_progress(cfg, state, bundle["bundle_id"], 1, 2)

    assert captured["text"] == "⏳ Publishing 2 phishing threats · 1/2 knowledge assets verified."


def test_publish_start_stays_short_without_review_preview(tmp_path, state, monkeypatch):
    import continuous.slack as slack_module

    cfg = config(tmp_path)
    cfg["slack"].update({"enabled": True, "webhook_url_credential": "slack_webhook_url"})
    state.insert_observation(observation("source-a", "preview-one.example"))
    state.insert_observation(observation("source-a", "192.0.2.4"))
    bundle = build_bundle(cfg, state, AuditLog(tmp_path, "start-message-test"))
    captured = {}
    monkeypatch.setattr(slack_module, "read_secret", lambda *_args: "https://example.test/hook")
    monkeypatch.setattr(
        slack_module, "_slack_webhook",
        lambda _url, payload: captured.update(payload) or {"ok": True, "transport": "incoming_webhook"},
    )

    slack_module.post_publish_progress(cfg, state, bundle["bundle_id"], 0, 1)

    assert captured["text"] == "🚀 Publishing 2 phishing threats · 0/1 knowledge assets."


def test_publish_failure_names_storage_quorum_without_operator_boilerplate(tmp_path, state, monkeypatch):
    import continuous.slack as slack_module

    cfg = config(tmp_path)
    cfg["slack"].update({"enabled": True, "webhook_url_credential": "slack_webhook_url"})
    state.insert_observation(observation("source-a", "failed-one.example"))
    state.insert_observation(observation("source-a", "failed-two.example"))
    bundle = build_bundle(cfg, state, AuditLog(tmp_path, "failure-message-test"))
    state.db.execute(
        "UPDATE bundles SET state='ambiguous',last_error=? WHERE bundle_id=?",
        ("storage_ack_insufficient: got 1/3 valid ACKs", bundle["bundle_id"]),
    )
    captured = {}
    monkeypatch.setattr(slack_module, "read_secret", lambda *_args: "https://example.test/hook")
    monkeypatch.setattr(
        slack_module, "_slack_webhook",
        lambda _url, payload: captured.update(payload) or {"ok": True, "transport": "incoming_webhook"},
    )

    slack_module.post_publish_failure(cfg, state, bundle["bundle_id"])

    assert captured["text"] == (
        "❌ Publishing stopped: DKG storage quorum returned 1/3 acknowledgements "
        "before blockchain submission · 0/1 assets verified · no automatic retry."
    )


def test_bundle_download_is_exact_and_fails_on_batch_tampering(tmp_path, state):
    cfg = config(tmp_path)
    for index in range(4):
        state.insert_observation(observation("source-a", f"download-{index}.example"))
    bundle = build_bundle(cfg, state, AuditLog(tmp_path, "download-export-test"))
    exported = json.loads(bundle_export_bytes(cfg, state, bundle["bundle_id"]))

    assert exported["bundleId"] == bundle["bundle_id"]
    assert exported["manifestSha256"] == bundle["manifest_sha256"]
    assert len(exported["threats"]) == 4

    first_batch = Path(bundle["path"]) / "batches" / "batch-001.json"
    first_batch.write_text(first_batch.read_text() + " ", encoding="utf-8")
    with pytest.raises(RuntimeError, match="downloadable batch checksum mismatch"):
        bundle_export_bytes(cfg, state, bundle["bundle_id"])


def test_bundle_manifest_contains_worst_case_inline_storage_ack_proof(tmp_path, state):
    cfg = config(tmp_path)
    state.insert_observation(observation("source-a", "inline-one.example"))
    state.insert_observation(observation("source-a", "inline-two.example"))

    bundle = build_bundle(cfg, state, AuditLog(tmp_path, "inline-size-test"))
    proof = bundle["review"]["inlineStorageAck"]

    assert proof["graphUriPolicy"] == "vm-max-uint96-ka-number"
    assert proof["maxStagingBytes"] == 4 * 1024 * 1024
    assert proof["assets"] == 1
    assert proof["maxAssetBytes"] < proof["maxStagingBytes"]
    assert proof["minHeadroomBytes"] == proof["maxStagingBytes"] - proof["maxAssetBytes"]


def test_live_slack_approval_creates_exact_publish_trigger(tmp_path, state):
    cfg = config(tmp_path)
    state.insert_observation(observation("source-a", "trigger-one.example"))
    state.insert_observation(observation("source-a", "trigger-two.example"))
    bundle = build_bundle(cfg, state, AuditLog(tmp_path, "trigger-test"))
    row = state.bundle_row(bundle["bundle_id"])
    snapshot = {
        "mode": "live-read-only", "publisherEnabled": True,
        "manifestSha256": row["manifest_sha256"], "createdAt": "2026-07-26T10:00:00Z",
    }
    state.db.execute(
        "UPDATE bundles SET state='approved',approval_preflight_sha256=?,approval_preflight_json=? WHERE bundle_id=?",
        (sha256(canonical_json(snapshot)), canonical_json(snapshot).decode(), bundle["bundle_id"]),
    )
    cfg["publisher"]["enabled"] = True

    result = request_publish(cfg, state, bundle["bundle_id"])
    trigger = json.loads((tmp_path / "state" / "publish.trigger").read_text())

    assert result == {"status": "queued", "bundle_id": bundle["bundle_id"]}
    assert trigger["bundleId"] == bundle["bundle_id"]
    assert trigger["manifestSha256"] == bundle["manifest_sha256"]


def test_reconciliation_counts_only_required_vm_swm_verification(tmp_path, state):
    cfg = config(tmp_path)
    for index in range(4):
        state.insert_observation(observation("source-a", f"evil-{index}.example"))
    bundle = build_bundle(cfg, state, AuditLog(tmp_path, "reconcile-test"))
    assert bundle is not None
    state.db.execute("UPDATE bundles SET state='publishing' WHERE bundle_id=?", (bundle["bundle_id"],))
    root = Path(bundle["path"])
    registry = {
        "batches": {
            "batch-001": {
                "status": "finalized", "txHash": "0x1", "ual": "did:dkg:1",
                "finalizedAt": "2026-07-26T10:00:00Z", "swmReplicatedAt": "2026-07-26T10:02:00Z",
            },
            "batch-002": {
                "status": "finalized", "txHash": "0x2", "ual": "did:dkg:2",
                "finalizedAt": "2026-07-26T10:05:00Z", "swmRestoreSkippedAt": "2026-07-26T10:06:00Z",
            },
        }
    }
    (root / "registry.json").write_text(json.dumps(registry), encoding="utf-8")

    result = reconcile_bundle(cfg, state, bundle["bundle_id"])
    assert result == {"finalized": 1, "ambiguous": 0}
    assert state.bundle_row(bundle["bundle_id"])["state"] == "publishing"
    assert state.published_today("2026-07-26") == 2

    registry["batches"]["batch-002"]["swmReplicatedAt"] = "2026-07-26T10:07:00Z"
    (root / "registry.json").write_text(json.dumps(registry), encoding="utf-8")
    reconcile_bundle(cfg, state, bundle["bundle_id"])
    assert state.bundle_row(bundle["bundle_id"])["state"] == "published"
    assert state.published_today("2026-07-26") == 4


def test_progress_reconciliation_does_not_mark_an_active_paid_call_ambiguous(tmp_path, state):
    cfg = config(tmp_path)
    cfg["publisher"].update(swm_restore_mode="skip", require_swm_verification=False)
    state.insert_observation(observation("source-a", "inflight-one.example"))
    state.insert_observation(observation("source-a", "inflight-two.example"))
    bundle = build_bundle(cfg, state, AuditLog(tmp_path, "inflight-test"))
    state.db.execute(
        "UPDATE bundles SET state='publishing' WHERE bundle_id=?", (bundle["bundle_id"],),
    )
    root = Path(bundle["path"])
    (root / "registry.json").write_text(
        json.dumps(
            {
                "batches": {
                    "batch-001": {
                        "status": "publishing", "publishStartedAt": "2026-07-28T10:00:00Z",
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    active = reconcile_bundle(cfg, state, bundle["bundle_id"], publisher_active=True)

    assert active == {"finalized": 0, "ambiguous": 0}
    assert state.bundle_row(bundle["bundle_id"])["state"] == "publishing"
    assert state.db.execute(
        "SELECT status FROM assets WHERE bundle_id=? AND ordinal=1", (bundle["bundle_id"],)
    ).fetchone()["status"] == "pending"

    stopped = reconcile_bundle(cfg, state, bundle["bundle_id"])

    assert stopped == {"finalized": 0, "ambiguous": 1}
    assert state.bundle_row(bundle["bundle_id"])["state"] == "ambiguous"


def test_reconciliation_resumes_a_definitive_pre_publish_rejection(tmp_path, state):
    cfg = config(tmp_path)
    cfg["publisher"].update(swm_restore_mode="skip", require_swm_verification=False)
    state.insert_observation(observation("source-a", "quorum-one.example"))
    state.insert_observation(observation("source-a", "quorum-two.example"))
    bundle = build_bundle(cfg, state, AuditLog(tmp_path, "quorum-test"))
    state.db.execute(
        "UPDATE bundles SET state='error' WHERE bundle_id=?", (bundle["bundle_id"],),
    )
    root = Path(bundle["path"])
    (root / "registry.json").write_text(
        json.dumps(
            {
                "batches": {
                    "batch-001": {
                        "status": "shared",
                        "lastError": {
                            "phase": "publish", "status": 500,
                            "message": "storage_ack_timeout: only 2/3 ACKs received within 120000ms",
                        },
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    result = reconcile_bundle(cfg, state, bundle["bundle_id"])

    assert result == {"finalized": 0, "ambiguous": 0}
    assert state.bundle_row(bundle["bundle_id"])["state"] == "publishing"
    assert state.db.execute(
        "SELECT status FROM assets WHERE bundle_id=? AND ordinal=1", (bundle["bundle_id"],)
    ).fetchone()["status"] == "pending"


def test_vm_only_reconciliation_resumes_after_post_vm_swm_error(tmp_path, state):
    cfg = config(tmp_path)
    cfg["publisher"].update(
        swm_restore_mode="skip",
        require_swm_verification=False,
    )
    for index in range(4):
        state.insert_observation(observation("source-a", f"vm-only-{index}.example"))
    bundle = build_bundle(cfg, state, AuditLog(tmp_path, "vm-only-reconcile-test"))
    assert bundle is not None
    state.db.execute("UPDATE bundles SET state='ambiguous' WHERE bundle_id=?", (bundle["bundle_id"],))
    root = Path(bundle["path"])
    registry = {
        "batches": {
            "batch-001": {
                "status": "error",
                "publishStartedAt": "2026-07-26T10:00:00Z",
                "finalizedAt": "2026-07-26T10:01:00Z",
                "txHash": "0x1",
                "ual": "did:dkg:1",
                "lastError": {"phase": "swm-restore", "message": "fixture mismatch"},
            },
            "batch-002": {"status": "pending"},
        }
    }
    (root / "registry.json").write_text(json.dumps(registry), encoding="utf-8")

    result = reconcile_bundle(cfg, state, bundle["bundle_id"])

    assert result == {"finalized": 0, "ambiguous": 0}
    assert state.bundle_row(bundle["bundle_id"])["state"] == "publishing"
    assert state.db.execute(
        "SELECT status FROM assets WHERE bundle_id=? AND ordinal=1", (bundle["bundle_id"],)
    ).fetchone()["status"] == "pending"
    assert state.published_today("2026-07-26") == 0

    registry["batches"]["batch-001"].update(
        status="finalized",
        swmRestoreMode="skipped-vm-only",
        swmRestoreSkippedAt="2026-07-26T10:02:00Z",
    )
    registry["batches"]["batch-001"].pop("lastError")
    (root / "registry.json").write_text(json.dumps(registry), encoding="utf-8")

    result = reconcile_bundle(cfg, state, bundle["bundle_id"])

    assert result == {"finalized": 1, "ambiguous": 0}
    assert state.bundle_row(bundle["bundle_id"])["state"] == "publishing"
    assert state.published_today("2026-07-26") == 2


def test_paid_worker_is_disabled_by_default(tmp_path, state):
    cfg = config(tmp_path)
    with pytest.raises(RuntimeError, match="paid publishing is disabled"):
        publish_once(cfg, state, AuditLog(tmp_path, "publish-disabled"))


def test_paid_worker_requires_exact_reviewed_publisher_hash(tmp_path, state):
    cfg = config(tmp_path)
    cfg["publisher"].update(
        enabled=True,
        verified_incremental_support=True,
        approved_publish_script_sha256="0" * 64,
    )
    with pytest.raises(RuntimeError, match="not the reviewed paid boundary"):
        publish_once(cfg, state, AuditLog(tmp_path, "publish-hash"))


def test_graph_inventory_is_monotonic_and_filters_existing_canonical(tmp_path, state, monkeypatch):
    cfg = config(tmp_path)
    cfg["publisher"].update(
        context_graph_id="0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70/agent-blackbox-vm",
        context_graph_onchain_id=14,
    )
    cfg["graph_dedupe"]["enabled"] = True
    state.insert_observation(observation("source-a", "existing.example"))
    state.insert_observation(observation("source-a", "new.example"))
    state.insert_observation(observation("source-b", "NEW.EXAMPLE."))
    monkeypatch.setattr("continuous.graph._token", lambda _config: "test-token")
    monkeypatch.setattr("continuous.graph._probe_confirmed_graph", lambda _config, _token: None)
    monkeypatch.setattr(
        "continuous.graph._query_values",
        lambda _config, _token_value, values: {"existing.example"} & set(values),
    )

    result = sync_graph_entities(cfg, state, AuditLog(tmp_path, "graph-sync"))
    assert result["candidates_checked"] == 2
    assert result["existing_entities"] == 1
    assert state.graph_sync_row()["context_graph_id"] == cfg["publisher"]["context_graph_id"]

    candidates = state.bundle_candidates(10)
    assert [item.canonical_value for item in candidates] == ["new.example"]

    monkeypatch.setattr("continuous.graph._query_values", lambda *_args: set())
    sync_graph_entities(cfg, state, AuditLog(tmp_path, "graph-sync-2"))
    candidates = state.bundle_candidates(10)
    assert [item.canonical_value for item in candidates] == ["new.example"]


def test_graph_query_retries_transient_transport_failures(tmp_path, monkeypatch):
    cfg = config(tmp_path)
    cfg["graph_dedupe"].update(query_attempts=3, query_retry_delay_seconds=2)
    attempts = []
    sleeps = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self):
            return b'{"results":{"bindings":[]}}'

    def urlopen(*_args, **_kwargs):
        attempts.append(1)
        if len(attempts) < 3:
            raise TimeoutError("busy")
        return Response()

    monkeypatch.setattr(graph_module.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(graph_module.time, "sleep", sleeps.append)

    result = graph_module._query(cfg, "token", "SELECT * WHERE {}")

    assert result == {"results": {"bindings": []}}
    assert len(attempts) == 3
    assert sleeps == [2, 4]


def test_live_bundle_graph_check_fails_closed_on_existing_indicator(tmp_path, state, monkeypatch):
    cfg = config(tmp_path)
    cfg["publisher"].update(
        context_graph_id="0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70/agent-blackbox-vm",
        context_graph_onchain_id=14,
    )
    cfg["graph_dedupe"]["enabled"] = True
    state.insert_observation(observation("source-a", "existing.example"))
    state.insert_observation(observation("source-a", "new.example"))
    bundle = build_bundle(cfg, state, AuditLog(tmp_path, "bundle-graph-check"))
    monkeypatch.setattr("continuous.graph._token", lambda _config: "test-token")
    monkeypatch.setattr(
        "continuous.graph._query_values",
        lambda _config, _token_value, values: {"existing.example"} & set(values),
    )

    with pytest.raises(RuntimeError, match="superseded because 1 canonical indicators"):
        assert_bundle_absent_from_graph(cfg, state, bundle["bundle_id"])
    assert state.bundle_row(bundle["bundle_id"])["state"] == "superseded"
    assert state.db.execute(
        "SELECT state FROM observations WHERE canonical_value='existing.example'"
    ).fetchone()["state"] == "graph_duplicate"
    assert [item.canonical_value for item in state.bundle_candidates(10)] == ["new.example"]

    state.insert_observation(observation("source-b", "replacement.example"))
    replacement = build_bundle(cfg, state, AuditLog(tmp_path, "replacement-bundle"))
    assert replacement is not None
    assert state.bundle_row(replacement["bundle_id"])["record_count"] == 2


def test_bundle_keeps_incomplete_asset_remainder_queued(tmp_path, state):
    cfg = config(tmp_path)
    for index in range(3):
        state.insert_observation(observation("source-a", f"remainder-{index}.example"))
    bundle = build_bundle(cfg, state, AuditLog(tmp_path, "bundle-alignment"))
    assert bundle is not None
    assert state.bundle_row(bundle["bundle_id"])["record_count"] == 2
    assert state.pending_count() == 1


def test_git_line_adapter_resumes_cursor_and_records_removal(tmp_path, state, monkeypatch):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    feed = checkout / "active.txt"
    feed.write_text("# comment\none.example # analyst note\ntwo.example\nthree.example\n", encoding="utf-8")
    revision = {"value": "rev-1"}

    def snapshot(_source, _state_dir, cursor):
        current = revision["value"]
        is_new = cursor.get("last_complete_revision") != current
        return checkout, current, is_new

    monkeypatch.setattr("continuous.sources._snapshot_checkout", snapshot)
    source = {
        "id": "fixture", "enabled": True, "adapter": "git_lines",
        "line_parser": "maltrail",
        "repository": "https://github.com/example/feed.git", "paths": ["active.txt"],
        "category": "phishing", "confidence": 70, "severity": "high",
        "auto_candidate": True, "publish_removals": True, "max_records_per_run": 2,
        "license": {
            "id": "MIT", "url": "https://example.test/license", "attribution": "fixture",
            "redistribution_approved": True,
        },
    }
    cfg = config(tmp_path)
    log = AuditLog(tmp_path, "source-test")

    first = ingest_source(source, cfg, state, log)
    assert first["inserted"] == 2
    cursor = json.loads(state.db.execute("SELECT cursor_json FROM source_state").fetchone()[0])
    assert cursor["complete"] is False

    second = ingest_source(source, cfg, state, log)
    assert second["inserted"] == 1
    cursor = json.loads(state.db.execute("SELECT cursor_json FROM source_state").fetchone()[0])
    assert cursor["complete"] is True

    feed.write_text("one.example # updated note\nthree.example\n", encoding="utf-8")
    revision["value"] = "rev-2"
    source["max_records_per_run"] = 10
    third = ingest_source(source, cfg, state, log)
    assert third["removed"] == 1
    inactive = state.db.execute(
        "SELECT COUNT(*) FROM observations WHERE lifecycle_status='inactive'"
    ).fetchone()[0]
    assert inactive == 1
