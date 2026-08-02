"""Operator CLI and scheduler entrypoint for the continuous pipeline."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import threading
import uuid
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from .core import AuditLog, State, load_config, parse_time, utcnow
from .discovery import discover
from .downloads import serve_downloads
from .graph import required_sync_strategy, sync_graph_entities
from .pipeline import (
    build_bundle,
    decide_bundle,
    prepare_approval_preflight,
    publish_once,
    reconcile_all,
    reconcile_bundle,
    singleton_lock,
    verify_bundle,
)
from .slack import (
    post_bundle,
    post_publish_failure,
    post_publish_progress,
    post_publish_success,
    post_run_summary,
    run_socket_listener,
)
from .sources import ingest_all


def _state(config: Mapping[str, Any]) -> State:
    return State(Path(str(config["paths"]["state_dir"])) / "pipeline.sqlite3")


def _run_id(kind: str) -> str:
    return f"{kind}-{uuid.uuid4().hex[:16]}"


def _json(value: Any) -> None:
    print(json.dumps(value, sort_keys=True, indent=2, default=str))


def _safe_slack_call(log: AuditLog, event: str, callback, *args: Any) -> Dict[str, Any]:
    """Keep acquisition durable when the optional reporting channel is down."""
    try:
        return callback(*args)
    except Exception as exc:
        log.emit(
            event, error_type=type(exc).__name__,
            message="Slack reporting failed; durable acquisition state was preserved",
        )
        return {"status": "error", "error_type": type(exc).__name__}


def acquire(config: Mapping[str, Any], state: State) -> Dict[str, Any]:
    run_id = _run_id("acquire")
    log = AuditLog(Path(str(config["paths"]["state_dir"])), run_id)
    state.begin_run(run_id, "acquire")
    metrics: Dict[str, Any] = {}
    try:
        with singleton_lock(config, "acquire"):
            state.expire_bundles()
            if config["ai_discovery"].get("enabled", False):
                try:
                    metrics["ai_discovery"] = discover(config, state, log)
                except Exception as exc:
                    # Source discovery is advisory and must never prevent the
                    # deterministic reviewed feeds from being acquired.
                    metrics["ai_discovery"] = {
                        "status": "error", "error_type": type(exc).__name__,
                    }
                    log.emit(
                        "ai_discovery_error", error_type=type(exc).__name__,
                        message="AI source discovery failed; reviewed acquisition continues",
                    )
            metrics["acquisition"] = ingest_all(config, state, log)
            # Check values fetched in this same run before any can enter an
            # immutable approval bundle. This query and paid VM publication
            # share Blazegraph, so wait for any active publisher before issuing
            # the candidate-bound query workload.
            with singleton_lock(config, "dkg-workload", wait=True):
                metrics["graph_sync"] = sync_graph_entities(config, state, log)
            metrics["bundles"] = []
            metrics["slack_reports"] = []
            max_bundles = int(config.get("scheduler", {}).get("max_bundles_per_run", 1))
            for _index in range(max_bundles):
                bundle = build_bundle(config, state, log)
                if bundle is None:
                    break
                metrics["bundles"].append(bundle["bundle_id"])
                if config["slack"].get("enabled", False):
                    report = _safe_slack_call(
                        log, "slack_bundle_post_error", post_bundle,
                        config, state, bundle["bundle_id"],
                    )
                    metrics["slack_reports"].append({"bundle_id": bundle["bundle_id"], **report})
            metrics["state"] = state.stats()
            status = "partial" if (
                metrics["acquisition"].get("errors")
                or any(report.get("status") == "error" for report in metrics["slack_reports"])
            ) else "complete"
            metrics["slack_summary"] = _safe_slack_call(
                log, "slack_summary_post_error", post_run_summary,
                config, {"run_id": run_id, "status": status, **metrics["state"]},
            )
            if metrics["slack_summary"].get("status") == "error":
                status = "partial"
            state.finish_run(run_id, status, metrics)
            return {"run_id": run_id, "status": status, **metrics}
    except RuntimeError as exc:
        if "already running" in str(exc):
            metrics = {"status": "skipped_locked", "reason": str(exc)}
            state.finish_run(run_id, "skipped_locked", metrics)
            log.emit("skipped_locked", message=str(exc))
            return {"run_id": run_id, **metrics}
        state.finish_run(run_id, "error", metrics, str(exc))
        raise
    except Exception as exc:
        state.finish_run(run_id, "error", metrics, str(exc))
        raise


def _publish_and_report(
    config: Mapping[str, Any], state: State, *, bundle_id: Optional[str] = None,
) -> Dict[str, Any]:
    run_id = _run_id("publish")
    log = AuditLog(Path(config["paths"]["state_dir"]), run_id)
    if bundle_id is None and config["publisher"].get("auto_approve", False):
        # Recover durable, explicitly retry-safe states before selecting work.
        # No DKG call or paid action occurs during this reconciliation.
        reconcile_all(config, state)
        _refresh_graph_sync_for_auto_publish(config, state, log)
        bundle_id = _auto_approve_next(config, state, log)
    stop_progress = threading.Event()
    progress_thread: Optional[threading.Thread] = None
    if bundle_id:
        progress_thread = threading.Thread(
            target=_report_publish_progress,
            args=(config, Path(state.path), bundle_id, log, stop_progress),
            name=f"blackbox-progress-{bundle_id}", daemon=True,
        )
        progress_thread.start()
    try:
        result = publish_once(config, state, log, bundle_id=bundle_id)
    except Exception:
        stop_progress.set()
        if progress_thread:
            progress_thread.join(timeout=5)
        if bundle_id:
            _safe_slack_call(
                log, "slack_publish_failure_error", post_publish_failure,
                config, state, bundle_id,
            )
        raise
    stop_progress.set()
    if progress_thread:
        progress_thread.join(timeout=5)
    if result.get("status") == "published":
        result["slack"] = _safe_slack_call(
            log, "slack_publish_success_error", post_publish_success,
            config, state, result["bundle_id"],
        )
    return result


def _auto_publish_has_work(config: Mapping[str, Any], state: State) -> bool:
    if state.list_bundles(("approved", "publishing", "ambiguous", "error")):
        return True
    state.expire_bundles()
    bundled = state.list_bundles(("bundled",))
    if not bundled:
        return False
    used = state.published_today()
    limit = int(config["limits"]["daily_publish_records"])
    return used + int(bundled[0]["record_count"]) <= limit


def _graph_sync_is_fresh(config: Mapping[str, Any], state: State) -> bool:
    graph = config.get("graph_dedupe") or {}
    if not graph.get("required_for_publishing", True):
        return True
    if not graph.get("enabled", False):
        return False
    row = state.graph_sync_row()
    if row is None:
        return False
    if str(row["context_graph_id"]) != str(config["publisher"].get("context_graph_id") or ""):
        return False
    try:
        strategies = json.loads(str(row["views_json"]))
        age = parse_time(utcnow()) - parse_time(str(row["synced_at"]))
    except (TypeError, ValueError, json.JSONDecodeError):
        return False
    return (
        required_sync_strategy() in strategies
        and age.total_seconds() <= int(graph.get("max_age_hours", 6)) * 3600
    )


def _refresh_graph_sync_for_auto_publish(
    config: Mapping[str, Any], state: State, log: AuditLog,
) -> Optional[Dict[str, Any]]:
    """Refresh the read-only graph gate when auto mode has publishable work."""
    if not _auto_publish_has_work(config, state) or _graph_sync_is_fresh(config, state):
        return None
    if not config["graph_dedupe"].get("enabled", False):
        raise RuntimeError("auto publishing requires graph deduplication to be enabled")
    with singleton_lock(config, "dkg-workload", wait=True):
        # Another acquisition or publisher may have refreshed it while this
        # process waited for the shared DKG workload lock.
        if _graph_sync_is_fresh(config, state):
            return None
        result = sync_graph_entities(config, state, log)
    log.emit(
        "auto_publish_graph_sync_refreshed",
        candidates_checked=result.get("candidates_checked"),
        existing_entities=result.get("existing_entities"),
        message="refreshed the graph-deduplication gate before automatic publishing",
    )
    return result


def _auto_approve_next(
    config: Mapping[str, Any], state: State, log: AuditLog,
) -> Optional[str]:
    """Approve one oldest bundle through an explicit, audited operator mode."""
    existing = state.list_bundles(("approved", "publishing"))
    if existing:
        return str(existing[0]["bundle_id"])
    # Keep an unknown paid result quarantined without letting it permanently
    # block unrelated immutable bundles. Every later bundle is independently
    # graph-checked and still runs under the singleton paid-worker lock.
    state.expire_bundles()
    bundled = state.list_bundles(("bundled",))
    if not bundled:
        requeued = state.requeue_expired_observations()
        rebuilt = build_bundle(config, state, log)
        if requeued:
            log.emit(
                "expired_bundle_observations_requeued",
                observations=requeued,
                replacement_bundle=(rebuilt or {}).get("bundle_id"),
                message=(
                    f"requeued {requeued} observations from expired manifests "
                    "and built a fresh immutable bundle"
                ),
            )
        bundled = state.list_bundles(("bundled",))
    if not bundled:
        return None
    row = bundled[0]
    used = state.published_today()
    limit = int(config["limits"]["daily_publish_records"])
    if used + int(row["record_count"]) > limit:
        return None
    bundle_id = str(row["bundle_id"])
    if config["slack"].get("enabled", False):
        report = post_bundle(config, state, bundle_id, approval_required=False)
        if report.get("status") != "posted":
            raise RuntimeError("auto-approval requires a successful Slack JSON report")
    else:
        # Validation rejects this combination in production. Keep the preflight
        # for direct test/config callers so the helper still fails closed.
        prepare_approval_preflight(config, state, bundle_id)
    decision = decide_bundle(
        config, state, bundle_id, "approve", actor="publisher-cron",
        source="auto-publisher", reason="explicit publisher.auto_approve mode",
        manifest_sha256=str(row["manifest_sha256"]),
    )
    log.emit(
        "bundle_auto_approved", bundle_id=bundle_id,
        actor=decision["actor"], manifest_sha256=row["manifest_sha256"],
        message=f"auto-approved {bundle_id} after live preflight and Slack JSON report",
    )
    return bundle_id


def _report_publish_progress(
    config: Mapping[str, Any], state_path: Path, bundle_id: str,
    log: AuditLog, stop: threading.Event,
) -> None:
    """Reconcile the live registry and report each newly verified asset."""
    last_finalized: Optional[int] = None
    interval = int(config["slack"].get("progress_interval_seconds", 60))
    while not stop.is_set():
        local = State(state_path)
        try:
            row = local.bundle_row(bundle_id)
            if row["state"] in {"publishing", "published"}:
                reconcile_bundle(config, local, bundle_id, publisher_active=True)
                finalized = int(local.db.execute(
                    "SELECT COUNT(*) AS n FROM assets WHERE bundle_id=? AND status='finalized'",
                    (bundle_id,),
                ).fetchone()["n"])
                total = int(row["asset_count"])
                if finalized != last_finalized:
                    _safe_slack_call(
                        log, "slack_publish_progress_error", post_publish_progress,
                        config, local, bundle_id, finalized, total,
                    )
                    last_finalized = finalized
        except Exception as exc:
            log.emit(
                "publish_progress_poll_error", error_type=type(exc).__name__,
                message="publish progress polling failed; publishing continues",
            )
        finally:
            local.close()
        stop.wait(interval if last_finalized is not None else min(5, interval))


def _publish_triggered(config: Mapping[str, Any], state: State) -> Dict[str, Any]:
    trigger = Path(str(config["paths"]["state_dir"])) / "publish.trigger"
    if not trigger.is_file():
        return {"status": "idle", "reason": "no publish trigger"}
    try:
        payload = json.loads(trigger.read_text(encoding="utf-8"))
        bundle_id = str(payload.get("bundleId") or "")
        row = state.bundle_row(bundle_id)
        if not secrets.compare_digest(
            str(payload.get("manifestSha256") or ""), str(row["manifest_sha256"]),
        ):
            raise RuntimeError("publish trigger manifest does not match the approved bundle")
        return _publish_and_report(config, state, bundle_id=bundle_id)
    finally:
        trigger.unlink(missing_ok=True)


def command_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Continuous Blackbox threat publisher")
    parser.add_argument("--config", required=True, type=Path)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("acquire", help="fetch, normalize, stage, bundle, and report; never publishes")
    sub.add_parser("status", help="show durable pipeline status")
    build = sub.add_parser("bundle", help="build one immutable bundle from existing candidates")
    build.add_argument("--post-slack", action="store_true")
    inspect = sub.add_parser("inspect", help="verify and print a bundle approval manifest")
    inspect.add_argument("bundle_id")
    report = sub.add_parser("post-slack", help="refresh preflight and post a new approval report")
    report.add_argument("bundle_id")
    for name in ("approve", "decline"):
        decision = sub.add_parser(name, help=f"manual test-only {name} decision")
        decision.add_argument("bundle_id")
        decision.add_argument("--actor", required=True)
        decision.add_argument("--reason")
    sub.add_parser("publish-once", help="drain one approved bundle if the daily cap allows")
    sub.add_parser("publish-triggered", help="publish the exact live-approved Slack-triggered bundle")
    sub.add_parser("reconcile", help="read registries and reconcile verified assets")
    sub.add_parser("graph-sync", help="read-only inventory of indicators already in the DKG graph")
    sub.add_parser("discover", help="run one optional budgeted source-discovery request")
    sub.add_parser("slack-listen", help="run outbound Socket Mode approval listener")
    sub.add_parser("downloads-serve", help="serve immutable bundle JSON to authenticated tailnet users")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = command_parser().parse_args(argv)
    config = load_config(args.config)
    state = _state(config)
    try:
        if args.command == "acquire":
            _json(acquire(config, state))
        elif args.command == "status":
            _json(state.stats())
        elif args.command == "bundle":
            run_id = _run_id("bundle")
            bundle = build_bundle(config, state, AuditLog(Path(config["paths"]["state_dir"]), run_id))
            if bundle and args.post_slack:
                bundle["slack"] = post_bundle(config, state, bundle["bundle_id"])
            _json(bundle or {"status": "deferred"})
        elif args.command == "inspect":
            row = state.bundle_row(args.bundle_id)
            _json({"database": dict(row), "manifest": verify_bundle(config, row)})
        elif args.command == "post-slack":
            _json(post_bundle(config, state, args.bundle_id))
        elif args.command in {"approve", "decline"}:
            if not config["slack"].get("allow_manual_cli_approval", False):
                raise RuntimeError("manual CLI approvals are disabled; use signed Slack approval")
            _json(
                decide_bundle(
                    config, state, args.bundle_id, args.command, actor=args.actor,
                    source="manual-cli", reason=args.reason,
                )
            )
        elif args.command == "publish-once":
            _json(_publish_and_report(config, state))
        elif args.command == "publish-triggered":
            _json(_publish_triggered(config, state))
        elif args.command == "reconcile":
            _json(reconcile_all(config, state))
        elif args.command == "graph-sync":
            run_id = _run_id("graph-sync")
            _json(sync_graph_entities(config, state, AuditLog(Path(config["paths"]["state_dir"]), run_id)))
        elif args.command == "discover":
            run_id = _run_id("discover")
            _json(discover(config, state, AuditLog(Path(config["paths"]["state_dir"]), run_id)))
        elif args.command == "slack-listen":
            state.close()
            run_socket_listener(config, str(Path(config["paths"]["state_dir"]) / "pipeline.sqlite3"))
        elif args.command == "downloads-serve":
            state.close()
            serve_downloads(config)
        return 0
    except Exception as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 1
    finally:
        try:
            state.close()
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
