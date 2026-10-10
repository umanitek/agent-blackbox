"""Background work the hooks start but never wait for.

OSV discovery for installed dependencies, the opt-in LLM second opinion on
suspected injections, and periodic auto-attach of newly found agents — each
on a daemon thread, each fail-open, each reporting through :mod:`.reporting`.
"""

from __future__ import annotations

import logging
from typing import Any, Dict
from .. import audit, detection
from ..kernel import threat_ids
from ..kernel import constants
from ..kernel.config import BlackboxConfig
from . import reporting
from . import session_context

logger = logging.getLogger(__name__)

def _spawn_osv_discovery(cfg: BlackboxConfig, rs: Any, tool_name: str, args: Any) -> None:
    """Run OSV dependency auto-discovery on a daemon thread (never blocks)."""
    import threading

    from ..detection import osv

    def _run() -> None:
        try:
            findings = reporting._flag_worthy(
                cfg, detection.discover_dependency_candidates(tool_name, args, rs, osv.lookup)
            )
            if findings:
                reporting._report_and_audit(cfg, "osv_discovery", findings, {"tool_name": tool_name})
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("blackbox: OSV discovery failed: %s", exc)

    try:
        threading.Thread(target=_run, name="blackbox-osv", daemon=True).start()
    except Exception:  # pragma: no cover - fail open
        pass


def _spawn_llm_review(cfg: BlackboxConfig, text: str, detail: Dict[str, Any]) -> None:
    """Ask the configured LLM for an injection second opinion on a daemon thread.

    A positive verdict becomes a local ``source="llm"`` finding: audited and
    shown, never blocks, never shared to the graph.
    """
    import threading

    from ..detection import reviewer as llm

    def _run() -> None:
        try:
            verdict = llm.review_injection(text, cfg)
            if not verdict:
                return
            reason = verdict.get("reason") or "LLM flagged prompt injection"
            finding = detection.Finding(
                identifier=f"injection:llm:{threat_ids.stable_hash(reason, 12)}",
                category="injection",
                severity=verdict.get("severity", "high"),
                title="Prompt injection (LLM review)",
                evidence=reason,
                matched=reason,
                confirmed=False,
                source="llm",
            )
            worthy = reporting._flag_worthy(cfg, [finding])
            if worthy:
                review_detail = {**detail, "llm": True}
                # Give the LLM finding the same context; when the pattern scan
                # flagged nothing, pull the turn from the per-session store.
                if "context" not in review_detail:
                    turns = session_context._recent_convo(str(detail.get("session_id") or ""))
                    if turns:
                        review_detail["context"] = {"turns": turns}
                reporting._report_and_audit(cfg, "pre_api_request", worthy, review_detail)
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("blackbox: LLM review failed: %s", exc)

    try:
        threading.Thread(target=_run, name="blackbox-llm", daemon=True).start()
    except Exception:  # pragma: no cover - fail open
        pass


_AUTO_ATTACH_INTERVAL_SECS = 24 * 60 * 60


def _auto_attach_due() -> bool:
    """True once per interval, or immediately when a new agent target appears.

    Stamps the timestamp *before* the sweep so concurrent session starts don't
    each fan out their own attach thread.  Including the discovered target set
    prevents the 24-hour throttle from delaying protection for a Hermes profile
    or OpenClaw workspace installed after the last sweep.
    """
    import json
    import time

    try:
        path = constants.blackbox_home() / "auto_attach.json"
        now = time.time()
        try:
            from .. import attach

            targets = sorted(
                [f"hermes:{item}" for item in attach.discover_hermes_homes()]
                + [f"openclaw:{item}" for item in attach.discover_openclaw_workspaces()]
            )
        except Exception:
            targets = []
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
            last = float(state.get("last_run", 0.0))
            previous_targets = sorted(str(item) for item in (state.get("targets") or []))
        except Exception:
            last = 0.0
            previous_targets = []
        if now - last < _AUTO_ATTACH_INTERVAL_SECS and targets == previous_targets:
            return False
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"last_run": now, "targets": targets}), encoding="utf-8")
        return True
    except Exception as exc:
        logger.debug("blackbox: auto-attach throttle failed: %s", exc)
        return False


def _spawn_auto_attach(cfg: BlackboxConfig) -> None:
    """Re-run the attach sweep on a daemon thread (throttled, fail-open).

    Keeps protection current: a Hermes home or OpenClaw workspace created after
    install gets attached the next time any protected agent starts a session.
    """
    import threading

    if not cfg.auto_attach or not _auto_attach_due():
        return

    def _run() -> None:
        try:
            from .. import attach

            report = attach.attach_all()
            changed = [
                row.get("target")
                for group in ("hermes", "openclaw")
                for row in report.get(group, [])
                if row.get("changed")
            ]
            if changed:
                audit.record(event="auto_attach", detail={"targets": changed})
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("blackbox: auto-attach failed: %s", exc)

    try:
        threading.Thread(target=_run, name="blackbox-auto-attach", daemon=True).start()
    except Exception:  # pragma: no cover - fail open
        pass


def review_request(cfg, sources, text, detail):
    from . import semantic_review
    semantic_review.schedule(cfg, sources, detail)
    if cfg.llm_ready and not getattr(getattr(cfg, "semantic", None), "enabled", False):
        _spawn_llm_review(cfg, text, detail)


def review_tool(cfg, tool, args, detail):
    import json
    from . import semantic_review
    if getattr(getattr(cfg, "semantic", None), "enabled", False):
        semantic_review.schedule(cfg, [("tool-call:" + tool, json.dumps(audit.redact(args), default=str))], detail)
