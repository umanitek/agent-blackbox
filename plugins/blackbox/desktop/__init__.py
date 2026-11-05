"""Blackbox inside Hermes Desktop: what the Desktop half shows, and the live alert it hears.

Hermes Desktop loads a plugin's ``desktop/plugin.js`` (this folder) as a native part of the app
and reaches the plugin's backend through ``/api/plugins/blackbox/…`` (``dashboard/plugin_api.py``).
This module is the one door both use — a Facade over the config, the ruleset and the findings log:

- :func:`status_payload` — protection at a glance for the status bar and the page header;
- :func:`findings_payload` — the newest findings for the page's list;
- :func:`announce_findings` — called by the hook right after findings are recorded; pushes one
  ``plugin.blackbox.finding`` event per finding to every connected Desktop window (Observer).

The alert carries what a person needs to react — title, severity, category, the tool, blocked or
flagged — and never the evidence, the command, its arguments or any matched text: those stay in the
local log, which the page reads through :func:`findings_payload` on this machine only.

Fail-open throughout: a Hermes without plugin events, a ruleset that cannot load, or an unreadable
log gives a calm answer, never an exception into the hook or the Desktop app.

    from plugins.blackbox import desktop
    desktop.status_payload()            # {"mode": "audit", "rules": 1234, "today": {...}, ...}
    desktop.findings_payload(limit=20)  # {"findings": [...], "total": 42}
    desktop.announce_findings("pre_tool_call", finding_dicts, {"decision": "block"})
"""

from __future__ import annotations

import logging
import time
from typing import Any, Mapping, Optional, Sequence, TypedDict

from .. import audit, ruleset
from ..kernel.config import load_blackbox_config

logger = logging.getLogger(__name__)

#: The catalog name: Hermes namespaces the event as ``plugin.<PLUGIN_ID>.<event>``.
PLUGIN_ID = "blackbox"
FINDING_EVENT = "finding"
#: The page shows at most this many findings; the full history is on the local dashboard.
MAX_FINDINGS = 100
_DAY_SECONDS = 86_400


class FindingAlert(TypedDict):
    """One finding as the Desktop alert and list show it: no evidence, command or matched text."""

    time: float
    title: str
    severity: str
    category: str
    tool: str
    outcome: str      # "blocked" | "flagged"
    sandbox: bool     # a Playground test, not a real agent action


def _outcome(detail: Mapping[str, Any]) -> str:
    return "blocked" if str(detail.get("decision") or "") == "block" else "flagged"


def _alert(finding: Mapping[str, Any], detail: Mapping[str, Any], when: float, sandbox: bool) -> FindingAlert:
    return FindingAlert(
        time=float(finding.get("ts") or when),
        title=str(finding.get("title") or finding.get("identifier") or "Threat")[:160],
        severity=str(finding.get("severity") or "unknown")[:16],
        category=str(finding.get("category") or "")[:32],
        tool=str(finding.get("tool_name") or detail.get("tool_name") or "")[:64],
        outcome=_outcome(detail),
        sandbox=sandbox,
    )


def _broadcast() -> Any:
    """Hermes's ``broadcast_plugin_event``, or None on a Hermes that has no plugin events."""
    try:
        from hermes_cli.plugin_events import broadcast_plugin_event
    except ImportError:
        return None
    return broadcast_plugin_event


def announce_findings(event: str, findings: Sequence[Mapping[str, Any]], detail: Mapping[str, Any]) -> None:
    """Tell every connected Desktop window about *findings* just recorded for *event*. Fail-open."""
    broadcast = _broadcast() if findings else None
    if broadcast is None:
        return
    now = time.time()
    sandbox = audit.in_sandbox_run()
    for finding in findings:
        try:
            broadcast(PLUGIN_ID, FINDING_EVENT, dict(_alert(finding, detail or {}, now, sandbox)))
        except Exception as exc:   # health: allow BLE001 -- the hook boundary is fail-open: a Desktop alert must never break the agent's tool call
            logger.warning("blackbox: Desktop alert not sent: %s", exc)
            return


def _rows(limit: int) -> list[dict[str, Any]]:
    try:
        return audit.read_findings(limit=limit)
    except Exception as exc:   # health: allow BLE001 -- an unreadable log is an empty list on the page, never an error
        logger.warning("blackbox: findings unreadable for Desktop: %s", exc)
        return []


def _list_item(row: Mapping[str, Any]) -> FindingAlert:
    finding = row.get("finding") if isinstance(row.get("finding"), Mapping) else {}
    detail = row.get("detail") if isinstance(row.get("detail"), Mapping) else {}
    # Playground tests are recorded in the sandbox folder's own log (audit.sandbox_run), never this one.
    return _alert(finding, detail, float(row.get("ts") or 0), sandbox=False)


def findings_payload(limit: int = 20) -> dict[str, Any]:
    """The newest findings, newest first, as alerts (``{"findings": [...], "total": n}``)."""
    rows = _rows(max(1, min(int(limit), MAX_FINDINGS)))
    try:
        total = audit.count_findings()
    except Exception:   # health: allow BLE001 -- a count is a nicety; the list still shows
        total = len(rows)
    return {"findings": [_list_item(row) for row in rows], "total": total}


def _rules(cfg: Any) -> tuple[Optional[int], float]:
    """(rules loaded or None when the ruleset cannot be read, when it was last synced)."""
    try:
        rules = ruleset.get(cfg)
        return sum(rules.counts().values()), float(getattr(rules, "synced_at", 0) or 0)
    except Exception as exc:   # health: allow BLE001 -- a ruleset that cannot load reads as "unknown", never an error
        logger.warning("blackbox: ruleset unreadable for Desktop: %s", exc)
        return None, 0.0


def status_payload() -> dict[str, Any]:
    """Protection at a glance: mode, rules loaded, today's findings, the local dashboard's address."""
    cfg = load_blackbox_config()
    rules, synced_at = _rules(cfg)
    since = time.time() - _DAY_SECONDS
    today = [item for item in (_list_item(row) for row in _rows(MAX_FINDINGS)) if item["time"] >= since]
    return {
        "mode": cfg.mode,
        "blockSeverity": cfg.block_severity,
        "rules": rules,
        "syncedAt": synced_at,
        "today": {
            "findings": len(today),
            "blocked": sum(1 for item in today if item["outcome"] == "blocked"),
        },
        "last": today[0] if today else None,
        "dashboardUrl": f"http://127.0.0.1:{cfg.dashboard_port}/",
    }


__all__ = ["FINDING_EVENT", "PLUGIN_ID", "FindingAlert", "announce_findings", "findings_payload", "status_payload"]
