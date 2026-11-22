"""File Shield's alerts: what a Mac notification may say about the shield, newest first.

Blackbox Desktop (and any notifier) polls ``GET /api/shields/file-shield/api/alerts`` and shows one
notification per alert it has not seen (``key``). Three kinds:

* ``protected-change`` — something changed inside an item the person protects (the system
  protection helper's real-time file events, :mod:`.changes`);
* ``file-hit`` / ``folder-hit`` — File Shield refused an AI agent reaching an item (the guard's
  findings, every route, and the OS sandbox's refusals);
* ``path-restored`` — the block that puts the agent sandbox's launchers first on PATH was removed or
  changed in a shell startup file, and File Shield put it back (KI-535);

WHY (KI-532, E2E full3 2026-11-22): a change inside a protected folder raised no notification at
all, and a refusal reached the person only as the generic "Blocked: a critical threat".

Lock-screen safe: ``text`` and ``title`` name an item by its LAST NAME only (``Taxes``, never
``~/Documents/Taxes``) and never a file inside it, an address or a user name; the full item is in
``item`` for the app's own window. New files in a watched (not protected) folder are not alerts
here — Blackbox Desktop's add-on reports those.

Shape of one alert (all strings except ``ts``)::

    {"key": "protected-change:12", "kind": "protected-change", "ts": 1795310813.2,
     "severity": "high", "item": "~/Documents/Taxes", "item_name": "Taxes",
     "agent": "", "title": "File Shield", "text": "Something changed inside Taxes, which you protect."}
"""

from __future__ import annotations

import os
from typing import Any

from ... import audit
from . import changes, sandbox
from .protect import FILE_HIT_ID, FOLDER_HIT_ID, SANDBOX_AGENT

MAX_ALERTS = 50
FINDINGS_SCANNED = 500
TITLE = "File Shield"
_HITS = {FILE_HIT_ID: "file-hit", FOLDER_HIT_ID: "folder-hit"}
_CHANGED = {"created": "Something was added inside", "removed": "Something was removed inside",
            "renamed": "Something was renamed inside", "modified": "Something changed inside"}


def item_name(item: str) -> str:
    """The last name of a protected *item* (``~/Documents/Taxes`` → ``Taxes``)."""
    return os.path.basename(str(item).rstrip("/")) or str(item)


def _alert(key: str, kind: str, ts: float, severity: str, item: str, agent: str, text: str) -> dict[str, Any]:
    return {"key": key, "kind": kind, "ts": ts, "severity": severity, "item": item,
            "item_name": item_name(item), "agent": agent, "title": TITLE, "text": text}


def _change_alerts() -> list[dict[str, Any]]:
    rows = []
    for change in changes.recent(MAX_ALERTS):
        if change.scope != changes.PROTECTED or change.kind == changes.DENIED:
            continue   # a sandbox denial is alerted from its hit; a watched folder is not protected
        verb = _CHANGED.get(change.kind, "Something changed inside")
        rows.append(_alert(f"protected-change:{change.seq}", "protected-change", change.ts, "high", change.item, "",
                           f"{verb} {item_name(change.item)}, which you protect."))
    return rows


def _hit_alerts() -> list[dict[str, Any]]:
    try:
        findings = audit.read_findings(limit=FINDINGS_SCANNED)
    except Exception:   # health: allow BLE001 -- an unreadable log alerts nothing
        return []
    rows = []
    for row in findings:
        kind = _HITS.get(str(row.get("identifier") or ""))
        if kind is None:
            continue
        item = str((row.get("fields") or {}).get("item") or "")
        sandbox = row.get("framework") == SANDBOX_AGENT
        agent = "" if sandbox else str(row.get("framework") or "")
        who = "a program in the agent sandbox" if sandbox else "an AI agent"
        name = item_name(item) if item else "an item you protect"
        ts = float(row.get("ts") or 0)
        rows.append(_alert(f"{kind}:{ts:.6f}:{name}", kind, ts, "critical", item, agent,
                           f"File Shield stopped {who} reaching {name}."))
    return rows


def _restore_alerts() -> list[dict[str, Any]]:
    return [_alert(f"path-restored:{float(row.get('ts') or 0):.6f}", "path-restored", float(row.get("ts") or 0), "high",
                   "", "", "Something removed Blackbox's agent sandbox from your shell settings. File Shield put it back.")
            for row in sandbox.restorations()]


def alerts(limit: int = MAX_ALERTS) -> list[dict[str, Any]]:
    """The shield's latest alerts (changes inside protected items, refusals, a restored PATH block), newest first."""
    merged = _change_alerts() + _hit_alerts() + _restore_alerts()
    return sorted(merged, key=lambda alert: -alert["ts"])[:max(0, limit)]
