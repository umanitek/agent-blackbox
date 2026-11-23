"""File Shield's alerts: what a Mac notification may say about the shield, newest first.

A companion app (and any notifier) polls ``GET /api/shields/file-shield/api/alerts`` and shows one
notification per alert it has not seen (``key``). These kinds:

* ``protected-change`` — something changed inside an item the person protects (the system
  protection helper's real-time file events, :mod:`.changes`);
* ``file-hit`` / ``folder-hit`` — File Shield refused an AI agent reaching an item (the guard's
  findings, every route, and the OS sandbox's refusals);
* ``permission-request`` — an agent inside the sandbox wants a permission on "ask" (sandbox
  permissions: Docker, opening an app …); the person answers in Blackbox;
* ``path-restored`` — the block that puts the agent sandbox's launchers first on PATH was removed or
  changed in a shell startup file, and File Shield put it back (KI-535);
* ``file-known-bad`` / ``file-new`` — a watched folder's scan (an add-on, through
  :mod:`.watched`) found a file the verified graph lists, or a new file. A known-bad file is a
  ``security`` notice; a new file is ``watched`` (the person's own switch). WHY here: the add-on
  used to word and send these itself; one wording now lives in the core (engine rule, 2026-11-22).

WHY (KI-532, E2E full3 2026-11-22): a change inside a protected folder raised no notification at
all, and a refusal reached the person only as the generic "Blocked: a critical threat".

Lock-screen safe: ``text`` and ``title`` never name a protected item, a file, an address or a user
name — they name the AGENT (its product) and what happened (KI-PENDING-c4249e: "… reaching Secret"
named a protected folder, which can itself be private, and not the agent). The item's last name
(``Taxes``) is in ``detail`` (shown when the person chose "show details") and ``item_name``; the
full item is in ``item`` for the app's own window.

Shape of one alert (all strings except ``ts``)::

    {"key": "protected-change:12", "kind": "protected-change", "ts": 1795310813.2,
     "severity": "high", "item": "~/Documents/Taxes", "item_name": "Taxes",
     "agent": "", "title": "File Shield", "text": "Something changed inside a folder you protect.",
     "detail": "Something changed inside Taxes, which you protect."}
"""

from __future__ import annotations

import hashlib
import os
from typing import Any

from ... import audit
from ...kernel import agent_hosts
from ..contract import ShieldAlert
from . import changes, sandbox, watched
from .protect import FILE_HIT_ID, FOLDER_HIT_ID, SANDBOX_AGENT

MAX_ALERTS = 50
#: Who an OS-sandbox refusal is said to be from here: the kernel's log names a program, not an
#: agent. The notifier (``notify.wording.SANDBOX_PROGRAM``, the same words) puts the agent
#: instance it was attributed to in its place (KI-586).
SANDBOX_WHO = "a program in Blackbox's agent sandbox"
FINDINGS_SCANNED = 500
TITLE = "File Shield"
_HITS = {FILE_HIT_ID: "file-hit", FOLDER_HIT_ID: "folder-hit"}
_CHANGED = {"created": "Something was added inside", "removed": "Something was removed inside",
            "renamed": "Something was renamed inside", "modified": "Something changed inside"}


def item_name(item: str) -> str:
    """The last name of a protected *item* (``~/Documents/Taxes`` → ``Taxes``)."""
    return os.path.basename(str(item).rstrip("/")) or str(item)


_CATEGORY = {"file-new": "watched"}   # every other kind is a security notice
_WATCHED_TEXT = {
    "file-known-bad": "A file in a watched folder is on the threat list. Do not open it — open Blackbox to see which.",
    "file-new": "A new file arrived in a watched folder. Open Blackbox to see the details.",
}


def _alert(key: str, kind: str, ts: float, severity: str, item: str, agent: str, text: str, detail: str = "",
           title: str = TITLE) -> dict[str, Any]:
    return {"key": key, "kind": kind, "ts": ts, "severity": severity, "item": item,
            "item_name": item_name(item), "agent": agent, "title": title, "text": text,
            "detail": detail or (f"{text} ({item})" if item else text),
            "category": _CATEGORY.get(kind, "security")}


def _agent_name(agent: str) -> str:
    """The agent's product name (``Claude Code``), for the lock screen."""
    host = agent_hosts.BY_ID.get(agent)
    return host.name if host is not None else "Your Hermes agent" if agent in ("", "hermes") else agent


def _change_alerts() -> list[dict[str, Any]]:
    rows = []
    for change in changes.recent(MAX_ALERTS):
        if change.scope != changes.PROTECTED or change.kind == changes.DENIED:
            continue   # a sandbox denial is alerted from its hit; a watched folder is not protected
        verb = _CHANGED.get(change.kind, "Something changed inside")
        rows.append(_alert(f"protected-change:{change.seq}", "protected-change", change.ts, "high", change.item, "",
                           f"{verb} a folder you protect.", f"{verb} {item_name(change.item)}, which you protect."))
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
        who = SANDBOX_WHO if sandbox else _agent_name(agent)
        name = item_name(item) if item else "an item you protect"
        ts = float(row.get("ts") or 0)
        rows.append(_alert(f"{kind}:{ts:.6f}:{name}", kind, ts, "critical", item, agent,
                           f"File Shield stopped {who} from reaching something you protect.",
                           f"File Shield stopped {who} reaching {name}.", title=f"File Shield stopped {who}"))
    return rows


def _restore_alerts() -> list[dict[str, Any]]:
    return [_alert(f"path-restored:{float(row.get('ts') or 0):.6f}", "path-restored", float(row.get("ts") or 0), "high",
                   "", "", "Something removed Blackbox's agent sandbox from your shell settings. File Shield put it back.")
            for row in sandbox.restorations()]


def _package_alerts() -> list[dict[str, Any]]:
    """A Homebrew install Blackbox ran for a sandboxed agent (KI-593): said every time."""
    return [_alert(row["key"], "package-install", row["ts"], "info" if row["ok"] else "high", "", str(row.get("agent") or ""), row["text"])
            for row in sandbox.packages.alerts()]


def _request_alerts() -> list[dict[str, Any]]:
    """An agent wants a sandbox permission it does not have: the person is asked (no path, no command)."""
    return [_alert(f"permission-request:{request.id}", "permission-request", request.created, "medium", "", request.agent,
                   f"{_agent_name(request.agent)} wants to use {sandbox.permissions.BY_ID[request.permission].name}. "
                   "Open Blackbox to allow it once, always here, or keep it blocked.")
            for request in sandbox.permissions.requests.pending()]


def _watched_alerts() -> list[dict[str, Any]]:
    rows = []
    for found in watched.recent(MAX_ALERTS):
        bad = found.kind == "file-known-bad"
        # WHY a hash: the key travels in the notification feed; the file's name stays out of it.
        where = hashlib.sha256(found.path.encode("utf-8")).hexdigest()[:12]
        rows.append(_alert(f"{found.kind}:{found.ts:.6f}:{where}", found.kind, found.ts,
                           "critical" if bad else "info", found.path, "", _WATCHED_TEXT[found.kind]))
    return rows


def shield_alerts() -> list[ShieldAlert]:
    """The same alerts as the framework's typed ``Shield.alerts`` (``notify`` reads these). A
    refusal names the finding it speaks for, so that finding is not announced twice."""
    return [ShieldAlert(key=row["key"], kind=row["kind"], ts=row["ts"], severity=row["severity"], title=row["title"],
                        text=row["text"], detail=row["detail"] if row["item"] else "", agent=row["agent"],
                        finding={"file-hit": FILE_HIT_ID, "folder-hit": FOLDER_HIT_ID}.get(row["kind"], ""),
                        category=row["category"])
            for row in alerts()]


def alerts(limit: int = MAX_ALERTS) -> list[dict[str, Any]]:
    """The shield's latest alerts (changes inside protected items, refusals, a restored PATH block,
    a watched folder's new and known-bad files), newest first."""
    merged = _change_alerts() + _hit_alerts() + _restore_alerts() + _watched_alerts() + _package_alerts() + _request_alerts()
    return sorted(merged, key=lambda alert: -alert["ts"])[:max(0, limit)]
