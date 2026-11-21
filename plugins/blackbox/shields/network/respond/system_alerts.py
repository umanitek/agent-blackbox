"""The system watch's events as alerts for a person: a sentence and a severity each (newest first).
Merged into Network Shield's ``overview`` alerts, so they reach the app's Mac notifications.

Severity follows what the event means: a new startup item or listener is judged by who signed its
program (:func:`..monitor.exposure.judge`); Blackbox's own helper changing is critical; DNS
moved away, a proxy set or the firewall switched off is high.
"""

from __future__ import annotations

import os
from typing import Any, Mapping

from ..monitor import exposure, system_report

_FIX_NAMES = {"firewall-on": "the macOS firewall", "stealth-on": "stealth mode", "guest-off": "the guest account",
              "screen-sharing-off": "Screen Sharing", "file-sharing-off": "File Sharing", "remote-login-off": "Remote Login",
              "remote-management-off": "Remote Management"}
_FIXED = {"firewall-on": "is on", "stealth-on": "is on", "guest-off": "is off", "screen-sharing-off": "is off",
          "file-sharing-off": "is off", "remote-login-off": "is off", "remote-management-off": "is off"}


def _name(path: str) -> str:
    return os.path.basename(path.rstrip("/")) or path or "an unknown program"


def text_of(event: Mapping[str, Any]) -> str:
    kind = str(event.get("kind"))
    if kind == "listener-new":
        service = exposure.SERVICES.get(int(event.get("port", 0)), "")
        return f"{_name(str(event.get('program', '')))} started listening on port {event.get('port')}" + (f" ({service})" if service else "") + " — reachable from the network."
    if kind == "listener-closed":
        return f"{_name(str(event.get('program', '')))} stopped listening on port {event.get('port')}."
    if kind.startswith("persistence-"):
        what = exposure.ITEM_NAMES.get(str(event.get("item_kind")), "startup item")
        label = event.get("label") or _name(str(event.get("id", "")))
        verb = {"persistence-new": "was added", "persistence-changed": "changed", "persistence-removed": "was removed"}[kind]
        return f"{what} “{label}” {verb}."
    if kind == "dns-changed":
        return f"This Mac's DNS changed to {', '.join(event.get('servers') or []) or 'none'}."
    if kind == "proxy-set":
        return f"A system proxy was set ({', '.join(event.get('proxies') or [])}) — traffic may be routed elsewhere."
    if kind == "proxy-removed":
        return "The system proxy was removed."
    if kind == "vpn-added":
        return "A new VPN configuration was added."
    if kind == "firewall-changed":
        return f"The macOS firewall was switched {event.get('state')}."
    if kind == "helper-modified":
        return "Blackbox's network helper was modified on disk."
    if kind == "dns-restored":
        return "DNS was changed away from Blackbox — the tamper guard put it back."
    if kind == "dns-restore-failed":
        return "DNS was changed away from Blackbox and could not be put back."
    if kind.startswith("fix-"):
        fix = str(event.get("fix"))
        name = _FIX_NAMES.get(fix, fix)
        if kind == "fix-applied":
            return f"Fixed: {name} {_FIXED.get(fix, 'is set')}." if event.get("how") == "changed" else f"{name.capitalize()} was already safe."
        if kind == "fix-undone":
            return f"Undone: {name} is back as it was."
        return f"Could not change {name}: {event.get('error') or 'unknown error'}"
    return kind


def severity(event: Mapping[str, Any]) -> str:
    kind = str(event.get("kind"))
    if kind in ("listener-new", "persistence-new", "persistence-changed"):
        risk, _, _ = exposure.judge(str(event.get("program", "")), startup=kind != "listener-new")
        return {"critical": "critical", "high": "high", "medium": "medium"}.get(risk, "low" if risk == "low" else "medium")
    if kind == "firewall-changed":
        return "high" if event.get("state") == "off" else "info"
    return {"helper-modified": "critical", "dns-changed": "high", "proxy-set": "high", "vpn-added": "medium",
            "dns-restored": "medium", "dns-restore-failed": "high", "fix-failed": "medium"}.get(kind, "info")


def alerts(limit: int = 20) -> list[dict[str, Any]]:
    """The latest system events as alerts (``kind``, ``ts``, ``severity``, ``text``)."""
    return [{"kind": e["kind"], "ts": e["ts"], "severity": severity(e), "text": text_of(e),
             **({"path": e["program"]} if e.get("program") else {})} for e in system_report.events(limit)]
