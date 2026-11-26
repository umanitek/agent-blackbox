"""Posture fixes the person asked for — the few safe one-click changes the root helper can make
(``netd/enforce/posture.rs``): macOS firewall on, stealth mode on, guest account off, Screen
Sharing / File Sharing / Remote Login / Remote Management off. Each is asked for in the app first.

Kept in ``<BLACKBOX_HOME>/network-shield/posture.json`` (the fixes wanted, and a counter the app
bumps to ask the helper for a fresh posture look). The helper reads them through the system plan.

**Undo:** removing a fix from the list (the person pressed Undo) makes the helper put that setting
back exactly as it found it; with Network Shield off the plan carries no fixes, so every fix is
undone — and a fix that found the Mac already safe changed nothing and undoes nothing.
"""

from __future__ import annotations

import threading
from typing import Any

from ....kernel import constants
from ....kernel.bounded_files import read_json_object, write_json_object
from ....shields.shield_api import ShieldApiError

FIXES = ("firewall-on", "stealth-on", "guest-off", "screen-sharing-off", "file-sharing-off", "remote-login-off",
         "remote-management-off")
_lock = threading.Lock()


def _path() -> Any:
    return constants.blackbox_home() / "network-shield" / "posture.json"


def _state() -> dict[str, Any]:
    return read_json_object(_path()) or {}


def wanted() -> list[str]:
    """The fixes the person asked for, in the helper's order."""
    chosen = set(_state().get("fixes", []))
    return [fix for fix in FIXES if fix in chosen]


def set_fix(fix: Any, apply: Any) -> list[str]:
    """Asks for *fix* (``apply`` True) or its Undo (False); answers the fixes wanted now."""
    if fix not in FIXES:
        raise ShieldApiError(400, f"fix must be one of: {', '.join(FIXES)}")
    if not isinstance(apply, bool):
        raise ShieldApiError(400, "apply must be true or false")
    with _lock:
        state = _state()
        chosen = set(state.get("fixes", []))
        (chosen.add if apply else chosen.discard)(fix)
        state["fixes"] = [f for f in FIXES if f in chosen]
        write_json_object(_path(), state, what="Network Shield's posture fixes")
        return state["fixes"]


def request_refresh() -> int:
    """Asks the helper for a fresh posture look; answers the new counter."""
    with _lock:
        state = _state()
        state["refresh"] = int(state.get("refresh", 0)) + 1
        write_json_object(_path(), state, what="Network Shield's posture fixes")
        return state["refresh"]


def plan_part(shield_on: bool) -> dict[str, Any]:
    """The helper's part of the system plan: no fixes at all while the shield is off."""
    state = _state()
    return {"posture_fixes": wanted() if shield_on else [], "posture_refresh": int(state.get("refresh", 0))}
