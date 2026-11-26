"""Which of Network Shield's own writes turn protection DOWN — they then wait for the person.

The core's ``approvals`` gate asks each shield about its own writes (``ShieldApi.weakening``): the
shield knows its current state, the core names no shield. Each judge here takes the write's body
and answers the reasons (sentences for the confirmation dialog); an empty answer applies at once.
Judged against what is on now; a write that cannot be judged asks (``shields.write_weakening``).

**Undo:** nothing to undo — this module changes nothing; it only judges the writes that would.

Usage::

    JUDGES["remote-settings"]({"lock": False})   # ["Unlock remote access …"] while locked
"""

from __future__ import annotations

from typing import Any, Callable, Mapping

from . import posture_fix, remote_lock, tamper_guard

#: Brute-force rules where a HIGHER value lets more guessing through (raising weakens) and where
#: a LOWER value does (shrinking weakens): more failures allowed, a shorter window, shorter blocks.
LOOSER_WHEN_HIGHER = ("failures",)
LOOSER_WHEN_LOWER = ("window_minutes", "block_minutes")


def remote_settings(body: Mapping[str, Any]) -> list[str]:
    now = remote_lock.settings()
    out: list[str] = []
    if body.get("lock") is False and now["lock"]:
        out.append("Unlock remote access (SSH, Screen Sharing, Remote Desktop and file sharing reachable again)")
    raw = body.get("brute_force")
    if not isinstance(raw, Mapping):
        return out
    rules = now["brute_force"]
    if raw.get("enabled") is False and rules.get("enabled"):
        out.append("Stop blocking password-guessing attempts")
    for key in LOOSER_WHEN_HIGHER:
        if isinstance(raw.get(key), int) and raw[key] > rules.get(key, raw[key]):
            out.append(f"Allow more failed logins before blocking ({rules.get(key)} → {raw[key]})")
    for key in LOOSER_WHEN_LOWER:
        if isinstance(raw.get(key), int) and raw[key] < rules.get(key, raw[key]):
            label = "Count failed logins over a shorter time" if key == "window_minutes" else "Block guessers for less time"
            out.append(f"{label} ({rules.get(key)} → {raw[key]} minutes)")
    return out


def unblock_address(body: Mapping[str, Any]) -> list[str]:
    return [f"Unblock {body.get('ip') or body.get('address') or 'a blocked address'}"] if body else []


def tamper_guard_write(body: Mapping[str, Any]) -> list[str]:
    return ["Turn off the DNS tamper guard"] if body.get("on") is False and tamper_guard.is_on() else []


def posture_fix_write(body: Mapping[str, Any]) -> list[str]:
    fix = body.get("fix")
    if body.get("apply") is False and fix in posture_fix.wanted():
        return [f"Undo the “{fix}” fix (that setting goes back to how it was)"]
    return []


JUDGES: dict[str, Callable[[Mapping[str, Any]], list[str]]] = {
    "remote-settings": remote_settings,
    "unblock-address": unblock_address,
    "tamper-guard": tamper_guard_write,
    "posture-fix": posture_fix_write,
}
