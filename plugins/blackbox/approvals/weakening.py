"""Which changes turn protection DOWN — those wait for the person's approval in Blackbox Desktop.

A change is judged by what it ASKS (its route and body) against what is on now. Anything that
makes Blackbox see or stop less is weakening; anything else (turning a protection on, a stricter
mode, a new protected path, a change of an unrelated option) applies at once. When the current
value cannot be read, a change that COULD weaken is treated as weakening (fails toward asking).

Each gated route has one judge in :data:`JUDGES` — ``judge(body, current) -> [reasons]``, each
reason a short sentence for the dialog. *current* is :class:`Current`, read lazily.

Usage::

    reasons("/api/settings", {"mode": "audit"}, Current.read())   # ["Switch Blackbox from Block to Audit mode …"]
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

#: Stronger modes rank higher.
MODE_RANK = {"audit": 0, "block": 1}
SEVERITY_RANK = {name: rank for rank, name in enumerate(("info", "low", "medium", "high", "critical"))}
#: Settings switches that, turned off, make Blackbox see less.
PROTECTING_SWITCHES = {"auto_attach": "protecting new agents automatically", "discover": "discovering new threats",
                       "osv_lookup": "checking packages against the vulnerability database"}


@dataclass(frozen=True)
class Current:
    """What is on now: the settings view (``read_settings``) and each shield's mode
    (``{shield id: {"enabled": bool, <option>: [values]}}``). Empty = could not be read."""

    settings: Mapping[str, Any] = field(default_factory=dict)
    shields: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)

    @staticmethod
    def read() -> Current:
        from .. import shields
        from ..kernel import settings
        try:
            view = settings.read_settings()
        except Exception:   # health: allow BLE001 -- unknown current value: a possibly weakening change asks
            view = {}
        try:
            modes = {shield_id: entry.get("mode") or {} for shield_id, entry in shields.settings_view().items()}
        except Exception:   # health: allow BLE001 -- as above
            modes = {}
        return Current(view, modes)


def _settings(body: Mapping[str, Any], current: Current) -> list[str]:
    if _invalid(body):
        return []   # refused by the route with its 400: nothing to confirm
    now = current.settings
    out: list[str] = []
    mode = body.get("mode")
    if isinstance(mode, str) and MODE_RANK.get(mode.lower(), -1) < MODE_RANK.get(str(now.get("mode", "block")).lower(), 1):
        out.append(f"Switch Blackbox to {mode.capitalize()} mode (threats are recorded, no longer stopped)")
    severity = body.get("block_severity")
    if isinstance(severity, str) and SEVERITY_RANK.get(severity.lower(), 99) > SEVERITY_RANK.get(str(now.get("block_severity", "info")), 0):
        out.append(f"Block only {severity.lower()} threats and above")
    for key, what in PROTECTING_SWITCHES.items():
        if body.get(key) is False and now.get(key, True) is not False:
            out.append(f"Stop {what}")
    categories = body.get("categories")
    if isinstance(categories, Mapping):
        current_categories = now.get("categories") or {}
        for name, policy in categories.items():
            if not isinstance(policy, Mapping):
                continue
            was = current_categories.get(name) if isinstance(current_categories, Mapping) else None
            was = was if isinstance(was, Mapping) else {}
            if policy.get("enabled") is False and was.get("enabled", True) is not False:
                out.append(f"Turn off {name} detection")
            floor = policy.get("min_severity")
            if isinstance(floor, str) and SEVERITY_RANK.get(floor, 0) > SEVERITY_RANK.get(str(was.get("min_severity", "info")), 0):
                out.append(f"Flag {name} only at {floor} and above")
    paths = body.get("protected_paths")
    if isinstance(paths, list):
        dropped = [p for p in now.get("protected_paths") or [] if p not in paths]
        if dropped:
            out.append(f"Stop protecting {len(dropped)} file path{'s' if len(dropped) != 1 else ''} ({', '.join(map(str, dropped[:3]))})")
    out.extend(_shields(body.get("shields"), current))
    return out


def _invalid(body: Mapping[str, Any]) -> bool:
    """True when the settings writer would refuse *body* (so it would change nothing)."""
    from .. import shields
    from ..kernel import settings
    try:
        return bool(settings.settings_problems(dict(body), shields.settings_validators()))
    except Exception:   # health: allow BLE001 -- cannot tell: judge it (a possibly weakening change asks)
        return False


def _shields(sections: Any, current: Current) -> list[str]:
    if not isinstance(sections, Mapping):
        return []
    out: list[str] = []
    for shield_id, section in sections.items():
        if not isinstance(section, Mapping):
            continue
        now = current.shields.get(shield_id) or {}
        if section.get("enabled") is False and now.get("enabled", True) is not False:
            out.append(f"Turn off {shield_id}")
        for option, chosen in section.items():
            if isinstance(chosen, list) and isinstance(now.get(option), list):
                dropped = [value for value in now[option] if value not in chosen]
                if dropped:
                    out.append(f"Turn off {', '.join(map(str, dropped[:4]))} in {shield_id}")
    return out


def _agents(body: Mapping[str, Any], _current: Current) -> list[str]:
    targets = body.get("targets") if isinstance(body.get("targets"), list) else []
    return [f"Stop protecting {item.get('target') or item.get('kind')}" for item in targets
            if isinstance(item, Mapping) and item.get("enabled") is False]


def _agent_hooks(body: Mapping[str, Any], _current: Current) -> list[str]:
    return [f"Stop protecting {body.get('kind')}"] if body.get("enabled") is False else []


def _tamper_guard(body: Mapping[str, Any], _current: Current) -> list[str]:
    return ["Turn off the DNS tamper guard"] if body.get("on") is False else []


def _unblock(body: Mapping[str, Any], _current: Current) -> list[str]:
    return [f"Unblock {body.get('address') or 'a blocked address'}"]


def _remote(body: Mapping[str, Any], _current: Current) -> list[str]:
    out = ["Unlock remote access"] if body.get("lock") is False else []
    brute = body.get("brute_force")
    if isinstance(brute, Mapping) and brute.get("enabled") is False:
        out.append("Stop blocking password-guessing attempts")
    return out


Judge = Callable[[Mapping[str, Any], Current], list[str]]
NETWORK_API = "/api/shields/network-shield/api/"
JUDGES: dict[str, Judge] = {
    "/api/settings": _settings,
    "/api/agents/protection": _agents,
    "/api/agent-hooks/protection": _agent_hooks,
    NETWORK_API + "tamper-guard": _tamper_guard,
    NETWORK_API + "unblock-address": _unblock,
    NETWORK_API + "remote-settings": _remote,
}


def gated(route: str) -> bool:
    return route in JUDGES


def reasons(route: str, body: Any, current: Current) -> list[str]:
    """Why the change on *route* weakens protection (empty: it does not, apply it)."""
    judge = JUDGES.get(route)
    return judge(body, current) if judge is not None and isinstance(body, Mapping) else []
