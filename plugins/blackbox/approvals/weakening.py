"""Which changes turn protection DOWN — those wait for the person's approval.

A change is judged by what it ASKS (its route and body) against what is on now. Anything that
makes Blackbox see or stop less is weakening — and so is one privacy choice, starting to keep
the text of prompts (``agent_activity.record_prompt_text``): it too waits for the person; anything else (turning a protection on, a stricter
mode, a new protected path, a change of an unrelated option) applies at once. When the current
value cannot be read, a change that COULD weaken is treated as weakening (fails toward asking).

Each gated route has one judge in :data:`JUDGES` — ``judge(body, current) -> [reasons]``, each
reason a short sentence for the dialog. *current* is :class:`Current`, read lazily. A shield's own
writes (``/api/shields/<id>/api/<name>``) are judged by that shield (``ShieldApi.weakening``:
it knows its own state), so the core names no shield here.

Lists have a DIRECTION: on a shield's allow-lists (``Shield.allow_lists`` — who may SSH in, hosts
an agent may reach, names never blocked) ADDING an entry turns protection down; on every other
list (block lists, protected paths, chosen protections, wallets) REMOVING one does.

Usage::

    reasons("/api/settings", {"mode": "audit"}, Current.read())   # ["Switch Blackbox from Block to Audit mode …"]
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional

#: Stronger modes rank higher.
MODE_RANK = {"audit": 0, "block": 1}
SEVERITY_RANK = {name: rank for rank, name in enumerate(("info", "low", "medium", "high", "critical"))}
#: Settings switches that, turned off, make Blackbox see less.
PROTECTING_SWITCHES = {"auto_attach": "protecting new agents automatically", "discover": "discovering new threats",
                       "osv_lookup": "checking packages against the vulnerability database"}


#: Settings sections another package owns: ``{key: judge(proposed) -> [reasons]}`` (its own state
#: is read by the judge). ``notify`` registers ``notifications`` through the dashboard.
SECTION_JUDGES: dict[str, Callable[[Any], list[str]]] = {}


@dataclass(frozen=True)
class Current:
    """What is on now: the settings view (``read_settings``) and each shield's mode
    (``{shield id: {"enabled": bool, <option>: [values]}}``). Empty = could not be read."""

    settings: Mapping[str, Any] = field(default_factory=dict)
    shields: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    #: ``{shield id: allow-list option names}`` (adding to these weakens).
    allow_lists: Mapping[str, frozenset[str]] = field(default_factory=dict)

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
        try:
            allow = shields.allow_lists()
        except Exception:   # health: allow BLE001 -- unknown direction: every list change is judged both ways
            allow = {}
        return Current(view, modes, allow)


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
    activity = body.get("agent_activity")
    if isinstance(activity, Mapping) and activity.get("record_prompt_text") is True:
        was = now.get("agent_activity") if isinstance(now.get("agent_activity"), Mapping) else {}
        if was.get("record_prompt_text") is not True:   # a privacy change: the person confirms it, in plain words
            days = activity.get("history_days") or was.get("history_days") or 30
            out.append(f"Start keeping the text of the prompts you send to AI agents — on this Mac only, with secrets removed, for {days} days")
    for key, judge in SECTION_JUDGES.items():   # a section another package owns (notifications)
        if key in body:
            out.extend(judge(body[key]))
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
            out.append(f"Turn off {_name(shield_id)}")
        allow = current.allow_lists.get(shield_id)
        for option, chosen in section.items():
            if not isinstance(chosen, list):
                continue
            was = now.get(option) if isinstance(now.get(option), list) else None
            if was is None and not now:
                was = []   # current state unknown: judge against nothing (an allow-list addition asks)
            if was is None:
                continue
            # Unknown direction (allow-lists not readable) judges both ways: fails toward asking.
            if allow is None or option in allow:
                added = [value for value in chosen if value not in was]
                if added:
                    out.append(_describe(shield_id, option, added, True))
            if allow is None or option not in allow:
                dropped = [value for value in was if value not in chosen]
                if dropped:
                    out.append(_describe(shield_id, option, dropped, False))
    return out


def _name(shield_id: str) -> str:
    from .. import shields
    try:
        return shields.shield_name(shield_id)
    except Exception:   # health: allow BLE001 -- the registry unreadable: the id still names it
        return shield_id


def _describe(shield_id: str, option: str, values: list[Any], added: bool) -> str:
    """The person's sentence for a weakening list change (KI-538: words, not internal ids)."""
    from .. import shields
    shown = [str(value) for value in values]
    try:
        return shields.describe_change(shield_id, option, shown, added)
    except Exception:   # health: allow BLE001 -- a describer failed: a plain sentence still asks
        verb = "Allow" if added else "Remove"
        return f"{verb} {', '.join(shown[:4])} ({option} in {shield_id})"


def _agents(body: Mapping[str, Any], _current: Current) -> list[str]:
    targets = body.get("targets") if isinstance(body.get("targets"), list) else []
    return [f"Stop protecting {item.get('target') or item.get('kind')}" for item in targets
            if isinstance(item, Mapping) and item.get("enabled") is False]


def _agent_hooks(body: Mapping[str, Any], _current: Current) -> list[str]:
    return [f"Stop protecting {body.get('kind')}"] if body.get("enabled") is False else []


Judge = Callable[[Mapping[str, Any], Current], list[str]]
JUDGES: dict[str, Judge] = {
    "/api/settings": _settings,
    "/api/agents/protection": _agents,
    "/api/agent-hooks/protection": _agent_hooks,
}
SHIELD_API = re.compile(r"/api/shields/([a-z0-9-]{1,48})/api/([a-z][a-z0-9-]{0,47})")


def _shield_write(route: str) -> Optional[tuple[str, str]]:
    match = SHIELD_API.fullmatch(route)
    return (match.group(1), match.group(2)) if match else None


def gated(route: str) -> bool:
    """True when a POST to *route* may turn protection down (it is then judged)."""
    if route in JUDGES:
        return True
    write = _shield_write(route)
    if write is None:
        return False
    from .. import shields
    return shields.write_weakening(write[0], write[1], {}) is not None


def reasons(route: str, body: Any, current: Current) -> list[str]:
    """Why the change on *route* weakens protection (empty: it does not, apply it)."""
    if not isinstance(body, Mapping):
        return []
    judge = JUDGES.get(route)
    if judge is not None:
        return judge(body, current)
    write = _shield_write(route)
    if write is None:
        return []
    from .. import shields
    return shields.write_weakening(write[0], write[1], body) or []
