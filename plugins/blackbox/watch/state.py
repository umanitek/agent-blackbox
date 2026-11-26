"""What watch rules leave on disk: each rule's hits, and the rules an organisation's add-on handed in.

* ``$BLACKBOX_HOME/watch/hits.json`` — ``{rule id: {"count", "last_at", "last_agent"}}``;
* ``$BLACKBOX_HOME/watch/organisation.json`` — ``{"version": int, "rules": [...]}``, written only
  through :func:`set_organisation_rules` (an add-on that verified the organisation's signature).

Both are in Blackbox's home, which self-protection guards: an agent can neither clear the hits nor
hand in rules of its own.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, TypedDict

from ..kernel import constants
from ..kernel.bounded_files import file_lock, read_json_object, write_json_object
from . import rules as rules_module

LOCK_TIMEOUT_S = 2.0
MAX_AGENT_CHARS = 64


class Hits(TypedDict):
    """One rule's hits: how many calls named it, the last one's time and agent."""

    count: int
    last_at: float
    last_agent: str


def _folder() -> Path:
    return constants.blackbox_home() / "watch"


def hits() -> dict[str, Hits]:
    """Every rule's hits (rules never hit are absent)."""
    out: dict[str, Hits] = {}
    for key, entry in (read_json_object(_folder() / "hits.json") or {}).items():
        if isinstance(entry, dict) and isinstance(entry.get("count"), int):
            out[str(key)] = {"count": entry["count"], "last_at": float(entry.get("last_at") or 0.0),
                             "last_agent": str(entry.get("last_agent") or "")[:MAX_AGENT_CHARS]}
    return out


def count(rule_ids: list[str], agent: str) -> None:
    """Add one hit to each of *rule_ids*."""
    path = _folder() / "hits.json"
    with file_lock(path.with_suffix(".lock"), timeout_s=LOCK_TIMEOUT_S):
        current = hits()
        now = time.time()
        for key in rule_ids:
            previous = current.get(key) or {"count": 0}
            current[key] = {"count": int(previous["count"]) + 1, "last_at": now,
                            "last_agent": (agent or "hermes")[:MAX_AGENT_CHARS]}
        write_json_object(path, dict(current), what="Blackbox's watch rule hits")


def organisation_rules() -> tuple[int, tuple[rules_module.WatchRule, ...]]:
    """(version, rules) an organisation's add-on handed in; (0, ()) when none."""
    saved = read_json_object(_folder() / "organisation.json") or {}
    version = saved.get("version")
    if not isinstance(version, int) or version < 1:
        return 0, ()
    return version, rules_module.parse(saved.get("rules"), origin="organisation")


def set_organisation_rules(version: int, entries: list[dict[str, Any]]) -> tuple[rules_module.WatchRule, ...]:
    """Run exactly *entries* (``{kind, value}``) as the organisation's watch rules (they never block).
    *version* 0 clears them. An older version than the one held is refused (``ValueError``), so a
    replayed set can not bring back a rule the organisation took off."""
    held, _ = organisation_rules()
    if version and version < held:
        raise ValueError(f"organisation watch rules version {version} is older than {held}")
    path = _folder() / "organisation.json"
    if not version:
        path.unlink(missing_ok=True)
        return ()
    taken = rules_module.parse(entries, origin="organisation")
    write_json_object(path, {"version": version, "rules": [{"kind": r.kind, "value": r.value} for r in taken]},
                      what="the organisation's watch rules")
    return taken
