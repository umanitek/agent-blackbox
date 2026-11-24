"""Watch rules as data: what one rule names, its id, its state, and the section it is saved in.

A rule names a host (``files.example.top``; its subdomains too) or a package
(``<ecosystem>:<name>``, ``npm:left-pad``) and is in one of two states:

* ``watch`` — a call that names it is flagged and counted, never refused;
* ``enforce`` — it is refused like a rule from the person's block list (in Block mode).

A rule's id is derived from what it names (:func:`rule_id`), so its hits stay with it when the
rule moves from watch to enforce, and never pass to another rule.

The person's rules are the ``watch_rules`` section of Blackbox's config::

    watch_rules:
      rules:
        - {kind: host, value: files.example.top, state: watch, note: "seen in a report"}
        - {kind: package, value: "npm:left-pad", state: enforce}
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Mapping

SECTION = "watch_rules"
HOST, PACKAGE = "host", "package"
KINDS = (HOST, PACKAGE)
WATCH, ENFORCE = "watch", "enforce"
STATES = (WATCH, ENFORCE)
#: The ecosystems a package rule may name (``detection.parse_dependency_installs`` names them so).
ECOSYSTEMS = ("npm", "pypi", "cargo", "rubygems", "homebrew", "go", "nuget", "maven", "composer")
#: The most rules the person keeps (each call is checked against all of them).
MAX_RULES = 500
MAX_NOTE_CHARS = 200
_HOST = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$")
_PACKAGE = re.compile(r"^[a-z0-9@._/+-]{1,200}$")
#: An organisation's watch rules name ``gem`` for what the install parser calls ``rubygems``.
_ECOSYSTEM_ALIASES = {"gem": "rubygems"}


@dataclass(frozen=True)
class WatchRule:
    """One rule: *kind* host|package, *value* normalised, *state* watch|enforce, *origin* where
    it came from (``person``, or ``organisation`` for an add-on's rules, which always watch)."""

    kind: str
    value: str
    state: str = WATCH
    note: str = ""
    origin: str = "person"

    @property
    def rule_id(self) -> str:
        return rule_id(self.kind, self.value)


def rule_id(kind: str, value: str) -> str:
    """The id of the rule naming *value* of *kind* (an organisation's add-on derives the same)."""
    return "w" + hashlib.sha256(f"{kind}|{value}".encode()).hexdigest()[:12]


def normalise(kind: Any, value: Any) -> str:
    """*value* as a rule of *kind* keeps it, or "" when it is not one."""
    text = str(value or "").strip().lower().rstrip(".")
    if kind == HOST:
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            return text if _HOST.match(text) else ""
    if kind == PACKAGE:
        ecosystem, _, name = text.partition(":")
        ecosystem = _ECOSYSTEM_ALIASES.get(ecosystem, ecosystem)
        return f"{ecosystem}:{name}" if ecosystem in ECOSYSTEMS and _PACKAGE.match(name) else ""
    return ""


def parse(raw: Any, *, origin: str = "person", errors: list[str] | None = None) -> tuple[WatchRule, ...]:
    """The rules in a ``watch_rules`` section (or a bare list); a bad entry is skipped, and said
    in *errors* when given. An organisation's rules always watch."""
    entries = raw.get("rules") if isinstance(raw, Mapping) else raw
    out: dict[str, WatchRule] = {}
    for index, entry in enumerate(entries if isinstance(entries, list) else []):
        if not isinstance(entry, Mapping):
            _say(errors, f"{SECTION}.rules[{index}] must be a mapping")
            continue
        kind, state = entry.get("kind"), entry.get("state", WATCH)
        value = normalise(kind, entry.get("value"))
        if kind not in KINDS or not value or state not in STATES:
            _say(errors, f"{SECTION}.rules[{index}]: kind must be host or package, value a host or "
                         f"<ecosystem>:<name>, state watch or enforce")
            continue
        rule = WatchRule(kind=kind, value=value, state=WATCH if origin != "person" else state,
                         note=str(entry.get("note") or "")[:MAX_NOTE_CHARS], origin=origin)
        out[rule.rule_id] = rule
    if len(out) > MAX_RULES:
        _say(errors, f"{SECTION}: at most {MAX_RULES} rules")
    return tuple(out.values())[:MAX_RULES]


def section(rules: tuple[WatchRule, ...]) -> dict[str, Any]:
    """The ``watch_rules`` section that saves *rules* (the person's)."""
    return {"rules": [{"kind": r.kind, "value": r.value, "state": r.state, **({"note": r.note} if r.note else {})}
                      for r in rules]}


def _say(errors: list[str] | None, message: str) -> None:
    if errors is not None:
        errors.append(message)
