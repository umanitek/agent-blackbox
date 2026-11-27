"""Watch rules: watch a host or a package first, see how often agents reach for it, then block it.

A rule starts in ``watch``: every tool call that names it is flagged (never refused) and counted, so
the person sees whether blocking it would stop real work before they do. Promoted to ``enforce``,
it refuses the call like their block list (in Block mode). Rules come from the person (the
``watch_rules`` section of Blackbox's config, :mod:`.rules`) and from an organisation's add-on
(:func:`set_organisation_rules`, always ``watch``: an organisation blocks through its own policy).

Turning protection down waits for the person: taking an ``enforce`` rule off, or moving it back to
``watch``, is a weakening change (:func:`weakening`, registered with the approval gate by the
dashboard). Adding a rule or promoting one only strengthens and is written at once.

Usage::

    from plugins.blackbox import watch
    watch.check("terminal", {"command": "npm install left-pad"}, agent="codex")   # [Finding] — counted
    watch.add("host", "files.example.top", note="seen in a report")               # starts in watch
    watch.promote(rule_id)                                                         # now enforce
    watch.view()           # every rule with its state, origin and hits (the dashboard's list)
    watch.suggest(finding) # a watch rule pre-filled from a finding, or None
"""

from __future__ import annotations

from typing import Any, Mapping, Optional, TypedDict

from .. import shields
from ..detection import KIND_FLAG_ONLY, Finding, parse_dependency_installs
from ..kernel import config, settings, threat_ids
from . import rules as rules_module
from . import state
from .rules import ENFORCE, HOST, PACKAGE, SECTION, WATCH, WatchRule, normalise, rule_id
from .state import Hits, hits, organisation_rules, set_organisation_rules

__all__ = [
    "CATEGORY", "ENFORCE", "HOST", "PACKAGE", "SECTION", "WATCH", "Hits", "RuleView", "WatchRule", "add", "all_rules",
    "check", "hits", "normalise", "organisation_rules", "person_rules", "promote", "rule_id",
    "set_organisation_rules", "suggest", "validate", "view", "weakening",
]

CATEGORY = "watch"
MAX_COMMAND_CHARS = 8192


class RuleView(TypedDict):
    """One rule as the dashboard lists it."""

    rule_id: str
    kind: str
    value: str
    state: str
    origin: str
    note: str
    hits: int
    last_at: float
    last_agent: str


def person_rules() -> tuple[WatchRule, ...]:
    """The person's own rules, as saved."""
    return rules_module.parse(config.raw_section(SECTION))


def all_rules() -> tuple[WatchRule, ...]:
    """The person's rules, then the organisation's (a rule both name is the person's)."""
    mine = person_rules()
    taken = {r.rule_id for r in mine}
    return mine + tuple(r for r in organisation_rules()[1] if r.rule_id not in taken)


def _named(tool_name: str, args: Any) -> tuple[set[str], set[str]]:
    """(hosts, packages) one call names."""
    hosts = set(shields.hosts_in(args))
    command = args.get("command") if isinstance(args, Mapping) else None
    packages: set[str] = set()
    if isinstance(command, str):
        for install in parse_dependency_installs(command[:MAX_COMMAND_CHARS]):
            value = normalise(PACKAGE, f"{install.get('ecosystem')}:{install.get('name')}")
            if value:
                packages.add(value)
    return hosts, packages


def _matches(rule: WatchRule, hosts: set[str], packages: set[str]) -> bool:
    if rule.kind == HOST:
        return any(host == rule.value or host.endswith("." + rule.value) for host in hosts)
    return rule.value in packages


def check(tool_name: str, args: Any, *, agent: str = "") -> list[Finding]:
    """The findings of every rule *args* names; each hit is counted. ``watch``: a flag that never
    blocks; ``enforce``: a critical rule of the person's that blocks in Block mode. The findings
    are built first and the count is best-effort (``state.count``): a hit that can not be written
    never loses an enforced rule's refusal (review 2026-11-26)."""
    rules = all_rules()
    if not rules:
        return []
    hosts, packages = _named(tool_name, args)
    hit = [rule for rule in rules if _matches(rule, hosts, packages)]
    found = [_finding(rule, tool_name) for rule in hit]
    if hit:
        state.count([rule.rule_id for rule in hit], agent)
    return found


def _finding(rule: WatchRule, tool_name: str) -> Finding:
    watching = rule.state == WATCH
    who = "your organisation's" if rule.origin == "organisation" else "your"
    return Finding(
        identifier=f"watch:{rule.rule_id}", category=CATEGORY, severity="low" if watching else "critical",
        title=(f"Watched: {rule.value} is on {who} watch list (counted, not blocked)" if watching
               else f"Blocked by your rule: {rule.value}"),
        tool_name=tool_name, matched=rule.value, evidence=rule.value, source="custom",
        kind=KIND_FLAG_ONLY if watching else None,
        fields={"rule_id": rule.rule_id, "kind": rule.kind, "state": rule.state, "origin": rule.origin})


def view() -> list[RuleView]:
    """Every rule with its hits, the person's first."""
    counted = hits()
    out: list[RuleView] = []
    for rule in all_rules():
        hit: Hits = counted.get(rule.rule_id) or {"count": 0, "last_at": 0.0, "last_agent": ""}
        out.append(RuleView(rule_id=rule.rule_id, kind=rule.kind, value=rule.value, state=rule.state,
                            origin=rule.origin, note=rule.note, hits=hit["count"], last_at=hit["last_at"],
                            last_agent=hit["last_agent"]))
    return out


def _save(rules: tuple[WatchRule, ...]) -> dict[str, Any]:
    return settings.write_settings({SECTION: rules_module.section(rules)})


def add(kind: str, value: str, *, note: str = "") -> dict[str, Any]:
    """Add a rule in ``watch`` (an existing one is kept as it is). The settings writer's answer."""
    normalised = normalise(kind, value)
    if not normalised:
        return {"ok": False, "errors": ["not a host or <ecosystem>:<name> package"]}
    mine = person_rules()
    if any(r.rule_id == rule_id(kind, normalised) for r in mine):
        return {"ok": True, "errors": []}
    return _save(mine + (WatchRule(kind=kind, value=normalised, note=note[:rules_module.MAX_NOTE_CHARS]),))


def promote(wanted: str) -> dict[str, Any]:
    """Move the person's rule *wanted* to ``enforce``. An organisation's rule can not be promoted
    here (the organisation blocks through its own policy): add it as the person's own first."""
    mine = person_rules()
    if not any(r.rule_id == wanted for r in mine):
        return {"ok": False, "errors": ["no rule of yours with that id"]}
    return _save(tuple(WatchRule(r.kind, r.value, ENFORCE if r.rule_id == wanted else r.state, r.note)
                       for r in mine))


def validate(raw: Any, errors: list[str]) -> dict[str, Any]:
    """The settings writer's validator for ``watch_rules`` (``kernel.settings.SECTION_VALIDATORS``)."""
    found: list[str] = []
    parsed = rules_module.parse(raw, errors=found)
    errors.extend(found)
    return rules_module.section(parsed) if not found else {}


def weakening(proposed: Any) -> list[str]:
    """Why saving *proposed* as ``watch_rules`` turns protection down: each enforced rule it takes
    off or moves back to watch (``approvals.SECTION_JUDGES``)."""
    wanted = {r.rule_id: r for r in rules_module.parse(proposed)}
    return [f"Stop blocking {rule.value} (your watch rule)" for rule in person_rules()
            if rule.state == ENFORCE and (rule.rule_id not in wanted or wanted[rule.rule_id].state != ENFORCE)]


def _url_host(text: str) -> str:
    """The host of a ``scheme://host/…`` URL in *text* ("" when it is not one)."""
    return text.split("://", 1)[1].split("/", 1)[0].split("@")[-1].rsplit(":", 1)[0] if "://" in text else ""


def _named_by(finding: Mapping[str, Any]) -> list[tuple[str, Any]]:
    """Every (kind, value) *finding* may name, most precise first.

    WHY the identifier comes first (KI-694/KI-702): the findings feed (``GET /api/findings``) keeps
    a row's identifier but not always its ``matched`` or ``fields``, and that row is what the
    dashboard's "Watch this" link sends. The identifier names the threat in one canonical form
    (``dep:<ecosystem>:<name>@<version>``, ``ioc:<type>:<value>``) on every row."""
    identifier = str(finding.get("identifier") or "")
    fields = finding.get("fields") if isinstance(finding.get("fields"), Mapping) else {}
    matched = str(finding.get("matched") or "")
    named: list[tuple[str, Any]] = []
    dependency = threat_ids.parse_dependency_identifier(identifier)
    if dependency:
        named.append((PACKAGE, f"{dependency[0]}:{dependency[1]}"))
    ioc = threat_ids.parse_ioc_identifier(identifier)
    if ioc and ioc[0] in ("domain", "ip"):
        named.append((HOST, ioc[1]))
    elif ioc and ioc[0] == "url":
        named.append((HOST, _url_host(ioc[1])))
    named += [(PACKAGE, f"{fields.get('ecosystem')}:{fields.get('package_name')}"), (HOST, fields.get("host")),
              (HOST, _url_host(matched)), (HOST, matched)]
    return named


def suggest(finding: Mapping[str, Any]) -> Optional[dict[str, str]]:
    """A watch rule pre-filled from *finding* (a row of the findings feed, or a ``Finding.to_dict()``):
    the host or package it names, to watch before blocking; None when it names neither, or when it
    is a watch rule's own finding (that rule already exists)."""
    if str(finding.get("identifier") or "").startswith(f"{CATEGORY}:"):
        return None
    for kind, value in _named_by(finding):
        normalised = normalise(kind, value)
        if normalised:
            title = str(finding.get("title") or "")[:120]
            return {"kind": kind, "value": normalised, "note": f"from a finding: {title}" if title else ""}
    return None


settings.SECTION_VALIDATORS[SECTION] = validate
