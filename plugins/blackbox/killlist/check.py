"""Matching a tool call against the kill list, in the hook (R14) — microseconds, offline.

Skills: the host's skill-install tools expose name, version and the
artifact hash (``detection.skill_install_arg``); an entry
matches on registry ``skill`` + name (or publisher-wide ``*``) + an exact
version pin if given + an exact hash pin if given. MCP servers: the host
names a server's tools with a prefix; an entry with registry ``mcp`` and a
``tool_prefix`` matches any tool whose name starts with it.

The match becomes a :class:`detection.Finding` with source ``custom`` — the
local-policy tier: it always flags, blocks in block mode, bypasses the
per-category policy and is NEVER shared to the community graph (a kill is
not a sighting). DISABLE is critical and blocks in block mode; WARN is
medium and only flags. Files and config are never touched.

Publisher-wide kills (``identifier="*"`` + ``publisher``; owner decision 2026-11-27). The publisher
an install names is SELF-REPORTED (the call's ``publisher`` / ``author``): naming the killed one is
reason enough to refuse (believing a claim that refuses is safe). The owner's rule until a registry
resolver exists: while a publisher-wide DISABLE is in force for a registry, an install there that
names NO publisher is a critical finding matched ``kernel.constants.UNNAMED_PUBLISHER`` (decided by
the person's ``unnamed-publisher`` permission: blocked in Block mode by default) — it could be the
killed publisher's package under a name that does not show it. WHY not every unconfirmed one: the
owner chose "name no publisher" as the interim line; an install naming ANOTHER publisher still
proves nothing, and that gap closes when :func:`_confirmed_publisher` gets a local, offline resolver
(none may be added on the hot path: no network call between an agent and its action). With no
publisher kill in force nothing changes.

Usage::

    finding = finding_for(kill_list, tool_name, args)   # None when nothing matches
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

from ..detection import Finding, skill_install_arg
from ..kernel import constants
from .statement import KillAction, KillEntry, KillList


def _canonical(text: object) -> str:
    """A name or publisher as matched: trimmed and case-folded (review 2026-11-26: a publisher-wide
    kill missed ``"evilcorp "`` — the spelling is the caller's, the match is on the canonical value)."""
    return str(text or "").strip().casefold()


def _skill_matches(entry: KillEntry, name: str, version: str, artifact_hash: str, publisher: str) -> bool:
    if entry.registry != "skill":
        return False
    if entry.publisher:
        return bool(publisher) and _canonical(entry.publisher) == publisher
    if _canonical(entry.identifier) != _canonical(name):
        return False
    if entry.version and entry.version != version:
        return False
    return not entry.artifact_hash or entry.artifact_hash == artifact_hash.lower()


def match(entries: Iterable[KillEntry], tool_name: str, args: Any) -> Optional[KillEntry]:
    """The first entry the call hits (DISABLE entries are checked before WARN ones)."""
    tool = (tool_name or "").strip().lower()
    skill = skill_install_arg(tool_name, args)
    publisher = _canonical(args.get("publisher") or args.get("author")) if isinstance(args, dict) else ""
    ordered = sorted(entries, key=lambda e: e.action is not KillAction.DISABLE)
    for entry in ordered:
        if entry.registry == "mcp" and entry.tool_prefix and tool.startswith(entry.tool_prefix):
            return entry
        if skill and _skill_matches(entry, skill["name"], skill["version"], skill["artifact_hash"], publisher):
            return entry
    return None


def _confirmed_publisher(registry: str, name: str) -> str:
    """The publisher the *registry* itself confirms for package *name*, "" when unknown.

    WHY always "" today: no registry resolver exists, and the hot path makes no network call. Until a
    local, offline resolver exists, only the owner's interim line holds (see the module doc)."""
    return ""


def _unnamed_publisher(kill_list: KillList, tool_name: str, args: Any) -> Optional[Finding]:
    """The finding for an install that names no publisher (and none the registry confirms) while a
    publisher-wide DISABLE is in force for its registry (only skills install through a tool call), else None."""
    skill = skill_install_arg(tool_name, args)
    kills = [entry for entry in kill_list.disables if entry.registry == "skill" and entry.publisher]
    named = _canonical(args.get("publisher") or args.get("author")) if isinstance(args, dict) else ""
    if skill is None or not kills or named or _confirmed_publisher("skill", skill["name"]):
        return None
    killed = ", ".join(sorted({entry.publisher for entry in kills}))
    return Finding(
        identifier=f"kill:skill:{constants.UNNAMED_PUBLISHER}", category="skill", severity="critical",
        title=f"No publisher named while the curators' kill list disables publisher {killed}",
        tool_name=(tool_name or "").lower(), matched=constants.UNNAMED_PUBLISHER,
        evidence=(f"kill list v{kill_list.version}: a publisher-wide kill is in force, and this install names no "
                  "publisher, so it could be the killed publisher's package"),
        confirmed=True, source="custom",
        advice=("While a whole publisher is disabled, installs that name no publisher are refused. "
                "Install it yourself if you trust it, or allow \"Installs that name no publisher\" for this agent."),
        fields={"registry": "skill", "kill_action": KillAction.DISABLE.value, "reason": "unnamed-publisher"},
    )


def finding_for(kill_list: Optional[KillList], tool_name: str, args: Any) -> Optional[Finding]:
    """The finding a kill produces for this call, or None."""
    if kill_list is None or not kill_list.entries:
        return None
    entry = match(kill_list.entries, tool_name, args)
    if entry is None:
        return _unnamed_publisher(kill_list, tool_name, args)
    disable = entry.action is KillAction.DISABLE
    target = entry.publisher or entry.identifier
    return Finding(
        identifier=f"kill:{entry.registry}:{target}@{entry.version or '*'}",
        category="skill",   # the capability category the detection policy knows; the registry is in the fields
        severity="critical" if disable else "medium",
        title=f"{'DISABLED' if disable else 'WARNING'} by the curators' kill list: {entry.registry} {target} ({entry.reason})",
        tool_name=(tool_name or "").lower(),
        matched=target,
        evidence=(f"kill list v{kill_list.version}: {entry.action.value} {entry.key}; "
                  "the tool call is refused — nothing is uninstalled or changed on disk" if disable
                  else f"kill list v{kill_list.version}: warn {entry.key}"),
        confirmed=True,
        source="custom",
        kind="malware",
        fields={"registry": entry.registry, "kill_action": entry.action.value, "reason": entry.reason},
    )
