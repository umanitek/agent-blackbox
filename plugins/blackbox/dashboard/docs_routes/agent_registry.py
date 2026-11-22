"""The platform map and test registry of the coding agents Blackbox protects — one data file
(``agent_registry.json``) that the Docs page, the generated ``docs/agent-compat/coverage-matrix.md``
and the "newer than tested" notice all read, so they cannot drift apart.

Per agent the file says how it starts processes, where its profiles live per operating system,
every config scope and launch mode, every hook event (hooked or not, and why not), and — per
operating system × launch mode × protection layer — whether that was TESTED on a real machine
(date, Blackbox version, how, result), is covered by automated tests only, or is not covered and
why. ``tests/plugins/test_blackbox_agent_registry.py`` holds it equal to the code's catalogue
(``kernel/agent_hosts``).

Usage::

    from .agent_registry import load, docs_section, render_markdown
    docs_section()          # what GET /api/docs carries under "agents"
    render_markdown()       # the text of docs/agent-compat/coverage-matrix.md
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

PATH = Path(__file__).with_name("agent_registry.json")
LAYERS = ("hooks", "sandbox", "os")
STATUS_WORDS = {"tested": "Tested", "covered-untested": "Built, not yet run in the product", "not-covered": "Not covered"}


def load() -> dict[str, Any]:
    return json.loads(PATH.read_text(encoding="utf-8-sig"))


def _key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split(".") if part.isdigit())


def version_notice(agent: Mapping[str, Any], installed_version: str) -> str:
    """What to say about the installed version against the versions Blackbox was tested with
    ("" when the installed one is among them or older)."""
    tested = [row.get("agent_version", "") for row in agent["coverage"] if row["status"] == "tested"]
    known = [version for version in tested if version]
    if not installed_version:
        return ""
    if not known:
        return f"Version {installed_version} is installed. No test run recorded the agent's version yet."
    newest = max(known, key=_key)
    if _key(installed_version) > _key(newest):
        return f"Version {installed_version} is installed — newer than the last tested version ({newest})."
    return ""


def docs_section() -> dict[str, Any]:
    """The registry with, per agent, what is installed here and the version notice."""
    from ...agent_hooks import versions

    registry = load()
    found = versions.installed()
    for agent in registry["agents"]:
        here = found.get(agent["id"])
        agent["installed"] = {"path": here.path, "version": here.version} if here else None
        agent["version_notice"] = version_notice(agent, here.version) if here else ""
    return registry


def _levels(agent: Mapping[str, Any]) -> dict[str, str]:
    """The best status each layer reached for *agent* (tested > covered-untested > not-covered)."""
    order = ("tested", "covered-untested", "not-covered")
    best = {}
    for layer in LAYERS:
        statuses = [row["status"] for row in agent["coverage"] if row["layer"] == layer]
        best[layer] = min(statuses, key=order.index) if statuses else "not-covered"
    return best


def _agent_markdown(agent: Mapping[str, Any]) -> list[str]:
    lines = [f"## {agent['name']}", "", agent["processes"], "",
             f"**Profiles:** macOS `{agent['profiles']['macos']}` · Linux `{agent['profiles']['linux']}` · Windows `{agent['profiles']['windows']}`"
             + (f" · moved by `{agent['home_env']}`" if agent["home_env"] else ""), "",
             "| Scope | Where | Blackbox's hooks there | Note |", "|---|---|---|---|"]
    lines += [f"| {row['scope']} | `{row['where']}` | {'yes' if row['hooked'] else 'no'} | {row.get('note', '')} |" for row in agent["scopes"]]
    lines += ["", "| Launch mode | How | Hooks run | Note |", "|---|---|---|---|"]
    lines += [f"| {row['mode']} | `{row['how']}` | {'yes' if row['hooks_run'] else 'no'} | {row.get('note', '')} |" for row in agent["launch_modes"]]
    lines += ["", "| Hook event | Blackbox reads it as | Hooked | Why not |", "|---|---|---|---|"]
    lines += [f"| {row['event']} | {row.get('kind', '')} | {'yes' if row['hooked'] else 'no'} | {row.get('why', '')} |" for row in agent["events"]]
    lines += ["", f"**Sub-agents:** {agent['sub_agents']}", "", "| OS | Launch mode | Layer | Status | Detail |", "|---|---|---|---|---|"]
    for row in agent["coverage"]:
        detail = (f"{row['date']}, Blackbox {row['blackbox']}" + (f", agent {row['agent_version']}" if row.get("agent_version") else ", agent version not recorded")
                  + f": {row['how']} — {row['result']}") if row["status"] == "tested" else row.get("why", "")
        lines.append(f"| {row['os']} | {row['launch']} | {row['layer']} | {STATUS_WORDS[row['status']]} | {detail} |")
    lines += ["", "**Not covered:**"] + [f"- {item}" for item in agent["not_covered"]]
    lines += ["", "Sources: " + ", ".join(f"<{source['url']}> (read {source['read']})" for source in agent["sources"]), ""]
    return lines


def render_markdown() -> str:
    """``docs/agent-compat/coverage-matrix.md``, generated from the registry."""
    registry = load()
    lines = ["# What Blackbox protects, per coding agent", "",
             "Generated from `dashboard/docs_routes/agent_registry.json` — edit that file, never this one "
             f"(a test holds them equal). Last updated {registry['updated']} for Blackbox {registry['blackbox']}.", "",
             "Three layers:", ""]
    lines += [f"- **{layer}** — {registry['layers'][layer]}" for layer in LAYERS]
    lines += ["", "Statuses:", ""] + [f"- **{STATUS_WORDS[key]}** — {text}" for key, text in registry["statuses"].items()]
    lines += ["", "| Agent | Hooks | Sandbox | OS-level |", "|---|---|---|---|"]
    for agent in registry["agents"]:
        levels = _levels(agent)
        lines.append(f"| {agent['name']} | " + " | ".join(STATUS_WORDS[levels[layer]] for layer in LAYERS) + " |")
    lines.append("")
    for agent in registry["agents"]:
        lines += _agent_markdown(agent)
    return "\n".join(lines).rstrip() + "\n"
