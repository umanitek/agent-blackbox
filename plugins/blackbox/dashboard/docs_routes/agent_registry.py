"""The platform map and test registry of the coding agents Blackbox protects — one data file
(``agent_registry.json``) that the Docs page, the generated ``docs/agent-compat/coverage-matrix.md``
and the "newer than tested" notice all read, so they cannot drift apart.

Per agent the file says how it starts processes, where its profiles live per operating system,
every config scope and launch mode, every hook event (hooked or not, and why not), and — per
operating system × launch mode × protection layer — whether that was TESTED on a real machine
(date, Blackbox version, how, result), is covered by automated tests only, or is not covered and
why. ``tests/plugins/test_blackbox_agent_registry.py`` holds it equal to the code's catalogue
(``kernel/agent_hosts``).

A test run adds its own row (:func:`record_test`; ``record_test.py`` is its command), so the
record of what was run — which agent version, on which OS version, with which Blackbox — stays
current without hand edits.

Usage::

    from .agent_registry import load, docs_section, render_markdown
    docs_section()          # what GET /api/docs carries under "agents"
    render_markdown()       # the text of docs/agent-compat/coverage-matrix.md
    record_test(registry, TestRun(agent="codex", os="macos", launch="interactive", layer="hooks", ...))
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

PATH = Path(__file__).with_name("agent_registry.json")
LAYERS = ("hooks", "sandbox", "os")
STATUS_WORDS = {"tested": "Tested", "covered-untested": "Built, not yet run in the product", "not-covered": "Not covered"}


MATRIX = PATH.parents[2] / "docs" / "agent-compat" / "coverage-matrix.md"
RESULTS = ("pass", "partial", "fail")


def load() -> dict[str, Any]:
    return json.loads(PATH.read_text(encoding="utf-8-sig"))


@dataclass(frozen=True)
class TestRun:
    """One run on a real machine: which agent (and version) was run how, on which OS, against
    which protection layer, with which Blackbox — and what came of it."""

    agent: str
    os: str            # "macos" / "linux" / "windows"
    launch: str        # a launch mode of the agent, e.g. "interactive"
    layer: str         # one of LAYERS
    agent_version: str
    os_version: str
    blackbox: str
    date: str          # YYYY-MM-DD
    how: str
    result: str        # one of RESULTS


def record_test(registry: dict[str, Any], run: TestRun) -> dict[str, Any]:
    """*registry* with *run* written as the TESTED row for its (os, launch, layer): the row that
    was there is replaced, a new one is added. Raises ValueError for an unknown agent, layer or
    result, or a run that does not say how it was done."""
    agent = next((item for item in registry["agents"] if item["id"] == run.agent), None)
    if agent is None:
        raise ValueError(f"unknown agent: {run.agent}")
    if run.layer not in LAYERS or run.result not in RESULTS:
        raise ValueError("layer must be one of hooks/sandbox/os and result one of pass/partial/fail")
    if not (run.how.strip() and run.date.strip() and run.blackbox.strip()):
        raise ValueError("a tested row says when, with which Blackbox and how")
    row = {"os": run.os, "launch": run.launch, "layer": run.layer, "status": "tested", "agent_version": run.agent_version,
           "os_version": run.os_version, "date": run.date, "blackbox": run.blackbox, "how": run.how, "result": run.result}
    key = (run.os, run.launch, run.layer)
    rows = agent["coverage"]
    index = next((at for at, item in enumerate(rows) if (item["os"], item["launch"], item["layer"]) == key), None)
    if index is None:
        rows.append(row)
    else:
        rows[index] = row
    registry["updated"], registry["blackbox"] = run.date, run.blackbox
    return registry


def save(registry: Mapping[str, Any]) -> None:
    """Write the registry and the coverage page generated from it (the two a test holds equal)."""
    PATH.write_text(json.dumps(registry, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    MATRIX.write_text(render_markdown(), encoding="utf-8")


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
    from ...agent_hooks import prompt_text, versions

    registry = load()
    registry["prompt_text"] = prompt_text.status().statement   # "Prompt text: not recorded." unless the person turned it on
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
                  + (f", {row['os_version']}" if row.get("os_version") else "")
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
