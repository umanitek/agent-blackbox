"""Hooks that are files of Blackbox's own: Copilot CLI's hooks file, Cline's per-event scripts,
OpenCode's plugin. Nothing of the user's is edited: Blackbox writes its own files and removes only
files that carry :data:`.config_edit.MARK`.

Cline runs one script per event (``~/Documents/Cline/Hooks/PreToolUse``). When the user already has
a script for an event, Blackbox does NOT replace it: that event is left to the user's script and
the result says so.

Usage: same as :mod:`.config_edit` — ``install(host, home, invocations)``, ``uninstall(host, home)``,
``installed_commands(host, home)``; *invocations* maps each agent event to ``(argv, command)``.

**Undo:** Blackbox-owned hook files are removed when protection is switched off; a user's own
file for the same event is never replaced or removed.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from ...kernel.bounded_files import atomic_write
from .config_edit import HOOK_TIMEOUT, MARK, EditResult
from ...kernel.agent_hosts import Host

Invocations = dict[str, tuple[list[str], str]]

_OPENCODE_PLUGIN = """// Blackbox Agent Hooks — written by Blackbox ({mark}); removing Blackbox removes this file.
// Asks Blackbox before every tool call (a verified threat is refused) and after it (an output
// carrying a known prompt injection is replaced). Fail-open: any error lets the tool run.
import {{ spawnSync }} from "node:child_process";
const BEFORE = {before};
const AFTER = {after};
function ask(argv, payload) {{
  try {{
    const run = spawnSync(argv[0], argv.slice(1), {{ input: JSON.stringify(payload), encoding: "utf8", timeout: 8000 }});
    return run.stdout ? JSON.parse(run.stdout) : {{}};
  }} catch {{
    return {{}};
  }}
}}
export const BlackboxPlugin = async ({{ directory }} = {{}}) => ({{
  "tool.execute.before": async (input, output) => {{
    const answer = ask(BEFORE, {{ tool: input.tool, args: output.args, sessionID: input.sessionID, cwd: directory }});
    if (answer.decision === "block") throw new Error(answer.reason || "Blocked by Blackbox");
  }},
  "tool.execute.after": async (input, output) => {{
    const text = typeof output?.output === "string" ? output.output.slice(0, 262144) : output?.output;
    const answer = ask(AFTER, {{ tool: input.tool, sessionID: input.sessionID, cwd: directory, output: text }});
    // A known prompt injection in the output: the model reads Blackbox's notice instead.
    if (answer.decision === "block" && output) output.output = answer.reason || "Blackbox withheld this output: it carries a known prompt injection.";
  }},
}});
"""


def _ours(path: Path) -> bool:
    try:
        return path.is_file() and MARK in path.read_text(encoding="utf-8-sig", errors="replace")[:4096]
    except OSError:
        return False


def install(host: Host, home: Path, invocations: Invocations) -> EditResult:
    target = host.config_path(home)
    try:
        if host.style == "own-json":
            hooks = {event: [{"type": "command", "bash": command, "timeoutSec": HOOK_TIMEOUT}]
                     for event, (_argv, command) in invocations.items()}
            target.parent.mkdir(parents=True, exist_ok=True)
            atomic_write(target, json.dumps({"version": 1, "hooks": hooks}, indent=2) + "\n")
            return EditResult(True, str(target))
        if host.style == "plugin":
            by_kind = {host.events[event]: argv for event, (argv, _command) in invocations.items()}
            text = _OPENCODE_PLUGIN.format(mark=MARK, before=json.dumps(by_kind.get("pre_tool", [])),
                                           after=json.dumps(by_kind.get("post_tool", [])))
            target.parent.mkdir(parents=True, exist_ok=True)
            atomic_write(target, text)
            return EditResult(True, str(target))
        return _install_scripts(target, invocations)
    except OSError as exc:
        return EditResult(False, str(target), f"could not write: {exc.strerror or exc}")


def _install_scripts(folder: Path, invocations: Invocations) -> EditResult:
    folder.mkdir(parents=True, exist_ok=True)
    left = []
    for event, (_argv, command) in invocations.items():
        script = folder / event
        if script.exists() and not _ours(script):
            left.append(event)   # the user's own script for this event stays
            continue
        atomic_write(script, f"#!/bin/sh\n# Blackbox Agent Hooks ({MARK}) — written by Blackbox\nexec {command}\n", mode=0o755)
    note = f"your own {', '.join(left)} script{'s' if len(left) > 1 else ''} kept; Blackbox does not see those events" if left else ""
    return EditResult(True, str(folder), note)


def uninstall(host: Host, home: Path) -> EditResult:
    target = host.config_path(home)
    try:
        if host.style == "scripts":
            for event in host.events:
                if _ours(target / event):
                    (target / event).unlink()
        elif _ours(target):
            target.unlink()
    except OSError as exc:
        return EditResult(False, str(target), f"could not remove: {exc.strerror or exc}")
    return EditResult(True, str(target))


def installed_commands(host: Host, home: Path) -> list[str]:
    target = host.config_path(home)
    if host.style == "scripts":
        return [str(target / event) for event in host.events if _ours(target / event)]
    return [str(target)] if _ours(target) else []


def runnable(paths: list[str]) -> bool:
    """True when every file a hook runs exists (a moved Python or runner makes the hook a no-op)."""
    return all(os.path.exists(path) for path in paths)
