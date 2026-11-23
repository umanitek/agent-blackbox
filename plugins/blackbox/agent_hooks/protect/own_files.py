"""Hooks that are files of Blackbox's own: Copilot CLI's hooks file, Cline's per-event scripts,
OpenCode's plugin. Nothing of the user's is edited: Blackbox writes its own files and removes only
files that carry :data:`.config_edit.MARK`.

Cline runs one script per event (``~/Documents/Cline/Hooks/PreToolUse``). When the user already has
a script for an event, Blackbox does NOT replace it: that event is left to the user's script and
the result says so.

Usage: same as :mod:`.config_edit` — ``install(host, home, invocations)``, ``uninstall(host, home)``,
``installed_commands(host, home)``; *invocations* maps each agent event to ``(argv, command)``.

Two agents take hooks in a second form as well (``Host.companions``): Cline's CLI and SDK load an
SDK plugin (:data:`_CLINE_PLUGIN`, ``~/Documents/Cline/Plugins/blackbox.js``) beside the scripts,
and OpenCode 2 loads :data:`_OPENCODE_V2_PLUGIN` (``plugins/blackbox/index.js``) and runs no
version-1 plugin. Both are written with the main form; ``installed_commands`` lists them, so a
missing one is repaired by the sweep.

**Undo:** Blackbox-owned hook files are removed when protection is switched off; a user's own
file for the same event is never replaced or removed.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from ...kernel.bounded_files import atomic_write
from .config_edit import MARK, EditResult
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
// A sub-agent (the task tool) runs as a CHILD session: its parent is named with every call, so
// Blackbox shows it under the session that started it. Learned from OpenCode's session events,
// or asked of OpenCode once per session.
const parents = new Map();
async function parentOf(client, sessionID) {{
  if (!sessionID) return "";
  if (!parents.has(sessionID)) {{
    try {{
      const found = await client?.session?.get?.({{ path: {{ id: sessionID }} }});
      parents.set(sessionID, found?.data?.parentID ?? "");
    }} catch {{
      parents.set(sessionID, "");
    }}
  }}
  return parents.get(sessionID) ?? "";
}}
export const BlackboxPlugin = async ({{ directory, client }} = {{}}) => ({{
  event: async ({{ event }}) => {{
    const info = event?.properties?.info;
    if ((event?.type === "session.created" || event?.type === "session.updated") && info?.id) parents.set(info.id, info.parentID ?? "");
  }},
  "tool.execute.before": async (input, output) => {{
    const parent = await parentOf(client, input.sessionID);
    const answer = ask(BEFORE, {{ tool: input.tool, args: output.args, sessionID: input.sessionID, callID: input.callID, cwd: directory,
                                 parent_session_id: parent, parents_named: true }});
    if (answer.decision === "block") throw new Error(answer.reason || "Blocked by Blackbox");
  }},
  "tool.execute.after": async (input, output) => {{
    const text = typeof output?.output === "string" ? output.output.slice(0, 262144) : output?.output;
    const parent = await parentOf(client, input.sessionID);
    const answer = ask(AFTER, {{ tool: input.tool, sessionID: input.sessionID, callID: input.callID, cwd: directory, output: text,
                                parent_session_id: parent, parents_named: true }});
    // A known prompt injection in the output: the model reads Blackbox's notice instead.
    if (answer.decision === "block" && output) output.output = answer.reason || "Blackbox withheld this output: it carries a known prompt injection.";
  }},
}});
"""

#: OpenCode 2 (opencode.ai/docs/build/plugins/server, read 2026-11-22): a default export with an
#: ``id`` and ``setup(ctx)``; ``ctx.tool.hook("execute.before" | "execute.after")`` gets ONE
#: mutable event ({tool, sessionID, id, input} + {status, result}); throwing refuses the call.
_OPENCODE_V2_PLUGIN = """// Blackbox Agent Hooks — written by Blackbox ({mark}); removing Blackbox removes this file.
// OpenCode 2 plugin. Asks Blackbox before every tool call (a verified threat is refused) and
// after it (an output carrying a known prompt injection is replaced). Fail-open: any error lets
// the tool run. OpenCode 1 reads ../../plugin/blackbox.js instead.
import {{ spawnSync }} from "node:child_process";
const BEFORE = {before};
const AFTER = {after};
function ask(argv, payload) {{
  try {{
    if (!argv.length) return {{}};
    const run = spawnSync(argv[0], argv.slice(1), {{ input: JSON.stringify(payload), encoding: "utf8", timeout: 8000 }});
    return run.stdout ? JSON.parse(run.stdout) : {{}};
  }} catch {{
    return {{}};
  }}
}}
export default {{
  id: "blackbox",
  async setup(ctx) {{
    const cwd = ctx?.location?.directory ?? "";
    await ctx.tool.hook("execute.before", (event) => {{
      const answer = ask(BEFORE, {{ tool: event.tool, args: event.input, sessionID: event.sessionID, callID: event.id, cwd }});
      if (answer.decision === "block") throw new Error(answer.reason || "Blocked by Blackbox");
    }});
    await ctx.tool.hook("execute.after", (event) => {{
      if (event.status !== "completed") return;
      const content = event.result?.content;
      const text = (typeof content === "string" ? content : JSON.stringify(content ?? "")).slice(0, 262144);
      const answer = ask(AFTER, {{ tool: event.tool, sessionID: event.sessionID, callID: event.id, cwd, output: text }});
      // A known prompt injection in the output: the model reads Blackbox's notice instead.
      if (answer.decision === "block") event.result = {{ ...event.result, content: answer.reason || "Blackbox withheld this output: it carries a known prompt injection." }};
    }});
  }},
}};
"""

#: Cline's SDK plugin (docs.cline.bot/sdk/plugins, read 2026-11-22; checked against the SDK
#: 3.0.75's own loader): an ``AgentPlugin`` default export whose ``beforeTool`` may return
#: ``{skip, reason}`` and whose ``afterTool`` may return ``{result}``. It sends the runner the
#: SAME payload the hook scripts get, so one mapping serves both. Each hook call has 3 seconds.
#: ``beforeRun`` (KI-617): Cline 3.0.75's TaskStart script payload carries NO task text and its
#: UserPromptSubmit fires only for later messages, so the task the person starts with is read
#: here, from the run's ``snapshot.messages`` (docs.cline.bot/sdk/plugins: every hook's context
#: holds the snapshot with its messages) — once, on the run whose snapshot holds ONE user message —
#: and sent as the prompt it is (``userPromptSubmit.prompt``); a refused one stops the run.
_CLINE_PLUGIN = """// Blackbox Agent Hooks — written by Blackbox ({mark}); removing Blackbox removes this file.
// Cline SDK plugin (CLI, SDK, Kanban). Asks Blackbox before every tool call (a refused call is
// skipped with Blackbox's reason) and after it (an output carrying a known prompt injection is
// replaced). Cline's hook scripts report the same calls; Blackbox answers one call once.
// Fail-open: any error lets the tool run.
import {{ spawnSync }} from "node:child_process";
const BEFORE = {before};
const AFTER = {after};
const PROMPT = {prompt};
let cwd = "";
function words(message) {{
  const content = message?.content;
  if (typeof content === "string") return content;
  if (Array.isArray(content)) return content.map((part) => (typeof part === "string" ? part : part?.text ?? "")).join("\\n");
  return "";
}}
function ask(argv, payload) {{
  try {{
    if (!argv.length) return {{}};
    const run = spawnSync(argv[0], argv.slice(1), {{ input: JSON.stringify(payload), encoding: "utf8", timeout: 2500 }});
    return run.stdout ? JSON.parse(run.stdout) : {{}};
  }} catch {{
    return {{}};
  }}
}}
function event(context, name, data) {{
  const snapshot = context?.snapshot ?? {{}};
  return {{ taskId: snapshot.conversationId ?? "", agent_id: snapshot.agentId ?? "", parent_agent_id: snapshot.parentAgentId ?? null,
           workspaceRoots: cwd ? [cwd] : [], tool_call: {{ id: context?.toolCall?.toolCallId ?? "" }}, [name]: data }};
}}
const plugin = {{
  name: "blackbox",
  manifest: {{ capabilities: ["hooks"] }},
  setup(_api, ctx) {{
    cwd = ctx?.cwd ?? "";
  }},
  hooks: {{
    beforeRun(context) {{
      // The task Cline starts with: the first run is the one whose snapshot holds one user message.
      const users = (context?.snapshot?.messages ?? []).filter((message) => message?.role === "user");
      if (users.length !== 1) return;
      const prompt = words(users[0]).slice(0, 262144);
      if (!prompt) return;
      const answer = ask(PROMPT, event(context, "userPromptSubmit", {{ prompt }}));
      if (answer.cancel === true) return {{ stop: true, reason: answer.errorMessage || "Blocked by Blackbox" }};
    }},
    beforeTool(context) {{
      const call = {{ toolName: context?.toolCall?.toolName ?? context?.tool?.name ?? "", parameters: context?.input ?? {{}} }};
      const answer = ask(BEFORE, event(context, "preToolUse", call));
      if (answer.cancel === true) return {{ skip: true, reason: answer.errorMessage || "Blocked by Blackbox" }};
    }},
    afterTool(context) {{
      const output = context?.result?.output;
      const result = (typeof output === "string" ? output : JSON.stringify(output ?? "")).slice(0, 262144);
      const call = {{ toolName: context?.toolCall?.toolName ?? context?.tool?.name ?? "", parameters: context?.input ?? {{}}, result }};
      const answer = ask(AFTER, event(context, "postToolUse", call));
      // A known prompt injection in the output: the model reads Blackbox's notice instead.
      if (answer.contextModification) return {{ result: {{ ...context.result, output: answer.contextModification }} }};
    }},
  }},
}};
export default plugin;
"""

_COMPANION_TEXT = {"cline-plugin": _CLINE_PLUGIN, "opencode-v2": _OPENCODE_V2_PLUGIN}


def _ours(path: Path) -> bool:
    try:
        return path.is_file() and MARK in path.read_text(encoding="utf-8-sig", errors="replace")[:4096]
    except OSError:
        return False


def _by_kind(host: Host, invocations: Invocations) -> dict[str, list[str]]:
    """The runner's argv for each kind of event (``pre_tool`` → argv), from the agent's events."""
    return {host.events[event]: argv for event, (argv, _command) in invocations.items()}


def _install_companions(host: Host, home: Path, invocations: Invocations) -> None:
    by_kind = _by_kind(host, invocations)
    for target, (_path, form) in zip(host.companion_paths(home), host.companions):
        if target.exists() and not _ours(target):
            continue   # a file of the person's own at that path stays
        text = _COMPANION_TEXT[form].format(mark=MARK, before=json.dumps(by_kind.get("pre_tool", [])),
                                            after=json.dumps(by_kind.get("post_tool", [])),
                                            prompt=json.dumps(by_kind.get("prompt", [])))
        target.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(target, text)


def install(host: Host, home: Path, invocations: Invocations) -> EditResult:
    target = host.config_path(home)
    try:
        _install_companions(host, home, invocations)
        if host.style == "own-json":
            limit = host.hook_timeout
            hooks = {event: [{"type": "command", "bash": command, **({limit.key: limit.value(event)} if limit else {})}]
                     for event, (_argv, command) in invocations.items()}
            target.parent.mkdir(parents=True, exist_ok=True)
            atomic_write(target, json.dumps({"version": 1, "hooks": hooks}, indent=2) + "\n")
            return EditResult(True, str(target))
        if host.style == "plugin":
            by_kind = _by_kind(host, invocations)
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


def _remove_companions(host: Host, home: Path) -> None:
    for target in host.companion_paths(home):
        if _ours(target):
            target.unlink()
            if target.parent.name == "blackbox" and not any(target.parent.iterdir()):
                target.parent.rmdir()   # the folder Blackbox made for its OpenCode 2 plugin


def uninstall(host: Host, home: Path) -> EditResult:
    target = host.config_path(home)
    try:
        _remove_companions(host, home)
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
    """Every file of Blackbox's own that is in place for *host* (its main form, then companions)."""
    target = host.config_path(home)
    companions = [str(path) for path in host.companion_paths(home) if _ours(path)]
    if host.style == "scripts":
        return [str(target / event) for event in host.events if _ours(target / event)] + companions
    return ([str(target)] if _ours(target) else []) + companions


def runnable(paths: list[str]) -> bool:
    """True when every file a hook runs exists (a moved Python or runner makes the hook a no-op)."""
    return all(os.path.exists(path) for path in paths)
