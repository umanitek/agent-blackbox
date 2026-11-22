"""The coding agents Blackbox can protect through their own hooks — one record each (data, not code).

A :class:`Host` says where an agent keeps its user-level hook config, how that config is written
(:attr:`Host.style`), which of its hook events Blackbox listens to and what each means
(:attr:`Host.events`: the agent's event name → ``session_start`` / ``prompt`` / ``pre_tool`` /
``post_tool`` / ``turn_end`` (the agent finished answering) / ``stop`` (the session ended) /
``subagent_start`` / ``subagent_stop`` (an instance the agent spawned inside its session) /
``config_change`` (the agent's own settings were edited) / ``attention`` (the agent is waiting
for its person: a permission question or an idle prompt)), whether the agent asks its user to
trust new hooks first, and where ELSE the agent can keep a profile (:attr:`Host.home_env`: the
environment variable that moves its config home; :attr:`Host.switches`: the settings that turn
its hooks off — ``agent_hooks.profiles`` reads both).

Styles (how :mod:`.config_edit` and :mod:`.own_files` write them):

* ``nested`` — ``{"hooks": {Event: [{"matcher"?, "hooks": [{"type": "command", "command"}]}]}}``
  inside a settings file shared with the user (Claude Code, Codex, Gemini CLI);
* ``flat`` — ``{"hooks": {event: [{"command"}]}}`` (Cursor adds ``"version": 1``; Windsurf);
* ``own-json`` — a file of Blackbox's own in the agent's hooks folder (Copilot CLI);
* ``scripts`` — one executable per event in the agent's hooks folder (Cline);
* ``plugin`` — a small JS plugin of Blackbox's own (OpenCode).

Some agents take hooks in TWO forms at once (:attr:`Host.companions`): Cline's CLI and SDK run
the hook scripts AND load SDK plugins (``~/Documents/Cline/Plugins``); OpenCode 1 loads
``plugin/blackbox.js`` while OpenCode 2 loads ``plugins/blackbox/index.js`` and runs no V1 plugin.
Blackbox writes each form; one tool call that reaches it twice is answered once
(``agent_hooks.protect.events``, by the agent's own tool-call id).

Sources (re-read 2026-11-22; the per-agent pages and ``docs/agent-compat/coverage-matrix.md``
carry the URLs): code.claude.com/docs/en/hooks + settings, developers.openai.com/codex/hooks,
cursor.com/docs/agent/hooks, geminicli.com/docs/hooks/reference + reference/configuration,
docs.github.com copilot hooks-configuration, docs.devin.ai cli/extensibility/hooks,
docs.cline.bot, opencode.ai/docs/plugins.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

#: Where user tools live beyond PATH. WHY: the dashboard runs as a login service with a minimal
#: PATH, so an agent installed with npm, Homebrew, bun or its own installer is not on it (found on
#: bb-desktop-1120: Claude Code and Copilot CLI in ~/.npm-global/bin went undetected).
USER_BIN_DIRS = (".npm-global/bin", ".local/bin", ".bun/bin", ".claude/local", ".opencode/bin", "bin",
                 "/opt/homebrew/bin", "/usr/local/bin")

#: What every agent event is mapped to.
EVENTS = ("session_start", "prompt", "pre_tool", "post_tool", "turn_end", "stop", "subagent_start", "subagent_stop",
          "config_change", "attention")
#: The kinds a ``nested`` group's tool matcher applies to. WHY: Gemini CLI compares a lifecycle
#: event's matcher as an EXACT string ("startup"), so a tool regex there never matches — the
#: lifecycle groups carry no matcher (every agent treats a missing matcher as "every occurrence").
TOOL_KINDS = ("pre_tool", "post_tool")


@dataclass(frozen=True)
class Host:
    """One coding agent. Paths are relative to the user's home folder."""

    id: str
    name: str
    style: str
    config: str
    events: dict[str, str]
    #: Folders or apps whose presence says the agent is installed (any one is enough).
    signs: tuple[str, ...] = ()
    #: Commands on PATH that say the agent is installed.
    commands: tuple[str, ...] = ()
    #: The matcher a ``nested`` group carries ("" = none: the agent matches every tool).
    matcher: str = ""
    #: The agent asks its user to review and trust new hooks before running them.
    trust_note: str = ""
    extra: dict[str, object] = field(default_factory=dict)
    #: The environment variable that moves this agent's config home (another PROFILE), and the
    #: config's path inside that folder ("" = no such variable is documented).
    home_env: str = ""
    home_config: str = ""
    #: Program names (argv[0] or a script's file name) that say a running process is this agent.
    programs: tuple[str, ...] = ()
    #: Settings that switch this agent's hooks off: ``(file relative to the config's folder,
    #: dotted key, the value that means OFF)``; read by ``agent_hooks.profiles``.
    switches: tuple[tuple[str, str, object], ...] = ()
    #: Per-project files (relative to a project folder) that can carry the same switches.
    project_files: tuple[str, ...] = ()
    #: More files of Blackbox's own this agent needs beside :attr:`config`: ``(path relative to
    #: the home folder, form)`` — the form names the template ``own_files`` writes
    #: (``cline-plugin``: Cline's SDK plugin; ``opencode-v2``: OpenCode 2's plugin).
    companions: tuple[tuple[str, str], ...] = ()

    def config_path(self, home: Path) -> Path:
        return home / self.config

    def companion_paths(self, home: Path) -> list[Path]:
        """Where each companion file goes under *home* (see :attr:`companions`)."""
        return [home / path for path, _form in self.companions]

    def installed(self, home: Path) -> bool:
        """True when the agent is on this machine (its folder, app or command)."""
        if any((home / sign).exists() or Path(sign).exists() for sign in self.signs):
            return True
        folders = [str(home / folder) for folder in USER_BIN_DIRS]
        return any(shutil.which(command) or any(shutil.which(command, path=folder) for folder in folders)
                   for command in self.commands)


_CLAUDE_EVENTS = {"SessionStart": "session_start", "UserPromptSubmit": "prompt", "PreToolUse": "pre_tool",
                  "PostToolUse": "post_tool", "Stop": "turn_end", "SessionEnd": "stop",
                  "SubagentStart": "subagent_start", "SubagentStop": "subagent_stop"}

HOSTS: tuple[Host, ...] = (
    Host("claude-code", "Claude Code", "nested", ".claude/settings.json",
         {**_CLAUDE_EVENTS, "ConfigChange": "config_change", "Notification": "attention"},
         signs=(".claude",), commands=("claude",), matcher="*",
         home_env="CLAUDE_CONFIG_DIR", home_config="settings.json", programs=("claude",),
         switches=(("settings.json", "disableAllHooks", True), ("settings.local.json", "disableAllHooks", True)),
         project_files=(".claude/settings.json", ".claude/settings.local.json")),
    Host("codex", "Codex", "nested", ".codex/hooks.json", _CLAUDE_EVENTS,
         signs=(".codex",), commands=("codex",),
         trust_note="Codex asks you to review new hooks once: run codex, type /hooks and trust Blackbox's.",
         home_env="CODEX_HOME", home_config="hooks.json", programs=("codex",),
         switches=(("config.toml", "features.hooks", False), ("config.toml", "features.codex_hooks", False))),
    # Cursor (2026-11-22): the generic preToolUse / postToolUse fire for EVERY tool (Shell, Read,
    # Write, MCP, Task…), so they replace the shell- and MCP-only hooks; beforeReadFile stays for
    # the file's text (the injection check), and the session and sub-agent events are tracked.
    Host("cursor", "Cursor", "flat", ".cursor/hooks.json",
         {"preToolUse": "pre_tool", "beforeReadFile": "pre_tool", "postToolUse": "post_tool",
          "beforeSubmitPrompt": "prompt", "stop": "turn_end", "sessionStart": "session_start", "sessionEnd": "stop",
          "subagentStart": "subagent_start", "subagentStop": "subagent_stop"},
         signs=(".cursor", "/Applications/Cursor.app"), commands=("cursor-agent",), extra={"version": 1},
         programs=("cursor-agent", "Cursor"), project_files=(".cursor/hooks.json",)),
    Host("gemini-cli", "Gemini CLI", "nested", ".gemini/settings.json",
         {"SessionStart": "session_start", "BeforeAgent": "prompt", "BeforeTool": "pre_tool",
          "AfterTool": "post_tool", "AfterAgent": "turn_end", "SessionEnd": "stop", "Notification": "attention"},
         signs=(".gemini",), commands=("gemini",), matcher=".*",
         home_env="GEMINI_CLI_HOME", home_config=".gemini/settings.json", programs=("gemini",),
         switches=(("settings.json", "hooksConfig.enabled", False),), project_files=(".gemini/settings.json",)),
    Host("copilot-cli", "GitHub Copilot CLI", "own-json", ".copilot/hooks/blackbox.json",
         {"sessionStart": "session_start", "userPromptSubmitted": "prompt", "preToolUse": "pre_tool",
          "postToolUse": "post_tool", "agentStop": "turn_end", "sessionEnd": "stop",
          "subagentStart": "subagent_start", "subagentStop": "subagent_stop"},
         signs=(".copilot",), commands=("copilot",),
         home_env="COPILOT_HOME", home_config="hooks/blackbox.json", programs=("copilot",)),
    # Windsurf ships as "Devin.app" since 2026-11 (docs moved to docs.devin.ai); the documented
    # user-level hooks file is unchanged.
    Host("windsurf", "Windsurf (Devin)", "flat", ".codeium/windsurf/hooks.json",
         {"pre_run_command": "pre_tool", "pre_read_code": "pre_tool", "pre_write_code": "pre_tool",
          "pre_mcp_tool_use": "pre_tool", "post_run_command": "post_tool", "pre_user_prompt": "prompt"},
         signs=(".codeium/windsurf", "/Applications/Windsurf.app", "/Applications/Devin.app"), commands=("windsurf",),
         programs=("windsurf", "Windsurf")),
    # Devin CLI / Devin Local (2026-11-22, docs.devin.ai/cli/extensibility/hooks): Claude-shaped
    # hooks under the "hooks" key of its own user config. It ALSO reads Claude Code's files by
    # default, so the runner drops a Claude-config event that arrives from a Devin session once
    # Devin's own hooks are installed (``runner.shadowed``).
    Host("devin", "Devin", "nested", ".config/devin/config.json",
         {"SessionStart": "session_start", "UserPromptSubmit": "prompt", "PreToolUse": "pre_tool",
          "PostToolUse": "post_tool", "Stop": "turn_end", "SessionEnd": "stop"},
         signs=(".config/devin",), commands=("devin",), programs=("devin",), project_files=(".devin/hooks.v1.json",)),
    # Cline (re-read 2026-11-22 against the CLI/SDK 3.0.75 itself): the hook SCRIPTS still run —
    # the SDK searches ~/Documents/Cline/Hooks and <its home>/hooks (resolveHooksConfigSearchPaths)
    # — and its payload names the instance (agent_id, parent_agent_id). The CLI, SDK and Kanban
    # also load SDK plugins from ~/Documents/Cline/Plugins, whatever CLINE_DIR says: Blackbox's
    # plugin there is the documented form (docs.cline.bot/sdk/plugins) and can REPLACE a tool's
    # output, which a script cannot. The IDE extensions run the scripts only.
    Host("cline", "Cline", "scripts", "Documents/Cline/Hooks",
         {"TaskStart": "session_start", "TaskResume": "session_start", "UserPromptSubmit": "prompt",
          "PreToolUse": "pre_tool", "PostToolUse": "post_tool", "TaskComplete": "turn_end", "TaskCancel": "turn_end",
          "SessionShutdown": "stop"},
         signs=("Documents/Cline", ".cline"), commands=("cline",), programs=("cline",),
         companions=(("Documents/Cline/Plugins/blackbox.js", "cline-plugin"),)),
    # OpenCode: version 1 loads plugin/blackbox.js (a function returning hooks by name); version 2
    # runs NO V1 plugin and loads plugins/<name>/index.js (a default export with id + setup that
    # registers ctx.tool.hook). Both files are written; each version reads only its own.
    Host("opencode", "OpenCode", "plugin", ".config/opencode/plugin/blackbox.js",
         {"tool.execute.before": "pre_tool", "tool.execute.after": "post_tool"},
         signs=(".config/opencode",), commands=("opencode",), programs=("opencode",),
         companions=((".config/opencode/plugins/blackbox/index.js", "opencode-v2"),)),
)

BY_ID = {host.id: host for host in HOSTS}


def host(agent_id: str) -> Optional[Host]:
    return BY_ID.get(agent_id)


__all__ = ["BY_ID", "EVENTS", "HOSTS", "TOOL_KINDS", "USER_BIN_DIRS", "Host", "host"]
