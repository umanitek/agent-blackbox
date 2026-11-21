"""The coding agents Blackbox can protect through their own hooks — one record each (data, not code).

A :class:`Host` says where an agent keeps its user-level hook config, how that config is written
(:attr:`Host.style`), which of its hook events Blackbox listens to and what each means
(:attr:`Host.events`: the agent's event name → ``session_start`` / ``prompt`` / ``pre_tool`` /
``post_tool`` / ``turn_end`` (the agent finished answering) / ``stop`` (the session ended)), and whether the agent asks its user to trust new hooks first.

Styles (how :mod:`.config_edit` and :mod:`.own_files` write them):

* ``nested`` — ``{"hooks": {Event: [{"matcher"?, "hooks": [{"type": "command", "command"}]}]}}``
  inside a settings file shared with the user (Claude Code, Codex, Gemini CLI);
* ``flat`` — ``{"hooks": {event: [{"command"}]}}`` (Cursor adds ``"version": 1``; Windsurf);
* ``own-json`` — a file of Blackbox's own in the agent's hooks folder (Copilot CLI);
* ``scripts`` — one executable per event in the agent's hooks folder (Cline);
* ``plugin`` — a small JS plugin of Blackbox's own (OpenCode).

Sources (2026-11-21): code.claude.com/docs/en/hooks, developers.openai.com/codex/hooks,
cursor.com/docs/hooks, geminicli.com/docs/hooks, docs.github.com copilot-cli hooks reference,
docs.windsurf.com cascade hooks, docs.cline.bot hooks, opencode.ai/docs/plugins.
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
EVENTS = ("session_start", "prompt", "pre_tool", "post_tool", "turn_end", "stop")


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

    def config_path(self, home: Path) -> Path:
        return home / self.config

    def installed(self, home: Path) -> bool:
        """True when the agent is on this machine (its folder, app or command)."""
        if any((home / sign).exists() or Path(sign).exists() for sign in self.signs):
            return True
        folders = [str(home / folder) for folder in USER_BIN_DIRS]
        return any(shutil.which(command) or any(shutil.which(command, path=folder) for folder in folders)
                   for command in self.commands)


_CLAUDE_EVENTS = {"SessionStart": "session_start", "UserPromptSubmit": "prompt", "PreToolUse": "pre_tool",
                  "PostToolUse": "post_tool", "Stop": "turn_end"}

HOSTS: tuple[Host, ...] = (
    Host("claude-code", "Claude Code", "nested", ".claude/settings.json", _CLAUDE_EVENTS,
         signs=(".claude",), commands=("claude",), matcher="*"),
    Host("codex", "Codex", "nested", ".codex/hooks.json", _CLAUDE_EVENTS,
         signs=(".codex",), commands=("codex",),
         trust_note="Codex asks you to review new hooks once: run codex, type /hooks and trust Blackbox's."),
    Host("cursor", "Cursor", "flat", ".cursor/hooks.json",
         {"beforeShellExecution": "pre_tool", "beforeMCPExecution": "pre_tool", "beforeReadFile": "pre_tool",
          "afterShellExecution": "post_tool", "beforeSubmitPrompt": "prompt", "stop": "turn_end"},
         signs=(".cursor", "/Applications/Cursor.app"), commands=("cursor-agent",), extra={"version": 1}),
    Host("gemini-cli", "Gemini CLI", "nested", ".gemini/settings.json",
         {"SessionStart": "session_start", "BeforeAgent": "prompt", "BeforeTool": "pre_tool",
          "AfterTool": "post_tool", "SessionEnd": "stop"},
         signs=(".gemini",), commands=("gemini",), matcher=".*"),
    Host("copilot-cli", "GitHub Copilot CLI", "own-json", ".copilot/hooks/blackbox.json",
         {"sessionStart": "session_start", "userPromptSubmitted": "prompt", "preToolUse": "pre_tool",
          "postToolUse": "post_tool", "sessionEnd": "stop"},
         signs=(".copilot",), commands=("copilot",)),
    # Windsurf ships as "Devin.app" since 2026-11 (docs moved to docs.devin.ai); the documented
    # user-level hooks file is unchanged.
    Host("windsurf", "Windsurf (Devin)", "flat", ".codeium/windsurf/hooks.json",
         {"pre_run_command": "pre_tool", "pre_read_code": "pre_tool", "pre_write_code": "pre_tool",
          "pre_mcp_tool_use": "pre_tool", "post_run_command": "post_tool", "pre_user_prompt": "prompt"},
         signs=(".codeium/windsurf", "/Applications/Windsurf.app", "/Applications/Devin.app"), commands=("windsurf",)),
    Host("cline", "Cline", "scripts", "Documents/Cline/Hooks",
         {"TaskStart": "session_start", "UserPromptSubmit": "prompt", "PreToolUse": "pre_tool",
          "PostToolUse": "post_tool", "TaskComplete": "stop"},
         signs=("Documents/Cline",), commands=("cline",)),
    Host("opencode", "OpenCode", "plugin", ".config/opencode/plugin/blackbox.js",
         {"tool.execute.before": "pre_tool", "tool.execute.after": "post_tool"},
         signs=(".config/opencode",), commands=("opencode",)),
)

BY_ID = {host.id: host for host in HOSTS}


def host(agent_id: str) -> Optional[Host]:
    return BY_ID.get(agent_id)


__all__ = ["BY_ID", "EVENTS", "HOSTS", "Host", "host"]
