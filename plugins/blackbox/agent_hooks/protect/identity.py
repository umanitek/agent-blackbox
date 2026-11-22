"""Which instance and which agent a hook event belongs to — the runner's sibling (standard
library only; copied beside ``runner.py`` into Blackbox's data folder).

``identity`` reads the fields each agent's documented payload names an instance by;
``effective_agent`` tells a Devin session that runs Claude Code's hook file from Claude Code.
"""

from __future__ import annotations

import os
from pathlib import Path

#: The environment variable that moves each agent's config home — its PROFILE (the catalogue's
#: ``Host.home_env``, repeated here because the runner imports nothing of the plugin).
HOME_ENV = {"claude-code": "CLAUDE_CONFIG_DIR", "codex": "CODEX_HOME", "gemini-cli": "GEMINI_CLI_HOME",
            "copilot-cli": "COPILOT_HOME", "cline": "CLINE_DIR"}


def identity(agent: str, payload: dict, _first) -> dict:
    """Which INSTANCE this event belongs to, as each agent's documented payload names it: the
    sub-agent (``agent_id`` — Claude Code, Codex, Copilot CLI; ``subagent_id`` — Cursor) and its
    type, the parent session a Cursor sub-agent names, the model, why a session started or ended,
    whether it is a background agent, the profile (a moved config home) and the process that ran
    this hook. Ids are hashed by the dashboard; nothing here is prompt text."""
    sub = str(_first(payload, "agent_id", "agentId", "subagent_id") or "")[:200]
    if agent == "cline" and not payload.get("parent_agent_id"):
        sub = ""   # Cline names agent_id on EVERY event; only an agent with a parent was spawned
    return {
        "sub": sub,
        "sub_type": str(_first(payload, "agent_type", "agentType", "subagent_type") or "")[:80],
        "parent": str(_first(payload, "parent_conversation_id", "parent_session_id") or "")[:200],
        "model": str(_first(payload, "model", "subagent_model", "model_id") or "")[:80],
        "why": str(_first(payload, "source", "reason", "status", "notification_type") or "")[:40],
        "background": payload.get("is_background_agent") is True or payload.get("is_parallel_worker") is True,
        "profile": os.environ.get(HOME_ENV.get(agent, ""), "")[:500] if agent in HOME_ENV else "",
        "entry": os.environ.get("CLAUDE_CODE_ENTRYPOINT", "")[:40] if agent == "claude-code" else "",
        "pid": os.getppid(),
    }


def workspace(payload: dict, _first) -> str:
    """The project folder the event comes from, as each agent's payload names it: ``cwd`` (Claude
    Code, Codex, Gemini CLI, Copilot CLI, Devin), ``workspace_roots`` (Cursor, a list),
    ``workspaceRoots`` (Cline, a list), ``tool_info.cwd`` (Windsurf's command hooks). When the
    payload names none (Windsurf's other hooks, OpenCode without a directory), the hook's own
    working folder — a hook starts in its agent's — unless that is ``/`` or the person's home,
    which name no project (KI-547)."""
    named = _first(payload, "cwd", "workspace", "workspaceRoot")
    roots = payload.get("workspace_roots") or payload.get("workspaceRoots")
    info = payload.get("tool_info") if isinstance(payload.get("tool_info"), dict) else {}
    found = named or (roots[0] if isinstance(roots, list) and roots else "") or info.get("cwd") or ""
    if found:
        return str(found)
    try:
        here = os.getcwd()
    except OSError:
        return ""
    return "" if here in ("/", str(Path.home())) else here


#: Devin CLI sets this for every hook it runs.
DEVIN_ENV = "DEVIN_PROJECT_DIR"


def devin_config() -> Path:
    """Devin's user config (read at call time: the home folder can differ per profile)."""
    return Path.home() / ".config" / "devin" / "config.json"


def effective_agent(agent: str) -> str:
    """The agent an event really comes from. WHY: Devin CLI reads Claude Code's hook files by
    default, so a Devin session runs the hook written for Claude Code. That event is Devin's —
    and it is DROPPED ("") when Devin's own config already carries Blackbox's hooks, so one
    action is never checked and counted twice."""
    if agent != "claude-code" or not os.environ.get(DEVIN_ENV):
        return agent
    try:
        with open(devin_config(), encoding="utf-8-sig") as handle:
            if "agent-hooks" in handle.read(256 * 1024):
                return ""
    except OSError:
        pass
    return "devin"
