"""Which instance and which agent a hook event belongs to — the runner's sibling (standard
library only; copied beside ``runner.py`` into Blackbox's data folder).

``identity`` reads the fields each agent's documented payload names an instance by;
``effective_agent`` tells a Devin session that runs Claude Code's hook file from Claude Code.
"""

from __future__ import annotations

import os
import re
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
        # A sub-agent's task title as its agent names it (Cursor's ``task``; OpenCode's plugin sends
        # its ``task`` call's description) — never a prompt.
        "task": str(payload.get("task") or "")[:200] if sub and isinstance(payload.get("task"), str) else "",
        # Hooks that always name a child session's parent (OpenCode 1's plugin): no other link is guessed.
        "parents_named": payload.get("parents_named") is True,
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


#: Events after which the agent's transcript holds a model answer (and so the model's name).
MODEL_EVENTS = frozenset({"turn_end", "stop", "subagent_stop"})
#: The most of a transcript read for its model's name (its first lines).
MAX_TRANSCRIPT_BYTES = 128 * 1024
#: A model field in a transcript line: ``"model":"claude-haiku-5-5"`` (Claude Code), ``"model":
#: "gemini-3.5-flash-lite"`` (Gemini CLI). Placeholders (``<synthetic>``) are not names.
_MODEL_FIELD = re.compile(r'"model"\s*:\s*"([A-Za-z0-9][A-Za-z0-9._:/@+-]{1,79})"')


def transcript_model(payload: dict) -> str:
    """The model an agent's session ran on, from its transcript's first lines (``transcript_path``
    in Claude Code's and Gemini CLI's payloads) — the MODEL FIELD only: nothing else read is kept
    or sent. WHY (KI-566): neither agent's hook payload names the model (real Claude Code 2.1.330 and
    Gemini CLI 0.70.0 payloads, 2026-11-22). "" when there is no transcript or no model in it yet."""
    path = payload.get("transcript_path")
    if not isinstance(path, str) or not path.startswith("/"):
        return ""
    try:
        with open(path, "rb") as handle:   # windows-footgun: ok (bytes, decoded below)
            head = handle.read(MAX_TRANSCRIPT_BYTES).decode("utf-8", "replace")
    except OSError:
        return ""
    found = _MODEL_FIELD.search(head)
    return found.group(1) if found else ""


#: How a turn the AGENT starts (not its person) begins: Claude Code's background-task result (KI-567).
AGENT_TURN_MARKS = ("<task-notification", "<system-reminder")
#: Cline wraps the person's words in its mode tag (``<user_input mode="act">…</user_input>``,
#: @cline/shared 3.0.75): the check reads the person's words, not Cline's markup (KI-573).
_CLINE_WRAPPER = re.compile(r"^\s*<user_input\b[^>]*>(.*)</user_input>\s*$", re.DOTALL)


def persons_words(agent: str, text: str) -> str:
    """*text* (a prompt from *agent*'s payload) without the agent's own wrapper around it."""
    unwrapped = _CLINE_WRAPPER.match(text) if agent == "cline" else None
    return unwrapped.group(1).strip() if unwrapped else text
