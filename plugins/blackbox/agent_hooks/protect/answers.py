"""What the hook runner prints for each agent, in that agent's own documented hook format.

Split out of :mod:`.runner` (a move only): the runner asks the dashboard, then answers the agent
with one of these — a refusal before a tool runs (:func:`deny_output`), a refused prompt
(:func:`prompt_output`), a tool output kept from steering the model (:func:`post_output`), or
the "go ahead" an agent that expects an answer needs (:func:`allow_output`). Standard library
only; copied beside ``runner.py`` into Blackbox's data folder (``agent_hooks.RUNNER_FILES``).
docs/agent-compat/ has the per-agent references.

Usage::

    out, code = deny_output("claude-code", "Blocked by Blackbox: …")   # print out, exit code
"""

from __future__ import annotations

import json


def deny_output(agent: str, reason: str) -> tuple[str, int]:
    """(stdout, exit code) that make *agent* refuse the tool call, in its documented format."""
    if agent in ("claude-code", "codex", "devin"):
        return json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                                  "permissionDecisionReason": reason}}), 0
    if agent == "cursor":
        return json.dumps({"permission": "deny", "user_message": reason, "agent_message": reason}), 0
    if agent == "gemini-cli":
        return json.dumps({"decision": "deny", "reason": reason}), 0
    if agent == "copilot-cli":
        return json.dumps({"permissionDecision": "deny", "permissionDecisionReason": reason}), 0
    if agent == "cline":
        return json.dumps({"cancel": True, "errorMessage": reason}), 0
    if agent == "opencode":
        return json.dumps({"decision": "block", "reason": reason}), 0
    return "", 2   # windsurf: a pre-hook blocks by exiting 2; the reason goes to stderr


def prompt_output(agent: str, reason: str) -> tuple[str, int]:
    """(stdout, exit code) that make *agent* refuse to send a prompt carrying a known injection —
    where its prompt hook can refuse (Copilot CLI's and OpenCode's cannot: recorded only)."""
    if agent in ("claude-code", "codex", "devin"):
        return json.dumps({"decision": "block", "reason": reason}), 0
    if agent == "cursor":
        return json.dumps({"continue": False, "user_message": reason}), 0
    if agent == "gemini-cli":
        return json.dumps({"decision": "deny", "reason": reason}), 0
    if agent == "cline":
        return json.dumps({"cancel": True, "errorMessage": reason}), 0
    if agent == "windsurf":
        return "", 2
    return "", 0


def post_output(agent: str, reason: str) -> tuple[str, int]:
    """(stdout, exit code) that keep a tool output carrying a known injection from steering the
    model, as far as *agent*'s post-tool hook allows: Codex and Gemini CLI REPLACE the output with
    the reason; Claude Code puts the reason beside it; Cline adds it as context; OpenCode's plugin
    replaces the output itself; Cursor's, Copilot's and Windsurf's post hooks can only be
    recorded (their pre-read / pre-tool hooks are where they are protected)."""
    if agent == "claude-code":
        return json.dumps({"decision": "block", "reason": reason,
                           "hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": reason}}), 0
    if agent == "codex":
        return json.dumps({"decision": "block", "reason": reason}), 0
    if agent == "gemini-cli":
        return json.dumps({"decision": "deny", "reason": reason}), 0
    if agent == "cline":
        return json.dumps({"cancel": False, "contextModification": reason}), 0
    if agent == "opencode":
        return json.dumps({"decision": "block", "reason": reason}), 0
    return "", 0


def allow_output(agent: str, event: str) -> str:
    """What an agent that expects an answer gets when the action may go ahead."""
    if agent == "cursor" and event in ("pre_tool", "prompt", "subagent_start"):
        return json.dumps({"continue": True} if event == "prompt" else {"permission": "allow"})
    if agent == "cline":
        return json.dumps({"cancel": False})
    return ""
