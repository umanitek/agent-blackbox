"""Claude Code and Codex command-hook bridge for Agent Blackbox.

Both hosts send one JSON object on stdin. This adapter normalizes their shared
events into the existing Blackbox hook contract and emits each host's own JSON
shape only when a tool call must be denied. Every failure is fail-open:
malformed input or an internal Blackbox error produces no stdout and exits
successfully.

The file is intentionally directly executable. Installed hook definitions use
the managed Hermes virtualenv's absolute Python path plus this file's absolute
path, avoiding PATH and shell-profile assumptions in GUI-launched agents.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import types
from pathlib import Path
from typing import Any, Dict, Optional


# A direct ``python /path/plugins/blackbox/external_hook.py`` invocation has no
# package context. Seed a private namespace so the normal relative imports load
# this exact installed plugin copy rather than whichever checkout happens to be
# on sys.path.
if not __package__:  # pragma: no branch - true for the command-hook entrypoint
    _PACKAGE = "_agent_blackbox_external"
    package = types.ModuleType(_PACKAGE)
    package.__path__ = [str(Path(__file__).resolve().parent)]  # type: ignore[attr-defined]
    sys.modules.setdefault(_PACKAGE, package)
    __package__ = _PACKAGE

audit = None
hooks = None
try:
    from . import audit, hooks  # type: ignore[assignment]  # noqa: E402
except Exception:
    # Import errors must be fail-open too. Otherwise a damaged optional
    # dependency would print a traceback before main() can suppress it, and
    # both hosts would surface that as a hook error on every prompt.
    pass


_PATCH_PATH_RE = re.compile(
    r"^\*\*\*\s+(?:Update|Add|Delete)\s+File:\s*(.+?)\s*$",
    re.MULTILINE,
)


def _framework(value: str, payload: Dict[str, Any]) -> str:
    explicit = str(value or "").strip().lower()
    if explicit in {"claude", "claude-code", "claudecode"}:
        return "claude-code"
    if explicit == "codex":
        return "codex"
    # Codex adds model + turn_id to the common hook wire format. Claude Code's
    # current command hooks do not, making this a useful fallback for the
    # portable plugin bundle used outside the generated installer config.
    if payload.get("model") is not None or payload.get("turn_id") is not None:
        return "codex"
    return "claude-code"


def _tool_input(payload: Dict[str, Any]) -> Any:
    args = payload.get("tool_input")
    if args is None:
        args = payload.get("tool_args")
    if args is None:
        args = payload.get("input")
    if not isinstance(args, dict):
        return args
    normalized = dict(args)
    tool = str(payload.get("tool_name") or "").strip().lower()
    if tool == "apply_patch" and not any(
        isinstance(normalized.get(key), str) and normalized.get(key)
        for key in ("path", "file", "file_path", "target")
    ):
        patch = normalized.get("command") or normalized.get("patch") or normalized.get("input")
        if isinstance(patch, str):
            match = _PATCH_PATH_RE.search(patch)
            if match:
                normalized["path"] = match.group(1).strip()
    return normalized


def _prompt(payload: Dict[str, Any]) -> str:
    for key in ("prompt", "user_prompt", "message", "input"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def _session_id(payload: Dict[str, Any]) -> str:
    for key in ("session_id", "conversation_id", "thread_id"):
        value = payload.get(key)
        if isinstance(value, (str, int)) and str(value).strip():
            return str(value).strip()
    return ""


def _session_slug(payload: Dict[str, Any]) -> str:
    for key in ("session_slug", "conversation_slug", "thread_slug"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _session_title(payload: Dict[str, Any], event: str) -> "tuple[str, str]":
    """Return only a title supplied explicitly by the host.

    A submitted prompt is conversation content, not the Claude/Codex window or
    task title.  Keeping it out of the session registry also prevents long or
    sensitive prompts from being surfaced as agent names in the dashboard.
    ``event`` remains part of the signature for the hook-call contract.
    """
    del event
    for key in ("session_title", "conversation_title", "thread_title"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip(), "host"
    return "", ""


def _deny_output(message: str, framework: str) -> Dict[str, Any]:
    if framework == "codex":
        # Codex uses the top-level command-hook decision contract.
        return {"decision": "block", "reason": message}
    # Claude Code's PreToolUse decision lives inside hookSpecificOutput.
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": message,
        }
    }


def handle_payload(payload: Dict[str, Any], *, framework: str = "") -> Optional[Dict[str, Any]]:
    """Handle one command-hook payload and return optional JSON output."""
    host = _framework(framework, payload)
    event = str(payload.get("hook_event_name") or payload.get("event") or "")
    session_id = _session_id(payload)
    turn_id = str(payload.get("turn_id") or "")
    workspace = str(payload.get("cwd") or payload.get("workspace") or "")

    if hooks is None or audit is None:
        return None

    session_title, title_source = _session_title(payload, event)
    audit.record_agent_session(
        framework=host,
        session_id=session_id,
        workspace=workspace,
        session_slug=_session_slug(payload),
        session_title=session_title,
        title_source=title_source,
    )

    if event == "SessionStart":
        hooks.on_session_start(
            session_id=session_id,
            framework=host,
            workspace=workspace,
        )
        return None

    if event == "UserPromptSubmit":
        prompt = _prompt(payload)
        hooks.on_pre_api_request(
            user_message=prompt,
            request_messages=[{"role": "user", "content": prompt}] if prompt else [],
            session_id=session_id,
            turn_id=turn_id,
            model=payload.get("model"),
            provider=host,
            framework=host,
            workspace=workspace,
        )
        return None

    if event == "PreToolUse":
        decision = hooks.on_pre_tool_call(
            tool_name=str(payload.get("tool_name") or ""),
            args=_tool_input(payload),
            session_id=session_id,
            task_id=turn_id,
            tool_call_id=str(payload.get("tool_use_id") or payload.get("tool_call_id") or ""),
            framework=host,
            workspace=workspace,
        )
        if isinstance(decision, dict) and decision.get("action") == "block":
            return _deny_output(
                str(decision.get("message") or "Blackbox blocked this tool call."),
                host,
            )
        return None

    if event == "PostToolUse":
        result = payload.get("tool_response")
        if result is None:
            result = payload.get("tool_result")
        if result is None:
            result = payload.get("tool_output")
        hooks.on_post_tool_call(
            tool_name=str(payload.get("tool_name") or ""),
            args=_tool_input(payload),
            result=result,
            session_id=session_id,
            task_id=turn_id,
            tool_call_id=str(payload.get("tool_use_id") or payload.get("tool_call_id") or ""),
            framework=host,
            workspace=workspace,
        )
        return None

    if event == "Stop":
        # Stop is turn-scoped in both hosts, not a true session-end signal.
        audit.record(
            event="stop",
            detail={"session_id": session_id, "turn_id": turn_id},
            framework=host,
            workspace=workspace or None,
        )
    return None


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--framework", default="")
    args, _unknown = parser.parse_known_args(argv)
    try:
        raw = sys.stdin.read()
        payload = json.loads(raw) if raw.strip() else {}
        if not isinstance(payload, dict):
            return 0
        output = handle_payload(payload, framework=args.framework)
        if output:
            sys.stdout.write(json.dumps(output, separators=(",", ":")))
            sys.stdout.flush()
    except Exception:
        # A security observer must never take down the host agent. Avoid stderr
        # too: both hosts surface hook stderr prominently to the user.
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
