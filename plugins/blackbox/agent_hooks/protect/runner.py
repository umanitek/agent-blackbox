"""The hook command every protected coding agent runs: one payload in, Blackbox's answer out.

Installed (copied to ``$BLACKBOX_HOME/agent-hooks/runner.py``) and named in each agent's own hook
config as ``<python> <runner.py> <agent> <event> <dashboard url>``. It reads the agent's JSON on
stdin, turns it into ONE shape — ``{agent, event, session, cwd, tool_name, args}`` — and asks the
local Blackbox dashboard (``POST /api/agent-hooks/event``), which records the event and answers
with the same guard a Hermes agent gets: before a tool runs, the tool-call verdict (threats and
self-protection); for a prompt about to be sent and a tool's output about to reach the model, the
prompt-injection verdict of the verified threat graph (``guard.text_verdict``). Each answer goes
back in the agent's own documented format (:func:`deny_output`, :func:`prompt_output`,
:func:`post_output`; docs/agent-compat/ has the per-agent references).

Standard library only and import-free of the plugin, so it starts in a few tens of milliseconds
under any Python. FAIL-OPEN: any error, a missing dashboard or a slow answer lets the agent
continue — Blackbox never makes an agent unusable. The prompt and the tool output go only to the
LOCAL dashboard (127.0.0.1) to be checked; they are never recorded or shared — the records keep
their length, and a finding keeps only the matched phrase as its local evidence (as for Hermes).

Usage (what an agent runs)::

    python3 runner.py claude-code pre_tool http://127.0.0.1:9700 < payload.json

**Undo:** stateless — it answers one hook call; with protection off it is no longer named in
any agent's config. Fail-open: any error lets the agent continue.
"""

from __future__ import annotations

import json
import os
import re
import stat
import sys
import urllib.request
from pathlib import Path

#: The most of stdin read (a write tool's whole file can be in the payload).
MAX_INPUT_BYTES = 1024 * 1024
#: The most text (a prompt, a tool's output, a file about to be read) sent for the injection check.
MAX_TEXT_CHARS = 256 * 1024
#: Events whose TEXT is checked for prompt injection.
TEXT_EVENTS = frozenset({"prompt", "post_tool"})
#: How long one answer may take before the agent continues without it.
TIMEOUT_SECONDS = 2.5
#: Events whose answer can stop the action.
BLOCKING_EVENTS = frozenset({"pre_tool", "prompt", "post_tool"})
SHELL_NAMES = frozenset({"bash", "shell", "run_shell_command", "run_terminal_cmd", "execute_command", "exec", "terminal", "command"})
READ_NAMES = frozenset({"read", "read_file", "view", "readfile", "read_many_files"})
WRITE_NAMES = frozenset({"write", "write_file", "edit", "multiedit", "replace", "write_to_file", "replace_in_file", "create_file",
                         "str_replace_editor", "create", "notebookedit", "notebook_edit", "edit_file"})
#: Where each agent's tools carry a file path, and a file's new text (Claude, Codex, Cursor,
#: Gemini, Copilot, Windsurf, Cline, OpenCode — each spells them its own way).
PATH_KEYS = ("file_path", "path", "absolute_path", "target_file", "notebook_path", "filePath", "filepath")
CONTENT_KEYS = ("content", "new_string", "new_str", "file_text", "newString", "new_source", "diff")
#: Codex's patch tool: every file it adds, updates, deletes or moves to.
PATCH_FILE = re.compile(r"^\*\*\* (?:Add|Update|Delete) File: (.+)$|^\*\*\* Move to: (.+)$", re.MULTILINE)


def _first(mapping: object, *keys: str) -> object:
    if not isinstance(mapping, dict):
        return None
    for key in keys:
        if mapping.get(key) not in (None, ""):
            return mapping[key]
    return None


def _command_text(command: object) -> str:
    """A shell command as one line. Codex can send an argv list — ``["bash", "-lc", "npm i x"]``:
    the script after ``-c`` / ``-lc`` is the command; any other list is joined."""
    if isinstance(command, list):
        parts = [str(part) for part in command]
        if len(parts) >= 3 and parts[1] in ("-c", "-lc", "-ic"):
            return parts[2]
        return " ".join(parts)
    return str(command or "")


def _canonical(tool_name: str, args: object) -> tuple[str, object]:
    """The guard's own vocabulary: ``terminal`` / ``read_file`` / ``write_file``, else as given."""
    name = (tool_name or "").strip()
    lowered = name.lower()
    if isinstance(args, str) and args.lstrip().startswith("{"):
        try:
            args = json.loads(args)
        except ValueError:
            pass
    if lowered in SHELL_NAMES:
        command = _first(args, "command", "cmd", "command_line") if isinstance(args, dict) else args
        return "terminal", {"command": _command_text(command)}
    if lowered == "apply_patch":
        return "apply_patch", {"patch": _patch_text(args)[:200_000]}
    if lowered in READ_NAMES:
        return "read_file", {"path": str(_first(args, *PATH_KEYS) or "")}
    if lowered in WRITE_NAMES:
        path = _first(args, *PATH_KEYS)
        content = _first(args, *CONTENT_KEYS)
        return "write_file", {"path": str(path or ""), "content": str(content or "")[:200_000]}
    return name or "tool", args


def _patch_text(args: object) -> str:
    """The patch Codex's ``apply_patch`` carries: as ``input`` / ``patch`` text, or inside its argv."""
    if isinstance(args, dict):
        for key in ("input", "patch", "command", "cmd"):
            value = args.get(key)
            if isinstance(value, str) and value:
                return value
            if isinstance(value, list):
                return "\n".join(str(part) for part in value)
    return str(args or "") if not isinstance(args, dict) else ""


def patch_files(patch: str) -> list[str]:
    """Every file path an ``apply_patch`` patch touches (added, updated, deleted or moved to)."""
    return [(match.group(1) or match.group(2)).strip() for match in PATCH_FILE.finditer(patch or "")][:200]


def _text(value: object) -> str:
    """Any value as text for the injection check (a dict or list as compact JSON), bounded."""
    if value is None:
        return ""
    if not isinstance(value, str):
        try:
            value = json.dumps(value, ensure_ascii=False)
        except (TypeError, ValueError):
            value = str(value)
    return value[:MAX_TEXT_CHARS]


def prompt_text(agent: str, payload: dict) -> str:
    """The user's prompt in *agent*'s payload (Windsurf nests it in ``tool_info``, Cline in its event)."""
    nested = payload.get("tool_info") if agent == "windsurf" else payload.get("userPromptSubmit") if agent == "cline" else None
    return _text(_first(nested, "user_prompt", "prompt") if isinstance(nested, dict) else _first(payload, "prompt", "user_prompt", "message"))


def output_text(agent: str, payload: dict) -> str:
    """The tool's output in *agent*'s post-tool payload — what the model is about to read."""
    if agent == "cline":
        return _text(_first(payload.get("postToolUse") or {}, "result", "output", "response"))
    if agent == "windsurf":
        return _text(_first(payload.get("tool_info") or {}, "output", "stdout", "response", "result"))
    if agent == "copilot-cli":
        result = payload.get("toolResult")
        return _text(_first(result, "textResultForLlm", "text") if isinstance(result, dict) else result)
    return _text(_first(payload, "tool_response", "tool_output", "output", "result_json", "result", "response"))


def read_text(agent: str, payload: dict) -> str:
    """A file's text that the agent is about to READ, when its pre-read hook can refuse the read:
    Cursor sends it (``beforeReadFile`` ``content``); Windsurf sends only the path, so the file is
    read here (bounded, a regular file only)."""
    if agent == "cursor" and "file_path" in payload and "tool_name" not in payload:
        return _text(payload.get("content"))
    if agent == "windsurf" and str(payload.get("agent_action_name") or "") == "pre_read_code":
        path = str((payload.get("tool_info") or {}).get("file_path") or "")
        try:
            info = os.stat(path)
            if stat.S_ISREG(info.st_mode):
                with open(path, encoding="utf-8-sig", errors="replace") as handle:
                    return handle.read(MAX_TEXT_CHARS)
        except OSError:
            return ""
    return ""


def _tool(agent: str, payload: dict) -> tuple[str, object]:
    """The tool call inside one agent's payload (each agent names the fields its own way)."""
    if agent == "cursor":
        if "command" in payload:                       # beforeShellExecution
            return _canonical("terminal", {"command": payload.get("command")})
        if "file_path" in payload and "tool_name" not in payload:   # beforeReadFile
            return _canonical("read_file", {"path": payload.get("file_path")})
    if agent == "windsurf":
        info = payload.get("tool_info") if isinstance(payload.get("tool_info"), dict) else {}
        if "command_line" in info:
            return _canonical("terminal", {"command": info.get("command_line")})
        if "mcp_tool_name" in info:
            return _canonical(str(info.get("mcp_tool_name")), info.get("mcp_tool_arguments"))
        if "file_path" in info:
            action = str(payload.get("agent_action_name") or "")
            return _canonical("write_file" if "write" in action else "read_file", {"path": info.get("file_path")})
    if agent == "cline":
        call = payload.get("preToolUse") or payload.get("postToolUse") or {}
        return _canonical(str(_first(call, "toolName", "tool") or ""), _first(call, "parameters", "params"))
    if agent == "copilot-cli":
        return _canonical(str(payload.get("toolName") or ""), payload.get("toolArgs"))
    if agent == "opencode":
        return _canonical(str(payload.get("tool") or ""), payload.get("args"))
    return _canonical(str(_first(payload, "tool_name", "toolName") or ""), _first(payload, "tool_input", "tool_args", "input", "arguments"))


def _session(payload: dict) -> str:
    value = _first(payload, "session_id", "sessionId", "sessionID", "conversation_id", "trajectory_id", "taskId", "thread_id")
    return str(value or "")[:200]


#: Blackbox's home at run time. WHY: this runner is a COPY installed at
#: ``$BLACKBOX_HOME/agent-hooks/runner.py``, so its grandparent folder is that home — not the plugin
#: source tree. Files below it are created at run time, never shipped as package data.
INSTALLED_HOME = Path(__file__).resolve().parent.parent

#: File Shield's sandbox canary (``shields/files/sandbox``), written into Blackbox's home at run time.
CANARY = INSTALLED_HOME / "sandbox" / "canary"


def sandboxed() -> bool:
    """True when this hook (so the agent that started it) runs inside Blackbox's OS sandbox: only a
    sandboxed process is refused the canary — a variable could be faked, the kernel's refusal can not."""
    try:
        with open(CANARY, encoding="utf-8-sig") as handle:
            handle.read(1)
        return False
    except PermissionError:
        return True
    except OSError:
        return False


def summary(agent: str, event: str, payload: dict) -> dict:
    """The one shape the dashboard checks: the tool call, and the TEXT to check for injection (a
    prompt, a tool's output, a file about to be read). The text is checked, never recorded."""
    body = {"agent": agent, "event": event, "session": _session(payload),
            "cwd": str(_first(payload, "cwd", "workspace", "workspaceRoot") or "")[:500], "sandboxed": sandboxed()}
    if event in ("pre_tool", "post_tool"):
        body["tool_name"], body["args"] = _tool(agent, payload)
        call = _first(payload, "tool_use_id", "toolCallId", "callID", "call_id", "execution_id")
        body["tool_call_id"] = str(call or "")[:200]
    if event == "pre_tool":
        body["text"] = read_text(agent, payload)
    if event == "post_tool":
        body["text"] = output_text(agent, payload)
    if event == "prompt":
        body["text"] = prompt_text(agent, payload)
        body["prompt_chars"] = len(body["text"])
    return body


def ask(url: str, body: dict) -> dict:
    """POST *body* to the dashboard with its session token; {} when it cannot answer."""
    with urllib.request.urlopen(f"{url}/api/session", timeout=TIMEOUT_SECONDS) as response:
        token = json.loads(response.read(65536)).get("token", "")
    request = urllib.request.Request(f"{url}/api/agent-hooks/event", data=json.dumps(body).encode("utf-8"), method="POST",
                                     headers={"content-type": "application/json", "X-Blackbox-Token": token})
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        answer = json.loads(response.read(65536))
    return answer if isinstance(answer, dict) else {}


def deny_output(agent: str, reason: str) -> tuple[str, int]:
    """(stdout, exit code) that make *agent* refuse the tool call, in its documented format."""
    if agent in ("claude-code", "codex"):
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
    if agent in ("claude-code", "codex"):
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
    if agent == "cursor" and event in ("pre_tool", "prompt"):
        return json.dumps({"permission": "allow"} if event == "pre_tool" else {"continue": True})
    if agent == "cline":
        return json.dumps({"cancel": False})
    return ""


def main(argv: list) -> int:
    if len(argv) < 4:
        return 0
    agent, event, url = argv[1], argv[2], argv[3].rstrip("/")
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES)
        payload = json.loads(raw.decode("utf-8", "replace") or "{}")
        payload = payload if isinstance(payload, dict) else {}
        answer = ask(url, summary(agent, event, payload))
    except Exception:   # health: allow BLE001 -- fail open: the agent continues without Blackbox's answer
        answer = {}
    if event in BLOCKING_EVENTS and answer.get("decision") == "block":
        reason = str(answer.get("message") or "Blocked by Blackbox: this action matches a verified threat.")[:1000]
        out, code = (prompt_output if event == "prompt" else post_output if event == "post_tool" else deny_output)(agent, reason)
        if out:
            sys.stdout.write(out)
        sys.stderr.write(reason + "\n")
        return code
    out = allow_output(agent, event)
    if out:
        sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
