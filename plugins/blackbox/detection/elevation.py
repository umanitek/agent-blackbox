"""An AI agent ASKING for root: ``sudo`` and every other way a tool call reaches for more than
the person's own rights.

One finding, ``agent:elevation-request`` (high), per call. It is a FLAG, never a refusal: the
person decided agents keep their ``sudo`` (process-level file protection, D7 — refusing it would
break what broad-permission agents are for), so this rule only makes the request visible — in the
agent's timeline, the findings and a notification. Every other rule still judges the same call.
The FACT of an agent's process running as root is watched separately (``agent_hooks.root_watch``).

What counts (``Finding.fields["way"]``):

* ``sudo`` — ``sudo``, ``sudoedit``, ``doas``, ``pkexec``, ``su`` as a command of the line;
* ``admin-prompt`` — AppleScript's ``with administrator privileges``, ``security
  authorizationdb write``, ``runas`` / ``Start-Process -Verb RunAs``;
* ``sudoers`` — a write to ``/etc/sudoers`` or ``/etc/sudoers.d`` (a file tool, a redirect,
  ``tee``, ``visudo``);
* ``admin-group`` — putting an account in the admin group (``dseditgroup``, ``dscl``,
  ``usermod -aG``, ``gpasswd``, ``net localgroup administrators``);
* ``setuid`` — making a program run as its owner (``chmod u+s``, ``chmod 4755``);
* ``system-service`` — installing a system-wide service (``/Library/LaunchDaemons``,
  ``launchctl bootstrap system``, ``/etc/systemd/system``).

Local only: source ``custom`` (never shared with the community graph) and kind ``flag-only``.

Usage::

    detect_elevation("terminal", {"command": "sudo rm -rf /var/log/x"})
    # -> [Finding(identifier="agent:elevation-request", severity="high", fields={"way": "sudo"})]
    detect_elevation("terminal", {"command": "echo sudo make me a sandwich"})   # -> []
"""

from __future__ import annotations

import re
from typing import Any, Optional

from . import action_parsing, shell_shapes
from .finding import KIND_FLAG_ONLY, Finding
from .paths import shell_words

ELEVATION_ID = "agent:elevation-request"
MATCHED = "agent-elevation"
TITLE = "An AI agent asked for administrator (root) rights"
#: Commands that run what follows as another user.
_SUDO = frozenset({"sudo", "sudoedit", "doas", "pkexec", "su", "dzdo"})
#: Words a shell allows before the command itself.
_PREFIXES = frozenset({"command", "exec", "nohup", "time", "env", "builtin", "nice", "caffeinate", "stdbuf", "xargs", "then", "do", "else", "!", "{", "("})
_SUDOERS = re.compile(r"(?:^|[\s\"'=>])/(?:private/)?etc/sudoers(?:\.d(?:/|\b)|\b)")
_ADMIN_PROMPT = re.compile(r"with\s+administrator\s+privileges|authorizationdb\s+write|-Verb\s+RunAs|\brunas\b\s+/user", re.IGNORECASE)
_ADMIN_GROUP = re.compile(
    r"dseditgroup\b[^|;&\n]*\badmin\b|dscl\b[^|;&\n]*/Groups/admin|"
    r"usermod\b[^|;&\n]*-a?G\s*\S*\b(?:sudo|wheel|admin)\b|gpasswd\b[^|;&\n]*\b(?:sudo|wheel|admin)\b|"
    r"net\s+localgroup\s+administrators\b[^|;&\n]*/add", re.IGNORECASE)
_SETUID = re.compile(r"\bchmod\b[^|;&\n]*\s(?:[ugoa]*\+[rwxXt]*s[rwxXt]*|[2467][0-7]{3})(?:\s|$)")
_SYSTEM_SERVICE = re.compile(
    r"launchctl\s+(?:bootstrap|enable|load)\s+(?:-w\s+)?system\b|"
    r"(?:>|>>|\btee\b|\bcp\b|\bmv\b|\binstall\b|\bln\b)[^|;&\n]*/Library/LaunchDaemons/|"
    r"(?:>|>>|\btee\b|\bcp\b|\bmv\b|\binstall\b|\bln\b)[^|;&\n]*/etc/systemd/system/")
_SUDOERS_WRITE = re.compile(r"(?:>|>>|\btee\b|\bcp\b|\bmv\b|\binstall\b|\bvisudo\b|\bsed\b[^|;&\n]*\s-i|\bchmod\b|\bln\b)")


def _command_words(command: str) -> list[str]:
    """The word each simple command of *command* starts with (after assignments and prefixes)."""
    words = shell_words._words(command)
    starts, index = [], 0
    while index < len(words):
        end = shell_words._segment_end(words, index)
        cursor = index
        while cursor < end and (shell_words._ASSIGNMENT.match(words[cursor]) or words[cursor] in _PREFIXES
                                or (words[cursor].startswith("-") and cursor > index)):
            cursor += 1
        if cursor < end:
            starts.append(words[cursor].rsplit("/", 1)[-1])
        index = end + 1
    return starts


def way_of(command: str) -> str:
    """How *command* asks for more rights ("" when it does not). Each line of a script is read
    as its own command; a word that merely appears as an argument is not a request."""
    for line in command.splitlines() or [command]:
        if _SUDO & set(_command_words(line)):
            return "sudo"
        if _ADMIN_PROMPT.search(line):
            return "admin-prompt"
        if _SUDOERS.search(line) and _SUDOERS_WRITE.search(line):
            return "sudoers"
        if _ADMIN_GROUP.search(line):
            return "admin-group"
        if _SETUID.search(line):
            return "setuid"
        if _SYSTEM_SERVICE.search(line):
            return "system-service"
    return ""


def _finding(tool: str, way: str) -> Finding:
    return Finding(identifier=ELEVATION_ID, category="escalation", severity="high", title=TITLE, tool_name=tool,
                   matched=MATCHED, evidence=f"asked through: {way}", confirmed=False, source="custom",
                   kind=KIND_FLAG_ONLY, fields={"way": way})


def _file_way(tool_name: str, args: Any) -> Optional[str]:
    access = action_parsing.file_access_arg(tool_name, args)
    if access is None or access["mode"] != "write":
        return None
    path = access["path"]
    if _SUDOERS.search(" " + path):
        return "sudoers"
    if "/Library/LaunchDaemons/" in path or path.startswith("/etc/systemd/system/"):
        return "system-service"
    return None


def detect_elevation(tool_name: str, args: Any) -> list[Finding]:
    """The elevation request in one tool call, or []. Never raises (fail open)."""
    tool = (tool_name or "").strip().lower()
    try:
        way = _file_way(tool_name, args)
        if way is None:
            command = shell_shapes.command_from_args(tool_name, args)
            way = way_of(command) if command else ""
        return [_finding(tool, way)] if way else []
    except Exception:  # pragma: no cover  # health: allow BLE001 -- fail open: a detector fault never breaks the agent's tool call
        return []
