"""Blackbox's own settings: an agent must not switch off the guard that watches it (KI-473).

Found 2026-11-06 with a text-only probe of the hook: in block mode, an agent could set Blackbox to
audit mode or remove it by editing Hermes's ``config.yaml`` (``sed -i``, the patch tool,
``write_file``), unchecked. A prompt-injected agent's first move is to lower its own guard.

What counts, by an AGENT's tool call (the person changes settings through the dashboard, the
Hermes Desktop page, the ``blackbox`` commands they type, or their own editor — none of which pass
through these hooks):

* a file tool that writes Hermes's config (``config.yaml`` in the Hermes home or any profile) with
  Blackbox or the plugin list in what it changes — including text inside Blackbox's section of the
  file as it is now (``mode: block`` → ``mode: audit``) — or replaces or deletes that file whole;
* a file tool that writes into Blackbox's plugin folder or its data folder ($BLACKBOX_HOME —
  overrides, consent, ledgers);
* a terminal command that writes one of those places (``sed -i``, ``perl -i``, ``>``/``>>``,
  ``tee``, ``cp``/``mv``/``ln``/``install``/``rsync`` onto it, ``rm``/``truncate``, a script that
  opens it for writing), or runs Hermes or Blackbox to switch Blackbox off
  (``hermes plugins disable|remove blackbox``, ``hermes config set …blackbox…``,
  ``blackbox detach|uninstall|rules unblock``), or calls Blackbox's settings APIs (the dashboard's
  settings and session-token routes, the Desktop page's switch);
* code handed to a code tool (``execute_code``) that writes one of those places.

A built-in rule, not an entry in the editable protected-path list (LES-053: a default added to a
list the dashboard saves whole never reaches an install that saved it). ``source="custom"``: it
flags in audit mode, blocks in block mode, and never leaves the machine.

Usage::

    detect_guard_tamper("terminal", {"command": "sed -i 's/mode: block/mode: audit/' ~/.hermes/config.yaml"})
    # -> [Finding(identifier="fileaccess:terminal:blackbox-settings", severity="critical", ...)]
"""

from __future__ import annotations

import os
import re
import shlex
from typing import Any

from .. import action_parsing, shell_shapes
from ..finding import Finding
from ...kernel import constants, threat_ids
from ...kernel.bounded_files import read_small_text
from . import protected, shell_files

MATCHED = "blackbox-settings"
_TITLE = "Change to Blackbox's own settings"
#: In a config edit, the text that touches Blackbox: its entry, or the plugin lists that enable it.
_BLACKBOX_TEXT = re.compile(r"blackbox|plugins\s*:|enabled\s*:|disabled\s*:", re.IGNORECASE)
#: Commands that change the file they are given in place, delete it, or put another file over it.
_WRITING_COMMANDS = frozenset({"cp", "mv", "ln", "install", "rsync", "ditto", "rm", "unlink", "truncate", "shred",
                               "chmod", "chflags"})
_IN_PLACE = re.compile(r"^(?:sed|gsed|perl|yq)$")
#: Where a redirect or ``tee`` writes: the word after ``>``/``>>`` (not ``2>``-style fd duplication
#: onto ``&1``), or after ``tee`` and its flags.
_REDIRECT_TARGET = re.compile(r"(?<![0-9&])>>?\s*([^\s;&|<>]+)|\btee\b(?:\s+-[a-zA-Z]+)*\s+([^\s;&|<>]+)")
#: Code that writes or deletes a file.
_CODE_WRITES = re.compile(r"open\([^)]*['\"][wax][+b]?['\"]|write_text|write_bytes|\.write\(|os\.remove|os\.unlink"
                          r"|\.unlink\(|rmtree|os\.replace|os\.rename|shutil\.(?:copy|move)|yaml\.(?:safe_)?dump")
#: Blackbox's own settings APIs: the local dashboard's settings, session-token and protection routes,
#: and the Hermes Desktop page's switch. An agent fetching the dashboard's page token and posting a
#: mode change is the same self-disable by another road.
_SETTINGS_API = re.compile(
    r"(?:127\.0\.0\.1|localhost|\[::1\]|0\.0\.0\.0):\d+/api/(?:settings|session|agents/protection|attach|report)\b"
    r"|/api/plugins/blackbox/(?:mode|dash|setup)\b", re.IGNORECASE)
#: Commands that switch Blackbox off without naming a file.
_SWITCH_OFF = re.compile(
    r"\bhermes\b(?:\s+-p\s+\S+)?\s+(?:plugins\s+(?:disable|remove|uninstall|rm)\b[^|;&]*\bblackbox\b"
    r"|config\s+set\b[^|;&]*(?:blackbox|plugins))"
    r"|\b(?:hermes\s+)?blackbox\s+(?:detach|uninstall|rules\s+unblock)\b", re.IGNORECASE)


def _guarded_places() -> tuple[str, ...]:
    """Absolute places an agent may not write: Hermes's config files, Blackbox's plugin and data folders."""
    home = str(constants.hermes_home())
    return (os.path.join(home, "config.yaml"), os.path.join(home, "profiles", "*", "config.yaml"),
            os.path.join(home, "plugins", "blackbox"), os.path.join(home, "profiles", "*", "plugins", "blackbox"),
            os.path.join(home, "desktop-plugins", "blackbox"), str(constants.blackbox_home()))


def _guarded(path: str) -> bool:
    if not path:
        return False
    expanded = os.path.expanduser(os.path.expandvars(str(path)))
    if not os.path.isabs(expanded):
        return False
    return any(protected._protected_path_match(expanded, place) for place in _guarded_places())


def _is_config(path: str) -> bool:
    return os.path.basename(os.path.expanduser(str(path or ""))) == "config.yaml"


#: A config larger than this is not read for the section check; the edit then counts as a change to Blackbox.
_MAX_CONFIG_BYTES = 1_000_000
#: Blackbox's own keys, for when the config cannot be read: an edit naming one is taken as Blackbox's.
_BLACKBOX_KEYS = re.compile(r"\b(?:mode|block_severity|protected_paths|shields|report|detection|auto_attach)\s*:")


def _blackbox_section(config_text: str) -> str:
    """The lines of the ``blackbox:`` entry in a Hermes config (the key and everything indented under it)."""
    lines, section, indent = config_text.splitlines(), [], None
    for line in lines:
        stripped = line.lstrip()
        if indent is None:
            if re.match(r"blackbox\s*:", stripped):
                indent = len(line) - len(stripped)
                section.append(line)
            continue
        if stripped and len(line) - len(stripped) <= indent:
            break
        section.append(line)
    return "\n".join(section)


def _edit_reaches_blackbox(config_path: str, edits: list[str]) -> bool:
    """True when an edit's text touches Blackbox: names it or the plugin lists, or changes text that sits
    inside Blackbox's section of the file as it is now (``mode: block`` → ``mode: audit``)."""
    if any(_BLACKBOX_TEXT.search(edit) for edit in edits):
        return True
    text = read_small_text(os.path.expanduser(config_path), _MAX_CONFIG_BYTES)
    if text is None:
        return any(_BLACKBOX_KEYS.search(edit) for edit in edits)
    section = _blackbox_section(text)
    return bool(section) and any(edit.strip() and edit.strip() in section for edit in edits)


def _file_tool_tampers(access: dict[str, str], args: Any) -> bool:
    if access["mode"] != "write" or not _guarded(access["path"]):
        return False
    if not _is_config(access["path"]) or not isinstance(args, dict):
        return True                        # Blackbox's own folders: any write
    edits = [args.get(key) for key in ("old_string", "new_string", "old_str", "new_str", "patch", "diff", "edits")]
    if not any(isinstance(edit, str) and edit for edit in edits):
        return True                        # a whole-file write or a delete can drop Blackbox
    return _edit_reaches_blackbox(access["path"], [edit for edit in edits if isinstance(edit, str) and edit])


def _words(command: str) -> list[str]:
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>")
        lexer.whitespace_split = True
        return list(lexer)
    except ValueError:
        return command.split()


def _place(word: str, folder: str) -> str:
    """*word* as a path, joined onto the folder an earlier ``cd`` moved to when it is relative."""
    if folder and not os.path.isabs(os.path.expanduser(os.path.expandvars(word))):
        return folder.rstrip("/") + "/" + word.removeprefix("./")
    return word


def _inline_code(command: str) -> list[str]:
    """Code handed to an interpreter on the command line (``python3 -c CODE``)."""
    words = _words(command)
    return [words[index + 1] for index, word in enumerate(words[:-1])
            if word in ("-c", "-e", "--eval", "-r", "-E") and index > 0
            and words[index - 1].rsplit("/", 1)[-1].lower() in shell_files._INTERPRETERS]


_SEPARATOR_WORDS = frozenset({";", "&&", "||", "|", "&", ">", ">>", "<", "|&"})
#: Commands whose LAST operand is where they write; their other operands are only read (``mv`` also
#: removes its sources, so for it every operand counts).
_DESTINATION_LAST = frozenset({"cp", "ln", "install", "rsync", "ditto"})


def _segments(words: list[str]) -> list[list[str]]:
    segments, current = [], []
    for word in words:
        if word in _SEPARATOR_WORDS:
            segments.append(current)
            current = []
        else:
            current.append(word)
    return segments + [current]


def _written_operands(segment: list[str]) -> list[str]:
    """The operands one simple command writes, changes in place or deletes (``[]`` for any other command)."""
    if not segment:
        return []
    name = segment[0].rsplit("/", 1)[-1].lower()
    operands = [word for word in segment[1:] if not word.startswith("-")]
    if _IN_PLACE.match(name):
        flags = [word for word in segment[1:] if word.startswith("-")]
        in_place = any(flag.startswith("--in-place") or (not flag.startswith("--") and "i" in flag) for flag in flags)
        return operands if in_place else []
    if name in _DESTINATION_LAST:
        return operands[-1:] if len(operands) >= 2 else []
    return operands if name in _WRITING_COMMANDS else []


def _shell_tampers(command: str) -> bool:
    """True when *command* writes a guarded place, or switches Blackbox off by command."""
    if _SWITCH_OFF.search(command) or _SETTINGS_API.search(command):
        return True
    folder = ""
    for segment in _segments(_words(command)):
        if segment and segment[0].rsplit("/", 1)[-1].lower() in ("cd", "pushd"):
            folder = segment[1] if len(segment) > 1 else "~"
            continue
        if any(_guarded(_place(word, folder)) for word in _written_operands(segment)):
            return True
    for match in _REDIRECT_TARGET.finditer(command):
        if _guarded(_place(match.group(1) or match.group(2) or "", folder)):
            return True
    return False


def _code_tampers(code: str) -> bool:
    """True when *code* names a guarded place and writes or deletes a file."""
    if _SETTINGS_API.search(code):
        return True
    paths = [arg.path for arg in shell_files.code_file_args(code)]
    return any(_guarded(path) for path in paths) and bool(_CODE_WRITES.search(code))


def _finding(tool: str, evidence: str) -> Finding:
    return Finding(
        identifier=threat_ids.fileaccess_identifier(tool, MATCHED),
        category="fileaccess",
        severity="critical",
        title=_TITLE,
        tool_name=tool,
        matched=MATCHED,
        evidence=evidence,
        confirmed=False,
        source="custom",
        fields={},
    )


def detect_guard_tamper(tool_name: str, args: Any) -> list[Finding]:
    """A finding when an agent's call would change Blackbox's settings or switch it off, else []."""
    tool = (tool_name or "").strip().lower()
    try:
        access = action_parsing.file_access_arg(tool_name, args)
        if access is not None:
            return [_finding(access["tool"], "write to Blackbox's settings")] if _file_tool_tampers(access, args) else []
        if tool in protected.CODE_TOOLS and isinstance(args, dict) and isinstance(args.get("code"), str):
            return [_finding(tool, "code that writes Blackbox's settings")] if _code_tampers(args["code"]) else []
        if tool in shell_shapes.SHELL_TOOLS:
            command = shell_shapes.command_from_args(tool_name, args)
            if _shell_tampers(command) or any(_code_tampers(arg) for arg in _inline_code(command)):
                return [_finding(tool, "command that changes Blackbox's settings or switches it off")]
    except Exception:  # pragma: no cover  # health: allow BLE001 -- fail open: a detector fault never breaks the agent's tool call
        return []
    return []
