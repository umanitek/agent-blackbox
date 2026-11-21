"""Blackbox's own core: an agent must not switch off, reconfigure, edit or stop the guard that
watches it — in ANY mode (KI-473, rebuilt 2026-11-20 after a red-team pass).

The first version (2026-11-06) listed the writing commands it knew and blocked only in Block mode.
A red-team pass of 164 attempts got 93 through in Block mode and all 164 in Audit mode: there is
always another command (``git``, ``patch``, ``vim``, ``find -delete``, ``at``, a script written
first), another spelling (a wildcard, a parent folder, ``$HOME``, base64) and another surface
(OpenClaw's config, the plugin file OpenClaw loads, the source checkout, the service definitions,
the control API by another address, ``BLACKBOX_MODE=audit`` in a startup file).

The rule is now the other way round (deny by reference):

* a command line that NAMES a guarded place (:mod:`.guard_places`) is refused unless every
  command on it only reads — or copies FROM it — and nothing is redirected onto it
  (:mod:`.guard_paths`);
* a command that switches Blackbox off, stops it, talks to its control API other than by a plain
  read, or sets its environment is refused by what it says (:mod:`.guard_commands`);
* code (a code tool, ``python3 -c``, a heredoc) that names a guarded place and writes, deletes or
  runs anything is refused; so is a file tool writing a guarded place, a startup file given a
  ``BLACKBOX_…`` variable, or a script whose text would itself be refused;
* a browser tool pointed at the dashboard is refused: the dashboard is the person's.

A command is read WHOLE (the other checks read a long one by its first and last part), line by
line: the cheap tests on every line, the word-by-word reading only on lines that can name a place
or run code, up to :data:`MAX_READ_CLOSELY` characters of those — past that, and past
:data:`MAX_COMMAND_CHARS` in all, the command is refused as unreadable. Nested shells and line
variables are put in and base64 words decoded. What stays open: :data:`KNOWN_LIMITS`.

``source="custom"``, and its findings ALWAYS block (``guard.hooks._would_block``): the person
changes Blackbox through its dashboard, the Desktop page, the ``blackbox`` commands they type or
their own editor — none of which pass through an agent's tool calls.

Usage::

    detect_guard_tamper("terminal", {"command": "git -C ~/.hermes checkout -- config.yaml"})
    # -> [Finding(identifier="fileaccess:terminal:blackbox-settings", severity="critical", ...)]
    detect_guard_tamper("terminal", {"command": "cat ~/.hermes/config.yaml"})   # -> [] (a read)
"""

from __future__ import annotations

import base64
import binascii
import os
import re
from typing import Any

from .. import action_parsing, shell_shapes
from ..finding import Finding
from ...kernel import addons as guarded_extra, threat_ids
from ...kernel.bounded_files import read_small_text
from ...kernel.config import load_blackbox_config
from . import guard_commands, guard_paths, guard_places, protected, shell_files

MATCHED = "blackbox-settings"
_TITLE = "Change to Blackbox's own settings"
#: What this rule cannot see, said plainly (each is a reason for the layers beyond it).
KNOWN_LIMITS = (
    "a script fetched from elsewhere and run without its text passing through a tool call",
    "a command built at run time from pieces this rule cannot join (encodings other than base64)",
    "a program started earlier that changes Blackbox later without a further tool call",
)
#: Code that writes, deletes or runs something.
_CODE_ACTS = re.compile(
    r"\bopen\(.*['\"][wax][+bt]?['\"]|write_text|write_bytes|\.write\(|\.writelines\(|os\.remove|os\.unlink|\.unlink\(|rmtree"
    r"|os\.replace|os\.rename|\.rename\(|shutil\.|yaml\.(?:safe_)?dump|json\.dump\(|truncate|chmod|subprocess|os\.system|Popen|os\.exec"
    r"|writeFile|appendFile|rmSync|unlinkSync|renameSync|copyFile|child_process|execSync|spawn\(|File\.(?:write|delete)|FileUtils", re.IGNORECASE)
#: In an edit of a host's config, the text that touches Blackbox: its entry, or the plugin lists that enable it.
_BLACKBOX_TEXT = re.compile(r"blackbox|plugins|\benabled\b|\bdisabled\b|\ballow\b|\bentries\b|\bload\b", re.IGNORECASE)
_BLACKBOX_KEYS = re.compile(r"\b(?:mode|block_severity|protected_paths|shields|report|detection|auto_attach)\s*:")
_MAX_CONFIG_BYTES = 1_000_000
_HOST_CONFIGS = ("config.yaml", "openclaw.json")
#: Startup files: a ``BLACKBOX_…`` variable written there lowers the guard of every later session.
_STARTUP_FILES = frozenset({".zshrc", ".zshenv", ".zprofile", ".bashrc", ".bash_profile", ".profile", ".env", "config.fish"})
#: A file whose text is run: a script that would itself be refused may not be written.
_SCRIPT = re.compile(r"\.(?:sh|bash|zsh|command|py|js|mjs|rb|pl|plist|service)$|^#!", re.IGNORECASE)
_BASE64_WORD = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
#: Tools that drive a browser: pointed at the dashboard they would press its switches.
_BROWSER_TOOL = re.compile(r"browser|navigate|computer|click|open_url", re.IGNORECASE)
#: A command longer than this is refused unread: no model writes one in a single call, and a
#: command this rule cannot read whole is one it cannot vouch for.
MAX_COMMAND_CHARS = 1_000_000
#: How many characters of a command are read word by word (the lines that can name a place or
#: run code); a command with more of them than this is refused as one that cannot be read whole.
MAX_READ_CLOSELY = 200_000
_QUOTE_MARKS = re.compile(r"['\"\\]")
#: A line that starts another shell: its inner command is judged, not the wrapper.
_WRAPS_ANOTHER = re.compile(r"\s*(?:\S*/)?(?:sh|bash|zsh|dash|ksh|fish|eval)\b")
#: A line that hands text on to a shell or an interpreter (``-c``, ``-e``, ``eval``).
_HANDS_ON = re.compile(r"\s-{1,2}\w*[cerpE]\b|\beval\b")
#: A heredoc that ``cat`` writes to a file: ``cat > notes.md <<EOF`` or ``cat <<EOF > notes.md``.
_TEXT_HEREDOC = re.compile(
    r"(?m)^(?P<head>[ \t]*cat[ \t]*(?:>>?[ \t]*(?P<target>[^\s|;&<>]+)[ \t]*)?<<-?[ \t]*(?P<quote>['\"]?)(?P<tag>\w+)(?P=quote)"
    r"[ \t]*(?:>>?[ \t]*(?P<after>[^\s|;&<>]+)[ \t]*)?)\n(?P<body>.*?)\n[ \t]*(?P=tag)[ \t]*$", re.DOTALL)
_MAX_STAGED_CHARS = 200_000
#: Argument names under which any tool carries a command to run.
_COMMAND_KEY = re.compile(r"^(?:command|cmd|script|shell|code|argv|args|exec)$", re.IGNORECASE)
#: The old name of the list of guarded places, kept for the callers that read it.
_guarded_places = guard_places.guarded_places
READ_ONLY = guard_paths.READ_ONLY


def _read_ports() -> tuple[int, ...]:
    cfg = load_blackbox_config()
    node = re.search(r":(\d+)", str(cfg.dkg_url or ""))
    return (int(cfg.dashboard_port), *([int(node.group(1))] if node else []))


_PORTS = guard_places.Kept(_read_ports)


def _ports() -> tuple[int, ...]:
    """The ports Blackbox's own services answer on: the dashboard and its node."""
    return _PORTS.get(guard_places._machine())


def _decoded(text: str) -> str:
    """*text* with every base64 word that decodes to readable text added on its own line."""
    extra = []
    for word in _BASE64_WORD.findall(text):
        try:
            plain = base64.b64decode(word + "=" * (-len(word) % 4), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if plain.isprintable() or "\n" in plain:
            extra.append(plain)
    return "\n".join([text, *extra]) if extra else text


def _says_it(line: str, ports: tuple[int, ...]) -> bool:
    """True when *line*, as written or with its quote marks taken out (``he''rmes``), is a command
    that switches Blackbox off, stops it, sets its environment or uses its control API."""
    for text in dict.fromkeys((line, _QUOTE_MARKS.sub("", line))):
        if guard_commands.switches_off(text) or guard_commands.stops_service(text, ports) or guard_commands.sets_environment(text):
            return True
    return not _WRAPS_ANOTHER.match(line) and guard_commands.uses_control_api(line, ports)


def _read_closely(line: str, folder: str, ports: tuple[int, ...]) -> tuple[bool, str]:
    """``(tampers, folder)`` for a line that can name a place or run code: its variables put in,
    the commands it hands to another shell, the code it hands to an interpreter, then its paths."""
    if "$" in line and _says_it(" ".join(shell_files._with_variables(shell_files._words(line))), ports):
        return True, folder
    if _HANDS_ON.search(line):
        inner = shell_shapes.with_nested_commands(line, 1).split("\n")[1:]
        if any(_text_tampers(command) for command in inner) or any(_code_tampers(code) for code in _inline_code(line)):
            return True, folder
    return guard_paths.line_changes_a_place(line, folder)


def _lines(text: str) -> list[str]:
    """The lines of *text* to judge as commands: without the body of a heredoc that only writes
    plain text to a file never named again (notes, a README), with every base64 word that decodes
    to readable text added."""
    def plain(found: re.Match[str]) -> str:
        target = found.group("target") or found.group("after") or ""
        runs = _SCRIPT.search(target) or os.path.basename(target) in _STARTUP_FILES or text.count(target) != 1
        return found.group(0) if (not target or runs) else found.group("head")
    return _decoded(_TEXT_HEREDOC.sub(plain, text) if "<<" in text else text).split("\n")


def _text_tampers(text: str) -> bool:
    """True when command text *text* would change Blackbox, switch it off or go round it."""
    ports = _ports()
    folder, closely = guard_paths.START_FOLDER, MAX_READ_CLOSELY
    for line in _lines(text):
        if not line.strip():
            continue
        if _says_it(line, ports):
            return True
        if "$" in line or _HANDS_ON.search(line) or guard_paths.worth_reading(line, folder):
            closely -= len(line)
            tampers, folder = (True, folder) if closely < 0 else _read_closely(line, folder, ports)
            if tampers:
                return True
    # Code over several lines: after an interpreter's ``-c "…"`` (found by splitting the whole
    # command, when it is short enough to split), or on a heredoc.
    spread = _inline_code(text) if "\n" in text and len(text) <= MAX_READ_CLOSELY and _HANDS_ON.search(text) else []
    heredocs = [found.group("body") for found in shell_files._HEREDOC.finditer(text)] if "<<" in text else []
    return any(_code_tampers(code) for code in spread + heredocs)


def _inline_code(command: str) -> list[str]:
    """Code handed to an interpreter after ``-c`` / ``-e`` on the command line."""
    words = shell_files._words(command)
    return [words[index + 1] for index, word in enumerate(words[:-1])
            if word in ("-c", "-e", "--eval", "-r", "-E", "-p", "--print") and index > 0
            and words[index - 1].rsplit("/", 1)[-1].lower() in shell_files._INTERPRETERS]


def _code_tampers(code: str) -> bool:
    """True when *code* talks to the control API other than by a plain read, sets Blackbox's
    environment, or names a guarded place (whole or in pieces) and writes, deletes or runs anything."""
    if guard_commands.uses_control_api(code, _ports()) and (
            guard_commands._WRITES_OVER_HTTP.search(code) or guard_commands._DESKTOP_ROUTE.search(code)):
        return True
    if guard_commands.sets_environment(code) or guard_commands.switches_off(code):
        return True
    names = any(guard_places.reaches(arg.path) for arg in shell_files.code_file_args(code)) or guard_places.names_in_pieces(code)
    return names and bool(_CODE_ACTS.search(code))


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
    section = _blackbox_section(text) or _json_entry(text)
    return bool(section) and any(edit.strip() and edit.strip() in section for edit in edits)


def _json_entry(config_text: str) -> str:
    """The text of the ``"blackbox": {…}`` entry in a JSON config (OpenClaw's), braces matched."""
    start = re.search(r'"blackbox"\s*:\s*\{', config_text)
    if not start:
        return ""
    depth = 0
    for position in range(start.end() - 1, len(config_text)):
        depth += {"{": 1, "}": -1}.get(config_text[position], 0)
        if depth == 0:
            return config_text[start.start():position + 1]
    return config_text[start.start():]


def _written_text(args: Any) -> str:
    if not isinstance(args, dict):
        return ""
    return "\n".join(str(args[key]) for key in ("content", "new_string", "new_str", "text", "patch", "diff") if isinstance(args.get(key), str))


def _file_tool_tampers(access: dict[str, str], args: Any) -> bool:
    if access["mode"] != "write":
        return False
    path, text = access["path"], _written_text(args)[:_MAX_STAGED_CHARS]
    if not guard_places.reaches(path):
        name = os.path.basename(os.path.expanduser(str(path or "")))
        if name in _STARTUP_FILES and guard_commands.sets_environment(text):
            return True                    # a startup file given one of Blackbox's variables
        return bool(text) and bool(_SCRIPT.search(str(path)) or _SCRIPT.search(text)) and (
            _text_tampers(text) or _code_tampers(text))   # a script that would itself be refused
    host_configs = (*_HOST_CONFIGS, *guarded_extra.editable_configs())   # another program's file: Blackbox's part only
    if os.path.basename(os.path.expanduser(str(path))) not in host_configs or not isinstance(args, dict):
        return True                        # Blackbox's own folders and files: any write
    edits = [args.get(key) for key in ("old_string", "new_string", "old_str", "new_str", "patch", "diff", "edits")]
    if not any(isinstance(edit, str) and edit for edit in edits):
        return True                        # a whole-file write or a delete can drop Blackbox
    return _edit_reaches_blackbox(path, [edit for edit in edits if isinstance(edit, str) and edit])


def _other_tool_tampers(tool: str, args: Any) -> bool:
    """A tool that is not a shell, code or file tool: its words may still aim at the dashboard —
    the session-token route by any tool, or the dashboard itself by a tool that drives a browser."""
    values = args if isinstance(args, dict) else {}
    commands = [" ".join(map(str, value)) if isinstance(value, list) else value for key, value in values.items()
                if _COMMAND_KEY.search(str(key)) and isinstance(value, (str, list))]
    if any(_text_tampers(command[:_MAX_STAGED_CHARS]) for command in commands):
        return True                        # a shell by another name (an MCP shell, a process or schedule tool)
    words = " ".join(str(value) for value in (values.values() if values else [args]) if isinstance(value, str))
    if not guard_commands.names_control_address(words, _ports()):
        return False
    return bool(_BROWSER_TOOL.search(tool)) or "/api/session" in words or bool(guard_commands._WRITES_OVER_HTTP.search(words))


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
    """A finding when an agent's call would change Blackbox, switch it off or go round it, else []."""
    tool = (tool_name or "").strip().lower()
    try:
        access = action_parsing.file_access_arg(tool_name, args)
        if access is not None:
            return [_finding(access["tool"], "write to Blackbox's settings")] if _file_tool_tampers(access, args) else []
        if tool in protected.CODE_TOOLS and isinstance(args, dict) and isinstance(args.get("code"), str):
            return [_finding(tool, "code that changes Blackbox's settings")] if _code_tampers(args["code"]) else []
        if tool in shell_shapes.SHELL_TOOLS:
            # Read WHOLE, not by the first and last part as the other checks read a long command:
            # a change to Blackbox in the middle of a long one must not pass.
            command = shell_shapes.whole_command_from_args(tool_name, args)
            if len(command) > MAX_COMMAND_CHARS:
                return [_finding(tool, "command too long to be read in full")]
            if _text_tampers(command):
                return [_finding(tool, "command that changes Blackbox's settings or switches it off")]
            return []
        return [_finding(tool, "request to Blackbox's own control page")] if _other_tool_tampers(tool, args) else []
    except Exception:  # pragma: no cover  # health: allow BLE001 -- fail open: a detector fault never breaks the agent's tool call
        return []
