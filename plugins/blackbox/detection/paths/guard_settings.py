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
* a script file a shell call RUNS is judged by its text with its arguments, two scripts deep
  (``detection.script_files.judge_runs``, the one script judgement every place family reads);
* a browser tool pointed at the dashboard is refused: the dashboard is the person's.

A command is read WHOLE (the other checks read a long one by its first and last part), line by
line: the cheap tests on every line, the word-by-word reading only on lines that can name a place
or run code, up to :data:`MAX_READ_CLOSELY` characters of those — past that, and past
:data:`MAX_COMMAND_CHARS` in all, the command is refused as unreadable. Nested shells and line
variables are put in and base64 words decoded. What stays open: :data:`KNOWN_LIMITS`.

``source="custom"``, and its findings ALWAYS block (``guard.hooks._would_block``): the person
changes Blackbox through its dashboard, the Hermes Desktop page, the ``blackbox`` commands they type or
their own editor — none of which pass through an agent's tool calls.

Usage::

    detect_guard_tamper("terminal", {"command": "git -C ~/.hermes checkout -- config.yaml"})
    # -> [Finding(identifier="fileaccess:terminal:blackbox-settings", severity="critical", ...)]
    detect_guard_tamper("terminal", {"command": "cat ~/.hermes/config.yaml"})   # -> [] (a read)
"""

from __future__ import annotations

import os
import re
from typing import Any, Optional

from .. import action_parsing, script_files, shell_shapes
from ..finding import Finding
from ...kernel import action_context, addons as guarded_extra, agent_hosts, shell_path, threat_ids
from ...kernel.bounded_files import read_small_text
from ...kernel.config import BlackboxConfig, load_blackbox_config
from . import config_sections, guard_commands, guard_patch, guard_paths, guard_places, guard_secrets, guard_startup, protected, shell_files
from .shell_scripts import _LITERAL

MATCHED = threat_ids.SELF_PROTECTION
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
_CODE_WRITES = re.compile(_CODE_ACTS.pattern.replace(r"|subprocess|os\.system|Popen|os\.exec", "")
                          .replace(r"|child_process|execSync|spawn\(", ""), re.IGNORECASE)
#: In an edit of a host's config, the text that touches Blackbox: its entry, or the plugin lists that enable it.
_BLACKBOX_TEXT = re.compile(r"blackbox|plugins|\benabled\b|\bdisabled\b|\ballow\b|\bentries\b|\bload\b", re.IGNORECASE)
_BLACKBOX_KEYS = re.compile(r"\b(?:mode|block_severity|protected_paths|shields|report|detection|auto_attach)\s*:")
_MAX_CONFIG_BYTES = 1_000_000
#: Coding agents' hook styles whose file is the AGENT's own settings (Blackbox adds one entry there).
_SHARED_HOOK_STYLES = frozenset({"nested", "flat"})
#: Another program's file among the guarded places: only an edit that reaches Blackbox's part is refused.
_HOST_CONFIGS = ("config.yaml", "openclaw.json",
                 *sorted({os.path.basename(host.config) for host in agent_hosts.HOSTS if host.style in _SHARED_HOOK_STYLES}),
                 *shell_path.STARTUP_FILES)   # the person's startup file: everything but the sandbox's PATH block
#: Startup files: a ``BLACKBOX_…`` variable written there lowers the guard of every later session.
_STARTUP_FILES = frozenset({".zshrc", ".zshenv", ".zprofile", ".bashrc", ".bash_profile", ".profile", ".env", "config.fish"})
#: A file whose text is run: a script that would itself be refused may not be written. Each is judged
#: in its OWN language (KI-591): a shell script or service definition as command lines, a code file
#: as code — read as shell, a JavaScript ``// note`` or ``/* c */`` named the root folder.
_SHELL_SCRIPT = re.compile(r"\.(?:sh|bash|zsh|command|plist|service)$", re.IGNORECASE)
_CODE_SCRIPT = re.compile(r"\.(?:py|js|mjs|rb|pl)$", re.IGNORECASE)
_SHEBANG, _SHELLS = re.compile(r"\A#!\s*(\S+)(?:\s+(\S+))?"), frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish"})
#: Code that runs a command: its quoted command lines (``execSync('rm -rf ~')``) are judged as shell.
_RUNS_COMMANDS = re.compile(r"subprocess|os\.system|Popen|os\.exec|child_process|execSync|spawn|\bsystem\(|\bexec\(|%x|`", re.IGNORECASE)
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
#: A heredoc that ``cat`` writes to a file: ``cat > notes.md <<EOF`` or ``cat <<EOF > notes.md`` (after ``cd x &&`` too).
_TEXT_HEREDOC = re.compile(
    r"(?m)^(?P<head>(?:[^\n]*?(?:&&|;)[ \t]*)?[ \t]*cat[ \t]*(?:>>?[ \t]*(?P<target>[^\s|;&<>]+)[ \t]*)?<<-?[ \t]*(?P<quote>['\"]?)(?P<tag>\w+)(?P=quote)"
    r"[ \t]*(?:>>?[ \t]*(?P<after>[^\s|;&<>]+)[ \t]*)?)\n(?P<body>.*?)\n[ \t]*(?P=tag)[ \t]*$", re.DOTALL)
_MAX_STAGED_CHARS = 200_000
#: Argument names under which any tool carries a command to run.
_COMMAND_KEY = re.compile(r"^(?:command|cmd|script|shell|code|argv|args|exec)$", re.IGNORECASE)
#: The old name of the list of guarded places, kept for the callers that read it.
_guarded_places = guard_places.guarded_places
READ_ONLY = guard_paths.READ_ONLY


def _ports_of(cfg: BlackboxConfig) -> tuple[int, ...]:
    node = re.search(r":(\d+)", str(cfg.dkg_url or ""))
    return (int(cfg.dashboard_port), *([int(node.group(1))] if node else []))


def _read_ports() -> tuple[int, ...]:
    return _ports_of(load_blackbox_config())


_PORTS = guard_places.Kept(_read_ports)


def _ports() -> tuple[int, ...]:
    """The ports Blackbox's own services answer on: the dashboard and its node."""
    return _PORTS.get(guard_places._machine())


_decoded = shell_files.with_base64_decoded


def _says_it(line: str, ports: tuple[int, ...]) -> bool:
    """True when *line*, as written or with its quote marks taken out (``he''rmes``), is a command
    that switches Blackbox off, stops it, sets its environment or uses its control API."""
    if guard_places.scope() != guard_places.OWN:
        return False
    for text in dict.fromkeys((line, _QUOTE_MARKS.sub("", line))):
        if guard_commands.switches_off(text) or guard_commands.stops_service(text, ports) or guard_commands.sets_environment(text):
            return True
    return not _WRAPS_ANOTHER.match(line) and guard_commands.uses_control_api(line, ports)


def _read_closely(line: str, folder: str, ports: tuple[int, ...]) -> tuple[bool, str]:
    """``(tampers, folder)`` for a line that can name a place or run code: its variables put in,
    the commands it hides (another shell's, the shell's own decodes), its inline code, then its paths."""
    if "$" in line and _says_it(" ".join(shell_files._with_variables(shell_files._words(line))), ports):
        return True, folder
    # WHY every line, not only after ``-c`` (L-W5): the shell decodes ``~/$'.\x68ermes'`` before ``rm`` runs.
    inner = shell_shapes.with_nested_commands(line, 1).split("\n")[1:]
    if any(_text_tampers(command) for command in inner) or (_HANDS_ON.search(line) and any(
            _code_tampers(code, argv) for code, argv in shell_files.inline_runs(line))):
        return True, folder
    return guard_paths.line_changes_a_place(line, folder)


def _lines(text: str, code: list[tuple[str, str]]) -> list[str]:
    """The lines of *text* to judge as commands: without the body of a heredoc that only writes
    plain text to a file never named again (notes, a README), with every base64 word that decodes
    to readable text added. A heredoc that writes a code file is left out too, and its
    ``(file, body)`` added to *code* for :func:`script_tampers`."""
    def plain(found: re.Match[str]) -> str:
        target = found.group("target") or found.group("after") or ""
        if _script_kind(target, found.group("body")) == "code":
            code.append((target, found.group("body")))   # judged as the code it is, not as command lines
            return found.group("head")
        runs = _script_kind(target, "") or os.path.basename(target) in _STARTUP_FILES or text.count(target) != 1
        return found.group(0) if (not target or runs) else found.group("head")
    return _decoded(_TEXT_HEREDOC.sub(plain, text) if "<<" in text else text).split("\n")


def _patch_path(path: str) -> str:
    """A path an ``apply_patch`` names, joined onto the agent's working folder when relative."""
    expanded = os.path.expanduser(path)
    if os.path.isabs(expanded):
        return path
    return os.path.join(action_context.working_folder() or guard_paths.START_FOLDER, path)


def _patch_tampers(patch: guard_patch.Patch) -> bool:
    """True when a Codex ``apply_patch`` adds, changes, deletes or moves a file the way a file tool
    writing it would be refused (KI-583: the patch is judged as the writes it makes, not as shell)."""
    for path in patch.paths:
        text = patch.added.get(path, "")
        # An update is an edit (judged by what it adds to a host's config); an addition a whole file.
        args = ({"patch": text} if patch.verbs.get(path) == "Update File" else {"content": text}) if text else {}
        if _file_tool_tampers({"mode": "write", "path": _patch_path(path), "tool": "terminal"}, args):
            return True
    return False


def _text_tampers(text: str) -> bool:
    """True when command text *text* would change Blackbox, switch it off or go round it."""
    text, patches = guard_patch.split(text)
    if any(_patch_tampers(patch) for patch in patches):
        return True
    ports = _ports()
    folder, closely = guard_paths.START_FOLDER, MAX_READ_CLOSELY
    code_written: list[tuple[str, str]] = []
    for line in _lines(text, code_written):
        if not line.strip() or (guard_places.scope() == guard_places.OWN and guard_startup.plain_startup_append(line)):
            continue
        if _says_it(line, ports):
            return True
        if "$" in line or _HANDS_ON.search(line) or guard_paths.worth_reading(line, folder):
            closely -= len(line)
            tampers, folder = (True, folder) if closely < 0 else _read_closely(line, folder, ports)
            if tampers:
                return True
    if any(script_tampers(path, body) for path, body in code_written):
        return True
    # Code over several lines: after an interpreter's ``-c "…"`` (found by splitting the whole
    # command, when it is short enough to split), or on a heredoc.
    spread = shell_files.inline_runs(text) if "\n" in text and len(text) <= MAX_READ_CLOSELY and _HANDS_ON.search(text) else []
    heredocs = [(found.group("body"), ()) for found in shell_files._HEREDOC.finditer(text)] if "<<" in text else []
    return any(_code_tampers(code, argv) for code, argv in spread + heredocs)


def _script_kind(path: str, text: str) -> str:
    """``"shell"``, ``"code"`` or ``""``: the language a file at *path* holding *text* is run in —
    its ``#!`` line first, then its ending."""
    first = _SHEBANG.match(text or "")
    if first:
        runner = os.path.basename(first.group(2) if os.path.basename(first.group(1)) == "env" and first.group(2) else first.group(1))
        return "shell" if runner in _SHELLS else "code"
    return "shell" if _SHELL_SCRIPT.search(str(path)) else "code" if _CODE_SCRIPT.search(str(path)) else ""


def script_tampers(path: str, text: str) -> bool:
    """True when *text*, written to *path* as a script, would itself be refused when run: a shell
    script's lines as commands, a code file as code (and the command lines it runs as commands)."""
    kind = _script_kind(path, text)
    if kind == "shell":
        return _text_tampers(text) or _code_tampers(text)
    if kind == "code":
        return _code_tampers(text) or (bool(_RUNS_COMMANDS.search(text)) and any(
            " " in literal.group(2) and _text_tampers(literal.group(2)) for literal in _LITERAL.finditer(text)))
    return False


def _inline_code(command: str) -> list[str]:
    """Code handed to an interpreter after ``-c`` / ``-e`` on the command line."""
    return [code for code, _argv in shell_files.inline_runs(command)]


def _code_tampers(code: str, argv: tuple[str, ...] = ()) -> bool:
    """True when *code* talks to the control API other than by a plain read, sets Blackbox's
    environment, or names a guarded place (whole or in pieces) and writes, deletes or runs anything —
    in Homebrew's program folders only a write counts (running a program there is everyday work)."""
    if guard_places.scope() == guard_places.OWN and (guard_commands.sets_environment(code) or guard_commands.switches_off(code) or (
            guard_commands.uses_control_api(code, _ports()) and (
            guard_commands._WRITES_OVER_HTTP.search(code) or guard_commands._DESKTOP_ROUTE.search(code)))):
        return True
    names = any(guard_places.code_names(arg.path, code, argv) for arg in shell_files.code_file_args(code)) or guard_places.names_in_pieces(code)
    acts = _CODE_WRITES if guard_places.scope() == guard_places.PROGRAMS else _CODE_ACTS
    return names and bool(acts.search(code))


def _edit_reaches_blackbox(config_path: str, edits: list[str]) -> bool:
    """True when an edit's text touches Blackbox: names it or the plugin lists, or changes text that sits
    inside Blackbox's section of the file as it is now (``mode: block`` → ``mode: audit``).
    A shell startup file is judged by its PATH block alone: words like ``load`` or ``allow`` are
    ordinary there (``autoload -U compinit``)."""
    if os.path.basename(os.path.expanduser(config_path)) in shell_path.STARTUP_FILES:
        return guard_startup.edit_reaches_path_block(config_path, edits)
    if any(_BLACKBOX_TEXT.search(edit) for edit in edits):
        return True
    text = read_small_text(os.path.expanduser(config_path), _MAX_CONFIG_BYTES)
    if text is None:
        return any(_BLACKBOX_KEYS.search(edit) for edit in edits)
    section = config_sections.blackbox_section(text) or config_sections.json_entry(text) or shell_path.section(text)
    return bool(section) and any(edit.strip() and edit.strip() in section for edit in edits)


def _written_text(args: Any) -> str:
    if not isinstance(args, dict):
        return ""
    return "\n".join(str(args[key]) for key in ("content", "new_string", "new_str", "text", "patch", "diff") if isinstance(args.get(key), str))


def _file_tool_tampers(access: dict[str, str], args: Any) -> bool:
    if access["mode"] != "write":
        return False
    path, text, own = access["path"], _written_text(args)[:_MAX_STAGED_CHARS], guard_places.scope() == guard_places.OWN
    if not own:   # a persistence place: any write; a script that would write one (not in Homebrew's folders)
        scripts_judged = guard_places.scope() in (guard_places.STARTS, guard_places.SHELL, guard_places.HOOKS)
        return guard_places.reaches(path) or (scripts_judged and script_tampers(str(path), text))
    if not guard_places.reaches(path):
        name = os.path.basename(os.path.expanduser(str(path or "")))
        if name in _STARTUP_FILES and guard_commands.sets_environment(text):
            return True                    # a startup file given one of Blackbox's variables
        return bool(text) and script_tampers(str(path), text)   # a script that would itself be refused
    host_configs = (*_HOST_CONFIGS, *guarded_extra.editable_configs())   # another program's file: Blackbox's part only
    if os.path.basename(os.path.expanduser(str(path))) not in host_configs or not isinstance(args, dict):
        return True                        # Blackbox's own folders and files: any write
    if os.path.basename(os.path.expanduser(str(path))) in shell_path.STARTUP_FILES:
        kept = guard_startup.edit_keeps_path_block(path, args)
        if kept is not None:
            return not kept                # the edit applied: is the block still whole and unguarded?
    edits = [args.get(key) for key in (*guard_startup.OLD_KEYS, *guard_startup.NEW_KEYS, "patch", "diff")]
    edits += [str(item) for item in (args.get("edits") if isinstance(args.get("edits"), list) else [])]
    if not any(isinstance(edit, str) and edit for edit in edits):
        return not guard_startup.keeps_path_block(path, args)   # a whole-file write or a delete can drop Blackbox
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
    if guard_places.scope() != guard_places.OWN or not guard_commands.names_control_address(words, _ports()):
        return False
    return bool(_BROWSER_TOOL.search(tool)) or "/api/session" in words or bool(guard_commands._WRITES_OVER_HTTP.search(words))


def _finding(tool: str, evidence: str, title: str = _TITLE, advice: str = "") -> Finding:
    return Finding(
        identifier=threat_ids.fileaccess_identifier(tool, MATCHED),
        category="fileaccess",
        severity="critical",
        title=title,
        advice=advice,
        tool_name=tool,
        matched=MATCHED,
        evidence=evidence,
        confirmed=False,
        source="custom",
        fields={},
    )


#: What :func:`tampering` found, in the words of a self-protection finding.
_EVIDENCE = {"write": "write to Blackbox's settings", "code": "code that changes Blackbox's settings",
             "long": "command too long to be read in full", "page": "request to Blackbox's own control page",
             "command": "command that changes Blackbox's settings or switches it off"}


def tampering(tool_name: str, args: Any) -> tuple[str, str]:
    """``(tool, how)``: how a call changes a place of the set being judged (``guard_places.judging``)
    — ``"write"`` (a file tool), ``"code"``, ``"command"``, ``"long"`` (a command too long to read
    whole), ``"page"`` (Blackbox's control page) — or ``(tool, "")``. Raises on a detector fault."""
    tool = (tool_name or "").strip().lower()
    access = action_parsing.file_access_arg(tool_name, args)
    if access is not None:
        return access["tool"], "write" if _file_tool_tampers(access, args) else ""
    if tool in protected.CODE_TOOLS and isinstance(args, dict) and isinstance(args.get("code"), str):
        return tool, "code" if _code_tampers(args["code"]) else ""
    if tool in shell_shapes.SHELL_TOOLS:
        # Read WHOLE, not by the first and last part as the other checks read a long command:
        # a change in the middle of a long one must not pass.
        command = shell_shapes.whole_command_from_args(tool_name, args)
        return tool, "long" if len(command) > MAX_COMMAND_CHARS else "command" if _text_tampers(command) else ""
    return tool, "page" if _other_tool_tampers(tool, args) else ""


def _run_tampers(run: script_files.ScriptRun, call: dict[str, str]) -> str:
    """How one script a command runs would change Blackbox (an ``_EVIDENCE`` key, "" for none): a
    shell script as its command lines; code as code, with the arguments it is run with.

    WHY (KI-692, R8): a copied script building ``"~/." + sys.argv[2] + …``, run with ``ssh
    authorized_keys``, was refused as Blackbox's settings: its lines, read as shell, named the home."""
    if script_files.language_of(run) == "shell":
        return tampering("terminal", call)[1]
    text = run.text or ""
    runs_commands = bool(_RUNS_COMMANDS.search(text)) and any(
        " " in literal.group(2) and _text_tampers(literal.group(2)) for literal in _LITERAL.finditer(text))
    return "code" if _code_tampers(text, run.argv) or runs_commands else ""


def _script_tampering(tool: str, args: Any) -> str:
    """Evidence when a script this shell call runs would itself be refused (``python3 c.py hermes yaml``
    building ``~/.hermes/config.yaml``), by the one script judgement (LES-137); "" for none."""
    if tool not in shell_shapes.SHELL_TOOLS:
        return ""
    hit = script_files.judge_runs(shell_shapes.command_from_args(tool, args), _run_tampers)
    return f"a script it runs ({os.path.basename(hit[0].path)}): {_EVIDENCE[hit[1]]}" if hit else ""


def detect_guard_tamper(tool_name: str, args: Any, cfg: Optional[BlackboxConfig] = None) -> list[Finding]:
    """A finding when an agent's call would change Blackbox, switch it off or go round it, else [].
    *cfg*: the config the caller already loaded for this call (its ports are used, not re-read)."""
    if cfg is not None:
        _PORTS.put(guard_places._machine(), _ports_of(cfg))
    try:
        secret = guard_secrets.reads_a_secret(tool_name, args)   # a read is the harm for Blackbox's keys
        if secret:
            return [_finding((tool_name or "").strip().lower(), secret, guard_secrets.TITLE, guard_secrets.ADVICE)]
        tool, how = tampering(tool_name, args)
        evidence = _EVIDENCE[how] if how else _script_tampering(tool, args)
        return [_finding(tool, evidence)] if evidence else []
    except Exception:  # pragma: no cover  # health: allow BLE001 -- fail open: a detector fault never breaks the agent's tool call
        return []
