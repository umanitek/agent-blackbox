"""Escalation shapes: turn a shell tool call into a stable arg-shape signature.

``normalize_arg_shapes(tool_name, args)`` returns every shape of a small closed set of
dangerous shapes (``remote-script-pipe``, ``rm-rf-system-paths``, …) a call has —
the identifiers detection and reports use for escalations; ``normalize_arg_shape``
the first of them or None. The shapes are judged on shell words
(:mod:`.command_line.escalation_shapes`), tuned against false positives; ``NO_AUTO_NOMINATE_SHAPES``
lists shapes that match curated rules only.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from .paths.shell_words import _words as _command_words   # ONE way of splitting a command line
from .command_line.escalation_shapes import SHAPE_ORDER, shapes_of
from .hidden_commands import hidden_commands

# ---------------------------------------------------------------------------
# Arg-shape normalization
# ---------------------------------------------------------------------------

# A remote-download-piped-to-interpreter shape in TEXT (a skill's code: ``content_scanners``):
# `curl ... | sh`, `wget ... | bash`. A shell command is judged on its words (:mod:`.command_line.escalation_shapes`).
REMOTE_SCRIPT_RE = re.compile(
    r"\b(?:curl|wget)\b[\s\S]{0,500}\|\s*(?:sh|bash|zsh|python|python3|node)\b",
    re.IGNORECASE,
)
# Shapes that Blackbox still MATCHES against curated graph rules but never
# auto-nominates as heuristic candidates. `remote-script-pipe` (`curl … | bash`)
# is the canonical install idiom for rustup, nvm, Homebrew, oh-my-zsh, etc., so
# firing + reporting on the shape alone would flag routine agent behaviour and
# flood the community graph. A known-bad
# `curl|bash` into the graph and Blackbox will match it.
NO_AUTO_NOMINATE_SHAPES = frozenset({"remote-script-pipe"})

#: Every escalation arg shape detection can name — the closed vocabulary a
#: community escalation report is validated against (Refine R1).
ESCALATION_SHAPES = frozenset(SHAPE_ORDER)

# Tool names whose payload is treated as a shell command string (PowerShell's too: Windows agents).
SHELL_TOOLS = {"terminal", "shell", "bash", "run_command", "exec", "command", "powershell", "pwsh", "powershell.exe", "pwsh.exe"}
_COMMAND_KEYS = ("command", "cmd", "shell", "script", "input")

#: A command is read whole up to twice this many characters; a longer one by its first and
#: its last this-many (the secret scanners' rule, KI-376): harmless text before or after an
#: action never moves it out of the checks, and the cost stays bounded on any input. An
#: action in the middle of a command longer than twice this is a known gap.
COMMAND_SCAN_WINDOW = 50_000


def _bounded(command: str) -> str:
    """*command* as the checks read it (see :data:`COMMAND_SCAN_WINDOW`); the two halves of a
    long one are joined by a newline, which ends a shell command."""
    if len(command) <= 2 * COMMAND_SCAN_WINDOW:
        return command
    return command[:COMMAND_SCAN_WINDOW] + "\n" + command[-COMMAND_SCAN_WINDOW:]


#: Shells that run the code handed to them after ``-c`` (``sh -c 'cat x'``, ``bash -lc "…"``).
_NESTED_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish"})
#: How many shells deep a wrapped command is followed.
_NESTING_DEPTH = 3
_COMMAND_ENDS = frozenset({";", "&&", "||", "|", "&"})


#: util-linux ``script``'s option that hands it a command to run in a new shell (``script -qc 'crontab
#: f' /dev/null``). Linux round L1: that form wrote a cron job past every runner's hook; macOS's
#: ``script FILE command`` is a wrapper (``hidden_commands``).
_SCRIPT_COMMAND = "--command"


def _script_code(words: list[str]) -> str:
    """The command util-linux ``script`` runs from *words* (the words after ``script``), or ""."""
    for offset, option in enumerate(words):
        if option.startswith(_SCRIPT_COMMAND + "="):
            return option.split("=", 1)[1]
        if offset + 1 < len(words) and (option == _SCRIPT_COMMAND or (option[:1] == "-" and option[1:2] != "-" and option.endswith("c"))):
            return words[offset + 1]
        if option in _COMMAND_ENDS:
            break
    return ""


def _nested_code(command: str) -> list[str]:
    """The commands *command* hands to another shell: the word after a shell's ``-c`` (or
    ``script -c``), and what follows ``eval`` up to the end of that command (split as every path
    check splits it)."""
    words = _command_words(command)
    found: list[str] = []
    for position, word in enumerate(words):
        name = word.rsplit("/", 1)[-1].lower()
        if name == "script":
            found.append(_script_code(words[position + 1:]))
        elif name in _NESTED_SHELLS:
            for offset in range(position + 1, len(words) - 1):
                option = words[offset]
                if not option.startswith("-"):
                    break
                if not option.startswith("--") and option.endswith("c"):
                    found.append(words[offset + 1])
                    break
        elif name == "eval":
            rest = words[position + 1:]
            end = next((index for index, each in enumerate(rest) if each in _COMMAND_ENDS), len(rest))
            found.append(" ".join(rest[:end]))
    return [code for code in found if code.strip()]


#: Signs that a command line may hand something hidden on: a shell's ``-c``, ``eval``, inline code
#: (``-e``, ``-p``, ``-r``, ``-E``, ``eval``), a substitution, a decode, ANSI-C quoting or a wrapper.
_MAY_HIDE = re.compile(r" -[a-zA-Z]*[cepErS]\b|\beval\b|\$\(|`|\$'|base64|base32|xxd|printf|\b(?:env|nohup|nice|stdbuf|caffeinate|time|"
                       r"command|exec|sudo|doas|g?timeout|script|arch|flock|unbuffer|taskpolicy)\b")


def with_nested_commands(command: str, depth: int = _NESTING_DEPTH) -> str:
    """*command* followed, one per line, by every command it hands on — to another shell
    (``sh -c '…'``, ``bash -c``, ``eval``) or hidden in it some other way (inline interpreter code,
    a substitution, a static decode, a wrapper: :mod:`.hidden_commands`) — :data:`_NESTING_DEPTH`
    levels deep.

    WHY (2026-11-20): every check reads the command's own words, so wrapping a refused command
    in ``sh -c '…'`` hid it — a protected file was read and a verified-malware package installed
    that way. Appending the inner commands lets each check see them as it sees any command;
    a newline ends a shell command, so the two never run together. 2026-11-22: a real agent,
    refused twice, ran the same read through ``python3 -c "subprocess.run('cat …', shell=True)"``
    — the interpreter's code is now read the same way."""
    if depth <= 0 or not _MAY_HIDE.search(command):
        return command
    hidden = [code for code in _nested_code(command)] + hidden_commands(command)
    inner = [with_nested_commands(code, depth - 1) for code in dict.fromkeys(hidden) if code != command]
    if not inner:
        return command
    # Each line once: a wrapper chain or a decode reached twice adds nothing a second time.
    return "\n".join(dict.fromkeys(line for block in [command, *inner] for line in block.split("\n")))


def whole_command_from_args(tool_name: str, args: Any, *, any_tool: bool = False) -> str:
    """The shell command a tool call carries, every character of it (no window): its
    ``command``-like argument, else its string arguments joined — for shell tools only, or for
    every tool when *any_tool*; "" for anything else. For the one check that must read a long
    command whole (Blackbox's own protection); every other check asks :func:`command_from_args`."""
    if isinstance(args, str):
        return args
    if not isinstance(args, dict):
        return ""
    for key in _COMMAND_KEYS:
        val = args.get(key)
        if isinstance(val, str) and val:
            return val
    # Fall back to concatenating string values for shell-like tools only.
    if any_tool or (tool_name or "").lower() in SHELL_TOOLS:
        return " ".join(v for v in args.values() if isinstance(v, str))
    return ""


def command_from_args(tool_name: str, args: Any, *, any_tool: bool = False) -> str:
    """The shell command a tool call carries, as the checks read it (bounded, see
    :data:`COMMAND_SCAN_WINDOW`, with the commands it hands to other shells added): see
    :func:`whole_command_from_args` for which argument that is.

    The ONE reader of "the command of this call" — every check asks it, so no two checks can
    read different commands from the same call."""
    return with_nested_commands(_bounded(whole_command_from_args(tool_name, args, any_tool=any_tool)))


def normalize_arg_shapes(tool_name: str, args: Any) -> tuple[str, ...]:
    """Every escalation ``argShape`` a tool call has, in :data:`.command_line.escalation_shapes.SHAPE_ORDER`
    (``()`` for none) — judged on the shell words of every segment, so a harmless segment before a
    dangerous one hides nothing (``echo curl | sh; rm -rf /etc`` has both). Deterministic and pure
    so independent clients agree on identifiers."""
    command = command_from_args(tool_name, args)
    return shapes_of(command) if command else ()


def normalize_arg_shape(tool_name: str, args: Any) -> Optional[str]:
    """The first of :func:`normalize_arg_shapes` (the most specific / most dangerous), or ``None``."""
    shapes = normalize_arg_shapes(tool_name, args)
    return shapes[0] if shapes else None
