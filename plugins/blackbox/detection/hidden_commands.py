"""The commands a command line runs that its own words do not show — read so every check sees them.

Every check reads a command's words (``shell_shapes.command_from_args``). A refused command that is
wrapped stays the same command, only hidden: real agents, refused twice, routed round File Shield
on their own this way (OpenCode with a hosted model, 2026-11-22). This module finds what such a
command line will really run and hands it back as more command lines, judged like any other:

* a command an interpreter is told to run — the string literals of inline code
  (``python3 -c``, ``node -e/-p``, ``ruby -e``, ``perl -e/-E``, ``php -r``, ``bun -e``,
  ``deno eval``, ``osascript -e`` and its ``do shell script "…"``): each literal is read as a
  command (``subprocess.run('cat …', shell=True)``) and, through the path checks, as a path;
* a command substitution — ``$(…)`` and backticks — read on its own, and the line with every
  STATICALLY decodable substitution replaced by what it prints;
* a static decode — ``echo|printf LITERAL | base64 -d`` (``--decode``, ``-D``), ``| xxd -r [-p]``,
  ``printf`` escapes of a literal, ``$'\\x…'`` quoting, and in code ``bytes.fromhex``,
  ``b64decode``, ``unhexlify``, ``atob``, ``Buffer.from(…, "base64"|"hex")`` of a literal: the
  decoded text is read as a command, and the line is read again with the decode replaced by
  ``echo 'DECODED'`` (so ``… | base64 -d | xargs cat`` is the ``xargs cat`` the path checks know);
* a program started through a wrapper — ``env [VAR=…] cmd``, ``nohup``, ``timeout N``, ``nice``,
  ``stdbuf``, ``caffeinate``, ``time``, ``command``, ``exec``, ``sudo``/``doas`` with options:
  the wrapped command on its own.

``sh -c`` / ``bash -c`` / ``zsh -c`` and ``eval`` stay in :mod:`.shell_shapes`, which calls
:func:`hidden_commands` for each command it reads, so all of these nest (``eval "$(echo … | base64
-d)"``).

**Limits, said plainly (Layer 1):** only what is written IN the command line is seen. A decode
of something not written there (a file, the network, an environment variable set elsewhere), a
path assembled at run time from pieces (``Path.home().joinpath("Docu" + "ments")``), a script
file the command runs — none of that is visible to a hook; the OS sandbox (Layer 2) is what stops
those. Everything here is bounded: at most :data:`MAX_LITERALS` literals of at most
:data:`MAX_LITERAL_CHARS` each, :data:`MAX_DECODED_CHARS` decoded.

Usage::

    hidden_commands("python3 -c \\"import os; os.system('cat ~/.ssh/id_rsa')\\"")
    # -> ["import os; os.system('cat ~/.ssh/id_rsa')", "cat ~/.ssh/id_rsa"]   (code first, then literals)

Pure and deterministic; reads no files.
"""

from __future__ import annotations

import base64
import binascii
import re

from .paths.shell_scripts import _INTERPRETERS
from .paths.shell_words import _SEPARATORS, _words

#: The most string literals of one piece of inline code read as commands.
MAX_LITERALS = 64
#: The longest literal read (longer ones are data, not a command).
MAX_LITERAL_CHARS = 4096
#: The most text one decode may produce.
MAX_DECODED_CHARS = 8192
#: The most hidden commands one command line yields.
MAX_HIDDEN = 128

#: A quoted string in code: single, double or backtick quotes, escapes respected.
_LITERAL = re.compile(r"""(['"`])((?:\\.|(?!\1)[^\\]){1,""" + str(MAX_LITERAL_CHARS) + r"""}?)\1""", re.DOTALL)
#: A decode of a literal written in code (Python, JS, Ruby, Perl): the call, then its literal.
_CODE_DECODE = re.compile(
    r"""(?P<call>fromhex|unhexlify|a2b_hex|b16decode|b64decode|b32decode|urlsafe_b64decode|decodebytes|atob|decode64|unpack1?|Buffer\.from)"""
    r"""\s*\(\s*b?(?P<quote>['"])(?P<data>[A-Za-z0-9+/=_\-\s]{4,""" + str(MAX_DECODED_CHARS * 2) + r"""})(?P=quote)(?P<rest>[^)]{0,40})\)""")
#: ``echo|printf LITERAL | base64 -d`` / ``| xxd -r -p`` — a decode wholly written in the line.
_PIPE_DECODE = re.compile(
    r"""(?P<head>\b(?:echo|printf)\s+(?:-[neE]+\s+)*(?P<quote>['"]?)(?P<data>[A-Za-z0-9+/=_\-]{4,""" + str(MAX_DECODED_CHARS * 2) + r"""})(?P=quote))"""
    r"""\s*\|\s*(?P<tool>base64\s+(?:-d|--decode|-D)\b|base32\s+(?:-d|--decode)\b|xxd\s+(?:-r\s+-p|-p\s+-r|-rp|-pr|-r)\b)""")
#: ``printf 'ESCAPES'`` (``\\x2f``, ``\\057``) — a decode the shell itself does.
_PRINTF_ESCAPES = re.compile(r"""\bprintf\s+(?:--\s+)?(?P<quote>['"])(?P<data>(?:\\(?:x[0-9A-Fa-f]{1,2}|[0-7]{1,3})|[^'"\\]){1,""" + str(MAX_DECODED_CHARS) + r"""})(?P=quote)""")
#: ``$'…'`` ANSI-C quoting, which the shell decodes before the command runs.
_ANSI_C = re.compile(r"""\$'((?:\\.|[^'\\]){1,""" + str(MAX_DECODED_CHARS) + r"""})'""")
#: Wrappers that run the command after their own options; the value each option takes, if any.
_WRAPPERS = {"env": ("-u", "-C", "-S", "--unset", "--chdir"), "nohup": (), "nice": ("-n",), "stdbuf": ("-i", "-o", "-e"),
             "caffeinate": ("-t", "-w"), "time": (), "command": (), "exec": ("-a",), "sudo": ("-u", "-g", "-C", "-D", "-h", "-p", "-U"),
             "doas": ("-u", "-C"), "timeout": ("-s", "-k", "--signal", "--kill-after"), "gtimeout": ("-s", "-k")}
#: Wrappers whose first plain word is a value, not the command (``timeout 5 cat …``).
_TAKES_VALUE_FIRST = frozenset({"timeout", "gtimeout"})


def _printable(text: str) -> bool:
    return bool(text) and all(char.isprintable() or char in "\n\t" for char in text)


def _decode_bytes(data: str, how: str) -> str:
    """*data* decoded as *how* (``base64``, ``base32``, ``hex``) to printable text; "" when it does not decode."""
    compact = re.sub(r"\s+", "", data)
    try:
        if how == "hex":
            raw = binascii.unhexlify(compact)
        elif how == "base32":
            raw = base64.b32decode(compact + "=" * (-len(compact) % 8))
        else:
            raw = base64.b64decode(compact.replace("-", "+").replace("_", "/") + "=" * (-len(compact) % 4), validate=True)
        text = raw[:MAX_DECODED_CHARS].decode("utf-8")
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return ""
    return text if _printable(text) else ""


def _unescape(data: str) -> str:
    """Backslash escapes as ``printf`` and ``$'…'`` decode them (``\\x2f``, ``\\057``, ``\\n``)."""
    def one(match: re.Match[str]) -> str:
        code = match.group(1)
        if code[0] in "xX":
            return chr(int(code[1:], 16))
        if code[0].isdigit():
            return chr(int(code, 8) & 0xFF)
        return {"n": "\n", "t": "\t", "\\": "\\", "'": "'", '"': '"', "e": "", "a": "", "r": ""}.get(code, code)
    text = re.sub(r"\\(x[0-9A-Fa-f]{1,2}|[0-7]{1,3}|.)", one, data)
    return text if _printable(text) else ""


def _quoted(text: str) -> str:
    """*text* as one shell word: as it is when it needs no quoting (so it also reads right where it
    lands inside double quotes, ``cat "$(…)"``), else single-quoted."""
    if re.fullmatch(r"[\w@%+=:,./~-]+", text):
        return text
    return "'" + text.replace("'", "'\\''") + "'"


def _substitutions(command: str) -> list[tuple[int, int, str]]:
    """``(start, end, inner)`` for each ``$(…)`` (parentheses balanced, quotes respected) and each
    backtick pair in *command*, outermost first."""
    found: list[tuple[int, int, str]] = []
    index, length = 0, len(command)
    while index < length and len(found) < MAX_HIDDEN:
        if command.startswith("$(", index) and not command.startswith("$((", index):
            depth, position, quote = 1, index + 2, ""
            while position < length and depth:
                char = command[position]
                if quote:
                    quote = "" if char == quote else quote
                elif char in "'\"":
                    quote = char
                elif char == "(":
                    depth += 1
                elif char == ")":
                    depth -= 1
                position += 1
            if depth == 0:
                found.append((index, position, command[index + 2:position - 1]))
                index = position
                continue
        elif command[index] == "`":
            close = command.find("`", index + 1)
            if close > index:
                found.append((index, close + 1, command[index + 1:close]))
                index = close + 1
                continue
        index += 1
    return found


def _static_value(inner: str) -> str:
    """What a substitution's command *inner* prints, when that is fixed by the line alone: a
    decode of a literal or ``printf`` escapes ("" when it is not)."""
    inner = inner.strip()
    pipe = _PIPE_DECODE.fullmatch(inner)
    if pipe:
        return _decode_bytes(pipe.group("data"), _tool_kind(pipe.group("tool")))
    printf = _PRINTF_ESCAPES.fullmatch(inner)
    if printf:
        return _unescape(printf.group("data"))
    return ""


def _tool_kind(tool: str) -> str:
    return "hex" if tool.startswith("xxd") else "base32" if tool.startswith("base32") else "base64"


def _shell_decodes(command: str) -> list[str]:
    """Commands that only appear once the shell has decoded what the line spells out."""
    out: list[str] = []
    resolved = command
    for start, end, inner in reversed(_substitutions(command)):
        out.append(inner)   # what it runs, judged on its own
        value = _static_value(inner)
        if value:
            out.append(value)   # a decoded command handed to eval or a shell
            resolved = resolved[:start] + _quoted(value) + resolved[end:]
    for match in _PIPE_DECODE.finditer(command):
        value = _decode_bytes(match.group("data"), _tool_kind(match.group("tool")))
        if value:
            out.append(value)   # ``… | base64 -d | sh``
            resolved = resolved.replace(match.group(0), "echo " + _quoted(value), 1)
    for match in _PRINTF_ESCAPES.finditer(command):
        value = _unescape(match.group("data"))
        if value and value != match.group("data"):
            resolved = resolved.replace(match.group(0), "printf " + _quoted(value), 1)
    for match in _ANSI_C.finditer(command):
        value = _unescape(match.group(1))
        if value:
            resolved = resolved.replace(match.group(0), _quoted(value), 1)
    return out + ([resolved] if resolved != command else [])


def code_commands(code: str) -> list[str]:
    """The commands and paths inline *code* spells out: each string literal (a command it may run,
    a path it may open), and each literal it decodes from base64 or hex."""
    out: list[str] = []
    for match in _CODE_DECODE.finditer(code):
        call, data, rest = match.group("call"), match.group("data"), match.group("rest").lower()
        hexed = call in ("fromhex", "unhexlify", "a2b_hex", "b16decode") or "hex" in rest or (call.startswith("unpack") and "h" in rest)
        value = _decode_bytes(data, "hex" if hexed else "base32" if call == "b32decode" else "base64")
        if value:
            out.append(value)
    for index, match in enumerate(_LITERAL.finditer(code)):
        if index >= MAX_LITERALS:
            break
        literal = match.group(2)
        if literal.strip():
            out.append(_unescape(literal) or literal)
    return out


def _wrapped(words: list[str], index: int) -> str:
    """The command a wrapper at *index* runs (``env A=1 cat x`` → ``cat x``), "" when none."""
    name = words[index].rsplit("/", 1)[-1].lower()
    takes_value = _WRAPPERS[name]
    position, value_first = index + 1, name in _TAKES_VALUE_FIRST
    while position < len(words):
        word = words[position]
        if word in _SEPARATORS:
            return ""
        if word.startswith("-"):
            position += 2 if word in takes_value else 1
            continue
        if name == "env" and "=" in word:
            position += 1
            continue
        if value_first:
            value_first, position = False, position + 1
            continue
        break
    end = next((at for at in range(position, len(words)) if words[at] in _SEPARATORS), len(words))
    return " ".join(_quoted(word) if re.search(r"\s", word) else word for word in words[position:end])


def hidden_commands(command: str) -> list[str]:
    """Every command *command* runs that its own words do not show (see the module doc), each
    once, at most :data:`MAX_HIDDEN`. Empty for an ordinary command."""
    if not command:
        return []
    found: list[str] = _shell_decodes(command)
    words = _words(command)
    for index, word in enumerate(words):
        name = word.rsplit("/", 1)[-1].lower()
        if name in _INTERPRETERS:
            options = _INTERPRETERS[name]
            end = next((at for at in range(index + 1, len(words)) if words[at] in _SEPARATORS), len(words))
            for position in range(index + 1, end - 1):
                if words[position] in options:
                    found.extend(code_commands(words[position + 1]))
        elif name in _WRAPPERS:
            found.append(_wrapped(words, index))
    seen = {command}
    out = []
    for each in found:
        each = each.strip()
        if each and each not in seen:
            seen.add(each)
            out.append(each)
    return out[:MAX_HIDDEN]


#: A decode or a run-time spelling whose input is NOT a literal on the line (a variable, a file,
#: another command's output): what it produces cannot be known from the line.
_DYNAMIC_DECODE = re.compile(r"\b(?:base64|base32)\s+(?:-d|--decode|-D)\b|\bxxd\s+-r|\bopenssl\s+(?:enc|base64)\b[^|;&]*\s-d\b|\brev\b|"
                             r"\b(?:fromhex|unhexlify|b64decode|b32decode|atob|decode64)\s*\(\s*[A-Za-z_$]|\bchr\s*\(|String\.fromCharCode")


def undecidable(command: str) -> bool:
    """True when *command* builds part of what it runs or opens at run time in a way this module
    cannot read off the line: a substitution whose output is not fixed (``$(cat list | base64
    -d)``), or a decode of something that is not a literal. File Shield flags such a command —
    with that reason — when it also names the folder that holds a protected item."""
    if any(not _static_value(inner) for _start, _end, inner in _substitutions(command)):
        return True
    rest = _PIPE_DECODE.sub(" ", command)   # a decode of a literal is read, not unknown
    rest = _CODE_DECODE.sub(" ", rest)
    return bool(_DYNAMIC_DECODE.search(rest))


__all__ = ["MAX_DECODED_CHARS", "MAX_HIDDEN", "MAX_LITERALS", "MAX_LITERAL_CHARS", "code_commands", "hidden_commands", "undecidable"]
