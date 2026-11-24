"""Paths inside script code a command hands to an interpreter — part of the shell file view.

Split out of :mod:`.shell_files` (2026-11-20, a move only): a one-line script
(``python3 -c "open('…').read()"``, ``node -e``, ``ruby -e``, ``perl -e``, ``php -r``) or a script
fed on a heredoc (``python3 - <<EOF``) reads the quoted paths in its code. A path the code builds
piece by piece is not seen, except the common ``home + '.config/…'`` join.

``_script_args`` reads an interpreter's command-line code, ``_paths_in_code`` any piece of code,
``_HEREDOC`` finds heredoc bodies, ``_INTERPRETERS`` names the interpreters and their code option.

**What it works out statically** (:func:`_resolved`, the private security finding of round 2,
2026-11-22): the person's home where the code asks for it (``process.env.HOME``,
``os.homedir()``, ``Dir.home``, ``ENV['HOME']``, ``Path.home()``, ``os.path.expanduser('~')``,
``os.environ['HOME']``, ``$ENV{HOME}``), the arguments the command line hands the code
(``sys.argv[1]``, ``process.argv[2]``, ``ARGV[0]``, ``$ARGV[0]``) and literal pieces joined with
``+`` / ``.`` / ``/`` — so ``process.env.HOME + '/Documents/x'`` or ``sys.argv[1] + 'uments'`` read
as the path they make. Before that, :func:`_decoded` writes out every spelling fixed by the code's
own text (the private finding of round 7, 2026-11-23, a REAL Codex read through ``'\\/Documents'``):
escapes in string literals (``\\/``, ``\\x2f``, ``\\u002f``, ``\\u{2f}``, octal ``\\057``), the separator
spelled ``os.sep`` / ``os.path.sep`` / ``path.sep`` / ``File::SEPARATOR`` / ``chr(47)`` /
``String.fromCharCode(47)``, lists of literals joined with it, and decodes of a literal
(``bytes.fromhex``, ``unhexlify``, ``b64decode``, ``atob``, ``Buffer.from(…, 'base64'|'hex')``,
``Base64.decode64``, ``decode_base64``, ``codecs.decode(…, 'rot13'|'hex'|'base64')``).

**The sandbox's job, not this module's** — what only the running code can compute: a value from
input, a file, the network or the environment beyond ``HOME``; a variable assigned and used later
(``s = os.sep; home + s + …``); a string reversed, sliced, ``translate``d or ``replace``d; a loop
or ``map`` over character codes; ``eval`` / ``exec`` of a built string; and a decode applied to
anything but a literal. Anything else the code computes while it runs is NOT seen here; only the
OS sandbox stops that.

Pure and deterministic; reads no files (the home folder is written ``~``).
"""

from __future__ import annotations

import base64
import binascii
import json
import re

from .shell_words import ShellFileArg, _segment_end

#: The most text one decode may produce.
MAX_DECODED_CHARS = 8192

#: Interpreters and the option that hands them code on the command line.
_INTERPRETERS = {"python": ("-c",), "python3": ("-c",), "python2": ("-c",), "py": ("-c",),
                 "node": ("-e", "--eval", "-p", "--print"), "nodejs": ("-e", "--eval", "-p", "--print"),
                 "bun": ("-e", "--eval"), "deno": ("eval",), "ruby": ("-e",), "perl": ("-e", "-E"),
                 "php": ("-r",), "osascript": ("-e",)}


#: A quoted string in script code (single, double or JS backtick quotes).
_LITERAL = re.compile(r"""(['"`])((?:\\.|(?!\1).){1,1024}?)\1""")


#: Script code that walks or packs whole folders: its paths are folders handed over whole.
_WHOLE_FOLDER_CODE = re.compile(r"copytree|make_archive|tarfile|zipfile|os\.walk|\bwalk\(|rglob|glob\(|readdirSync|readdir\(|cpSync|archiver|ZipFile|Dir\.glob|File\.find")


#: Script code that joins a literal onto the home folder.
_HOME_CODE = re.compile(r"homedir\(|expanduser|Path\.home|environ\[.HOME.\]|getenv\(.HOME.\)|env\.HOME|ENV\[.HOME.\]|Dir\.home")


#: A heredoc fed to an interpreter: ``python3 - <<'EOF'`` … ``EOF``.
_HEREDOC = re.compile(r"(?m)^[^\n]*?\b(?P<interpreter>python[23]?|node|ruby|perl|php|bun)\b[^\n]*<<-?\s*(?P<quote>['\"]?)(?P<tag>\w+)(?P=quote)[^\n]*\n(?P<body>.*?)\n\s*(?P=tag)\s*$", re.DOTALL)


def _script_args(name: str, words: list[str], index: int) -> tuple[list[ShellFileArg], int]:
    """The paths in the code an interpreter is handed on its command line (the words after the
    code are the arguments it reads)."""
    end = _segment_end(words, index + 1)
    options = _INTERPRETERS[name]
    found: list[ShellFileArg] = []
    for position in range(index + 1, end - 1):
        if words[position] in options:
            found.extend(_paths_in_code(name, words[position + 1], tuple(words[position + 2:end])))
    return found, end


#: How code asks for the person's home folder, in the languages an agent runs inline.
_HOME_ASKED = re.compile(r"""\b(?:pathlib\.)?Path\.home\(\s*\)|\bos\.path\.expanduser\(\s*['"]~['"]\s*\)"""
                         r"""|(?:\bos|__import__\(\s*['"]os['"]\s*\))\.environ\s*\[\s*['"]HOME['"]\s*\]"""
                         r"""|(?:\bos|__import__\(\s*['"]os['"]\s*\))\.environ\.get\(\s*['"]HOME['"]\s*\)"""
                         r"""|(?:\bos|__import__\(\s*['"]os['"]\s*\))\.getenv\(\s*['"]HOME['"]\s*\)|\bprocess\.env\.HOME\b|\bprocess\.env\s*\[\s*['"]HOME['"]\s*\]"""
                         r"""|(?:\brequire\(\s*['"](?:node:)?os['"]\s*\)|\b\w+)\.homedir\(\s*\)|\bDir\.home\b(?:\(\s*\))?"""
                         r"""|\bENV\s*\[\s*['"]HOME['"]\s*\]|\$ENV\{\s*['"]?HOME['"]?\s*\}""")
#: Where each language keeps its command-line arguments, and the index of the first one.
_ARGV = {"python": (re.compile(r"\bsys\.argv\s*\[\s*(\d{1,2})\s*\]"), 1),
         "node": (re.compile(r"\bprocess\.argv\s*\[\s*(\d{1,2})\s*\]"), 1),
         "ruby": (re.compile(r"(?<![$\w])ARGV\s*\[\s*(\d{1,2})\s*\]"), 0),
         "perl": (re.compile(r"\$ARGV\s*\[\s*(\d{1,2})\s*\]"), 0)}
_LANGUAGE = {"python": "python", "python3": "python", "python2": "python", "py": "python", "node": "node", "nodejs": "node",
             "bun": "node", "deno": "node", "ruby": "ruby", "perl": "perl"}
#: Two literals joined: ``'a' + 'b'`` (Python, JS, Ruby), ``'a' . 'b'`` (Perl), ``'a' / 'b'`` (a path).
_JOINED = re.compile(r"""(['"`])((?:\\.|(?!\1)[^\\\n]){0,1024})\1\s*([+./])\s*(['"`])((?:\\.|(?!\4)[^\\\n]){0,1024})\4""")
#: A literal alone in brackets that are not a call: ``('Doc' + 'uments')`` once joined.
_BRACKETED = re.compile(r"""(?<![\w\])\]])\(\s*((['"`])(?:\\.|(?!\2)[^\\\n]){0,1024}\2)\s*\)""")
#: A template literal's home part: `` `${process.env.HOME}/x` ``.
_TEMPLATE_HOME = re.compile(r"\$\{\s*(" + _HOME_ASKED.pattern + r")\s*\}")
MAX_JOINS = 64


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
    """Backslash escapes as ``printf``, ``$'…'`` and code literals decode them (``\\x2f``, ``\\057``,
    ``\\u002f``, ``\\u{2f}``, ``\\/``, ``\\n``); "" when the result is not printable text."""
    def one(match: re.Match[str]) -> str:
        code = match.group(1)
        if code[0] in "xXuU":
            return chr(int(code[1:].strip("{}"), 16))
        if code[0].isdigit():
            return chr(int(code, 8) & 0xFF)
        return {"n": "\n", "t": "\t", "\\": "\\", "'": "'", '"': '"', "e": "", "a": "", "r": ""}.get(code, code)
    text = re.sub(r"\\(x[0-9A-Fa-f]{1,2}|u\{[0-9A-Fa-f]{1,6}\}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|[0-7]{1,3}|.)", one, data)
    return text if _printable(text) else ""


#: A decode of a literal in code, read as the text it produces: hex (``bytes.fromhex``, ``unhexlify``),
#: base64 / base32 (``b64decode``, ``atob``, ``Buffer.from(…, 'base64')``, ``Base64.decode64``,
#: ``decode_base64``) and ``codecs.decode(…, 'rot13' | 'hex' | 'base64')``, with a trailing
#: ``.decode()`` / ``.toString()`` taken in.
_DECODE_CALL = re.compile(
    r"""(?P<call>\b(?:bytes\.|bytearray\.)?fromhex|\bunhexlify|\ba2b_hex|\bb16decode|\bb32decode|\b(?:urlsafe_)?b64decode|\bdecodebytes|\batob"""
    r"""|\b(?:strict_|urlsafe_)?decode64|\bdecode_base64|\bBuffer\.from|\bcodecs\.(?:de|en)code)"""
    r"""\s*\(\s*b?(?P<quote>['"`])(?P<data>(?:\\.|(?!(?P=quote)).){1,""" + str(MAX_DECODED_CHARS * 2) + r"""}?)(?P=quote)"""
    r"""(?P<rest>\s*,[^()]{0,40})?\)(?:\s*\.\s*(?:decode|toString)\(\s*(?:['"][\w-]{0,16}['"])?\s*\))?""")
#: Spellings of the path separator that are not a ``/`` written out.
_SEPARATOR = re.compile(r"""\bos\.path\.sep\b|\bos\.sep\b|(?:\brequire\(\s*['"](?:node:)?path['"]\s*\)|\b\w+)\.sep\b(?!\s*\()"""
                        r"""|\bFile::SEPARATOR\b|\bchr\(\s*(?:47|0x2[fF])\s*\)|\bString\.fromCharCode\(\s*(?:47|0x2[fF])\s*\)|\b47\.chr\b""")
#: A list of literals joined with ``/``: Python's ``"/".join([...])``, JS's ``[...].join("/")``.
_LIST_JOIN = re.compile(r"""(?P<q1>['"`])/(?P=q1)\s*\.join\(\s*[\[(](?P<python>[^\[\]()]{1,1024})[\])]\s*\)"""
                        r"""|\[(?P<js>[^\[\]]{1,1024})\]\s*\.join\(\s*(?P<q2>['"`])/(?P=q2)\s*\)""")
_WHOLE_LITERAL = re.compile(r"""\s*(['"`])((?:\\.|(?!\1)[^\\\n]){0,1024})\1\s*""")


def _decode_call(found: re.Match[str]) -> str:
    """The literal a decode call of a literal produces, quoted; the call itself when it does not decode."""
    call, data, rest = found.group("call"), _unescape(found.group("data")) or found.group("data"), (found.group("rest") or "").lower()
    if call.startswith("codecs."):
        how = "rot13" if "rot" in rest else "hex" if "hex" in rest else "base64" if "base64" in rest else ""
    elif call == "Buffer.from":
        how = "base64" if "base64" in rest else "hex" if "hex" in rest else ""
    else:
        call = call.rsplit(".", 1)[-1]
        how = "hex" if call in ("fromhex", "unhexlify", "a2b_hex", "b16decode") else "base32" if call == "b32decode" else "base64"
    if not how:
        return found.group(0)
    value = data.translate(_ROT13) if how == "rot13" else _decode_bytes(data, how)
    return _quoted(value) if value else found.group(0)


_ROT13 = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm")


def _decoded(code: str) -> str:
    """*code* with each path spelling that is fixed by its own text written out plainly (the private
    security finding of round 7, 2026-11-23): escapes inside every string literal decoded
    (``'\\/Documents'``, ``'\\x2fSecret'``, ``'\\u002f'``, ``'\\057'``), a decode call of a literal
    replaced by the literal it produces, and every spelling of the separator (``os.sep``,
    ``path.sep``, ``chr(47)``, ``String.fromCharCode(47)``) written as ``"/"``."""
    def literal(found: re.Match[str]) -> str:
        body = found.group(2)
        if "\\" not in body:
            return found.group(0)
        value = _unescape(body)
        return _quoted(value) if value else found.group(0)
    text = _DECODE_CALL.sub(_decode_call, code)
    text = _LITERAL.sub(literal, text)
    return _SEPARATOR.sub(lambda _found: _quoted("/"), text)


def _list_joined(text: str) -> str:
    """*text* with each list of literals joined by ``/`` written as the one path it makes."""
    def join(found: re.Match[str]) -> str:
        items = (found.group("python") or found.group("js")).split(",")
        parts = [_WHOLE_LITERAL.fullmatch(item) for item in items if item.strip()]
        if not parts or not all(parts):
            return found.group(0)
        values = [part.group(2) for part in parts]
        return _quoted("/".join([values[0].rstrip("/")] + [value.strip("/") for value in values[1:]]))
    return _LIST_JOIN.sub(join, text)


def _quoted(text: str) -> str:
    return json.dumps(text, ensure_ascii=False)


def _resolved(interpreter: str, code: str, argv: tuple[str, ...] = ()) -> str:
    """*code* with what it builds statically written out (see the module doc): its arguments and
    the home folder as literals, then joined literals as one."""
    # Escapes, decodes of literals and separator spellings first: the joins below then see plain text.
    # The home folder as ``~``: every path check expands it, and the reading stays the same on any machine.
    text = _TEMPLATE_HOME.sub("~", _decoded(code))
    text = _HOME_ASKED.sub(lambda _found: _quoted("~"), text)
    language = _LANGUAGE.get(interpreter)
    if language in _ARGV and argv:
        pattern, first = _ARGV[language]
        def argument(found: re.Match[str]) -> str:
            at = int(found.group(1)) - first
            return _quoted(argv[at]) if 0 <= at < len(argv) else found.group(0)
        text = pattern.sub(argument, text)
    text = _list_joined(text)
    for _ in range(MAX_JOINS):
        def join(found: re.Match[str]) -> str:
            left, operator, right = found.group(2), found.group(3), found.group(5)
            return _quoted(left.rstrip("/") + "/" + right.lstrip("/") if operator == "/" else left + right)
        joined = _BRACKETED.sub(lambda found: found.group(1), _JOINED.sub(join, text, count=1), count=1)
        if joined == text:
            break
        text = joined
    return text


#: A call that joins its arguments into one path: ``joinpath(…)``, ``os.path.join(…)``,
#: ``path.join(…)`` / ``path.resolve(…)``, ``File.join(…)``, ``Path(…)``.
_JOIN_CALL = re.compile(r"""(?:\bjoinpath|\bos\.path\.join|\bpath\.join|\bpath\.resolve|\bFile\.join|\bPath)\s*\(([^()]{1,1024})\)""")
#: The ``/`` operator on paths: ``home / "Documents" / "Secret"``.
_SLASH_CHAIN = re.compile(r"""(?:\)|\w)\s*/\s*['"][^'"\n]{1,256}['"](?:\s*/\s*['"][^'"\n]{1,256}['"])*""")
_JOIN_PART = re.compile(r"""['"`]([^'"`\n]{1,256})['"`]""")


def _joined_paths(code: str) -> list[str]:
    """Paths *code* builds by joining literals (``Path.home().joinpath("Documents", "Secret", "x")``
    → ``Documents/Secret/x``). WHY: a real agent wrote exactly that into a script and ran it
    (2026-11-22); no single literal held a slash."""
    out = []
    for match in list(_JOIN_CALL.finditer(code)) + list(_SLASH_CHAIN.finditer(code)):
        raw = _JOIN_PART.findall(match.group(1) if match.re is _JOIN_CALL else match.group(0))
        parts = [part.strip("/") for part in raw if part.strip("/")]
        if len(parts) >= 2 and not any("://" in part for part in parts):
            out.append(("/" if raw[0].startswith("/") else "") + "/".join(parts))
    return out


def _paths_in_code(interpreter: str, code: str, argv: tuple[str, ...] = ()) -> list[ShellFileArg]:
    """Every quoted path in *code*, and every path it joins from literals — read as written AND
    as :func:`_resolved` writes it out with the command line's *argv*: whole folders when the code
    walks or packs folders; a relative one is also taken under the home folder when the code joins
    onto it."""
    recursive = bool(_WHOLE_FOLDER_CODE.search(code))
    joins_home = bool(_HOME_CODE.search(code))
    found: list[ShellFileArg] = []
    resolved = _resolved(interpreter, code, argv)
    literals = list(dict.fromkeys([match.group(2) for match in _LITERAL.finditer(code)] + _joined_paths(code)
                                  + ([match.group(2) for match in _LITERAL.finditer(resolved)] + _joined_paths(resolved)
                                     if resolved != code else [])))
    for literal in literals:
        if "://" in literal or not ("/" in literal or "\\" in literal or literal.startswith("~")):
            continue
        found.append(ShellFileArg(path=literal, command=interpreter, recursive=recursive))
        if joins_home and not literal.startswith(("/", "~", "$", "%")) and not re.match(r"[A-Za-z]:", literal):
            relative = literal.removeprefix("./")   # keep ".config"'s own dot
            found.append(ShellFileArg(path="~/" + relative, command=interpreter, recursive=recursive))
    return list({(arg.path, arg.recursive): arg for arg in found}.values())   # one per path
