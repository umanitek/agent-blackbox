"""Paths inside script code a command hands to an interpreter — part of the shell file view.

Split out of :mod:`.shell_files` (2026-11-20, a move only): a one-line script
(``python3 -c "open('…').read()"``, ``node -e``, ``ruby -e``, ``perl -e``, ``php -r``) or a script
fed on a heredoc (``python3 - <<EOF``) reads the quoted paths in its code. A path the code builds
piece by piece is not seen, except the common ``home + '.config/…'`` join.

``_script_args`` reads an interpreter's command-line code, ``_paths_in_code`` any piece of code,
``_HEREDOC`` finds heredoc bodies, ``_INTERPRETERS`` names the interpreters and their code option.

Pure and deterministic; reads no files.
"""

from __future__ import annotations

import re

from .shell_words import ShellFileArg, _segment_end

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
    """The paths in the code an interpreter is handed on its command line."""
    end = _segment_end(words, index + 1)
    options = _INTERPRETERS[name]
    found: list[ShellFileArg] = []
    for position in range(index + 1, end - 1):
        if words[position] in options:
            found.extend(_paths_in_code(name, words[position + 1]))
    return found, end


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


def _paths_in_code(interpreter: str, code: str) -> list[ShellFileArg]:
    """Every quoted path in *code*, and every path it joins from literals: whole folders when the
    code walks or packs folders; a relative one is also taken under the home folder when the code
    joins onto it."""
    recursive = bool(_WHOLE_FOLDER_CODE.search(code))
    joins_home = bool(_HOME_CODE.search(code))
    found: list[ShellFileArg] = []
    literals = [match.group(2) for match in _LITERAL.finditer(code)] + _joined_paths(code)
    for literal in literals:
        if "://" in literal or not ("/" in literal or "\\" in literal or literal.startswith("~")):
            continue
        found.append(ShellFileArg(path=literal, command=interpreter, recursive=recursive))
        if joins_home and not literal.startswith(("/", "~", "$", "%")) and not re.match(r"[A-Za-z]:", literal):
            relative = literal.removeprefix("./")   # keep ".config"'s own dot
            found.append(ShellFileArg(path="~/" + relative, command=interpreter, recursive=recursive))
    return found
