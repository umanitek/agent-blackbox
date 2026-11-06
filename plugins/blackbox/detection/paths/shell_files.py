"""Which files a shell command reads, copies or packs up — the shell channel's file view.

A file tool names its path in an argument; a shell command hides it among
words. An agent (or a poisoned skill steering it) reaches a secret file through
the terminal far more often than through a file tool: ``cat``, ``cp -r``,
``tar czf``, ``zip -r``, ``rsync``, ``ditto``, ``base64``. This module turns a
command line into the paths those commands touch, so a path rule (protected
paths, wallet key stores) sees the shell channel as well as the file tools.

Two more ways a command reads files without naming them to ``cat``:

* ``find ROOT … -exec cat {} +`` (or ``| xargs cat``): every file under ROOT is
  read, so ROOT counts as a folder handed over whole (:func:`_find_args`).
* a link: ``ln -s SRC DEST`` reaches SRC through DEST, so SRC counts like a copy's source.
* a one-line script — ``python3 -c "open('…').read()"``, ``node -e``, ``ruby -e``,
  ``perl -e``, ``php -r``, or a script fed on a heredoc (``python3 - <<EOF``): the
  quoted paths in its code are read (:func:`_script_args`). A path the code builds
  piece by piece is not seen, except the common ``home + '.config/…'`` join.

A ``cd`` earlier in the same command line is followed (``cd ~ && zip -r x .config/Exodus``
reads ``~/.config/Exodus``); the agent's starting folder is not known, so a relative path
with no ``cd`` before it stays relative.

Words are split the way a POSIX shell splits them (quotes and backslash
escapes respected), so ``~/Library/Application\\ Support/...`` stays ONE path.
A command line the shell parser cannot split (an unbalanced quote) falls back
to plain whitespace splitting, so a malformed command still yields its paths.

Usage::

    for arg in shell_file_args("tar czf out.tgz ~/Library/Application\\\\ Support/Google/Chrome"):
        arg.path        # "out.tgz", then "~/Library/Application Support/Google/Chrome"
        arg.recursive   # True for both: tar packs whole folders

Pure and deterministic; reads no files.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import List, Tuple
import itertools

#: Commands that read a file's contents.
_READ_COMMANDS = frozenset({
    "cat", "less", "more", "head", "tail", "bat", "xxd", "hexdump", "strings", "od", "nl",
    "base64", "base32", "sqlite3", "jq",
    "type", "get-content", "gc",                       # Windows cmd / PowerShell
})
#: Commands that copy, move or pack whole folders: an argument that is a
#: folder hands over everything inside it.
_RECURSIVE_COMMANDS = frozenset({
    "cp", "scp", "rsync", "tar", "zip", "7z", "7za", "rar", "ditto", "mv", "gzip", "rg",
    "ln", "link",   # a link reaches what it points at: ``ln -s KEY /tmp/y && cat /tmp/y`` (KI-472)
    "copy", "xcopy", "robocopy", "copy-item", "cpi", "compress-archive", "move-item",   # Windows
})
#: Commands that read whole folders only with a recursive flag.
_RECURSIVE_WITH_FLAG = {"grep": ("-r", "-R", "--recursive"), "egrep": ("-r", "-R"), "fgrep": ("-r", "-R")}
_SEPARATORS = frozenset({";", "&&", "||", "|", "&", ">", ">>", "<", "|&"})
#: Copy and move commands whose LAST path argument is where things go, not what is read
#: (unless ``-t``/``--target-directory`` names the destination up front).
_COPY_COMMANDS = frozenset({"cp", "scp", "rsync", "mv", "ditto", "copy", "xcopy", "robocopy", "copy-item", "cpi", "move-item",
                            "ln", "link"})
#: Archivers whose FIRST path argument is the archive being written (tar names it after ``f``).
_ARCHIVE_FIRST = frozenset({"zip", "7z", "7za", "rar"})
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
#: Commands that read what ``find`` hands them (``-exec cat {}``, ``| xargs tar …``).
_FIND_EXEC = ("-exec", "-execdir", "-ok", "-okdir")


@dataclass(frozen=True)
class ShellFileArg:
    """One path a shell command touches. ``path`` is the word as written (``~``
    and ``$HOME`` NOT expanded — matching code expands); ``recursive`` is True
    when the command takes a folder argument as everything inside it."""

    path: str
    command: str
    recursive: bool
    #: True for where a copy or archive WRITES (``cp src DEST``, ``tar czf OUT.tgz``) —
    #: nothing is read from it. Rules about what leaves a file skip these.
    destination: bool = False


#: A Windows path (``C:\\Users``, ``%APPDATA%\\``): backslash is a separator there,
#: not an escape, so such a line is split without POSIX escaping.
_WINDOWS_PATH = re.compile(r"[A-Za-z]:\\|%[A-Za-z_]+%\\")


def _words(command: str) -> list[str]:
    try:
        if _WINDOWS_PATH.search(command):
            lexer = shlex.shlex(command, posix=False, punctuation_chars=";&|<>")
            lexer.whitespace_split = True
            return [word.strip("\"'") for word in lexer]
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>")
        lexer.whitespace_split = True
        return list(lexer)
    except ValueError:  # an unbalanced quote: still find the paths
        return command.split()


def _looks_like_path(word: str) -> bool:
    return "/" in word or "\\" in word or word.startswith(("~", ".", "$HOME", "%")) or "." in word


def shell_file_args(command: str) -> list[ShellFileArg]:
    """Every path argument of a read, copy or archive command in *command*.

    Flags (``-r``, ``-czf``) are skipped; an argument after a separator
    (``;``, ``&&``, ``|``, a redirect) belongs to the next command. Duplicates
    are removed, first occurrence kept. Where a copy or archive writes is marked
    ``destination`` (:func:`_destinations`).
    """
    if not command:
        return []
    words = _words(command)
    out: list[ShellFileArg] = []
    seen: set = set()

    folder = ""   # where an earlier ``cd`` in this command line moved to ("" = unknown)

    def keep(found: list[ShellFileArg]) -> None:
        for arg in found:
            arg = _from_folder(arg, folder)
            if arg.path not in seen:
                seen.add(arg.path)
                out.append(arg)

    index = 0
    while index < len(words):
        name = words[index].rsplit("/", 1)[-1].lower()
        if name in ("cd", "pushd"):
            folder, index = _cd(words, index, folder)
            continue
        if name == "find":
            found, index = _find_args(words, index)
        elif name in _INTERPRETERS:
            found, index = _script_args(name, words, index)
        else:
            found, index = _command_args(name, words, index)
        keep(found)
    for match in _HEREDOC.finditer(command):
        keep(_paths_in_code(match.group("interpreter"), match.group("body")))
    return out


def _segment_end(words: list[str], start: int) -> int:
    """Index of the first separator at or after *start* (or the end)."""
    end = start
    while end < len(words) and words[end] not in _SEPARATORS:
        end += 1
    return end


def _command_args(name: str, words: list[str], index: int) -> tuple[list[ShellFileArg], int]:
    """The path arguments of one read, copy or archive command at *index*, and where
    the next command starts. A word that is not such a command yields nothing."""
    reads = name in _READ_COMMANDS
    recursive = name in _RECURSIVE_COMMANDS
    flags = _RECURSIVE_WITH_FLAG.get(name)
    if not (reads or recursive or flags):
        return [], index + 1
    end = _segment_end(words, index + 1)
    arguments = words[index + 1:end]
    if flags:
        recursive = any(word in flags or (word.startswith("-") and not word.startswith("--")
                                          and ("r" in word or "R" in word)) for word in arguments)
    # A copy or archive command's operands are all paths, bare folder names included
    # (``cd ~/.config && tar czf x.tgz Exodus``); a read command's need to look like one.
    old_style_tar_flags = name == "tar" and bool(arguments) and arguments[0].isalpha()   # ``tar czf …``
    paths = [word for position, word in enumerate(arguments) if not word.startswith("-")
             and not (old_style_tar_flags and position == 0)
             and (_looks_like_path(word) or (name in _RECURSIVE_COMMANDS and word != "{}"))]
    written = _destinations(name, arguments, paths)
    return [ShellFileArg(path=word, command=name, recursive=recursive, destination=word in written)
            for word in paths], end


def _destinations(name: str, arguments: list[str], paths: list[str]) -> set:
    """The path arguments *name* writes to rather than reads: a copy's last path
    (``-t DIR`` names it up front instead), tar's word after an ``f`` flag when it
    creates (``c``/``r``/``u``; extracting or listing reads it), zip's
    and 7z's first path, Compress-Archive's ``-DestinationPath``."""
    if name in _COPY_COMMANDS:
        for flag, value in itertools.pairwise(arguments):
            if flag in ("-t", "--target-directory"):
                return {value}
        targets = [word for word in arguments if word.startswith("--target-directory=")]
        if targets:
            return {targets[0].split("=", 1)[1]}
        return {paths[-1]} if len(paths) >= 2 else set()
    if name == "tar":
        # Short flags, plus tar's old-style first word without a dash (``tar xzf in.tgz``).
        clusters = [word.lstrip("-") for position, word in enumerate(arguments)
                    if (word.startswith("-") and not word.startswith("--")) or (position == 0 and word.isalpha())]
        if any(set(cluster) & {"x", "t"} for cluster in clusters) or {"--extract", "--list", "--get"} & set(arguments):
            return set()   # extracting or listing: the archive is READ
        for flag, value in itertools.pairwise(arguments):
            if not flag.startswith("--") and "f" in flag.lstrip("-") and flag.lstrip("-").isalpha():
                return {value}
        return set()
    if name in _ARCHIVE_FIRST:
        if "-" in arguments[:arguments.index(paths[0])] if paths else False:
            return set()   # ``zip -r - SRC``: the archive goes to stdout, every path is read
        return {paths[0]} if paths else set()
    if name == "compress-archive":
        lowered = [word.lower() for word in arguments]
        if "-destinationpath" in lowered:
            position = lowered.index("-destinationpath")
            return {arguments[position + 1]} if position + 1 < len(arguments) else set()
    return set()


def _reads_files(name: str) -> bool:
    return name in _READ_COMMANDS or name in _RECURSIVE_COMMANDS or name in _RECURSIVE_WITH_FLAG


def _find_args(words: list[str], index: int) -> tuple[list[ShellFileArg], int]:
    """``find``'s starting folders, as folders handed over whole — but only when what it
    finds is read: an ``-exec``/``-ok`` running a read, copy or archive command, or a
    pipe into ``xargs`` running one. A ``find`` that only lists names reads nothing."""
    position = index + 1
    roots: list[str] = []
    while position < len(words) and not words[position].startswith(("-", "(", "!")) and words[position] not in _SEPARATORS:
        roots.append(words[position])
        position += 1
    feeds_a_reader = False
    while position < len(words) and words[position] not in _SEPARATORS - {";"}:
        if words[position] in _FIND_EXEC and position + 1 < len(words):
            feeds_a_reader = feeds_a_reader or _reads_files(words[position + 1].rsplit("/", 1)[-1].lower())
            while position < len(words) and words[position] not in (";", "+"):
                position += 1
        elif words[position] == ";":
            break
        position += 1
    if position < len(words) and words[position] == "|":
        xargs = position + 1
        if xargs < len(words) and words[xargs].rsplit("/", 1)[-1] == "xargs":
            command = next((word for word in words[xargs + 1:_segment_end(words, xargs + 1)]
                            if not word.startswith("-") and word != "{}"), "")
            feeds_a_reader = feeds_a_reader or _reads_files(command.rsplit("/", 1)[-1].lower())
    if not feeds_a_reader:
        return [], position
    return [ShellFileArg(path=root, command="find", recursive=True) for root in roots], position


def _script_args(name: str, words: list[str], index: int) -> tuple[list[ShellFileArg], int]:
    """The paths in the code an interpreter is handed on its command line."""
    end = _segment_end(words, index + 1)
    options = _INTERPRETERS[name]
    found: list[ShellFileArg] = []
    for position in range(index + 1, end - 1):
        if words[position] in options:
            found.extend(_paths_in_code(name, words[position + 1]))
    return found, end


def code_file_args(code: str, language: str = "python") -> list[ShellFileArg]:
    """The paths a piece of *code* reads, for tools that run code directly rather than through a
    shell (Hermes's ``execute_code`` runs Python): the same reading as ``python3 -c CODE`` (KI-470).

        code_file_args("print(open('/home/me/.ssh/id_rsa').read())")   # -> [ShellFileArg(path='/home/me/.ssh/id_rsa', ...)]
    """
    return _paths_in_code(language, code or "")


def _paths_in_code(interpreter: str, code: str) -> list[ShellFileArg]:
    """Every quoted path in *code*: whole folders when the code walks or packs folders;
    a relative literal is also taken under the home folder when the code joins onto it."""
    recursive = bool(_WHOLE_FOLDER_CODE.search(code))
    joins_home = bool(_HOME_CODE.search(code))
    found: list[ShellFileArg] = []
    for match in _LITERAL.finditer(code):
        literal = match.group(2)
        if "://" in literal or not ("/" in literal or "\\" in literal or literal.startswith("~")):
            continue
        found.append(ShellFileArg(path=literal, command=interpreter, recursive=recursive))
        if joins_home and not literal.startswith(("/", "~", "$", "%")) and not re.match(r"[A-Za-z]:", literal):
            relative = literal.removeprefix("./")   # keep ".config"'s own dot
            found.append(ShellFileArg(path="~/" + relative, command=interpreter, recursive=recursive))
    return found


def _cd(words: list[str], index: int, folder: str) -> tuple[str, int]:
    """The folder a ``cd``/``pushd`` at *index* moves to: an absolute or home path as
    written, a relative one joined onto the folder already known; ``cd`` alone is home.
    Unknown (``""``) when it moves somewhere this cannot name (``cd -``, ``cd $DIR``)."""
    end = _segment_end(words, index + 1)
    targets = [word for word in words[index + 1:end] if not word.startswith("-") or word == "-"]
    target = targets[0] if targets else "~"
    if target == "-" or (target.startswith("$") and not target.startswith("$HOME")):
        return "", end
    if _is_anchored(target):
        return target.rstrip("/") or "/", end
    return (folder.rstrip("/") + "/" + target) if folder else "", end


def _is_anchored(path: str) -> bool:
    """True for a path that does not depend on the current folder."""
    return path.startswith(("/", "~", "$HOME", "%")) or bool(re.match(r"[A-Za-z]:[\\/]", path))


def _from_folder(arg: ShellFileArg, folder: str) -> ShellFileArg:
    """*arg* with a relative path placed under the folder an earlier ``cd`` moved to."""
    if not folder or _is_anchored(arg.path):
        return arg
    relative = arg.path.removeprefix("./")
    joined = folder if relative in (".", "") else folder.rstrip("/") + "/" + relative
    return ShellFileArg(path=joined, command=arg.command, recursive=arg.recursive, destination=arg.destination)
