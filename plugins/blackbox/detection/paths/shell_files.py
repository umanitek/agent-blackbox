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

The home folder is written ONE way in what comes back: ``$HOME/x``, ``${HOME}/x`` and
``%USERPROFILE%\\x`` become ``~/x`` (:func:`_home_as_tilde`), because every rule that reads these
paths expands ``~`` and none expanded ``$HOME`` — a blocked ``cat ~/.ssh/key`` was simply retried as
``cat $HOME/.ssh/key`` by a real agent and went through (2026-11-20).

More ways a command reads a file without handing its name to ``cat`` (each found by asking
"how would an agent that was just refused try again?", 2026-11-20):

* input redirection — ``cat < FILE``, ``pbcopy < FILE``: whatever follows ``<`` is read;
* a name piped to ``xargs`` — ``echo FILE | xargs cat``;
* a variable set earlier on the line — ``H=$HOME; cat $H/.ssh/key`` (:func:`_with_variables`);
* ``dd if=FILE``, a ``file://`` address, and an upload — ``curl -d @FILE``, ``-F name=@FILE``, ``-T FILE``;
* after a ``cd`` into a known folder, a read command's bare operand — ``cd ~/.ssh; cat id_rsa``.

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

import base64
import binascii
import functools
import itertools
import re
from dataclasses import replace

# The words of a command (shell_words) and the paths in script code (shell_scripts) live in their
# own files since 2026-11-20; their names stay reachable here for the callers that already use them.
from .shell_scripts import _HEREDOC, _INTERPRETERS, _paths_in_code, _script_args
from .shell_words import (ShellFileArg, _SEPARATORS, _home_as_tilde, _is_anchored, _looks_like_path,
                          _segment_end, _split, _with_variables, _words)

__all__ = ["_HEREDOC", "_INTERPRETERS", "_SEPARATORS", "ShellFileArg", "_split", "_words", "code_file_args", "shell_file_args", "with_base64_decoded"]

#: Commands that read a file's contents.
_READ_COMMANDS = frozenset({
    "cat", "less", "more", "head", "tail", "bat", "xxd", "hexdump", "strings", "od", "nl",
    "base64", "base32", "sqlite3", "jq",
    "awk", "gawk", "sed", "sort", "uniq", "wc", "cut", "paste", "rev", "tac", "column", "fold", "iconv",
    "diff", "cmp", "md5", "md5sum", "shasum", "sha1sum", "sha256sum", "file",
    "zcat", "gzcat", "bzcat", "xzcat", "zless",
    "vim", "vi", "view", "nano", "emacs", "open", "xdg-open", "code", "pbcopy",
    "type", "get-content", "gc",                       # Windows cmd / PowerShell
})
#: Commands that send a file somewhere: ``-d @FILE``, ``-F name=@FILE``, ``-T FILE``, ``file://``.
_UPLOAD_COMMANDS = frozenset({"curl", "wget", "http", "https"})
#: Options whose next word is a file to send as it is.
_UPLOAD_FILE_OPTIONS = frozenset({"-T", "--upload-file", "--post-file", "--body-file"})
#: Commands whose words name things rather than read them; what they print may be piped to ``xargs``.
_NAMING_COMMANDS = frozenset({"echo", "printf"})
#: Commands that copy, move or pack whole folders: an argument that is a
#: folder hands over everything inside it.
_RECURSIVE_COMMANDS = frozenset({
    "cp", "scp", "rsync", "tar", "zip", "7z", "7za", "rar", "ditto", "mv", "gzip", "rg",
    "ln", "link",   # a link reaches what it points at: ``ln -s KEY /tmp/y && cat /tmp/y`` (KI-472)
    "copy", "xcopy", "robocopy", "copy-item", "cpi", "compress-archive", "move-item",   # Windows
})
#: Commands that read whole folders only with a recursive flag.
_RECURSIVE_WITH_FLAG = {"grep": ("-r", "-R", "--recursive"), "egrep": ("-r", "-R"), "fgrep": ("-r", "-R")}
#: Copy and move commands whose LAST path argument is where things go, not what is read
#: (unless ``-t``/``--target-directory`` names the destination up front).
_COPY_COMMANDS = frozenset({"cp", "scp", "rsync", "mv", "ditto", "copy", "xcopy", "robocopy", "copy-item", "cpi", "move-item",
                            "ln", "link"})
#: Archivers whose FIRST path argument is the archive being written (tar names it after ``f``).
_ARCHIVE_FIRST = frozenset({"zip", "7z", "7za", "rar"})
#: Commands that read what ``find`` hands them (``-exec cat {}``, ``| xargs tar …``).
_FIND_EXEC = ("-exec", "-execdir", "-ok", "-okdir")


def shell_file_args(command: str) -> list[ShellFileArg]:
    """Every path argument of a read, copy or archive command in *command*.

    Flags (``-r``, ``-czf``) are skipped; an argument after a separator
    (``;``, ``&&``, ``|``, a redirect) belongs to the next command. Duplicates
    are removed, first occurrence kept. Where a copy or archive writes is marked
    ``destination`` (:func:`_destinations`). Several checks ask about the same command of one
    call, so the last few answers are remembered (the arguments are frozen values).
    """
    return list(_file_args(command)) if command else []


@functools.lru_cache(maxsize=4)
def _file_args(command: str) -> tuple[ShellFileArg, ...]:
    words = _with_variables(_words(command))
    out: list[ShellFileArg] = []
    seen: set = set()

    folder = ""   # where an earlier ``cd`` in this command line moved to ("" = unknown)
    named: list[str] = []   # the words of the last ``echo`` / ``printf``, in case they are piped to ``xargs``

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
        elif name == "<":
            found, index = _redirected_in(words, index)
        elif name in _NAMING_COMMANDS:
            end = _segment_end(words, index + 1)
            named, found, index = words[index + 1:end], [], end
        elif name == "xargs":
            found, index = _xargs_args(words, index, named)
        else:
            found, index = _command_args(name, words, index, in_known_folder=bool(folder))
        keep(found)
    for match in _HEREDOC.finditer(command):
        keep(_paths_in_code(match.group("interpreter"), match.group("body")))
    return tuple(out)


def _redirected_in(words: list[str], index: int) -> tuple[list[ShellFileArg], int]:
    """``< FILE``: the file a command is fed, whatever the command is."""
    if index + 1 >= len(words) or words[index + 1] in _SEPARATORS:
        return [], index + 1
    return [ShellFileArg(path=words[index + 1], command="<", recursive=False)], index + 2


def _xargs_args(words: list[str], index: int, named: list[str]) -> tuple[list[ShellFileArg], int]:
    """``echo FILE … | xargs READER``: the names the echo printed are what the reader reads."""
    end = _segment_end(words, index + 1)
    command = next((word for word in words[index + 1:end] if not word.startswith("-") and word != "{}"), "")
    reader = command.rsplit("/", 1)[-1].lower()
    if not _reads_files(reader):
        return [], end
    recursive = reader in _RECURSIVE_COMMANDS
    return [ShellFileArg(path=word, command=reader, recursive=recursive) for word in named if _looks_like_path(word)], end


def _upload_args(name: str, arguments: list[str]) -> list[ShellFileArg]:
    """The files an upload command sends: ``file://PATH``, ``@PATH`` (``-d @f``, ``-F a=@f``)
    and the word after ``-T`` / ``--upload-file`` / ``--post-file``."""
    paths: list[str] = []
    for position, word in enumerate(arguments):
        if word.startswith("file://"):
            paths.append(word[len("file://"):])
        elif "@" in word and not word.startswith("-") and (word.startswith("@") or "=@" in word):
            paths.append(word.split("@", 1)[1])
        elif word in _UPLOAD_FILE_OPTIONS and position + 1 < len(arguments):
            paths.append(arguments[position + 1])
    return [ShellFileArg(path=path, command=name, recursive=False) for path in paths if path]


def _command_args(name: str, words: list[str], index: int, *, in_known_folder: bool = False) -> tuple[list[ShellFileArg], int]:
    """The path arguments of one read, copy or archive command at *index*, and where
    the next command starts. A word that is not such a command yields nothing.
    *in_known_folder*: an earlier ``cd`` named the folder, so a read command's bare operand
    (``cd ~/.ssh; cat id_rsa``) is a file there."""
    if name in _UPLOAD_COMMANDS:
        end = _segment_end(words, index + 1)
        return _upload_args(name, words[index + 1:end]), end
    if name == "dd":
        end = _segment_end(words, index + 1)
        return [ShellFileArg(path=word[3:], command="dd", recursive=False)
                for word in words[index + 1:end] if word.startswith("if=") and len(word) > 3], end
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
    patterns = _name_patterns(name, arguments)
    paths = [word for position, word in enumerate(arguments) if not word.startswith("-")
             and not (old_style_tar_flags and position == 0) and position not in patterns
             and (_looks_like_path(word) or ((name in _RECURSIVE_COMMANDS or in_known_folder) and word != "{}"))]
    written = _destinations(name, arguments, paths)
    if name == "tar":
        paths = _tar_operands(arguments, paths, written)
    return [ShellFileArg(path=word, command=name, recursive=recursive, destination=word in written)
            for word in paths], end


def _name_patterns(name: str, arguments: list[str]) -> set[int]:
    """The positions of zip's ``-x`` / ``-i`` wildcard patterns (up to the next option): patterns to
    leave out or keep, not files it reads. WHY (KI-591): ``zip -r b.zip ~/Documents -x '*/Secret/*'``
    took ``*/Secret/*`` for a file read and matched it to Blackbox's keys; the folder itself is
    still read whole, whatever is left out (``guard_secrets``)."""
    if name != "zip":
        return set()
    positions, listing = set(), False
    for position, word in enumerate(arguments):
        if word.startswith("-"):
            listing = word in ("-x", "-i", "--exclude", "--include")
        elif listing and any(char in word for char in "*?["):
            positions.add(position)   # a plain path there is still taken as read: zip may read it
    return positions


def _tar_operands(arguments: list[str], paths: list[str], written: set) -> list[str]:
    """tar's file operands as files on disk: ``-C DIR`` / ``--directory=DIR`` changes the folder
    the operands are read in — it is not itself read — and an extraction or listing reads only its
    archive (its other operands name MEMBERS inside it, not files here).

    WHY: ``tar -C ~ -xf a.tar notes/todo.md`` was taken for a read of the whole home folder — and
    so of Blackbox's keys — while ``tar -C ~ -czf out.tgz .hermes`` must still be read as
    ``~/.hermes`` (2026-11-21)."""
    folder, skip_values = "", set()
    for flag, value in itertools.pairwise(arguments):
        if flag in ("-C", "--directory"):
            folder = value
            skip_values.add(value)
    folder = next((word.split("=", 1)[1] for word in arguments if word.startswith("--directory=")), folder)
    operands = [path for path in paths if path not in skip_values]
    clusters = [word.lstrip("-") for position, word in enumerate(arguments)
                if (word.startswith("-") and not word.startswith("--")) or (position == 0 and word.isalpha())]
    if any(set(cluster) & {"x", "t"} for cluster in clusters) or {"--extract", "--list", "--get"} & set(arguments):
        archive = next((value for flag, value in itertools.pairwise(arguments)
                        if not flag.startswith("--") and "f" in flag.lstrip("-") and flag.lstrip("-").isalpha()), "")
        return [archive] if archive in operands else []
    if not folder:
        return operands
    return [path if path in written or _is_anchored(path) else folder.rstrip("/") + "/" + path for path in operands]


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


def code_file_args(code: str, language: str = "python") -> list[ShellFileArg]:
    """The paths a piece of *code* reads, for tools that run code directly rather than through a
    shell (Hermes's ``execute_code`` runs Python): the same reading as ``python3 -c CODE`` (KI-470).

        code_file_args("print(open('/home/me/.ssh/id_rsa').read())")   # -> [ShellFileArg(path='/home/me/.ssh/id_rsa', ...)]
    """
    return [_from_folder(arg, "") for arg in _paths_in_code(language, code or "")]


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


def _from_folder(arg: ShellFileArg, folder: str) -> ShellFileArg:
    """*arg* with a relative path placed under the folder an earlier ``cd`` moved to, and the
    home folder written as ``~`` (:func:`_home_as_tilde`)."""
    path = arg.path
    if folder and not _is_anchored(path):
        relative = path.removeprefix("./")
        path = folder if relative in (".", "") else folder.rstrip("/") + "/" + relative
    path = _home_as_tilde(path)
    return arg if path == arg.path else replace(arg, path=path)


_BASE64_WORD = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


def with_base64_decoded(text: str) -> str:
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
