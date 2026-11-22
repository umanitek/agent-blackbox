"""File Shield, Layer 1, for a script an agent WRITES and then RUNS: judged by what it says.

A hook sees ``python3 r.py`` — not what ``r.py`` opens. Real agents (Claude Code, Gemini CLI and
the Hermes agent with hosted models, 2026-11-22) wrote a script that builds a protected file's path
and ran it; the file was read. Two checks close what a hook CAN see:

* **at write time** — a file an agent writes through a file tool (``write_file``, ``patch``, an
  edit's new text) or through the shell (a heredoc, ``echo``/``printf … >``, ``echo … | tee``,
  each word read whole as the shell joins it: ``'Doc''uments'`` is ``Documents``) that is a
  script (by its ending or a ``#!`` line) is judged by its content as inline code
  (``detection``'s one protected-path answer, every route): naming a protected item refuses the
  write;
* **at run time** — ANY script file a command runs (``python3 r.py``, ``node x.js``, ``bash x.sh``,
  ``./x``, ``source x``) is read from disk (at most :data:`MAX_SCRIPT_BYTES`) and judged the same
  way, with the arguments the command hands it (``python3 r.py Doc Sec`` → ``sys.argv[1]`` is
  ``Doc``): the scripts agents wrote through a tool (:data:`MAX_REMEMBERED`, found by name) and
  any other file at that path — a relative path is taken in the folder the command moves to with ``cd``,
  else in the folder the agent runs in (``kernel.action_context``). A script too large to read
  whole is flagged, not judged.

**Limits, said plainly:** this reads text; it does not run code. ``detection`` writes out what
code builds statically (the home folder, its command-line arguments, joined literals); a path the
script computes at run time any other way (input, files, the network, other variables), a
compiled program, a script fetched while it runs — none of that is visible here. Only the OS
sandbox (Layer 2, :mod:`.sandbox`) stops those, which is why each agent's page says whether it is
sandboxed (kernel-enforced) or on hooks only (docs/file-shield.md lists the forms).

State: an in-memory, bounded record of the scripts agents wrote (path → when), per dashboard or
Hermes process; nothing is written to disk and no content is kept.

Usage::

    remember(path)                            # a script an agent wrote (File Shield's detect does this)
    script_writes(tool_name, args)            # [(path, content)] a call writes as scripts
    scripts_run(command)                      # the remembered scripts a command runs
"""

from __future__ import annotations

import os
import re
import shlex
import threading
import time
from collections import OrderedDict
from typing import Any, NamedTuple, Optional

from ...kernel import action_context
from ...kernel.bounded_files import read_small_text

#: The most scripts remembered (the oldest forgotten first).
MAX_REMEMBERED = 256
#: The largest script read at run time.
MAX_SCRIPT_BYTES = 256 * 1024
#: The most of one written content judged.
MAX_CONTENT_CHARS = 64 * 1024
#: File endings that make a written file a script.
SCRIPT_ENDINGS = (".py", ".pyw", ".js", ".mjs", ".cjs", ".ts", ".mts", ".rb", ".pl", ".pm", ".php", ".sh", ".bash", ".zsh",
                  ".fish", ".ksh", ".applescript", ".scpt", ".jxa", ".lua", ".tcl", ".r", ".swift", ".command", ".tool")
#: Programs that run the script named after their options.
_RUNNERS = frozenset({"python", "python3", "python2", "py", "pypy", "pypy3", "node", "nodejs", "bun", "deno", "tsx", "ts-node",
                      "ruby", "perl", "php", "sh", "bash", "zsh", "dash", "ksh", "fish", "osascript", "lua", "Rscript",
                      "swift", "source", "."})
_FILE_TOOLS = frozenset({"write_file", "write", "create_file", "patch", "edit", "edit_file", "str_replace", "multiedit",
                         "notebookedit", "apply_patch", "replace", "write_to_file", "replace_in_file"})
_PATH_KEYS = ("path", "file_path", "filePath", "filename", "target_file", "notebook_path")
_CONTENT_KEYS = ("content", "new_string", "newString", "new_str", "text", "patch", "diff", "code", "file_text")
#: A heredoc opener and where its text goes, on one line: ``cat > x.py <<'EOF'``, ``tee x.py <<EOF``.
_HEREDOC_OPEN = re.compile(r"<<-?\s*(['\"]?)(\w+)\1")
_HEREDOC_TARGET = re.compile(r"(?:>>?|\btee\s+(?:-a\s+)?)\s*([^\s<>|;&]+)")
#: Words that end one simple command in a shell line (as :func:`_shell_words` splits them).
_COMMAND_ENDS = frozenset({";", "&&", "||", "&", "|"})
#: The escapes ``printf`` and ``echo -e`` turn into characters.
_ESCAPES = {"\\n": "\n", "\\t": "\t", "\\\\": "\\"}

_written: OrderedDict[str, float] = OrderedDict()
_lock = threading.Lock()


def is_script(path: str, content: str = "") -> bool:
    """True when *path* is a script by its ending, or *content* starts with ``#!``."""
    return path.lower().endswith(SCRIPT_ENDINGS) or content.lstrip().startswith("#!")


def _expanded(path: str) -> str:
    return os.path.normpath(os.path.expanduser(path.replace("$HOME", "~").replace("${HOME}", "~")))


def _tool_write(tool_name: str, args: Any) -> list[tuple[str, str]]:
    if not isinstance(args, dict) or (tool_name or "").strip().lower() not in _FILE_TOOLS:
        return []
    path = next((str(args[key]) for key in _PATH_KEYS if isinstance(args.get(key), str) and args[key].strip()), "")
    content = next((str(args[key]) for key in _CONTENT_KEYS if isinstance(args.get(key), str)), "")
    edits = args.get("edits")
    if isinstance(edits, list):   # a multi-edit: every new text it writes
        content += "\n".join(str(edit.get("new_string") or "") for edit in edits[:50] if isinstance(edit, dict))
    return [(path, content[:MAX_CONTENT_CHARS])] if path and content else []


def _shell_words(command: str) -> list[str]:
    """*command* split as the shell splits it: quotes joined (``'Doc''uments'`` → ``Documents``),
    and ``>``, ``>>``, ``|``, ``;``, ``&&`` as words of their own; [] when it can not be split."""
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>")
    lexer.whitespace_split = True
    try:
        return list(lexer)
    except ValueError:
        return []


def _echoed(words: list[str]) -> str:
    """What ``echo``/``printf`` *words* print (``printf``'s format and ``echo -e`` escapes read)."""
    name, rest = words[0], words[1:]
    escapes = name == "printf"
    while name == "echo" and rest and re.fullmatch(r"-[neE]+", rest[0]):
        escapes = escapes or "e" in rest[0]
        rest = rest[1:]
    text = " ".join(rest)
    return re.sub(r"\\[nt\\]", lambda found: _ESCAPES[found.group(0)], text) if escapes else text


def _printed_into_files(command: str) -> list[tuple[str, str]]:
    """``(file, text)`` for each ``echo``/``printf`` whose output a command sends into a file:
    ``printf '…' > x.sh``, ``echo '…' >> x.py``, ``echo '…' | tee [-a] x.sh``."""
    words = _shell_words(command[:MAX_CONTENT_CHARS * 2])
    out, start = [], 0
    while start < len(words):
        end = next((at for at in range(start, len(words)) if words[at] in _COMMAND_ENDS), len(words))
        segment = words[start:end]
        if segment and segment[0] in ("echo", "printf"):
            redirect = next((at for at, word in enumerate(segment) if word in (">", ">>")), -1)
            if redirect > 0 and redirect + 1 < len(segment):
                out.append((segment[redirect + 1], _echoed(segment[:redirect])))
            elif end < len(words) and words[end] == "|":
                tee_end = next((at for at in range(end + 1, len(words)) if words[at] in _COMMAND_ENDS), len(words))
                tee = words[end + 1:tee_end]
                if tee and tee[0] == "tee":
                    out += [(target, _echoed(segment)) for target in tee[1:] if not target.startswith("-") and target not in (">", ">>")]
        start = end + 1
    return [(path, text[:MAX_CONTENT_CHARS]) for path, text in out]


def _shell_writes(command: str) -> list[tuple[str, str]]:
    out = []
    lines = command.split("\n")
    for index, line in enumerate(lines):
        opener, target = _HEREDOC_OPEN.search(line), _HEREDOC_TARGET.search(_HEREDOC_OPEN.sub(" ", line))
        if opener and target:
            tag = opener.group(2)
            body = []
            for following in lines[index + 1:]:
                if following.strip() == tag:
                    break
                body.append(following)
            out.append((target.group(1).strip("'\""), "\n".join(body)[:MAX_CONTENT_CHARS]))
    return out + _printed_into_files(command)


def script_writes(tool_name: str, args: Any, command: str = "") -> list[tuple[str, str]]:
    """``(path, content)`` for each SCRIPT this call writes: a file tool's path and new text, or a
    heredoc / ``echo`` into a file in its shell *command*."""
    found = _tool_write(tool_name, args) + (_shell_writes(command) if command else [])
    return [(path, content) for path, content in found if is_script(path, content)]


def remember(path: str) -> None:
    """Notes that an agent wrote the script at *path* (absolute; relative ones are matched by name)."""
    with _lock:
        _written.pop(path, None)
        _written[path] = time.time()
        while len(_written) > MAX_REMEMBERED:
            _written.popitem(last=False)


def forget_all() -> None:
    """Forgets every remembered script (tests)."""
    with _lock:
        _written.clear()


class ScriptRun(NamedTuple):
    """A script file a command runs: its *path* (absolute), its *text* (None when it is larger than
    :data:`MAX_SCRIPT_BYTES`: not judged, flagged), the *argv* the command hands it and the
    *runner* that runs it (``python3``, ``bash``…; "" when run as a program by its path)."""

    path: str
    text: Optional[str]
    argv: tuple[str, ...]
    runner: str


#: A runner's options that hand it a module or inline code instead of a script file.
_NOT_A_FILE = frozenset({"-m", "-c", "-e", "-p", "-r", "-E"})


def _run_targets(command: str) -> list[tuple[str, tuple[str, ...], str, str]]:
    """``(target, argv, runner, folder)`` for each script file *command* runs: the first plain
    word after a runner (``python3 -u r.py a b``) or a word run as a program by its path (``./x``,
    ``~/bin/x.sh``), the words after it up to the end of that command, and the folder the line moves to
    with ``cd`` before it ("" = none)."""
    words = _shell_words(command) or command.split()
    targets, folder, start = [], "", 0
    while start < len(words):
        end = next((at for at in range(start, len(words)) if words[at] in _COMMAND_ENDS), len(words))
        segment = [word for word in words[start:end] if not re.fullmatch(r"\d?[<>]{1,2}", word)]
        name = segment[0].rsplit("/", 1)[-1] if segment else ""
        if name in ("cd", "pushd") and len(segment) > 1:
            folder = _expanded(segment[1]) if os.path.isabs(_expanded(segment[1])) else os.path.join(folder, segment[1]) if folder else ""
        elif name in _RUNNERS:
            for at, each in enumerate(segment[1:8], start=1):
                if each in _NOT_A_FILE:
                    break   # a module or inline code: not a script file
                if not each.startswith("-"):
                    targets.append((each, tuple(segment[at + 1:at + 41]), name, folder))
                    break
        elif segment and segment[0].startswith(("./", "../", "~/", "/")):
            targets.append((segment[0], tuple(segment[1:41]), "", folder))
        start = end + 1
    return targets


def _remembered(target: str) -> Optional[str]:
    """The remembered script *target* names: by its full path, else the newest one with its name."""
    full = _expanded(target)
    with _lock:
        if full in _written:
            return full
        if os.path.isabs(full):
            return None
        name = target.removeprefix("./")
        return next((path for path in reversed(_written) if path == name or path.endswith("/" + name)), None)


def _on_disk(target: str, folder: str) -> Optional[str]:
    """The file *target* names: as written when absolute, else in *folder* (the line's ``cd``) or
    the folder the action runs in (``kernel.action_context``); None when neither is known or no
    regular file is there."""
    full = _expanded(target)
    if not os.path.isabs(full):
        base = folder or action_context.working_folder()
        full = os.path.normpath(os.path.join(base, full)) if base else ""
    return full if full and os.path.isfile(full) else None


def scripts_run(command: str) -> list[ScriptRun]:
    """Each script file *command* runs, read now from disk (bounded): one an agent wrote through a
    tool, or any other file at that path (:func:`_on_disk`)."""
    out = []
    for target, argv, runner, folder in _run_targets(command):
        path = _on_disk(target, folder) or _remembered(target)
        if not path:
            continue
        text = read_small_text(path, MAX_SCRIPT_BYTES)
        if text is None and os.path.isfile(path) and os.path.getsize(path) <= MAX_SCRIPT_BYTES:
            continue   # unreadable (not a regular file, no permission): nothing to judge
        out.append(ScriptRun(path, text, argv, runner))
    return out


_SHELL_ENDINGS = (".sh", ".bash", ".zsh", ".ksh", ".fish", ".command", ".tool")
_SHELL_LINE = re.compile(r"^#!\s*\S*(?:/|\benv\s+)(?:ba|z|k|da|fi)?sh\b")
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish", "source", "."})
#: The inline-code form each language is judged in (``detection`` reads its code option).
_LANGUAGE_OF_ENDING = {".js": "node", ".mjs": "node", ".cjs": "node", ".ts": "node", ".mts": "node", ".rb": "ruby",
                       ".pl": "perl", ".pm": "perl"}
_INLINE = {"python3": "-c", "node": "-e", "ruby": "-e", "perl": "-e"}
#: A shell script's positional parameter: ``$1``, ``${2}``.
_POSITIONAL = re.compile(r"\$\{?([1-9])\}?")


_RUNTIME_LANGUAGE = {"node": "node", "nodejs": "node", "bun": "node", "deno": "node", "tsx": "node", "ts-node": "node",
                     "ruby": "ruby", "perl": "perl"}


def _language(path: str, runner: str, text: str) -> str:
    """``shell``, ``node``, ``ruby``, ``perl`` or ``python3`` — how a script's text is read: by the
    program that runs it, else (run by its own path) by its ending or ``#!`` line."""
    if runner in _SHELLS:
        return "shell"
    if runner in _RUNTIME_LANGUAGE:
        return _RUNTIME_LANGUAGE[runner]
    if not runner and (path.lower().endswith(_SHELL_ENDINGS) or _SHELL_LINE.match(text.lstrip())):
        return "shell"
    return "python3" if runner else _LANGUAGE_OF_ENDING.get(os.path.splitext(path.lower())[1], "python3")


def as_call(path: str, content: str, argv: tuple[str, ...] = (), runner: str = "", limit: int = MAX_CONTENT_CHARS) -> dict[str, str]:
    """A script as the terminal call every protected-path check reads: a shell script's text AS a
    command line (its ``$1``… written as the *argv* it is run with); any other script as inline
    code in its own language (``node -e CONTENT ARGS``…: its literals, the paths it joins, the
    home folder and arguments it asks for) — run with *argv*, as the command runs it."""
    text = content[:limit]
    language = _language(path, runner, text)
    if language == "shell":
        return {"command": _POSITIONAL.sub(lambda found: shlex.quote(argv[int(found.group(1)) - 1])
                                           if int(found.group(1)) <= len(argv) else found.group(0), text)}
    # node's own argv starts with the script: process.argv[2] is the first argument, as when run from its file.
    args = ((path,) if language == "node" else ()) + tuple(argv)
    return {"command": " ".join([language, _INLINE[language], shlex.quote(text), *map(shlex.quote, args)])}
