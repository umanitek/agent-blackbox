"""File Shield, Layer 1, for a script an agent WRITES and then RUNS: judged by what it says.

A hook sees ``python3 r.py`` — not what ``r.py`` opens. Real agents (Claude Code, Gemini CLI and
the Hermes agent with hosted models, 2026-11-22) wrote a script that builds a protected file's path
and ran it; the file was read. Two checks close what a hook CAN see:

* **at write time** — a file an agent writes through a file tool (``write_file``, ``patch``, an
  edit's new text) or through the shell (a heredoc, ``echo``/``printf … >``, ``tee``) that is a
  script (by its ending or a ``#!`` line) is judged by its content as inline code
  (``detection``'s one protected-path answer, every route): naming a protected item refuses the
  write;
* **at run time** — a script an agent wrote through a tool since Blackbox started
  (:data:`MAX_REMEMBERED`, newest kept) that a command runs (``python3 r.py``, ``node x.js``,
  ``bash x.sh``, ``./x``, ``source x``) is read again from disk (at most :data:`MAX_SCRIPT_BYTES`)
  and judged the same way — it may have been changed after it was written.

**Limits, said plainly:** this reads text; it does not run or analyse code. A path the script
assembles at run time from pieces that are not literals, data it fetches, a script it was handed
rather than wrote through a tool, a compiled program — none of that is visible here. Only the OS
sandbox (Layer 2, :mod:`.sandbox`) stops those, which is why each agent's page says whether it is
sandboxed (kernel-enforced) or on hooks only.

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
from typing import Any, Optional

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
#: ``echo '…' > x.py`` / ``printf '…' >> x.py``.
_ECHO_TO_FILE = re.compile(r"""\b(?:echo|printf)\s+(?:-[neE]+\s+)*(?P<q>['"])(?P<body>(?:\\.|(?!(?P=q)).){1,65536}?)(?P=q)\s*>>?\s*(?P<path>[^\s<>|;&]+)""",
                           re.DOTALL)

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
    for match in _ECHO_TO_FILE.finditer(command):
        out.append((match.group("path").strip("'\""), match.group("body")[:MAX_CONTENT_CHARS]))
    return out


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


def _run_targets(command: str) -> list[str]:
    """The script files *command* runs: the first plain word after a runner (``python3 -u r.py``)
    and a word run as a program by its path (``./x``, ``~/bin/x.sh``)."""
    try:
        words = shlex.split(command, posix=True)
    except ValueError:
        words = command.split()
    targets = []
    for index, word in enumerate(words):
        name = word.rsplit("/", 1)[-1]
        if name in _RUNNERS:
            following = words[index + 1:index + 8]
            options_with_value = ("-m", "-c", "-e", "-p", "-r", "-E")
            skip = False
            for each in following:
                if skip:
                    skip = False
                    continue
                if each in options_with_value:
                    break   # a module or inline code: not a script file
                if each.startswith("-"):
                    continue
                targets.append(each)
                break
        elif (word.startswith(("./", "../", "~/", "/")) and index == 0) or (index and words[index - 1] in (";", "&&", "||", "|")
                                                                            and word.startswith(("./", "~/", "/"))):
            targets.append(word)
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


def scripts_run(command: str) -> list[tuple[str, str]]:
    """``(path, content)`` of each remembered script *command* runs, read now from disk (bounded)."""
    out = []
    for target in _run_targets(command):
        path = _remembered(target)
        text = read_small_text(path, MAX_SCRIPT_BYTES) if path else None
        if path and text:
            out.append((path, text))
    return out


_SHELL_ENDINGS = (".sh", ".bash", ".zsh", ".ksh", ".fish", ".command", ".tool")
_SHELL_LINE = re.compile(r"^#!\s*\S*(?:/|\benv\s+)(?:ba|z|k|da|fi)?sh\b")


def as_call(path: str, content: str) -> dict[str, str]:
    """A written script as the terminal call every protected-path check reads: a shell script's
    text AS a command line; any other script as inline code (``python3 -c CONTENT``: its literals,
    the paths it joins, the commands it spells out) — the reading is the same for any language."""
    text = content[:MAX_CONTENT_CHARS]
    if path.lower().endswith(_SHELL_ENDINGS) or _SHELL_LINE.match(text.lstrip()):
        return {"command": text}
    return {"command": "python3 -c " + shlex.quote(text)}
