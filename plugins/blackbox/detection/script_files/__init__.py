"""The script files a command writes and runs, read so a hook can judge a script by what it says.

Moved from ``shields/files/written.py`` (a move only) so every detector reads ONE answer — File
Shield's protected items and the persistence places alike (LES-137). The words below are File
Shield's use of it.

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
    judge_runs(command, judge)                # (run, verdict): the first script it runs that *judge* refuses

:func:`judge_runs` is the ONE script judgement every protected-place family reads (LES-137): File
Shield's protected items, the persistence places and Blackbox's own places each hand it their own
*judge* — a third copy of the loop (read, as inline code, two scripts deep) is how the families
drifted apart before (private finding ``2026-11-23-hooks-only-self-protection-does-not-read``).
Pattern: **Template Method** in function form — the walk is fixed here, the verdict is the caller's.
"""

from __future__ import annotations

import os
import re
import shlex
import threading
import time
from collections import OrderedDict
from typing import Any, Callable, Iterable, NamedTuple, Optional, TypeVar

from ...kernel import action_context
from ...kernel.bounded_files import read_small_text
from ..shell_shapes import command_from_args
from .shell_writes import MAX_CONTENT_CHARS, _ends_command, _shell_words, _shell_writes

#: The most scripts remembered (the oldest forgotten first).
MAX_REMEMBERED = 256
#: How many scripts deep a run is followed (a shell script that runs ``python3 w.py`` is read too).
SCRIPT_DEPTH = 2
#: The largest script read at run time.
MAX_SCRIPT_BYTES = 256 * 1024
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
#: Options run together that end in ``c`` (``bash -lc``, ``sh -ec``, ``python3 -Bc``): the next word
#: is inline code (or, for node/ruby/perl, a syntax check) — never a script file's name. The code
#: itself is judged on its own line (``detection.command_from_args`` adds it).
_INLINE_CLUSTER = re.compile(r"-[A-Za-z]*c")


def _run_targets(command: str) -> list[tuple[str, tuple[str, ...], str, str]]:
    """``(target, argv, runner, folder)`` for each script file *command* runs: the first plain
    word after a runner (``python3 -u r.py a b``) or a word run as a program by its path (``./x``,
    ``~/bin/x.sh``), the words after it up to the end of that command, and the folder the line moves to
    with ``cd`` before it ("" = none)."""
    words = _shell_words(command) or command.split()
    targets, folder, start = [], "", 0
    while start < len(words):
        end = next((at for at in range(start, len(words)) if _ends_command(words[at])), len(words))
        segment = [word for word in words[start:end] if not re.fullmatch(r"\d?[<>]{1,2}", word)]
        name = segment[0].rsplit("/", 1)[-1] if segment else ""
        if name in ("cd", "pushd") and len(segment) > 1:
            folder = _expanded(segment[1]) if os.path.isabs(_expanded(segment[1])) else os.path.join(folder, segment[1]) if folder else ""
        elif name in _RUNNERS:
            for at, each in enumerate(segment[1:8], start=1):
                if each in _NOT_A_FILE or _INLINE_CLUSTER.fullmatch(each):
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


def _where(target: str, folder: str) -> str:
    """Where *target* (a path a command writes or runs) is, as :func:`_on_disk` would look for it
    — absolute, or in the line's ``cd`` folder or the action's folder — whether it exists or not."""
    full = _expanded(target)
    if os.path.isabs(full):
        return full
    base = folder or action_context.working_folder()
    return os.path.normpath(os.path.join(base, full)) if base else full


def _written_here(command: str) -> dict[str, str]:
    """``{where: text}`` for each file *command* itself writes (a heredoc, ``echo``/``printf …
    >``, ``tee``), whatever its name: a file written and run in ONE command is run with this text.
    Every text one file is given is kept, joined (an append, or the same heredoc read once inside
    ``bash -lc "…"`` and once as the inner command's own line, where its body is cut off)."""
    here: dict[str, str] = {}
    for path, text in _shell_writes(command):
        where = _where(path, "")
        here[where] = "\n".join(part for part in (here.get(where, ""), text) if part)
    return here


def scripts_run(command: str) -> list[ScriptRun]:
    """Each script file *command* runs: one the SAME command writes, judged by the text it writes
    (private finding ``2026-11-23-hooks-only-an-agent-writes-a-script-with``, round 6: Codex ran
    ``bash -lc "cat << 'EOF' > r.py … EOF" && python3 r.py Doc Sec`` — r.py did not exist yet when
    the hook looked, and the protected file was read); else read now from disk (bounded): one an
    agent wrote through a tool, or any other file at that path (:func:`_on_disk`). A file that is
    both on disk and written here is judged as both."""
    out, here = [], _written_here(command)
    for target, argv, runner, folder in _run_targets(command):
        written_now = here.get(_where(target, folder))
        if written_now is None and not os.path.isabs(_expanded(target)):   # written before a ``cd``: by its name
            written_now = next((text for where, text in here.items() if os.path.basename(where) == os.path.basename(target)), None)
        if written_now is not None:
            out.append(ScriptRun(_where(target, folder), written_now, argv, runner))
        path = _on_disk(target, folder) or (None if written_now is not None else _remembered(target))
        if not path:
            continue
        text = read_small_text(path, MAX_SCRIPT_BYTES)
        if text is None and (written_now is not None or (os.path.isfile(path) and os.path.getsize(path) <= MAX_SCRIPT_BYTES)):
            continue   # unreadable (not a regular file, no permission) or not there yet: nothing more to judge
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


Verdict = TypeVar("Verdict")


def judge_runs(command: str, judge: Callable[[ScriptRun, dict[str, str]], Verdict], depth: int = SCRIPT_DEPTH,
               runs: Optional[Iterable[ScriptRun]] = None) -> Optional[tuple[ScriptRun, Verdict]]:
    """``(run, verdict)`` for the first script file *command* runs that *judge* finds against, or None.

    *judge* is called with each run whose text could be read and that run as the terminal call
    every check reads (:func:`as_call`: the script's text as inline code with its arguments) and
    returns its verdict — anything truthy (an evidence string, a list of findings) counts. The
    command lines a script runs are walked too, *depth* scripts deep in all (``bash outer.sh``
    that runs ``python3 w.py``); the run named is the one *command* itself starts. A script larger
    than :data:`MAX_SCRIPT_BYTES` is skipped (``run.text`` is None): the caller decides whether to
    flag it. *runs*: :func:`scripts_run` of *command*, when the caller already read them.

    Usage::

        hit = judge_runs(command, lambda run, call: "evidence" if refused(call) else "")
        if hit:
            run, evidence = hit
    """
    if depth <= 0:
        return None
    for run in scripts_run(command) if runs is None else runs:
        if run.text is None:
            continue   # larger than Blackbox reads: beyond a hook (the sandbox's)
        call = as_call(run.path, run.text, run.argv, run.runner, limit=MAX_SCRIPT_BYTES)
        verdict = judge(run, call)
        if verdict:
            return run, verdict
        deeper = judge_runs(command_from_args("terminal", call), judge, depth - 1)
        if deeper:
            return run, deeper[1]
    return None
