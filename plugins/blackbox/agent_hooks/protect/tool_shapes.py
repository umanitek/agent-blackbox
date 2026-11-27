"""Tool calls that need more than a rename to become the guard's — the runner's sibling
(standard library only; copied beside ``runner.py`` into Blackbox's data folder).

Cline's CLI and SDK (the tools' own input schemas in the SDK 3.0.75): ``run_commands`` carries
SEVERAL commands (strings, or ``{command, args}``), ``read_files`` several files under half a
dozen spellings, ``editor`` one edit as ``old_text`` / ``new_text``. Gemini CLI's
``read_many_files`` names its files in lists too (``paths``, ``include``: review 2026-11-26 —
read by its single-path keys only, none of its files was judged). Left as they are, the guard
would see an unknown tool and judge none of the commands or paths in it.

Also the ONE reader of a tool's arguments sent as JSON text (:func:`parsed_json`), for the runner
and its siblings: tolerant — text that is not JSON, or nested too deep to parse, stays text.

Usage::

    cline_tool("run_commands", {"commands": ["ls", "npm i x"]})
    # ("terminal", {"command": "ls\\nnpm i x"})
    many_read({"paths": ["a.txt", "~/.ssh/id_rsa"]})
    # ("read_file", {"path": "a.txt", "paths": ["a.txt", "~/.ssh/id_rsa"]})
"""

from __future__ import annotations

import json
import shlex

#: The most commands or paths one call is read for.
MAX_ITEMS = 50
_PATH_KEYS = ("path", "file_path", "filePath")
_LIST_KEYS = ("files", "paths", "file_paths", "include")
#: Tools that read several files in one call (Cline's ``read_files``, Gemini CLI's ``read_many_files``).
READ_MANY_NAMES = frozenset({"read_files", "read_many_files"})


def parsed_json(value: object) -> object:
    """*value* read back from JSON text when it is a JSON object or list (a hook script gets each
    parameter as TEXT; some hosts send a tool's whole arguments so); anything else as given. Text
    that is not JSON, or is nested too deep to parse (``RecursionError``), stays text — never raises."""
    if isinstance(value, str) and value.lstrip()[:1] in ("[", "{"):
        try:
            return json.loads(value)
        except (ValueError, RecursionError):
            return value
    return value


def _command_line(entry: object) -> str:
    if isinstance(entry, dict):
        command = str(entry.get("command") or entry.get("cmd") or "")
        args = entry.get("args") if isinstance(entry.get("args"), list) else []
        return " ".join([command, *(shlex.quote(str(arg)) for arg in args)]).strip()
    return str(entry or "")


def commands_text(args: object) -> str:
    """Every command of a ``run_commands`` call, one per line (the guard reads each line)."""
    args = parsed_json(args)
    entries = parsed_json(args.get("commands")) if isinstance(args, dict) and "commands" in args else args
    if not isinstance(entries, list):
        entries = [entries]
    return "\n".join(line for line in (_command_line(entry) for entry in entries[:MAX_ITEMS]) if line)


def read_paths(args: object) -> list[str]:
    """Every file a many-file read names, whichever of its spellings (and lists) the model used."""
    args = parsed_json(args)
    if isinstance(args, dict):
        listed = [path for key in _LIST_KEYS if key in args for path in read_paths(parsed_json(args[key]))]
        if listed:
            return listed[:MAX_ITEMS]
        return [str(args[key]) for key in _PATH_KEYS if isinstance(args.get(key), str) and args[key]][:1]
    if isinstance(args, list):
        return [path for entry in args[:MAX_ITEMS] for path in read_paths(entry)]
    return [args] if isinstance(args, str) and args else []


def many_read(args: object) -> tuple[str, dict]:
    """A many-file read as the guard's ``read_file``: the first file as ``path``, every one as
    ``paths`` (``events._tool_verdicts`` judges each)."""
    paths = read_paths(args)
    return "read_file", {"path": paths[0] if paths else "", "paths": paths}


def cline_tool(name: str, args: object) -> tuple[str, object] | None:
    """A Cline CLI/SDK tool call in the guard's vocabulary; None for any other tool."""
    lowered = (name or "").strip().lower()
    if lowered == "run_commands":
        return "terminal", {"command": commands_text(args)}
    if lowered in READ_MANY_NAMES:
        return many_read(args)
    if lowered == "editor":
        fields = parsed_json(args) if isinstance(parsed_json(args), dict) else {}
        path, new = str(fields.get("path") or ""), str(fields.get("new_text") or "")[:200_000]
        call = {"path": path, "content": new}
        if isinstance(fields.get("old_text"), str) and fields["old_text"]:
            call.update(old_string=fields["old_text"][:200_000], new_string=new, replace_all=False)
        return "write_file", call
    return None
