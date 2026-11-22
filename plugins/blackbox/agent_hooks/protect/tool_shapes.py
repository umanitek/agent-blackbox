"""Tool calls that need more than a rename to become the guard's — the runner's sibling
(standard library only; copied beside ``runner.py`` into Blackbox's data folder).

Cline's CLI and SDK (the tools' own input schemas in the SDK 3.0.75): ``run_commands`` carries
SEVERAL commands (strings, or ``{command, args}``), ``read_files`` several files under half a
dozen spellings, ``editor`` one edit as ``old_text`` / ``new_text``. Left as they are, the guard
would see an unknown tool and judge none of the commands or paths in it.

Usage::

    cline_tool("run_commands", {"commands": ["ls", "npm i x"]})
    # ("terminal", {"command": "ls\\nnpm i x"})
"""

from __future__ import annotations

import json
import shlex

#: The most commands or paths one call is read for.
MAX_ITEMS = 50
_PATH_KEYS = ("path", "file_path", "filePath")
_LIST_KEYS = ("files", "paths", "file_paths")


def _parsed(value: object) -> object:
    """A hook script gets each parameter as TEXT (a list arrives as its JSON): read it back."""
    if isinstance(value, str) and value.lstrip()[:1] in ("[", "{"):
        try:
            return json.loads(value)
        except ValueError:
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
    args = _parsed(args)
    entries = _parsed(args.get("commands")) if isinstance(args, dict) and "commands" in args else args
    if not isinstance(entries, list):
        entries = [entries]
    return "\n".join(line for line in (_command_line(entry) for entry in entries[:MAX_ITEMS]) if line)


def read_paths(args: object) -> list[str]:
    """Every file a ``read_files`` call names, whichever of its spellings the model used."""
    args = _parsed(args)
    if isinstance(args, dict):
        for key in _LIST_KEYS:
            if key in args:
                return read_paths(_parsed(args[key]))
        return [str(args[key]) for key in _PATH_KEYS if isinstance(args.get(key), str) and args[key]][:1]
    if isinstance(args, list):
        return [path for entry in args[:MAX_ITEMS] for path in read_paths(entry)]
    return [args] if isinstance(args, str) and args else []


def cline_tool(name: str, args: object) -> tuple[str, object] | None:
    """A Cline CLI/SDK tool call in the guard's vocabulary; None for any other tool."""
    lowered = (name or "").strip().lower()
    if lowered == "run_commands":
        return "terminal", {"command": commands_text(args)}
    if lowered == "read_files":
        paths = read_paths(args)
        return "read_file", {"path": paths[0] if paths else "", "paths": paths}
    if lowered == "editor":
        fields = _parsed(args) if isinstance(_parsed(args), dict) else {}
        path, new = str(fields.get("path") or ""), str(fields.get("new_text") or "")[:200_000]
        call = {"path": path, "content": new}
        if isinstance(fields.get("old_text"), str) and fields["old_text"]:
            call.update(old_string=fields["old_text"][:200_000], new_string=new, replace_all=False)
        return "write_file", call
    return None
