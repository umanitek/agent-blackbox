"""Why an agent's hooks are switched off for one run — read from what the agent itself reads:
the settings its command line hands it and its project's settings files. READ-ONLY, like the
rest of :mod:`..observe`: it names the switch, it never flips it.

Usage::

    from .hooks_off import hooks_switched_off
    hooks_switched_off(host, args, pid, command)   # "started with --settings … which switches every hook off" / ""
"""

from __future__ import annotations

import json
from pathlib import Path

from ...kernel.agent_hosts import Host
from ...kernel.bounded_files import read_small_text
from . import platform


#: The options that hand an agent extra settings on its command line: a JSON text or a file.
_SETTINGS_OPTIONS = {"claude-code": ("--settings",)}
MAX_SETTINGS_BYTES = 256 * 1024


def _off_in(data: object, host: Host) -> str:
    """The switch in settings *data* that turns *host*'s hooks off ("" = none)."""
    for _name, key, off in host.switches:
        value: object = data
        for part in key.split("."):
            value = value.get(part) if isinstance(value, dict) else None
        if value == off:
            return f"{key} = {json.dumps(off)}"
    return ""


def _settings_value(text: str) -> object:
    try:
        return json.loads(text)
    except ValueError:
        return None


def _inline_json(given: str, option: str, command: str) -> object:
    """The JSON text given to *option*: *given* itself, or — when the words came from ``ps``'s
    joined line, which drops the quotes — the JSON value that starts right after *option* in
    *command* (bounded by :data:`MAX_SETTINGS_BYTES`)."""
    value = _settings_value(given)
    at = command.find(f"{option} {{")
    if value is None and at >= 0:
        try:
            value = json.JSONDecoder().raw_decode(command[at + len(option) + 1:][:MAX_SETTINGS_BYTES])[0]
        except ValueError:
            value = None
    return value


def hooks_switched_off(host: Host, args: list[str], pid: int, command: str = "") -> str:
    """Why *host*'s hooks are off for this run, naming EXACTLY what did it (KI-569): a
    ``--settings`` text (KI-576: inline JSON, whole) or file on its command line, or its project's
    settings file (the process's own working folder, ``Host.project_files``). *command*: the
    process list's line, read when *args* lost the JSON's quotes. "" when nothing this can read does."""
    for position, word in enumerate(args[:-1]):
        if word in _SETTINGS_OPTIONS.get(host.id, ()):
            given = args[position + 1]
            if given.lstrip().startswith("{"):
                found = _off_in(_inline_json(given, word, command), host)
                if found:
                    return f"started with --settings that sets {found}, which switches every hook off"
            else:
                text = read_small_text(given, MAX_SETTINGS_BYTES) if given.startswith(("/", "~", ".")) or "/" in given else None
                found = _off_in(_settings_value(text or ""), host) if text else ""
                if found:
                    return f"started with --settings {given}, which sets {found} and switches every hook off"
    folder = platform.process_cwd(pid) if host.project_files else ""
    for relative in host.project_files if folder else ():
        text = read_small_text(str(Path(folder) / relative), MAX_SETTINGS_BYTES)
        found = _off_in(_settings_value(text), host) if text else ""
        if found:
            return f"{Path(folder) / relative} sets {found}, which switches every hook off in that project"
    return ""
