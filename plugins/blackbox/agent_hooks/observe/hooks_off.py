"""Why an agent's hooks are switched off for one run — read from what the agent itself reads:
the settings its command line hands it and its project's settings files. READ-ONLY, like the
rest of :mod:`..observe`: it names the switch, it never flips it.

Usage::

    from .hooks_off import hooks_switched_off
    hooks_switched_off(host, args, pid, command)   # "started with --settings … which switches every hook off" / ""
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

from ...kernel.agent_hosts import Host
from ...kernel.bounded_files import read_small_text
from . import platform


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


def _file_value(name: str, text: str) -> object:
    """A settings file's text as the agent reads it: TOML for a ``.toml`` (Codex), else JSON."""
    if not name.endswith(".toml"):
        return _settings_value(text)
    try:
        return tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
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


def _toml_value(text: str) -> object:
    """A ``-c key=value`` value as Codex reads it: TOML (``false``, ``0``, ``"x"``), else the text."""
    try:
        return tomllib.loads(f"value = {text}")["value"]
    except (tomllib.TOMLDecodeError, ValueError):
        return text


def _key_value_off(host: Host, given: str) -> str:
    """The switch a ``key=value`` override turns to OFF ("" = none): ``features.hooks=false``."""
    key, sep, raw = given.partition("=")
    if not sep:
        return ""
    value = _toml_value(raw.strip())
    return next((f"{key.strip()}={raw.strip()}" for _name, switch, off in host.switches
                 if key.strip() == switch and value == off and type(value) is type(off)), "")


def _run_setting_off(host: Host, option: str, form: str, given: str, command: str) -> str:
    """Why one ``option given`` pair on the command line switches *host*'s hooks off ("" = it does not)."""
    if form == "key=value":
        found = _key_value_off(host, given)
        return f"started with {option} {found}, which switches every hook off" if found else ""
    if given.lstrip().startswith("{"):
        found = _off_in(_inline_json(given, option, command), host)
        return f"started with {option} that sets {found}, which switches every hook off" if found else ""
    text = read_small_text(given, MAX_SETTINGS_BYTES) if given.startswith(("/", "~", ".")) or "/" in given else None
    found = _off_in(_settings_value(text or ""), host) if text else ""
    return f"started with {option} {given}, which sets {found} and switches every hook off" if found else ""


def _run_settings(host: Host, args: list[str]) -> list[tuple[str, str, str]]:
    """Each ``(option, form, value)`` *args* hand *host*, written ``-c v`` or ``--config=v``."""
    forms, found = dict(host.run_settings), []
    for position, word in enumerate(args):
        option, sep, attached = word.partition("=")
        if word in forms and position + 1 < len(args):
            found.append((word, forms[word], args[position + 1]))
        elif sep and option in forms:
            found.append((option, forms[option], attached))
    return found


def hooks_switched_off(host: Host, args: list[str], pid: int, command: str = "") -> str:
    """Why *host*'s hooks are off for this run, naming EXACTLY what did it: an option that hands
    the run settings (:attr:`Host.run_settings` — Claude Code's ``--settings`` text, KI-576 inline
    JSON whole, or file, KI-569; Codex's ``-c features.hooks=false``, KI-578), or its project's
    settings file (the process's own working folder, ``Host.project_files``). *command*: the
    process list's line, read when *args* lost the JSON's quotes. "" when nothing this can read does."""
    for option, form, given in _run_settings(host, args):
        found = _run_setting_off(host, option, form, given, command)
        if found:
            return found
    folder = platform.process_cwd(pid) if host.project_files else ""
    for relative in host.project_files if folder else ():
        text = read_small_text(str(Path(folder) / relative), MAX_SETTINGS_BYTES)
        found = _off_in(_file_value(relative, text), host) if text else ""
        if found:
            return f"{Path(folder) / relative} sets {found}, which switches every hook off in that project"
    return ""
