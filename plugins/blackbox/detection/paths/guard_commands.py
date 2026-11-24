"""Commands and requests that switch Blackbox off, stop it, reconfigure it or go round it —
judged by what the text says, whatever file it names (red-team pass, 2026-11-20).

Four surfaces, each one function over a command line (after nested shells and line variables
have been put in — the caller does that):

* :func:`switches_off` — the host's and Blackbox's own commands: ``plugins disable|remove
  blackbox`` (Hermes or OpenClaw, any way the program is named), ``config set|unset`` on the
  plugin lists, ``blackbox detach|uninstall|settings|rules unblock``, ``attach --no-auto``,
  uninstalling the host.
* :func:`stops_service` — its launchd jobs / systemd units (stopped, killed, restarted, frozen),
  the person's whole service manager or login (``systemctl --user exit|isolate``, ``loginctl
  terminate-user``), a kill aimed at Blackbox, its node or the ports they hold, another program put
  on its port, a firewall rule on that port — and a signal to one of Blackbox's RUNNING processes
  (:func:`signals_own`: a pid, ``-1``, a process group, a ``pkill`` / ``killall`` pattern that
  matches one; the machine's reading is ``kernel.own_processes``, Linux round L1).
* :func:`uses_control_api` — the dashboard's address: only a plain read by ``curl`` / ``wget`` of
  a read-only route is left alone; a write, the session-token route or any other program is not.
* :func:`sets_environment` — ``BLACKBOX_…=`` anywhere (a startup file, a nested agent's
  environment), ``launchctl setenv``, or a host agent started under another home.

Usage::

    switches_off("python3 -m hermes_cli.main plugins disable blackbox")     # True
    uses_control_api("curl -s http://127.0.0.1:9700/api/findings", ports)   # False: a read
    uses_control_api("curl -X POST http://127.1:9700/api/settings", ports)  # True
"""

from __future__ import annotations

import os
import re
from typing import Iterable

from ...kernel import own_processes
from .shell_words import _segment_end, _words

_DYNAMIC = re.compile(r"\$\(|`")
_SWITCH_OFF = re.compile(
    r"\bplugins?\s+(?:disable|remove|uninstall|rm|delete)\b(?P<plugin>[^|;&\n]*)"
    r"|\bconfig\s+(?:set|unset|edit|delete|remove)\b[^|;&\n]*(?:blackbox|plugins)"
    r"|\bblackbox\s+(?:detach|uninstall|settings|rules\s+(?:unblock|allow|override|remove))\b"
    r"|\bblackbox\s+(?:attach|setup)\b[^|;&\n]*--no-(?:auto|protect)"
    r"|\b(?:pip3?|uv\s+pip|uv\s+tool|pipx)\s+uninstall\b[^|;&\n]*hermes", re.IGNORECASE)
_SERVICE_JOB = re.compile(
    r"\blaunchctl\s+(?:bootout|unload|remove|disable|kill|stop)\b[^|;&\n]*\bai\.umanitek\.blackbox"
    r"|\bsystemctl\b[^|;&\n]*\b(?:stop|disable|mask|kill|restart|try-restart|reload-or-restart|try-reload-or-restart"
    r"|condrestart|force-reload|freeze|revert)\b[^|;&\n]*\bblackbox-"
    # The person's whole service manager or login: every user unit (Blackbox's dashboard) stops.
    r"|\bsystemctl\b[^|;&\n]*--user\b[^|;&\n]*\b(?:exit|isolate|halt|poweroff|reboot|kexec|switch-root|emergency|rescue)\b"
    r"|\bloginctl\s+(?:terminate-user|kill-user|disable-linger)\b"
    r"|\blaunchctl\s+(?:reboot\b|bootout\s+(?:gui|user)/\d+\s*(?:$|[|;&\n]))", re.IGNORECASE)
_KILLS = re.compile(r"\b(?:pkill|killall5?|kill|skill|taskkill|stop-process)\b|\bfuser\b[^|;&\n]*\s-\w*k", re.IGNORECASE)
#: Hermes Desktop's route to Blackbox (the app's own port, whatever it is): its switches, never a read.
_DESKTOP_ROUTE = re.compile(r"/api/plugins/blackbox/(?:mode|dash|setup)\b", re.IGNORECASE)
_KILL_TARGET = re.compile(r"blackbox|ai\.umanitek|oxigraph|blazegraph|\bdkg\b|hermes[^|;&\n]{0,20}dashboard", re.IGNORECASE)
_LISTENS_OR_FILTERS = re.compile(r"http\.server|\b(?:nc|ncat|netcat|socat)\b|uvicorn|gunicorn|--port\b|\bpfctl\b|\biptables\b|\bnft\b|\bufw\b",
                                 re.IGNORECASE)
#: Programs that only look: fetch a page, list who holds a port, print text, open the page for the person.
_READER = re.compile(r"^\s*(?:curl|wget|lsof|ss|netstat|echo|printf|open|xdg-open)\b", re.IGNORECASE)
_WRITES_OVER_HTTP = re.compile(
    r"(?:^|\s)-(?:X|d|F|T)\b|--(?:request|data[\w-]*|form[\w-]*|json|upload-file|post-[\w-]+|method|body[\w-]*)\b"
    r"|\b(?:POST|PUT|PATCH|DELETE)\b|x-blackbox-token|/api/session\b|Request\(|data\s*=|method\s*=|\.post\(|\.put\(|\.delete\(",
    re.IGNORECASE)
_ENVIRONMENT = re.compile(
    r"\bBLACKBOX_[A-Z0-9_]+['\"\]\s]*=(?!=)|\b(?:putenv|setdefault)\(\s*['\"]BLACKBOX_|\b(?:setenv|unsetenv|export|set)\s+-?[a-z]*\s*BLACKBOX_[A-Z0-9_]+"
    r"|\bdefaults\s+write\s+ai\.umanitek"
    r"|\b(?:HERMES_HOME|OPENCLAW_(?:CONFIG_PATH|STATE_DIR|HOME))\s*=[^|;&\n]*\b(?:hermes|openclaw)\b", re.IGNORECASE)


def switches_off(command: str) -> bool:
    """True when *command* turns Blackbox off through the host's or Blackbox's own commands.
    A ``plugins disable`` whose target is built at run time (``$(…)``) is taken as aimed at Blackbox."""
    for found in _SWITCH_OFF.finditer(command):
        plugin = found.group("plugin")
        if plugin is None or "blackbox" in plugin.lower() or _DYNAMIC.search(command):
            return True
    return False


def _names_port(command: str, ports: Iterable[int]) -> bool:
    return any(re.search(rf"(?<![\w.]){int(port)}(?![\w.])", command) for port in ports)


def stops_service(command: str, ports: Iterable[int]) -> bool:
    """True when *command* stops Blackbox's services, kills them, or takes or filters their port."""
    if _SERVICE_JOB.search(command):
        return True
    names_port = _names_port(command, ports)
    if _KILLS.search(command) and (_KILL_TARGET.search(command) or names_port or signals_own(command, own_processes.running())):
        return True
    return names_port and bool(_LISTENS_OR_FILTERS.search(command))


#: The programs that signal processes, and their options that take a value (``kill -s KILL``,
#: ``pkill -u me``, ``killall -s 9``).
_SIGNALLERS = frozenset({"kill", "pkill", "killall", "skill", "killall5"})
_TAKES_VALUE = {"kill": frozenset({"-s", "-n", "--signal", "-q", "--queue", "--timeout"}),
                "pkill": frozenset({"-s", "--session", "-u", "--euid", "-U", "--uid", "-g", "--pgroup", "-G", "--group", "-P",
                                    "--parent", "-t", "--terminal", "-F", "--pidfile", "--signal", "--ns", "--nslist", "-q"}),
                "killall": frozenset({"-s", "--signal", "-u", "--user", "-o", "--older-than", "-y", "--younger-than", "-n", "--ns",
                                      "-C", "--context"})}


def _arguments(name: str, words: list[str]) -> tuple[set[str], list[str]]:
    """``(options, operands)`` of a signaller's *words* (after its name). ``kill``'s first ``-9`` /
    ``-KILL`` is its signal and every later ``-N`` an operand, so ``kill -9 -1`` aims at ``-1``."""
    options: set[str] = set()
    operands: list[str] = []
    index = 0
    while index < len(words):
        word = words[index]
        index += 1
        if word == "--":
            operands += words[index:]
            break
        if not word.startswith("-") or (name == "kill" and (options or operands) and re.fullmatch(r"-\d+", word)):
            operands.append(word)
            continue
        option = word.split("=", 1)[0]
        options.add(option)
        if option in _TAKES_VALUE.get(name, frozenset()) and "=" not in word:
            index += 1
    return options, operands


def _matches(pattern: str, text: str, exact: bool, folds: bool) -> bool:
    try:
        expression = re.compile(pattern, re.IGNORECASE if folds else 0)
    except re.error:
        return pattern in text
    return bool(expression.fullmatch(text) if exact else expression.search(text))


def signals_own(command: str, processes: Iterable[own_processes.OwnProcess]) -> bool:
    """True when *command* sends a signal that reaches one of *processes* (Blackbox's own): ``kill``
    of its pid, of ``-1`` (every process the user may signal) or of its process group; ``pkill``
    whose pattern matches its name (its command line with ``-f``), or with no pattern at all;
    ``killall`` of its name (``-r``: a pattern), or with none (``-u me``: every program); ``killall5``."""
    ours = tuple(processes)
    if not ours:
        return False
    words = _words(command)
    start = 0
    while start < len(words):
        end = _segment_end(words, start)
        segment = words[start:end]
        start = end + 1
        at = next((index for index, word in enumerate(segment) if os.path.basename(word) in _SIGNALLERS), None)
        if at is None:
            continue
        name = os.path.basename(segment[at])
        options, operands = _arguments(name, segment[at + 1:])
        if name == "killall5":
            return True
        if name == "kill":
            numbers = [int(word) for word in operands if re.fullmatch(r"-?\d+", word)]
            if any(n == -1 or n in {p.pid for p in ours} or (n < -1 and -n in {p.group for p in ours}) for n in numbers):
                return True
            continue
        if not operands:   # ``pkill -u me`` / ``killall -u me``: every program it may signal
            if options - {"-l", "--list", "-V", "--version", "-h", "--help"}:
                return True
            continue
        exact, folds, whole = "-x" in options or "--exact" in options, "-i" in options or "--ignore-case" in options, "-f" in options or "--full" in options
        for pattern in operands:
            for process in ours:
                program = os.path.basename(process.command.split(" ", 1)[0]) if process.command else ""
                if name == "killall" and "-r" not in options and "--regexp" not in options:
                    if pattern in (process.name, program):
                        return True
                elif _matches(pattern, process.command if whole else process.name, exact, folds):
                    return True
    return False


def uses_control_api(text: str, ports: Iterable[int]) -> bool:
    """True when *text* (a command or code) talks to Blackbox's local service other than by a
    plain read: it names the dashboard's port and writes, asks for the session token, or is not
    ``curl`` / ``wget`` at all."""
    if _DESKTOP_ROUTE.search(text):
        return True
    if not any(re.search(rf":{int(port)}(?!\d)", text) for port in ports):
        return False
    return bool(_WRITES_OVER_HTTP.search(text)) or not _READER.search(text)


def names_control_address(text: str, ports: Iterable[int]) -> bool:
    """True when *text* holds an address on this machine at one of Blackbox's ports (any spelling
    of the loopback host: ``127.0.0.1``, ``localhost``, ``[::1]``, ``127.1``, a number)."""
    return any(re.search(rf"(?:127\.[\d.]+|localhost|\[::1\]|0\.0\.0\.0|0x7f[0-9a-f]*|2130706433|//):{int(port)}(?!\d)", text, re.IGNORECASE)
               for port in ports)


def sets_environment(text: str) -> bool:
    """True when *text* sets one of Blackbox's own variables, or starts a host agent under another home."""
    return bool(_ENVIRONMENT.search(text))
