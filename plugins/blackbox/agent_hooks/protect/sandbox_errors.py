"""The OS sandbox's refusals as an agent sees them, read from a tool's output (KI-590).

Inside Blackbox's agent sandbox the kernel refuses some things outright, and the agent sees only
a bare error: ``operation not permitted: sudo`` (exit 127), LaunchServices'
``_LSOpenURLsWithCompletionHandler() failed … error -54``, ``kill 8240 failed: operation not
permitted``, ``sandbox-exec: sandbox_apply: Operation not permitted``. Nothing in them says
Blackbox refused it, so an agent could not tell "the sandbox stopped this" from "this is broken"
(sandbox developer day, 2026-11-22: unsure about ``open``, puzzled by exit 127). The system
protection helper's deny-log watch reports only refusals that name a protected path, so these
were never counted either.

:func:`refusals` reads a sandboxed tool call's output for those errors, and :func:`note` says each
in one line: "Blackbox's sandbox refused this (<what>): <why and what to do>". The hook post-call
passes that line to the agent (beside the output, where the agent's hook allows) and records the
call as refused on its instance, with the line as the reason — each thing refused by its
:attr:`Refusal.identity`, counted ONCE on the instance (``instances.refusals``, KI-637): a file the
helper's deny-log watch ALSO reports is paired with that log line, not counted twice, and a file it
never reports (a refused ``os.rename``, a sandboxed Codex's ``p.py``: security round 6) is still
counted. A place something starts from by itself is :data:`PERSISTENCE` (KI-614/618), judged against
the ONE list the sandbox profile is built from (``kernel.persistence_places``); launchd refusing a
sandboxed ``launchctl bootstrap`` / ``load`` (``Bootstrap failed: 5: Input/output error``) is one too.
Only a shell startup file (:data:`STARTUP`, an installer's lines handed to the person) is explained
and not counted.

It reads text only, only for a session the hook has proven to be inside the sandbox (the canary),
and only the output of a tool that runs programs or files (:data:`PROGRAM_TOOLS`): an output that
merely QUOTES such an error — a completion tool's summary (Cline's ``submit_and_exit`` repeated the
refusal it had been told, round 6), a sub-agent's answer — is not taken for one.

Each refusal seen on a sandboxed call is also handed to the listeners registered with
:func:`on_sandbox_refusal` as a typed :class:`RefusalSeen` (Observer): the dashboard wires File
Shield's sandbox permissions there, which may ask the person (a permission on "ask"). This
package never imports the shields; the composer connects them.

Usage::

    on_sandbox_refusal(listener)          # listener(RefusalSeen) per refusal seen
    found = refusals("(eval):1: operation not permitted: sudo")
    note(found)   # "Blackbox's sandbox refused this (sudo, a setuid program): macOS doesn't allow …" (Linux: no new privileges)
    counted(found)  # ["setuid:sudo"]: what the instance counts
"""

from __future__ import annotations

import fnmatch
import logging
import os
import re
import shutil
import stat
import sys
from dataclasses import dataclass
from typing import Callable

from ...kernel import persistence_places
from ...kernel.os_layout import machine_words

#: The kinds of refusal; only :data:`FILE` is left for the helper's deny-log watch to count.
SETUID, APP_DRIVER, OPEN_APP, SIGNAL, NESTED, FILE = "setuid", "app-driver", "open-app", "signal", "nested", "file"
#: Blackbox's own stand-in already said it (counted, not said again); a shell startup file an
#: installer tried to change (its lines are handed to the person); a place something starts from by
#: itself (a launchd job, cron/at, an SSH login file, Homebrew's folders).
OWN, STARTUP, PERSISTENCE = "own", "startup", "persistence"
#: The container engine's socket, kept closed while the ``docker`` sandbox permission is not allowed;
#: a program folder the person owns (``~/.local/bin`` …), closed while ``tool-folders`` is blocked.
DOCKER, TOOL_FOLDER = "docker", "tool-folder"
#: A service on this machine, refused while the ``local-ports`` sandbox permission is blocked.
LOCAL_PORT = "local-port"
#: Linux: the desktop's session or system bus (hidden inside: it starts programs outside the
#: sandbox and holds the keyring, F4); the display server (hidden while the clipboard is refused).
SYSTEM_SERVICES, DISPLAY = "system-services", "display"
LINUX = sys.platform.startswith("linux")
THIS_MACHINE = machine_words()
#: The shell startup files (as ``kernel.shell_path`` keeps them closed).
STARTUP_FILES = frozenset({".zshrc", ".zshenv", ".zprofile", ".zlogin", ".bashrc", ".bash_profile", ".profile", ".bash_login"})
#: What each well-known installer wanted to add to a startup file — said to the person to add
#: themselves (security round 4 UX: the installer failed with a bare error and the agent was stuck).
INSTALLER_LINES = {
    "nvm": ('export NVM_DIR="$HOME/.nvm"', '[ -s "$NVM_DIR/nvm.sh" ] && \\. "$NVM_DIR/nvm.sh"'),
    "pyenv": ('export PYENV_ROOT="$HOME/.pyenv"', '[[ -d $PYENV_ROOT/bin ]] && export PATH="$PYENV_ROOT/bin:$PATH"',
              'eval "$(pyenv init - zsh)"'),
    "rustup": ('. "$HOME/.cargo/env"',),
    "bun": ('export BUN_INSTALL="$HOME/.bun"', 'export PATH="$BUN_INSTALL/bin:$PATH"'),
    "deno": ('. "$HOME/.deno/env"',),
}
#: Programs that drive other apps: refused inside (the app they drive would act outside it).
APP_DRIVERS = frozenset({"osascript", "automator", "shortcuts"})
SETUID_NOTE = ("the agent sandbox runs with no new privileges, so sudo, su, pkexec and other setuid programs can not "
               "raise them; run it in your own terminal") if LINUX else \
    "macOS doesn't allow setuid programs inside the agent sandbox; run it in your own terminal"
_WHY = {
    SETUID: SETUID_NOTE,
    APP_DRIVER: "a program that drives another app would act outside the sandbox; do that step in your own terminal",
    OPEN_APP: "opening another app would run it outside the sandbox; open it yourself",
    SIGNAL: "an agent may stop only the programs it started itself, never one outside its sandbox",
    NESTED: ("a tool that starts its own sandbox can not run inside Blackbox's; SwiftPM: use `swift build "
             "--disable-sandbox` (Blackbox's sandbox still covers it, nothing is lost); anything else: run it in "
             "your own terminal"),
    FILE: "this file is kept closed to agents (a protected item, or a file that keeps Blackbox's hook)",
    LOCAL_PORT: (f"a service on {THIS_MACHINE} (a database, a dev server) is closed to this agent in Blackbox's sandbox "
                 "permissions; allow it, or the port it needs, there"),
    SYSTEM_SERVICES: ("the desktop's session bus is closed inside the sandbox (it starts programs outside it and holds "
                      "your keyring); run that step in your own terminal"),
    DISPLAY: ("the display (and with it the clipboard) is closed to this agent in Blackbox's sandbox permissions; "
              "allow the clipboard there, or run it in your own terminal"),
    TOOL_FOLDER: ("a program the agent leaves in your tool folders would run outside the sandbox the next time you type "
                  "its name; Blackbox installs global tools for agents itself, or allow it in Blackbox's sandbox permissions"),
    DOCKER: ("a container runs outside the sandbox and can mount any folder; Docker is allowed only when you allow it "
             "for this agent in Blackbox's sandbox permissions (it may be asking you now)"),
    PERSISTENCE: ("an agent may not leave something that starts by itself later, outside the sandbox (a launchd job, "
                  "a scheduled job, an SSH login key, a program in Homebrew's folders); if you meant it, do it in your "
                  "own terminal"),
}
_WHAT = {SETUID: "{name}, a setuid program", APP_DRIVER: "{name}", OPEN_APP: "open",
         SIGNAL: "a signal to a process outside the sandbox", NESTED: "a second sandbox", DOCKER: "Docker", TOOL_FOLDER: "{name}", LOCAL_PORT: f"a service on {THIS_MACHINE}", FILE: "{name}", STARTUP: "{name}",
         PERSISTENCE: "{name}", SYSTEM_SERVICES: "the session bus", DISPLAY: "the display"}
#: zsh: ``(eval):1: operation not permitted: sudo``; bash: ``bash: /usr/bin/sudo: Operation not
#: permitted``; sandbox-exec itself: ``execvp() of '/bin/ps' failed: Operation not permitted``.
_EXEC = re.compile(r"operation not permitted: (?P<z>\S+)\s*$|(?:^|\s)(?P<b>/\S+): operation not permitted"
                   r"|execvp\(\) of '(?P<x>[^']+)' failed: operation not permitted"
                   r"|\[Errno 1\] operation not permitted: '(?P<p>/[^']+)'", re.IGNORECASE | re.MULTILINE)
_OPEN = re.compile(r"LSOpenURLs\w*\(\) failed.*?error -54|LSOpenURLsWithRole\(\) failed with error -54", re.IGNORECASE)
_SIGNAL = re.compile(r"kill(?::\d+:?)? kill (?:-\S+ )?\d+ failed: operation not permitted|kill: \(\d+\) - operation not permitted"
                     r"|kill: \d+: operation not permitted", re.IGNORECASE)
_NESTED = re.compile(r"sandbox_apply: operation not permitted", re.IGNORECASE)
#: A container engine's socket refused (KI-646, security round 7: docker CLI 29 says ``permission
#: denied while trying to connect to the docker API at unix:///…/docker.sock``, and the old matcher
#: wanted "docker daemon … operation not permitted", so Docker on "ask" never asked). Read in order:
#: the SOCKET PATH itself — a ``docker.sock`` / ``podman.sock`` the refusal names (Docker Desktop,
#: colima, OrbStack, Rancher, Lima, Podman: every engine's socket ends so) on the same line as the
#: refusal — then the clients' own words for a refused connect (``… connect to the docker API|Docker
#: daemon …``, Python's docker SDK ``Error while fetching server API version … PermissionError(1``).
#: "Cannot connect to the Docker daemon … Is the docker daemon running?" alone is an engine that is
#: not started — unless the socket it names is the sandbox's MASK (:func:`_masked_socket`, Linux).
_REFUSED = r"(?:operation not permitted|permission denied)"
_DOCKER = re.compile(
    rf"[\w./-]*(?:docker|podman)\.sock\b[^\n]{{0,300}}?{_REFUSED}"
    rf"|{_REFUSED}[^\n]{{0,60}}connect to the (?:docker|podman) (?:api|daemon|socket)"
    r"|(?:docker|podman)[^\n]{0,200}server API version[^\n]{0,200}PermissionError\(1,", re.IGNORECASE)
#: The socket a client could not connect to, as docker / podman name it (``Cannot connect to the
#: Docker daemon at unix:///var/run/docker.sock.``, Go's ``dial unix /run/docker.sock: connect: …``).
_ENGINE_SOCKET = re.compile(r"cannot connect to the (?:docker|podman) (?:daemon|service|socket) at unix://(?P<at>/[^\s'\"]+?\.sock)\b"
                            r"|dial unix (?P<dial>/[^\s'\"]+?(?:docker|podman)\.sock): connect:", re.IGNORECASE)


def _is_mask(path: str) -> bool:
    """True when *path* is what Linux's sandbox covers a hidden place with: an empty regular file of
    mode 0000 (helper ``sandbox/system.rs`` ``Masks``) — never what an engine leaves (a socket, or
    nothing at all when it is not started)."""
    try:
        found = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISREG(found.st_mode) and found.st_size == 0 and stat.S_IMODE(found.st_mode) == 0


def _masked_socket(text: str) -> bool:
    """True when a client's "cannot connect" names an engine socket the sandbox hid (KI-679, Linux
    round L3: inside, Docker's socket is the mask, so docker 29 says "Cannot connect to the Docker
    daemon at unix:///var/run/docker.sock. Is the docker daemon running?" — the not-started words —
    and Docker on "ask" never asked). The socket path is the signal, not the wording."""
    return any(_is_mask(match.group("at") or match.group("dial")) for match in _ENGINE_SOCKET.finditer(text))


#: A connect to this computer refused: ``connect to 127.0.0.1 port 5432 … Operation not permitted``,
#: curl's ``Immediate connect fail for 127.0.0.1: Operation not permitted``, ``dial tcp [::1]:3000: … operation not permitted``.
#: On Linux the helper's per-agent rules REJECT (a dropped SYN would hang the connect): IPv4 says
#: ``ssh: connect to host 127.0.0.1 port 22: No route to host``, IPv6 ``… [::1] … Permission denied``.
_LOCAL_PORT = re.compile(r"(?:localhost|127\.0\.0\.1|\[?::1\]?)[^\n]{0,120}(?:operation not permitted|no route to host"
                         r"|permission denied(?! \())", re.IGNORECASE)   # not ssh's own "Permission denied (publickey)"
#: Linux's words for the sandbox's refusals (its mounts answer EROFS / EBUSY / EACCES, no new
#: privileges stops sudo): ``touch: cannot touch '/home/me/.bashrc': Read-only file system``,
#: ``mv: cannot move 'a' to 'b': Device or resource busy``, ``cat: /home/me/Taxes/x: Permission
#: denied``. A Permission denied is read only inside the person's home (outside it, an ordinary
#: file permission says the same).
_WORDS = r"(?P<why{n}>Read-only file system|Device or resource busy|Permission denied)"
_LINUX_PLACE = re.compile("|".join([
    r"'(?P<quoted>/[^'\n]+)'(?: to '[^'\n]*')?: " + _WORDS.format(n=1),
    r"(?:^|\s)(?P<bare>/[^\s:'\n]+): " + _WORDS.format(n=2),
    r"\[Errno (?:13|16|30)\] " + _WORDS.format(n=3) + r": '(?P<python>/[^'\n]+)'"]), re.IGNORECASE | re.MULTILINE)
_NO_NEW_PRIVILEGES = re.compile(r"^(?P<name>sudo|su|pkexec|doas|crontab|at|passwd|newgrp)\b[^\n]*(?:\"no new privileges\" flag is set"
                                r"|must be setuid root|cannot set groups|Authentication failure)", re.IGNORECASE | re.MULTILINE)
_BUS = re.compile(r"Failed to connect to (?:user )?bus|Could not connect: (?:Permission denied|No such file)"
                  r"|Cannot autolaunch D-Bus|org\.freedesktop\.DBus\.Error\.(?:NoServer|AccessDenied)", re.IGNORECASE)
_DISPLAY = re.compile(r"can(?:no|')t open display|Failed to connect to a Wayland server|cannot connect to X server", re.IGNORECASE)
#: Blackbox's own stand-ins already say it (``sudo``, ``crontab``, ``top``, the brew shim): counted,
#: and not said twice.
_OWN = re.compile(r"Blackbox's sandbox refused this \((?P<what>[^)]{1,80})\)")
#: launchd refusing a sandboxed caller's job: ``Bootstrap failed: 5: Input/output error`` (``launchctl
#: bootstrap``, real Codex in the sandbox, round 6) — ``Load failed: 5`` for ``launchctl load``.
_LAUNCHD = re.compile(r"^(?:Bootstrap|Load) failed: 5: Input/output error", re.IGNORECASE | re.MULTILINE)
#: The tools whose output is what a program printed, in the guard's vocabulary (``protect.runner``
#: names every agent's shell ``terminal``, Hermes runs code in ``execute_code``) — the only output a
#: refusal is read from; every other tool's output is words that can quote one (KI-637).
PROGRAM_TOOLS = frozenset({"terminal", "execute_code", "read_file", "write_file", "apply_patch", "patch"})
#: The most refusals one output is read for, and the most characters read.
MAX_FOUND = 8
MAX_READ_CHARS = 64 * 1024


@dataclass(frozen=True)
class Refusal:
    """One refusal: its *kind* (:data:`SETUID` …) and *name*, the program or file it named."""

    kind: str
    name: str = ""
    #: For a startup file: the installer whose lines the person is handed ("" when not known).
    installer: str = ""

    def line(self) -> str:
        """``<what>): <why>`` — the part of the note after "refused this (". """
        if self.kind == STARTUP:
            lines = INSTALLER_LINES.get(self.installer, ())
            ask = (f"; to finish {self.installer}'s setup, add these lines to {self.name} yourself: " + " | ".join(lines)
                   if lines else "; add the lines the installer printed to it yourself")
            return (f"{self.name}): Blackbox keeps your shell startup files closed to agents (they keep later agents inside "
                    f"the sandbox){ask}")
        return f"{_WHAT[self.kind].format(name=self.name)}): {_WHY[self.kind]}"

    @property
    def identity(self) -> str:
        """What was refused, as the instance counts it: the path, else ``<kind>:<name>``."""
        return self.name if self.name.startswith("/") else f"{self.kind}:{self.name}"


def _privileged(program: str) -> bool:
    found = program if os.path.isabs(program) else shutil.which(program, path="/usr/bin:/bin:/usr/sbin:/sbin")
    try:
        return bool(found) and bool(os.stat(found).st_mode & (stat.S_ISUID | stat.S_ISGID))
    except OSError:
        return False


def _installer(text: str) -> str:
    """The well-known installer whose output *text* is ("" for none)."""
    lowered = text.lower()
    return next((name for name in INSTALLER_LINES if re.search(rf"\b{name}\b", lowered)), "")


def _starts_things(path: str) -> bool:
    """True when *path* is, or lies inside, a place something starts from by itself (the sandbox
    profile's own list, ``kernel.persistence_places``; the shell startup files are :data:`STARTUP`)."""
    if not path.startswith("/"):
        return False
    places = persistence_places.hook_places(os.path.expanduser("~"), persistence_places.HOMEBREW_PREFIXES)
    return any(fnmatch.fnmatch(path, place) or path.startswith(place.rstrip("/") + "/") for place in (*places.starts, *places.programs))


def _in_tool_folder(path: str) -> bool:
    """True when *path* lies inside one of the person's program folders (the ONE list the profile
    closes, ``kernel.persistence_places.user_path_folders``)."""
    if not path.startswith("/"):
        return False
    folders, globs = persistence_places.user_path_folders(os.path.realpath(os.path.expanduser("~")), os.environ.get("PATH", ""))
    real = os.path.realpath(os.path.dirname(path))
    return any(real == folder or real.startswith(folder.rstrip("/") + "/") for folder in folders) or \
        any(fnmatch.fnmatch(real, glob) for glob in globs)


def _exec_kind(word: str, text: str = "") -> Refusal:
    """A program the kernel would not start, or a file it would not open (zsh words both alike)."""
    name = os.path.basename(word.rstrip(":"))
    if name in APP_DRIVERS:
        return Refusal(APP_DRIVER, name)
    if name in STARTUP_FILES:
        return Refusal(STARTUP, word.rstrip(":"), _installer(text))
    if _starts_things(word.rstrip(":")):
        return Refusal(PERSISTENCE, word.rstrip(":"))
    if _in_tool_folder(word.rstrip(":")):
        return Refusal(TOOL_FOLDER, word.rstrip(":"))
    if _privileged(word):
        return Refusal(SETUID, name)
    return Refusal(FILE, word)


def refusals(output: str) -> list[Refusal]:
    """The sandbox refusals a tool's *output* shows, each once, at most :data:`MAX_FOUND`."""
    text = (output or "")[:MAX_READ_CHARS]
    found: list[Refusal] = []
    signal = _SIGNAL.search(text)
    if signal:   # the process it named: the last number in the line (zsh puts its line number first)
        found.append(Refusal(SIGNAL, (re.findall(r"\d+", signal.group(0)) or [""])[-1]))
    if _OPEN.search(text):
        found.append(Refusal(OPEN_APP))
    if _NESTED.search(text):
        found.append(Refusal(NESTED))
    if _DOCKER.search(text) or _masked_socket(text):
        found.append(Refusal(DOCKER))
    elif _LOCAL_PORT.search(text):
        found.append(Refusal(LOCAL_PORT))
    if _LAUNCHD.search(text):
        found.append(Refusal(PERSISTENCE, "launchctl"))
    found += [Refusal(OWN, match.group("what")) for match in _OWN.finditer(text)]
    if LINUX:
        found += _linux_refusals(text)
    for match in _EXEC.finditer(text):
        word = match.group("z") or match.group("b") or match.group("x") or match.group("p") or ""
        if word:
            found.append(_exec_kind(word, text))
    return list(dict.fromkeys(found))[:MAX_FOUND]


def _linux_refusals(text: str) -> list[Refusal]:
    """The refusals only Linux's sandbox words show (see :data:`_LINUX_PLACE`)."""
    found = [Refusal(SETUID, match.group("name").lower()) for match in _NO_NEW_PRIVILEGES.finditer(text)]
    if _BUS.search(text):
        found.append(Refusal(SYSTEM_SERVICES))
    if _DISPLAY.search(text):
        found.append(Refusal(DISPLAY))
    homes = tuple({os.path.expanduser("~").rstrip("/") + "/", os.path.realpath(os.path.expanduser("~")).rstrip("/") + "/"})
    for match in _LINUX_PLACE.finditer(text):
        path = match.group("quoted") or match.group("bare") or match.group("python")
        why = match.group("why1") or match.group("why2") or match.group("why3")
        if why.lower() == "permission denied" and not path.startswith(homes):
            continue
        found.append(_exec_kind(path, text))
    return found


def read_output_of(tool_name: str) -> bool:
    """True when *tool_name*'s output is a program's (:data:`PROGRAM_TOOLS`): the only output read."""
    return tool_name in PROGRAM_TOOLS


def counted(found: list[Refusal]) -> list[str]:
    """The identities of the refusals in *found* the post-call counts — every kind but a shell
    startup file's — each once; [] for none (the instance pairs a file with the deny-log's line of it)."""
    return list(dict.fromkeys(each.identity for each in found if each.kind != STARTUP))


def note(found: list[Refusal]) -> str:
    """One line per refusal, "Blackbox's sandbox refused this (<what>): <why>." — "" for none, and
    nothing for what Blackbox's own stand-in already said."""
    return " ".join(f"Blackbox's sandbox refused this ({each.line()})." for each in found if each.kind != OWN)


def reason(found: list[Refusal]) -> str:
    """Why the call is recorded as refused, for its timeline: the note, or what Blackbox's own
    stand-in said (``Blackbox's sandbox refused this (crontab)``)."""
    return note(found) or " ".join(f"Blackbox's sandbox refused this ({each.name})." for each in found if each.kind == OWN)


@dataclass(frozen=True)
class RefusalSeen:
    """One sandbox refusal on a sandboxed call, and who it was: the *agent*, its *instance* (the
    session key Blackbox attributed the call to), its working *folder* and the hook's *pid* (0
    when not known)."""

    kind: str
    name: str
    agent: str
    instance: str
    folder: str
    pid: int = 0


_listeners: list[Callable[[RefusalSeen], None]] = []
logger = logging.getLogger(__name__)


def on_sandbox_refusal(listener: Callable[[RefusalSeen], None]) -> None:
    """Registers *listener* for every refusal seen (once per listener)."""
    if listener not in _listeners:
        _listeners.append(listener)


def emit(found: list[Refusal], agent: str, instance: str, folder: str, pid: int = 0) -> None:
    """Hands each of *found* to the listeners; a failing listener is logged, never raised."""
    for each in found:
        seen = RefusalSeen(each.kind, each.name, agent, instance, folder, pid)
        for listener in _listeners:
            try:
                listener(seen)
            except Exception:   # health: allow BLE001 -- a listener's fault never reaches the agent's answer
                logger.warning("blackbox: a sandbox refusal listener failed", exc_info=True)
