"""The brew runs Blackbox makes for sandboxed agents: a fixed argv, a clean environment, bounded output.

One :class:`Job` per validated request (``request.BrewRequest``). It runs
``<brew> <request.words()>`` as the person (never root: the dashboard's own user), outside the
sandbox, with :func:`clean_environment`, no stdin, its own process group, and at most
:data:`MAX_SECONDS`. Its output is kept in memory, bounded (:data:`MAX_LINES`), for the agent's
shim to read as it comes (:meth:`Job.since`). Nothing is written to disk here.

**Security cost, said plainly:** Homebrew's own install scripts (a formula's ``post_install``, a
cask's installer) run outside the sandbox, with the person's rights — the same as the person
typing ``brew install`` in their own terminal. That is why only names from the official taps,
checked against the threat graph first, are run, and why the person can choose "ask me each time"
or "off" (``packages``).

Usage::

    job = start(BrewRequest("install", ("tree",)))
    lines, next_line, done, code = job.since(0)
"""

from __future__ import annotations

import os
import re
import secrets
import threading
import time
from collections import OrderedDict
from typing import TYPE_CHECKING, Any, Callable, Optional

from .....kernel import shell_path
from .....kernel.bounded_files import read_small_text
from .. import platform
from .request import BrewRequest

if TYPE_CHECKING:
    import subprocess

#: Where Homebrew lives, newest layout first (Apple silicon, then Intel).
BREW_PATHS = ("/opt/homebrew/bin/brew", "/usr/local/bin/brew")
MAX_SECONDS = 30 * 60
MAX_LINES = 4000
MAX_LINE_CHARS = 2000
MAX_JOBS = 50
#: Starts the process: ``(argv, env, cwd) -> Popen`` (tests hand in their own).
Spawn = Callable[[list[str], dict[str, str], str], "subprocess.Popen[str]"]   # platform.spawn_brew by default


def brew_path() -> str:
    """The Homebrew on this Mac ("" when none): a regular, executable file at a known place."""
    return next((path for path in BREW_PATHS if os.path.isfile(path) and os.access(path, os.X_OK)), "")


#: The person's own Homebrew preferences passed through to a brokered run (KI-613): each only turns
#: something OFF (auto-update, cleanup, analytics, hints) — none changes what is installed or from where.
PERSONS_PREFERENCES = frozenset({
    "HOMEBREW_NO_AUTO_UPDATE", "HOMEBREW_NO_INSTALL_CLEANUP", "HOMEBREW_NO_ANALYTICS",
    "HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK", "HOMEBREW_NO_UPDATE_REPORT_NEW", "HOMEBREW_NO_INSTALL_UPGRADE",
    "HOMEBREW_NO_COLOR", "HOMEBREW_NO_GITHUB_API", "HOMEBREW_NO_INSECURE_REDIRECT",
})
#: ``export NAME=value`` / ``NAME=value`` in a shell startup file, the value plain or quoted.
_PREFERENCE_LINE = re.compile(r"^\s*(?:export\s+)?(HOMEBREW_NO_[A-Z_]+)=([\"']?)([A-Za-z0-9]{1,8})\2\s*(?:#.*)?$", re.MULTILINE)
_MAX_STARTUP_BYTES = 256 * 1024


def persons_preferences(home: str) -> dict[str, str]:
    """The person's :data:`PERSONS_PREFERENCES` — from their shell startup files (where macOS's
    shells read them: ``~/.zprofile`` …; an agent can not write those, File Shield keeps them
    closed) and from this process's own environment, never from the agent's request."""
    found: dict[str, str] = {}
    for name in shell_path.STARTUP_FILES:
        text = read_small_text(os.path.join(home, name), _MAX_STARTUP_BYTES) or ""
        for match in _PREFERENCE_LINE.finditer(text):
            if match.group(1) in PERSONS_PREFERENCES:
                found[match.group(1)] = match.group(3)   # a later line wins, as in a shell
    found.update({name: value for name, value in os.environ.items()
                  if name in PERSONS_PREFERENCES and re.fullmatch(r"[A-Za-z0-9]{1,8}", value)})
    return found


def clean_environment(brew: str) -> dict[str, str]:
    """The environment brew runs with: only what Homebrew needs and the person's own harmless
    Homebrew preferences (:func:`persons_preferences`), nothing the agent set."""
    home = os.path.expanduser("~")
    prefix_bin = os.path.dirname(brew)
    return {"HOME": home, "USER": os.environ.get("USER", ""), "LOGNAME": os.environ.get("LOGNAME", os.environ.get("USER", "")),
            "PATH": f"{prefix_bin}:/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8",
            **persons_preferences(home),
            "HOMEBREW_NO_ENV_HINTS": "1", "HOMEBREW_NO_EMOJI": "1",
            **({"TMPDIR": os.environ["TMPDIR"]} if os.environ.get("TMPDIR") else {})}


def argv(brew: str, request: BrewRequest) -> list[str]:
    """The FIXED argv Blackbox runs: Homebrew's own path, then the validated words."""
    return [brew, *request.words()]


class Job:
    """One brew run: its *id*, *request*, output lines (bounded), and whether / how it ended."""

    def __init__(self, request: BrewRequest, owner: Any = None) -> None:
        self.id = secrets.token_hex(8)
        self.request = request
        #: The agent instance that asked (``shields.InstanceRef``), None when not known (KI-605).
        self.owner = owner
        self.started = time.time()
        self._lines: list[str] = []
        self._dropped = 0
        self._code: Optional[int] = None
        self._lock = threading.Lock()

    def add(self, line: str) -> None:
        with self._lock:
            self._lines.append(line.rstrip("\n")[:MAX_LINE_CHARS])
            if len(self._lines) > MAX_LINES:
                self._lines.pop(0)
                self._dropped += 1

    def finish(self, code: int) -> None:
        with self._lock:
            self._code = code

    def since(self, line: int) -> tuple[list[str], int, bool, Optional[int]]:
        """``(new lines, next line number, done, exit code)`` from line *line* on."""
        with self._lock:
            first = max(0, line - self._dropped)
            return list(self._lines[first:]), self._dropped + len(self._lines), self._code is not None, self._code


_JOBS: OrderedDict[str, Job] = OrderedDict()
_lock = threading.Lock()


def get(job_id: str) -> Optional[Job]:
    with _lock:
        return _JOBS.get(str(job_id))


def recent() -> list[Job]:
    """The jobs kept, oldest first."""
    with _lock:
        return list(_JOBS.values())


def reset() -> None:
    """Tests: forget every job."""
    with _lock:
        _JOBS.clear()


def start(request: BrewRequest, brew: str, *, spawn: Optional[Spawn] = None, done: Optional[Callable[[Job], None]] = None,
          owner: Any = None) -> Job:
    """Runs *request* with Homebrew at *brew* in a thread; answers the :class:`Job` at once.
    *done* is called with the job when it has ended (the broker records and notifies there);
    *owner*: the agent instance that asked."""
    job = Job(request, owner)
    with _lock:
        _JOBS[job.id] = job
        while len(_JOBS) > MAX_JOBS:
            _JOBS.popitem(last=False)
    threading.Thread(target=_run, args=(job, brew, spawn or platform.spawn_brew, done), name=f"blackbox-brew-{job.id}", daemon=True).start()
    return job


def _run(job: Job, brew: str, spawn: Spawn, done: Optional[Callable[[Job], None]]) -> None:
    try:
        process = spawn(argv(brew, job.request), clean_environment(brew), os.path.expanduser("~"))
    except OSError as error:
        job.add(f"Blackbox could not start Homebrew: {error}")
        job.finish(127)
    else:
        timer = threading.Timer(MAX_SECONDS, lambda: platform.stop_group(process))
        timer.start()
        try:
            for line in process.stdout or ():
                job.add(line)
            job.finish(process.wait())
        finally:
            timer.cancel()
    if done is not None:
        done(job)

