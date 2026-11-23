"""The places from which something starts by itself, or is run by the person later — kept closed
to writes inside the agent sandbox (File Shield's Seatbelt profile), and watched for new entries.
The ONE definition of them: every consumer reads it from here, so they can not drift apart.

Private security finding ``2026-11-23-agent-sandbox-launchagents-opt-homebrew-`` (security round
4, the installed profile probed from inside): ``~/Library/LaunchAgents/`` was writable — launchd
loads an agent-written plist at the next login, OUTSIDE the sandbox — and so was Homebrew's prefix
(``/opt/homebrew/bin``, ``Cellar``, ``Library/Taps``: ``brew tap someone/x`` began cloning from
inside, and a program dropped in the brew ``bin`` runs outside the sandbox the next time the person
types its name). Nothing an agent legitimately does inside the sandbox writes these: Homebrew
installs go through Blackbox's broker (``packages``), which runs brew outside.

* :data:`PERSISTENCE_FOLDERS` — launchd jobs (the person's and the system's), the background-task
  and login-item stores, the cron and ``at`` spools, the old StartupItems;
* :data:`PERSISTENCE_FILES` — what OpenSSH runs or trusts at a login into this Mac
  (``~/.ssh/rc``, ``environment``, ``authorized_keys``);
* :data:`PERSISTENCE_GLOBS` — the login-items preference files;
* :func:`homebrew_folders` — the folders Homebrew owns in its prefix (Apple silicon
  ``/opt/homebrew``, Intel ``/usr/local`` when Homebrew is there): its programs, kegs, casks,
  taps and links. ``var`` (a brew service's data and logs) stays writable: a database the agent
  runs keeps working.

The hook judgement reads the SAME places (private security finding
``2026-11-23-hooks-only-an-agent-appends-an-ssh-key-t``, round 5, High: a hooks-only agent appended
a key to ``~/.ssh/authorized_keys``, wrote a LaunchAgent and a program into ``/opt/homebrew/bin`` and
scheduled an ``at`` job — the sandbox refused all of them, the hooks none):

* :func:`hook_places` — :func:`startup_places` plus the shell startup files (the sandbox closes them
  through :mod:`..shell_path`), split into the places where a write STARTS something
  (:attr:`HookPlaces.starts`) and Homebrew's program folders (:attr:`HookPlaces.programs`, where
  running and reading what is there is the person's everyday work — only a write is judged);
* :func:`schedules` — a command that leaves a job in one of these places without naming it
  (``crontab -``, ``at``, ``launchctl submit``, a login item made through System Events);
* :func:`describe` — the words for a place in a refusal ("an SSH login file").

NOT closed (founder decision 2026-11-23, option b): ``~/.local/bin`` (``pipx``, ``pip install
--user``), npm's global prefix outside Homebrew (``~/.npm-global``), ``~/bin`` and the other PATH
folders the person owns — closing them breaks ``pipx install`` and ``npm i -g``; the persistence
watch raises a CRITICAL alert for every new program an agent writes there instead. NOTE: with
Homebrew's node, npm's global prefix IS ``/opt/homebrew`` — ``npm i -g`` inside the sandbox is
refused (install it in your own terminal).

Paths use ``{home}`` for the person's home folder. Pure: no OS calls but ``os.path.isdir`` on the
Homebrew prefixes.

Usage::

    folders, files, globs = startup_places("/Users/me")       # the sandbox profile's deny list
    places = hook_places("/Users/me")                         # the same, for the hook judgement
    describe("/Users/me/.ssh/authorized_keys")                # "an SSH login file"
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from .. import shell_path

PERSISTENCE_FOLDERS = (
    "{home}/Library/LaunchAgents", "{home}/Library/LaunchDaemons", "/Library/LaunchAgents", "/Library/LaunchDaemons",
    "{home}/Library/Application Support/com.apple.backgroundtaskmanagementagent", "/private/var/db/com.apple.backgroundtaskmanagement",
    "/usr/lib/cron", "/private/var/at", "/Library/StartupItems", "{home}/Library/StartupItems", "{home}/.config/autostart",
)
PERSISTENCE_FILES = ("{home}/.ssh/rc", "{home}/.ssh/environment", "{home}/.ssh/authorized_keys", "{home}/.ssh/authorized_keys2",
                     "/etc/crontab")
PERSISTENCE_GLOBS = ("{home}/Library/Preferences/com.apple.loginitems*", "{home}/Library/Preferences/com.apple.LSSharedFileList*")
#: Homebrew's prefixes and the folders it owns in each (``var`` left out on purpose, see the module doc).
HOMEBREW_PREFIXES = ("/opt/homebrew", "/usr/local")
HOMEBREW_OWNED = ("bin", "sbin", "Cellar", "Caskroom", "Library", "opt", "etc", "lib", "share", "include", "Frameworks",
                  "Homebrew")


def homebrew_folders(prefixes: tuple[str, ...] = HOMEBREW_PREFIXES) -> list[str]:
    """The folders Homebrew owns in each prefix where it is installed (``<prefix>/Homebrew`` or
    ``<prefix>/bin/brew`` there)."""
    out = []
    for prefix in prefixes:
        if os.path.isdir(os.path.join(prefix, "Homebrew")) or os.path.exists(os.path.join(prefix, "bin", "brew")):
            out += [os.path.join(prefix, name) for name in HOMEBREW_OWNED]
    return out


def startup_places(home: str, prefixes: tuple[str, ...] = HOMEBREW_PREFIXES) -> tuple[list[str], list[str], list[str]]:
    """``(folders, files, globs)`` closed to writes inside the sandbox for the person at *home*."""
    def fill(paths: tuple[str, ...]) -> list[str]:
        return [path.replace("{home}", home.rstrip("/")) for path in paths]
    return fill(PERSISTENCE_FOLDERS) + homebrew_folders(prefixes), fill(PERSISTENCE_FILES), fill(PERSISTENCE_GLOBS)


def shell_startup_files(home: str) -> list[str]:
    """Every file zsh or bash reads when it starts, in *home* (:data:`..shell_path.STARTUP_FILES`):
    a line written there runs in every later shell."""
    return [os.path.join(home.rstrip("/"), name) for name in shell_path.STARTUP_FILES]


@dataclass(frozen=True)
class HookPlaces:
    """The persistence places as the hook judgement reads them (absolute patterns, ``*`` allowed).

    ``starts`` — a write there starts something by itself (launchd, login items, cron, ``at``,
    OpenSSH's login files, the shell startup files): any change but a read is refused.
    ``programs`` — Homebrew's own folders: running or reading a program there is everyday work,
    so only a WRITE there (a redirect, a copy, a writing command) is refused."""

    starts: tuple[str, ...]
    programs: tuple[str, ...]


def hook_places(home: str, prefixes: tuple[str, ...] = HOMEBREW_PREFIXES) -> HookPlaces:
    """The places of :func:`startup_places` (and the shell startup files) for the person at *home*,
    as the hook judgement reads them."""
    folders, files, globs = startup_places(home, prefixes)
    programs = tuple(homebrew_folders(prefixes))
    starts = [place for place in folders if place not in programs] + files + globs + shell_startup_files(home)
    return HookPlaces(starts=_with_real_spellings(starts), programs=_with_real_spellings(programs))


def _with_real_spellings(places: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    """*places* and, beside each, the path the system resolves it to (``/etc/crontab`` is
    ``/private/etc/crontab`` on macOS): an agent may write either spelling."""
    out = []
    for place in places:
        out.append(place)
        if "*" not in place:
            out.append(os.path.realpath(place))
    return tuple(dict.fromkeys(out))


#: Commands that leave a job in a persistence place without naming it, and the options with which
#: they only look or remove: a cron table written from text (``crontab -`` / ``crontab file`` /
#: ``crontab -e``), an ``at`` / ``batch`` job, a launchd job loaded or submitted (``launchctl
#: submit`` makes one with no file at all), a systemd user unit enabled.
_ONLY_LOOK = {"crontab": frozenset({"-l", "-r"}), "at": frozenset({"-l", "-r", "-c", "-d"}), "batch": frozenset()}
_LOADS = {"launchctl": frozenset({"load", "bootstrap", "submit", "enable"}), "systemctl": frozenset({"enable", "link"})}
#: A login item made through System Events (``osascript -e '… make login item …'``).
_LOGIN_ITEM = re.compile(r"\blogin\s+item\b", re.IGNORECASE)


def schedules(name: str, rest: list[str]) -> bool:
    """True when command *name* (its program name, lower case) with words *rest* leaves a job that
    starts by itself later: ``crontab -``, ``at now + 1 hour``, ``launchctl submit …``,
    ``systemctl --user enable x``, ``osascript -e '… make login item …'``."""
    if name in _ONLY_LOOK:
        return not (rest and rest[0] in _ONLY_LOOK[name])
    if name in _LOADS:
        return any(word in _LOADS[name] for word in rest[:3]) and (name != "systemctl" or "--user" in rest)
    if name == "osascript":
        return any(_LOGIN_ITEM.search(word) for word in rest)
    return False


#: The ``fileaccess`` category of an agent writing one of these places (``fileaccess:<tool>:startup-item``).
STARTUP_ITEM = "startup-item"


def is_startup_item(identifier: str) -> bool:
    """True for a finding of an agent writing a persistence place (``fileaccess:<tool>:startup-item``)."""
    return identifier.startswith("fileaccess:") and identifier.endswith(":" + STARTUP_ITEM)


#: What each place is, for the words of a refusal (the first match wins).
_KINDS = (
    ("/.ssh/", "an SSH login file"),
    ("LaunchAgents", "a launchd job"), ("LaunchDaemons", "a launchd job"),
    ("backgroundtaskmanagement", "a login item"), ("com.apple.loginitems", "a login item"),
    ("LSSharedFileList", "a login item"), ("StartupItems", "a startup item"), ("autostart", "a startup item"),
    ("cron", "a scheduled job (cron)"), ("/var/at", "a scheduled job (at)"),
)


def describe(path: str) -> str:
    """The words for persistence place *path* in a refusal ("an SSH login file", "Homebrew's
    programs", "a shell startup file")."""
    if os.path.basename(path) in shell_path.STARTUP_FILES:
        return "a shell startup file"
    for marker, words in _KINDS:
        if marker in path:
            return words
    if any(path.startswith(prefix + "/") for prefix in HOMEBREW_PREFIXES):
        return "Homebrew's programs"
    return "a startup item"


__all__ = [
    "HOMEBREW_OWNED",
    "HOMEBREW_PREFIXES",
    "PERSISTENCE_FILES",
    "PERSISTENCE_FOLDERS",
    "PERSISTENCE_GLOBS",
    "STARTUP_ITEM",
    "HookPlaces",
    "describe",
    "homebrew_folders",
    "hook_places",
    "is_startup_item",
    "schedules",
    "shell_startup_files",
    "startup_places",
]
