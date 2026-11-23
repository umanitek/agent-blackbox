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

NOT closed here (founder decision pending, see the round-5 notes): ``~/.local/bin`` (``pipx``,
``pip install --user`` scripts on Linux-style setups), npm's global prefix outside Homebrew
(``~/.npm-global``), ``~/bin`` and the other PATH folders the person owns — closing them breaks
``pipx install`` and ``npm i -g`` inside the sandbox; the persistence watch reports new programs
there instead. NOTE: with Homebrew's node, npm's global prefix IS ``/opt/homebrew`` — ``npm i -g``
inside the sandbox is refused now (install it in your own terminal).

Paths use ``{home}`` for the person's home folder. Pure: no OS calls but ``os.path.isdir`` on the
Homebrew prefixes.

Usage::

    folders, files, globs = startup_places("/Users/me")
"""

from __future__ import annotations

import os

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


__all__ = ["HOMEBREW_OWNED", "HOMEBREW_PREFIXES", "PERSISTENCE_FILES", "PERSISTENCE_FOLDERS", "PERSISTENCE_GLOBS",
           "homebrew_folders", "startup_places"]
