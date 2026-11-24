"""The commands that leave a job in a persistence place without naming its file — the half of
:mod:`..persistence_places` that reads a command's words instead of a path. Re-exported as
``persistence_places.schedules``; the hook judgement (``detection.persistence_writes``) asks it for
every command a call runs, nested shells included.

Usage::

    schedules("crontab", ["-"])                              # True: a cron table from text
    schedules("systemctl", ["--user", "status", "x"])        # False: a look
"""

from __future__ import annotations

import re


#: Commands that leave a job in a persistence place without naming it, and the options with which
#: they only look or remove: a cron table written from text (``crontab -`` / ``crontab file`` /
#: ``crontab -e``), an ``at`` / ``batch`` job, a launchd job loaded or submitted (``launchctl
#: submit`` makes one with no file at all; ``kickstart`` runs a loaded one now), a systemd user
#: unit enabled. launchctl's verb may come after ``asuser <uid>`` (round 6, KI-PENDING: an agent's
#: ``launchctl bootstrap gui/$UID <plist>`` loaded a job), so every word is read for it.
_ONLY_LOOK = {"crontab": frozenset({"-l", "-r"}), "at": frozenset({"-l", "-r", "-c", "-d"}), "batch": frozenset()}
_LOADS = {"launchctl": frozenset({"load", "bootstrap", "submit", "enable", "kickstart"}),
          "systemctl": frozenset({"enable", "link", "start", "restart", "edit", "daemon-reload", "reenable", "preset",
                                  "add-wants", "add-requires"})}
#: Linux (deep layers §3): ``systemd-run`` makes a transient unit that runs OUTSIDE the agent's
#: session (only its help and version are looks); ``loginctl enable-linger`` keeps the person's
#: units running with nobody logged in; a D-Bus call to systemd's ``StartTransientUnit`` is
#: ``systemd-run`` by hand; ``gnome-extensions install|enable`` loads code into the desktop shell.
_ONLY_HELP = frozenset({"-h", "--help", "--version"})
_LINGER = frozenset({"enable-linger"})
_BUS_CALLERS = frozenset({"busctl", "gdbus", "dbus-send"})
_TRANSIENT_UNIT = "StartTransientUnit"
_EXTENSION_CHANGES = frozenset({"install", "enable"})
#: A desktop setting that runs something: a custom keyboard shortcut's command, an autostart
#: entry, the shell's enabled extensions (``gsettings set …`` / ``dconf write|load …``).
_SETTING_WRITES = {"gsettings": frozenset({"set"}), "dconf": frozenset({"write", "load"})}
_RUNS_SETTING = re.compile(r"custom-keybinding|autostart|enabled-extensions", re.IGNORECASE)
#: ``sfltool``'s verbs that add a login item or reset the record of them (the person's own
#: approvals of what starts at login) — security round 6: ``sfltool add-item`` passed the hook.
_SFLTOOL_CHANGES = frozenset({"add-item", "resetbtm"})
#: ``defaults``' verbs that write a preference domain.
_DEFAULTS_WRITES = frozenset({"write", "import"})
#: The preference domains that start something at login: the login window's (``LoginHook``,
#: ``AutoLaunchedApplicationDictionary``) and the login items' — as a domain, by its short name or
#: as a plist path (round 6: ``defaults write loginwindow AutoLaunchedApplicationDictionary
#: -array-add …`` passed the hook).
_LOGIN_DOMAIN = re.compile(r"(?:^|[/.])(?:loginwindow|loginitems)(?:\.plist)?$", re.IGNORECASE)
#: Programs that run another program given as their words.
_RUNS_ANOTHER = frozenset({"xargs", "parallel", "watch"})
#: Every program :func:`schedules` judges.
_SCHEDULERS = frozenset({*_ONLY_LOOK, *_LOADS, "osascript", "sfltool", "defaults", "systemd-run", "loginctl",
                         *_BUS_CALLERS, "gnome-extensions", *_SETTING_WRITES})


def _program(word: str) -> str:
    return word.rsplit("/", 1)[-1].lower()


#: A login item made through System Events (``osascript -e '… make login item …'``).
_LOGIN_ITEM = re.compile(r"\blogin\s+item\b", re.IGNORECASE)


def schedules(name: str, rest: list[str]) -> bool:
    """True when command *name* (its program name, lower case) with words *rest* leaves a job that
    starts by itself later: ``crontab -``, ``at now + 1 hour``, ``launchctl submit …``,
    ``systemctl --user enable x``, ``osascript -e '… make login item …'``, ``sfltool add-item …``
    (or ``resetbtm``), ``defaults write com.apple.loginwindow …`` / ``… loginitems …``; on Linux
    ``systemd-run …``, ``loginctl enable-linger``, ``busctl … StartTransientUnit …``,
    ``gnome-extensions enable x``, ``gsettings set … custom-keybindings …``."""
    linux = _linux_schedules(name, rest)
    if linux is not None:
        return linux
    if name in _RUNS_ANOTHER:   # ``xargs launchctl load``: the command it runs, with its words
        found = next((index for index, word in enumerate(rest) if _program(word) in _SCHEDULERS), None)
        return found is not None and schedules(_program(rest[found]), rest[found + 1:])
    if name in _ONLY_LOOK:
        return not (rest and rest[0] in _ONLY_LOOK[name])
    if name == "launchctl":
        return any(word.lower() in _LOADS[name] for word in rest)
    if name in _LOADS:   # systemctl: a system unit needs root (sudo is judged on its own)
        return any(word in _LOADS[name] for word in rest) and "--user" in rest
    if name == "osascript":
        return any(_LOGIN_ITEM.search(word) for word in rest)
    if name == "sfltool":
        return any(word.lower() in _SFLTOOL_CHANGES for word in rest)
    if name == "defaults":
        verb = next((at for at, word in enumerate(rest) if word.lower() in _DEFAULTS_WRITES), None)
        return verb is not None and any(_LOGIN_DOMAIN.search(word) for word in rest[verb + 1:verb + 4] if not word.startswith("-"))
    return False


def _linux_schedules(name: str, rest: list[str]) -> bool | None:
    """:func:`schedules` for Linux's schedulers; None for a program that is not one of them."""
    if name == "systemd-run":
        return not (rest and all(word in _ONLY_HELP for word in rest))
    if name == "loginctl":
        return any(word in _LINGER for word in rest)
    if name in _BUS_CALLERS:
        return any(_TRANSIENT_UNIT in word for word in rest)
    if name == "gnome-extensions":
        return bool(rest) and rest[0] in _EXTENSION_CHANGES
    if name in _SETTING_WRITES:
        verb = next((at for at, word in enumerate(rest) if word in _SETTING_WRITES[name]), None)
        return verb is not None and any(_RUNS_SETTING.search(word) for word in rest[verb + 1:verb + 4])
    return None
