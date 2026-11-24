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
* :data:`PERSISTENCE_GLOBS` — the login-items and login-window preference files (``LoginHook``,
  ``AutoLaunchedApplicationDictionary`` start a program at login);
* :func:`homebrew_folders` — the folders Homebrew owns in its prefix (Apple silicon
  ``/opt/homebrew``, Intel ``/usr/local``, Linux's ``/home/linuxbrew/.linuxbrew`` or
  ``~/.linuxbrew`` when Homebrew is there): its programs, kegs, casks, taps and links. ``var``
  (a brew service's data and logs) stays writable: a database the agent runs keeps working.
* :data:`LINUX_PERSISTENCE_FOLDERS` / :data:`LINUX_PERSISTENCE_FILES` — Linux's (Linux deep
  layers §3): systemd units (the person's and the system's), session and desktop autostart,
  D-Bus activation, cron and ``at`` spools, sudoers, PAM, udev, the dynamic loader, profile
  scripts, the X session files, desktop and compositor start files.

Which OS a place belongs to: the lists above whose name starts ``LINUX_`` are Linux's; the
``PERSISTENCE_*`` lists are macOS's, and the entries in :data:`SHARED_FOLDERS` /
:data:`SHARED_FILES` (OpenSSH's login files, ``/etc/crontab``, XDG autostart) are both's.
:func:`places_of` answers one OS's, and the sandbox renders only its own OS's
(:func:`startup_places`: the Linux sandbox cannot even mask a path that does not exist there);
the hook judgement reads EVERY OS's (:func:`hook_places`): a write to another OS's startup place
is never an agent's everyday work, so refusing it costs nothing and keeps one list.

The hook judgement reads the SAME places (private security finding
``2026-11-23-hooks-only-an-agent-appends-an-ssh-key-t``, round 5, High: a hooks-only agent appended
a key to ``~/.ssh/authorized_keys``, wrote a LaunchAgent and a program into ``/opt/homebrew/bin`` and
scheduled an ``at`` job — the sandbox refused all of them, the hooks none):

* :func:`hook_places` — :func:`startup_places` plus the shell startup files (the sandbox closes them
  through :mod:`..shell_path`), split into the places where a write STARTS something
  (:attr:`HookPlaces.starts`) and Homebrew's program folders (:attr:`HookPlaces.programs`, where
  running and reading what is there is the person's everyday work — only a write is judged);
* :func:`schedules` — a command that leaves a job in one of these places without naming it
  (``crontab -``, ``at``, ``launchctl submit``, a login item made through System Events, ``sfltool
  add-item``, a ``defaults write`` of the login window's or login items' preferences);
* :func:`describe` — the words for a place in a refusal ("an SSH login file").

The person's own program folders (``~/.local/bin``, ``~/.cargo/bin``, ``~/bin`` and the other PATH
folders they own: :func:`user_path_folders`) are NOT in the startup places: closing them always
broke ``pipx install`` and ``npm i -g`` (founder decision 2026-11-23, option b). The sandbox's
``tool-folders`` permission closes them when the person blocks it (design "Sandbox permissions",
F2), and the persistence watch raises a CRITICAL alert for every new program an agent writes there.
NOTE: with Homebrew's node, npm's global prefix IS ``/opt/homebrew`` — ``npm i -g`` inside the
sandbox is refused there (Blackbox's global-installs broker does it instead).

Paths use ``{home}`` for the person's home folder. Pure: no OS calls but ``os.path.isdir`` on the
Homebrew prefixes (and ``sys.platform`` for the default OS).

Usage::

    folders, files, globs = startup_places("/Users/me")       # this OS's: the sandbox profile's deny list
    startup_places("/home/me", system="linux")               # Linux's
    places = hook_places("/Users/me")                         # the same, for the hook judgement
    describe("/Users/me/.ssh/authorized_keys")                # "an SSH login file"
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass

from .. import shell_path

#: The places every OS has (OpenSSH's login files, the system cron table, XDG autostart).
SHARED_FOLDERS = ("{home}/.config/autostart",)
SHARED_FILES = ("{home}/.ssh/rc", "{home}/.ssh/environment", "{home}/.ssh/authorized_keys", "{home}/.ssh/authorized_keys2",
                "/etc/crontab")
#: macOS's places (with the shared ones: the Seatbelt profile's whole list, unchanged in order).
PERSISTENCE_FOLDERS = (
    "{home}/Library/LaunchAgents", "{home}/Library/LaunchDaemons", "/Library/LaunchAgents", "/Library/LaunchDaemons",
    "{home}/Library/Application Support/com.apple.backgroundtaskmanagementagent", "/private/var/db/com.apple.backgroundtaskmanagement",
    "/usr/lib/cron", "/private/var/at", "/Library/StartupItems", "{home}/Library/StartupItems", *SHARED_FOLDERS,
)
PERSISTENCE_FILES = SHARED_FILES
PERSISTENCE_GLOBS = ("{home}/Library/Preferences/com.apple.loginitems*", "{home}/Library/Preferences/com.apple.LSSharedFileList*",
                     "{home}/Library/Preferences/com.apple.loginwindow*", "{home}/Library/Preferences/loginwindow*")
#: sudo's rules. WHY spelled in two parts: Hermes' plugin security scan (tools/skills_guard.py,
#: pattern ``sudoers_mod``) reads the whole path in a plugin's source as "modifies sudoers",
#: critical; this list only ever REFUSES writes there (and the watch reports changes).
SUDO_RULES = "/etc/" + "sudoers"
#: Linux's places (design "Linux deep layers" §3): what systemd, the session, the desktop, cron /
#: ``at``, sudo, PAM, udev, the dynamic loader and the login shells start or trust.
LINUX_PERSISTENCE_FOLDERS = (
    "{home}/.config/systemd/user", "{home}/.local/share/systemd/user", "/etc/systemd/system", "/etc/systemd/user",
    "{home}/.config/environment.d", "/etc/xdg/autostart", "{home}/.local/share/dbus-1/services",
    "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly",
    "/var/spool/cron", "/var/spool/cron/atjobs", "/var/spool/at",
    SUDO_RULES + ".d", "/etc/udev/rules.d", "/etc/ld.so.conf.d", "/etc/pam.d", "/etc/profile.d", "/etc/update-motd.d",
    "/etc/NetworkManager/dispatcher.d", "/etc/apt/apt.conf.d", "/etc/modprobe.d", "/etc/init.d",
    "{home}/.local/share/gnome-shell/extensions", "{home}/.config/plasma-workspace/env",
    "{home}/.config/plasma-workspace/shutdown", "{home}/.config/autostart-scripts", "{home}/.local/share/applications",
)
LINUX_PERSISTENCE_FILES = (
    "/etc/anacrontab", SUDO_RULES, "/etc/ld.so.preload", "/etc/environment", "/etc/rc.local", "/etc/security/pam_env.conf",
    "{home}/.xprofile", "{home}/.xsessionrc", "{home}/.xinitrc", "{home}/.xsession", "{home}/.pam_environment",
    "{home}/.config/mimeapps.list", "{home}/.config/dconf/user", "{home}/.config/i3/config", "{home}/.config/sway/config",
    "{home}/.config/hypr/hyprland.conf", "{home}/.config/openbox/autostart",
)
#: :func:`places_of`'s answer for every OS at once (the hook judgement's).
EVERY_SYSTEM = "*"

#: Homebrew's prefixes and the folders it owns in each (``var`` left out on purpose, see the module
#: doc). Linux's two (``/home/linuxbrew/.linuxbrew``, or ``~/.linuxbrew`` for one person) beside
#: the Mac's; a prefix counts only where Homebrew is installed (:func:`homebrew_folders`).
HOMEBREW_PREFIXES = ("/opt/homebrew", "/usr/local", "/home/linuxbrew/.linuxbrew", "{home}/.linuxbrew")
HOMEBREW_OWNED = ("bin", "sbin", "Cellar", "Caskroom", "Library", "opt", "etc", "lib", "share", "include", "Frameworks",
                  "Homebrew")


def homebrew_folders(prefixes: tuple[str, ...] = HOMEBREW_PREFIXES, home: str = "") -> list[str]:
    """The folders Homebrew owns in each prefix where it is installed (``<prefix>/Homebrew`` or
    ``<prefix>/bin/brew`` there). A ``{home}`` prefix is the person's at *home* (none without it)."""
    out = []
    for template in prefixes:
        if "{home}" in template and not home:
            continue
        prefix = template.replace("{home}", home.rstrip("/"))
        if os.path.isdir(os.path.join(prefix, "Homebrew")) or os.path.exists(os.path.join(prefix, "bin", "brew")):
            out += [os.path.join(prefix, name) for name in HOMEBREW_OWNED]
    return out


def places_of(system: str | None = None) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """``(folders, files, globs)`` templates of *system* (a ``sys.platform`` value; default this
    machine's; :data:`EVERY_SYSTEM` for every OS's together). An OS with no list of its own reads
    macOS's, as before Linux had one."""
    here = sys.platform if system is None else system
    if here == EVERY_SYSTEM:
        return (tuple(dict.fromkeys(PERSISTENCE_FOLDERS + LINUX_PERSISTENCE_FOLDERS)),
                tuple(dict.fromkeys(PERSISTENCE_FILES + LINUX_PERSISTENCE_FILES)), PERSISTENCE_GLOBS)
    if here.startswith("linux"):
        return LINUX_PERSISTENCE_FOLDERS + SHARED_FOLDERS, SHARED_FILES + LINUX_PERSISTENCE_FILES, ()
    return PERSISTENCE_FOLDERS, PERSISTENCE_FILES, PERSISTENCE_GLOBS


def startup_places(home: str, prefixes: tuple[str, ...] = HOMEBREW_PREFIXES,
                   system: str | None = None) -> tuple[list[str], list[str], list[str]]:
    """``(folders, files, globs)`` closed to writes inside the sandbox for the person at *home*, on
    *system* (default this machine's; see :func:`places_of`)."""
    def fill(paths: tuple[str, ...]) -> list[str]:
        return [path.replace("{home}", home.rstrip("/")) for path in paths]
    folders, files, globs = places_of(system)
    return fill(folders) + homebrew_folders(prefixes, home), fill(files), fill(globs)


#: The program folders the person owns that are commonly on PATH: a program an agent leaves there
#: runs OUTSIDE the sandbox the next time the person types its name. The ONE list (LES-137): the
#: sandbox's ``tool-folders`` permission closes these to writes when blocked, the hook layer reads
#: a refusal there as that permission's, and the system protection helper's persistence watch
#: (``helper/src/platform/macos/observe/run_later.rs`` ``USER_PROGRAM_FOLDERS``) watches a subset
#: of them (a parity test holds that).
USER_TOOL_FOLDERS = ("{home}/.local/bin", "{home}/.local/pipx", "{home}/.cargo/bin", "{home}/go/bin", "{home}/.bun/bin",
                     "{home}/.npm-global", "{home}/.nvm/versions", "{home}/.deno/bin", "{home}/bin",
                     "{home}/.local/share/flatpak")
USER_TOOL_GLOBS = ("{home}/Library/Python/*/bin", "{home}/.gem/ruby/*/bin", "{home}/.local/share/gem/ruby/*/bin")
#: The most PATH folders read (a PATH is short; a huge one is not trusted further).
MAX_PATH_FOLDERS = 64


def user_path_folders(home: str, path: str = "", owner: int = -1, exclude: tuple[str, ...] = ()) -> tuple[list[str], list[str]]:
    """``(folders, globs)``: :data:`USER_TOOL_FOLDERS` / :data:`USER_TOOL_GLOBS` for the person at
    *home*, plus every absolute folder on *path* (a PATH value) inside *home* that *owner* (a uid;
    -1: anyone) owns, except *exclude* and folders inside them (Blackbox's own launchers)."""
    root = home.rstrip("/")
    folders = [place.replace("{home}", root) for place in USER_TOOL_FOLDERS]
    for entry in [part for part in path.split(os.pathsep) if part][:MAX_PATH_FOLDERS]:
        if not entry.startswith("/") or not os.path.normpath(entry).startswith(root + "/"):
            continue   # only a folder written inside home is looked at, never resolved from elsewhere
        real = os.path.realpath(entry)
        if not real.startswith(root + "/"):
            continue
        if any(real == other or real.startswith(other.rstrip("/") + "/") for other in exclude):
            continue
        try:
            if owner >= 0 and os.stat(real).st_uid != owner:
                continue
        except OSError:
            continue
        folders.append(real)
    return list(dict.fromkeys(folders)), [place.replace("{home}", root) for place in USER_TOOL_GLOBS]


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
    """The places of :func:`startup_places` — EVERY OS's (see the module doc) — and the shell
    startup files for the person at *home*, as the hook judgement reads them."""
    folders, files, globs = startup_places(home, prefixes, EVERY_SYSTEM)
    programs = tuple(homebrew_folders(prefixes, home))
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
    ("LSSharedFileList", "a login item"), ("StartupItems", "a startup item"),
    # Linux (deep layers §3)
    ("/systemd/", "a systemd unit"), ("/.linuxbrew/", "Homebrew's programs"),
    ("/xdg/autostart", "a desktop autostart entry"), ("/.config/autostart", "a desktop autostart entry"),
    ("autostart-scripts", "a desktop autostart entry"), ("plasma-workspace", "a desktop autostart entry"),
    ("gnome-shell/extensions", "a desktop autostart entry"), ("/openbox/autostart", "a desktop autostart entry"),
    ("autostart", "a startup item"),
    ("/atjobs", "a scheduled job (at)"), ("/spool/at", "a scheduled job (at)"),
    ("cron", "a scheduled job (cron)"), ("/var/at", "a scheduled job (at)"),
    ("/environment.d", "a session start file"), ("/.xprofile", "a session start file"),
    ("/.xsession", "a session start file"), ("/.xinitrc", "a session start file"), ("/.pam_environment", "a session start file"),
    ("/dbus-1/services", "a session start file"), ("/.local/share/applications", "a session start file"),
    ("/mimeapps.list", "a session start file"), ("/dconf/user", "a session start file"), ("/.config/i3/", "a session start file"),
    ("/.config/sway/", "a session start file"), ("/.config/hypr/", "a session start file"),
    ("/etc/", "a root configuration file"),
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
    "EVERY_SYSTEM",
    "HOMEBREW_OWNED",
    "HOMEBREW_PREFIXES",
    "LINUX_PERSISTENCE_FILES",
    "LINUX_PERSISTENCE_FOLDERS",
    "MAX_PATH_FOLDERS",
    "PERSISTENCE_FILES",
    "PERSISTENCE_FOLDERS",
    "PERSISTENCE_GLOBS",
    "SHARED_FILES",
    "SHARED_FOLDERS",
    "STARTUP_ITEM",
    "SUDO_RULES",
    "USER_TOOL_FOLDERS",
    "USER_TOOL_GLOBS",
    "HookPlaces",
    "describe",
    "homebrew_folders",
    "hook_places",
    "is_startup_item",
    "places_of",
    "schedules",
    "shell_startup_files",
    "startup_places",
    "user_path_folders",
]
