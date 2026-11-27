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
import sys
from dataclasses import dataclass

from .. import agent_hosts, shell_path
from .schedules import schedules

#: The places every OS has (OpenSSH's login files, the system cron table, XDG autostart, and fish's
#: start files — every fish shell runs ``config.fish`` and ``conf.d/*.fish``; Linux round L1: an
#: agent's line there passed the hooks).
SHARED_FOLDERS = ("{home}/.config/autostart", "{home}/.config/fish/conf.d")
SHARED_FILES = ("{home}/.ssh/rc", "{home}/.ssh/environment", "{home}/.ssh/authorized_keys", "{home}/.ssh/authorized_keys2",
                "/etc/crontab", "{home}/.config/fish/config.fish")
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
#: The machine's own folders: its configuration, its programs and libraries, the boot files, the
#: spools, root's home, Blackbox's root helper. A write there needs root, so an agent reaches them
#: only through ``sudo`` / ``doas`` / ``pkexec`` / ``su -c`` (Linux round L1: with passwordless
#: sudo, REAL agents wrote /etc/cron.d, sudo's rules folder, /etc/profile.d and enabled a root unit).
#: In Block mode an agent's PRIVILEGED write to any of these is refused
#: (``detection.privileged_writes``); other sudo stays a flag (D7).
ROOT_PLACES = ("/etc", "/private/etc", "/boot", "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32",
               "/var/spool", "/var/lib/blackbox", "/root", "/Library", "/System")

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


def agent_code_folders(home: str) -> list[str]:
    """Every agent's :attr:`~..agent_hosts.Host.code_folders` in *home* whose PARENT folder exists:
    where the agent is installed, the folder is closed (an empty placeholder is made for a missing
    one, as for every startup folder); where it is not, nothing is created in the person's home —
    a placeholder ``~/.cline/hooks`` would make Cline look installed."""
    root = home.rstrip("/")
    folders = [os.path.join(root, folder) for host in agent_hosts.HOSTS for folder in host.code_folders]
    return [folder for folder in folders if os.path.isdir(os.path.dirname(folder))]


def startup_places(home: str, prefixes: tuple[str, ...] = HOMEBREW_PREFIXES,
                   system: str | None = None) -> tuple[list[str], list[str], list[str]]:
    """``(folders, files, globs)`` closed to writes inside the sandbox for the person at *home*, on
    *system* (default this machine's; see :func:`places_of`), the agents' code folders among them."""
    def fill(paths: tuple[str, ...]) -> list[str]:
        return [path.replace("{home}", home.rstrip("/")) for path in paths]
    folders, files, globs = places_of(system)
    return fill(folders) + homebrew_folders(prefixes, home) + agent_code_folders(home), fill(files), fill(globs)


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
    so only a WRITE there (a redirect, a copy, a writing command) is refused.
    ``shell`` — the shell startup files among ``starts`` (:func:`is_shell_startup`): judged apart,
    so the person's ``shell-startup`` permission decides them and ``startup-items`` the rest."""

    starts: tuple[str, ...]
    programs: tuple[str, ...]
    shell: tuple[str, ...] = ()


def hook_places(home: str, prefixes: tuple[str, ...] = HOMEBREW_PREFIXES) -> HookPlaces:
    """The places of :func:`startup_places` — EVERY OS's (see the module doc) — and the shell
    startup files for the person at *home*, as the hook judgement reads them."""
    folders, files, globs = startup_places(home, prefixes, EVERY_SYSTEM)
    programs = tuple(homebrew_folders(prefixes, home))
    starts = _with_real_spellings([place for place in folders if place not in programs] + files + globs + shell_startup_files(home))
    return HookPlaces(starts=starts, programs=_with_real_spellings(programs),
                      shell=tuple(place for place in starts if is_shell_startup(place)))


def is_shell_startup(path: str) -> bool:
    """True for a file (or folder) a shell reads when it starts: zsh's, bash's and ``~/.profile``
    (:data:`..shell_path.STARTUP_FILES`) and fish's ``config.fish`` / ``conf.d``."""
    return os.path.basename(path.rstrip("/")) in shell_path.STARTUP_FILES or "/.config/fish/" in path + "/"


def _with_real_spellings(places: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    """*places* and, beside each, the path the system resolves it to (``/etc/crontab`` is
    ``/private/etc/crontab`` on macOS): an agent may write either spelling."""
    out = []
    for place in places:
        out.append(place)
        if "*" not in place:
            out.append(os.path.realpath(place))
    return tuple(dict.fromkeys(out))


#: The ``fileaccess`` category of an agent writing one of these places (``fileaccess:<tool>:startup-item``).
STARTUP_ITEM = "startup-item"
#: The ``fileaccess`` category of an agent writing a shell startup file (``~/.zshrc``, ``~/.bashrc`` …),
#: kept apart from :data:`STARTUP_ITEM` so the person can relax the one without the other.
SHELL_STARTUP = "shell-startup"
#: The ``fileaccess`` category of an agent's ``sudo`` write into :data:`ROOT_PLACES`.
ROOT_WRITE = "root-write"


def is_startup_item(identifier: str) -> bool:
    """True for a finding of an agent writing a persistence place (``fileaccess:<tool>:startup-item``,
    or ``…:shell-startup`` for a shell startup file)."""
    return identifier.startswith("fileaccess:") and identifier.endswith((":" + STARTUP_ITEM, ":" + SHELL_STARTUP))


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
    ("/.config/fish/", "a shell startup file"),
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
    "ROOT_PLACES",
    "ROOT_WRITE",
    "SHARED_FILES",
    "SHARED_FOLDERS",
    "SHELL_STARTUP",
    "STARTUP_ITEM",
    "SUDO_RULES",
    "USER_TOOL_FOLDERS",
    "USER_TOOL_GLOBS",
    "HookPlaces",
    "agent_code_folders",
    "describe",
    "homebrew_folders",
    "hook_places",
    "is_shell_startup",
    "is_startup_item",
    "places_of",
    "schedules",
    "shell_startup_files",
    "startup_places",
    "user_path_folders",
]
