"""What Blackbox's installer put on this machine besides Blackbox itself — the install manifest — and
how ``blackbox uninstall`` takes exactly that away again (KI-610, KI-611).

Security round 5 (a clean Mac, no Hermes before): after ``blackbox uninstall`` the Hermes host the
installer had set up stayed — ``~/agent-blackbox`` (the checkout), ``~/.hermes``, ``~/.local/bin/hermes*``,
uv's files, the "ensure ~/.local/bin is on PATH" block appended to ``~/.zshrc`` and a DKG
dependency's telemetry id — 3.2 GB, with Blackbox still listed as enabled in it; and an empty
``~/Library/LaunchAgents`` the installer had created stayed too.

The installers (``scripts/blackbox-install.sh``: ``install_manifest_begin`` / ``install_manifest_write``;
``scripts/blackbox-install.ps1``: ``Start-InstallManifest`` / ``Write-InstallManifest``) note, before
their first change, which of those places did not exist, and on success write
``$BLACKBOX_HOME/install-manifest/manifest.tsv``, one entry per line (tab-separated):

* ``own-dir <path>`` — a folder made for Blackbox's own services (``~/Library/LaunchAgents``):
  removed on every uninstall when it is empty;
* ``host <path>`` — a file or folder of the Hermes host it installed: removed only on a yes;
* ``host-dir <path>`` — a folder made around those: removed on a yes when it is empty;
* ``host-append <file> <block>`` — the exact text appended to a shell startup file (the block is
  kept in ``blocks/``): on a yes taken out byte for byte; the person's own lines stay as they are,
  and a block the person changed is left alone and named;
* ``own-linger <file>`` (Linux) — systemd lingering the installer turned on for this user
  (``/var/lib/systemd/linger/<user>``): turned off on every uninstall;
* ``user-path <folder>`` (Windows) — the folder the installer added to the user PATH for the
  ``blackbox`` command: taken off it on every uninstall;
* ``system-helper <LaunchDaemon>`` (macOS) — the system protection helper this install added:
  uninstall removes it through itself (accepted only for the helper's own LaunchDaemon);
* ``notifier <folder>`` (macOS) — Blackbox's own notifier (``Blackbox.app``): removed on every
  uninstall (KI-629: both optional components are in the one list).

Beside it, the empty file ``installed-at``, written once by the first install: its time is when
the install finished, the time the person's own additions are told apart by (an older manifest
without it uses the manifest's own time).

A Hermes the person had before Blackbox is never in it (it existed when the installer looked), so
it is never offered for removal. **What the person added is never removed (KI-654):** a host folder
the person installs their own things into (:data:`PERSONS_PLACES`: ``~/.nvm``'s Node versions and
global npm packages, uv's tools and Pythons) is checked first. Anything there created after the
install is the person's: the folder stays, and only the installer's own parts that hold none of it
go (the Node version the installer added, when the person's packages are in another one); the
startup lines that make it work stay with it. Round 7 saw ``~/.nvm`` removed with the Claude Code
the person had installed into its Node. The rest of the host (the checkout, ``~/.hermes``, uv's
own commands, Hermes's launchers) is Hermes's own state, rewritten by Hermes as it runs, so a
change there is not the person's. Every path is checked again here: absolute, inside the home
folder, never the home itself, no ``..``; a link is removed as a link, never followed.

Usage::

    manifest = read(constants.blackbox_home())     # before Blackbox's home is deleted
    manifest.has_host, human_size(host_size(manifest))
    remove_own_dirs(manifest, report); remove_host(manifest, report)
    kept_host(manifest)        # a host the person kept: what to remove by hand later (KI-630)
"""

from __future__ import annotations

import getpass
import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from typing import Callable, Sequence

from ..kernel import shell_path, system_helper as system_helper_paths
from ..kernel.bounded_files import read_small_text
from . import platform
from .host_removal import PERSONS_PLACES, HostRemoval, PersonsPlaces, removal_for

Runner = Callable[[Sequence[str]], int]

FOLDER = "install-manifest"
MANIFEST = "manifest.tsv"
BLOCKS = "blocks"
STAMP = "installed-at"
#: The most entries read, and the most bytes of one appended block.
MAX_ENTRIES = 200
MAX_BLOCK_BYTES = 64 * 1024
MAX_MANIFEST_BYTES = 256 * 1024
#: The most of the person's additions named in one report line.
MAX_NAMED = 5


@dataclass(frozen=True)
class InstallManifest:
    """What the installer made (see the module doc). Empty when there is no manifest."""

    own_dirs: tuple[Path, ...] = ()
    host: tuple[Path, ...] = ()
    host_dirs: tuple[Path, ...] = ()
    appended: tuple[tuple[Path, str], ...] = ()   # (startup file, the exact text appended)
    linger_user: str = ""                         # Linux: the user lingering was turned on for
    user_path: tuple[Path, ...] = ()              # Windows: folders added to the user PATH
    system_helper: bool = False                   # macOS: the install added the system protection helper
    notifier: tuple[Path, ...] = ()               # macOS: the notifier folder it added
    installed_at: float = 0.0                     # when the first install finished (epoch seconds; 0: no manifest)

    @property
    def has_host(self) -> bool:
        return bool(self.host or self.appended)


#: Where systemd-logind keeps one file per lingering user (the installer's BLACKBOX_LINGER_DIR).
LINGER_DIR = Path("/var/lib/systemd/linger")


def _safe(raw: str, home: Path) -> Path | None:
    """*raw* as a path uninstall may remove: absolute (``/…``, or ``C:\\…`` on Windows), normalised
    as written, strictly inside *home*."""
    if not os.path.isabs(raw) or ".." in Path(raw).parts:
        return None
    path = Path(os.path.normpath(raw))
    real_home, real_parent = os.path.realpath(home), os.path.realpath(path.parent)
    inside = real_parent == real_home or real_parent.startswith(real_home + os.sep)   # no link out of the home
    return path if home in path.parents and inside else None


def _linger_user(raw: str, user: str) -> str:
    """The user of an ``own-linger`` entry: only this user's own file in systemd's linger folder."""
    path = Path(os.path.normpath(raw))
    return user if user and path.parent == LINGER_DIR and path.name == user else ""


def read(blackbox_home: Path, home: Path | None = None, user: str | None = None) -> InstallManifest:
    """The manifest the installer left in *blackbox_home* (an empty one when there is none).
    *home* and *user* default to this person's (tests pass their own)."""
    home = Path(os.path.normpath(home or Path.home()))
    user = getpass.getuser() if user is None else user
    folder = blackbox_home / FOLDER
    text = read_small_text(str(folder / MANIFEST), MAX_MANIFEST_BYTES) or ""
    found: dict[str, list] = {"own-dir": [], "host": [], "host-dir": [], "host-append": [], "user-path": [], "notifier": []}
    linger_user, helper = "", False
    for line in text.splitlines()[:MAX_ENTRIES]:
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0] == "own-linger":
            linger_user = _linger_user(parts[1], user) or linger_user
            continue
        if len(parts) >= 2 and parts[0] == "system-helper":
            helper = helper or parts[1] == str(system_helper_paths.LAUNCH_DAEMON)   # the helper's own path only
            continue
        if parts[0] not in found or len(parts) < 2:
            continue
        path = _safe(parts[1], home)
        if path is None:
            continue
        if parts[0] != "host-append":
            found[parts[0]].append(path)
            continue
        name = os.path.basename(parts[2]) if len(parts) > 2 else ""
        block = read_small_text(str(folder / BLOCKS / name), MAX_BLOCK_BYTES) if name else None
        # File Shield's own PATH block may sit inside what the run appended: it is taken out by
        # uninstall's own step (kernel.shell_path.remove) before this, so it is not part of it.
        block = shell_path.without_block(block) if block else None
        if block:
            found["host-append"].append((path, block))
    unique = {kind: tuple(dict.fromkeys(paths)) for kind, paths in found.items()}
    stamps = [folder / STAMP, folder / MANIFEST]   # a manifest from before the stamp: its own time
    installed_at = next((stamp.stat().st_mtime for stamp in stamps if stamp.is_file()), 0.0)
    return InstallManifest(unique["own-dir"], unique["host"], unique["host-dir"], unique["host-append"],
                           linger_user, unique["user-path"], helper, unique["notifier"], installed_at)


def host_removal(manifest: InstallManifest, home: Path | None = None) -> HostRemoval:
    """What removing *manifest*'s host takes, as the machine is now (``setup/host_removal``: the
    person's additions stay). *home* defaults to this person's. Reads only."""
    return removal_for(manifest.host, manifest.installed_at, Path(os.path.normpath(home or Path.home())))


def host_size(manifest: InstallManifest) -> int:
    """The bytes the host's files take (links not followed)."""
    total = 0
    for path in manifest.host:
        if path.is_symlink() or path.is_file():
            total += path.lstat().st_size
            continue
        for folder, _dirs, files in os.walk(path):
            for name in files:
                try:
                    total += os.lstat(os.path.join(folder, name)).st_size
                except OSError:
                    continue
    return total


def human_size(size: int) -> str:
    """``3.2 GB`` / ``72 MB`` / ``4 KB``."""
    for unit, scale in (("GB", 1e9), ("MB", 1e6), ("KB", 1e3)):
        if size >= scale:
            return f"{size / scale:.1f} {unit}" if unit == "GB" else f"{size / scale:.0f} {unit}"
    return f"{size} bytes"


def _remove_empty(folders: tuple[Path, ...], report: list[str]) -> None:
    """Each folder that is empty now, deepest first (a folder that holds anything stays)."""
    for folder in sorted(folders, key=lambda path: -len(path.parts)):
        try:
            folder.rmdir()
            report.append(f"removed the empty folder {folder}")
        except OSError:   # missing, or not empty: left as it is
            continue


def remove_own_dirs(manifest: InstallManifest, report: list[str]) -> None:
    """The folders the installer made for Blackbox's services, when empty now."""
    _remove_empty(manifest.own_dirs, report)


def remove_components(manifest: InstallManifest, report: list[str]) -> None:
    """The optional components the installer added that live in the person's folders: the
    notifier. (The system protection helper is root's: uninstall removes it through itself.)"""
    for folder in manifest.notifier:
        if folder.is_dir() and not folder.is_symlink():
            shutil.rmtree(folder, ignore_errors=True)
            report.append(f"removed Blackbox's notifier ({folder})")


def restore_system_settings(manifest: InstallManifest, run: Runner, report: list[str]) -> None:
    """The system settings the installer changed for Blackbox put back: lingering off (Linux), the
    ``blackbox`` command's folder off the user PATH (Windows). Through ``setup/platform``: on
    another system each answers False and nothing happens."""
    if manifest.linger_user:
        if platform.disable_linger(manifest.linger_user, run):
            report.append(f"turned lingering off for {manifest.linger_user} again (the installer had turned it on)")
        else:
            report.append(f"run to finish: loginctl disable-linger {manifest.linger_user}")
    for folder in manifest.user_path:
        if platform.remove_user_path_entry(str(folder)):
            report.append(f"took {folder} off your PATH again (the installer had added it)")


def _take_out(target: Path, block: str, report: list[str]) -> None:
    """*block* taken out of startup file *target*, byte for byte; the file removed when nothing of
    the person's is left in it (it did not exist before: the installer's block was all of it)."""
    try:
        data = target.read_bytes()   # bytes, not text: every other byte of the person's file stays exactly
    except OSError:
        return
    added = block.encode("utf-8")
    if added not in data:
        report.append(f"left {target} as it is: the lines the installer added there were changed since")
        return
    kept = data.replace(added, b"", 1)
    if kept:
        target.write_bytes(kept)
    else:
        target.unlink()
    report.append(f"took the installer's lines out of {target}")


#: Hermes's own commands in the person's ``~/.local/bin``: Hermes republishes them when it starts
#: (``hermes_cli/_launchers.py``, ``expose_cli``), so one may be written AFTER the install — round 6
#: saw ``hermes-agent`` rewritten by the uninstall's own Hermes and left pointing into the removed
#: checkout. Removed with the host only when it points into a folder the host removal took away.
HERMES_COMMANDS = ("hermes", "hermes-agent", "hermes-acp")
MAX_LAUNCHER_BYTES = 4096


def _points_into(command: Path, folders: tuple[Path, ...]) -> bool:
    """Whether the small launcher *command* (a shim or a link) leads into one of *folders*."""
    if command.is_symlink():
        target = os.path.realpath(command)
        return any(target == str(folder) or target.startswith(str(folder) + os.sep) for folder in folders)
    text = read_small_text(str(command), MAX_LAUNCHER_BYTES, nofollow=True) if command.is_file() else None
    return bool(text) and any(str(folder) + os.sep in text for folder in folders)


def _commands_into(home: Path, folders: tuple[Path, ...]) -> tuple[Path, ...]:
    """Hermes's commands in ``~/.local/bin`` that lead into one of the host's *folders*."""
    commands = (home / ".local" / "bin" / name for name in HERMES_COMMANDS)
    return tuple(command for command in commands
                 if (command.is_file() or command.is_symlink()) and _points_into(command, folders))


def _remove_commands_into(home: Path, folders: tuple[Path, ...], report: list[str]) -> None:
    """Each of Hermes's commands in ``~/.local/bin`` that leads into a removed host folder."""
    for command in _commands_into(home, folders):
        command.unlink(missing_ok=True)
        report.append(f"removed {command} (it ran the Hermes just removed)")


def remove_host(manifest: InstallManifest, report: list[str], home: Path | None = None) -> None:
    """Everything the manifest lists for the host, and nothing else — plus Hermes's own commands
    that lead into what was removed (written after the install, so not listed: see above).
    *home* defaults to this person's."""
    home = Path(os.path.normpath(home or Path.home()))
    removal = host_removal(manifest, home)
    for target, block in manifest.appended:
        if removal.keeps_block(block):
            report.append(f"left the lines the installer added to {target}: what you added to a folder kept below needs them")
            continue
        _take_out(target, block, report)
    for folder, added in removal.kept:
        names = ", ".join(entry.name for entry in added[:MAX_NAMED])
        report.append(f"kept {folder}: you added to it since the install ({names}); remove it yourself when you no longer need it")
    folders: list[Path] = []
    for path in removal.remove:
        if path.is_symlink() or path.is_file():
            path.unlink(missing_ok=True)
        elif path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
            folders.append(path)
        else:
            continue
        report.append(f"removed {path}")
    _remove_commands_into(home, tuple(folders), report)
    _remove_empty(manifest.host_dirs, report)


def empty_lines_above(target: Path, block: str) -> int:
    """How many empty lines the installer's *block* put above its first line in *target* (KI-650:
    the printed removal lines left the blank line before them, so the file was not as before). A
    leading line break that only ended the person's own last line is not an empty line."""
    leading = len(block) - len(block.lstrip("\n"))
    try:
        data = target.read_bytes()
    except OSError:
        return leading
    at = data.find(block.encode("utf-8"))
    ends_own_line = at > 0 and data[at - 1:at] != b"\n"
    return max(leading - (1 if ends_own_line else 0), 0)


@dataclass(frozen=True)
class KeptHost:
    """What :func:`remove_host` would take away, as the machine is now — for a host the person
    kept (KI-630). The ``blackbox`` command and this manifest go with Blackbox, so this is all the
    person has to remove the host by hand later: ``paths`` (files and folders, Hermes's commands
    that lead into them included), ``empty_dirs`` (deepest first; removed only when empty) and
    ``appended`` (startup file, the exact lines the installer added that are still in it)."""

    paths: tuple[Path, ...] = ()
    empty_dirs: tuple[Path, ...] = ()
    appended: tuple[tuple[Path, str], ...] = ()


def kept_host(manifest: InstallManifest, home: Path | None = None) -> KeptHost:
    """The host *manifest* lists, as it stands now (see :class:`KeptHost`). *home* defaults to this
    person's. Reads only."""
    home = Path(os.path.normpath(home or Path.home()))
    removal = host_removal(manifest, home)
    present = tuple(path for path in removal.remove if path.exists() or path.is_symlink())
    folders = tuple(path for path in present if path.is_dir() and not path.is_symlink())
    commands = _commands_into(home, folders)
    appended = []
    for target, block in manifest.appended:
        if removal.keeps_block(block):
            continue
        try:
            if block.encode("utf-8") in target.read_bytes():   # a block the person changed is not theirs to delete as ours
                appended.append((target, block))
        except OSError:
            continue
    return KeptHost(tuple(dict.fromkeys(present + commands)),
                    tuple(sorted(manifest.host_dirs, key=lambda path: -len(path.parts))), tuple(appended))


__all__ = [
    "BLOCKS",
    "FOLDER",
    "MANIFEST",
    "PERSONS_PLACES",
    "HostRemoval",
    "InstallManifest",
    "KeptHost",
    "PersonsPlaces",
    "empty_lines_above",
    "host_removal",
    "host_size",
    "human_size",
    "kept_host",
    "read",
    "remove_components",
    "remove_host",
    "remove_own_dirs",
    "restore_system_settings",
]
