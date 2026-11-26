"""Which parts of the Hermes host an install set up may go, and which stay because the person has
added their own things to them since (KI-654) — read by ``setup/install_manifest`` for the removal
and for the commands printed when the host is kept.

Security round 7 (Linux, Ubuntu 24.04): the installer put nvm and Node 22 in ``~/.nvm``; the person
then installed Claude Code into that Node (``npm install -g``); ``blackbox uninstall --remove-host``
deleted ``~/.nvm`` and the person's ``claude`` command with it. The rule, for every host item: only
what the installer created and the person has not added to goes. A folder a person installs their
own tools into is listed in :data:`PERSONS_PLACES` with where to look; an entry there whose status
time (``st_ctime``: set by the system on creation, rename or change, never back-dated by a copy or
an unpack) is after the install is the person's. Such a folder stays whole, with the startup lines
that make it work; only the installer's own units in it that hold nothing of the person's go (the
Node version the installer added, when the person's packages are in another version).

Usage::

    removal = removal_for(manifest.host, manifest.installed_at, Path.home())
    removal.remove        # remove these whole
    removal.kept          # ((folder, what the person added), ...): say so, keep them
    removal.keeps_block(block)   # True: leave these startup lines in place
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class PersonsPlaces:
    """Where, inside one host folder, a person installs their own things: *watch* globs (relative to
    the folder) of the entries to check, *units* a glob of the installer's own parts that can go on
    their own, *startup_marker* the text that marks the startup lines this folder needs."""

    watch: tuple[str, ...]
    units: str = ""
    startup_marker: str = ""


#: The host folders a person adds their own tools to, by their place under the home (KI-654).
PERSONS_PLACES = {
    ".nvm": PersonsPlaces(("versions/*/*", "versions/node/*/lib/node_modules/*", "versions/node/*/lib/node_modules/@*/*", "alias/*"),
                          units="versions/node/*", startup_marker="NVM_DIR"),
    ".local/share/uv": PersonsPlaces(("tools/*", "python/*")),
}


@dataclass(frozen=True)
class HostRemoval:
    """What removing the host takes, as the machine is now: ``remove`` (whole files and folders),
    ``kept`` (a host folder that stays, with what the person added to it since the install) and
    ``kept_markers`` (the startup-line markers of the kept folders: those lines stay too)."""

    remove: tuple[Path, ...] = ()
    kept: tuple[tuple[Path, tuple[Path, ...]], ...] = ()
    kept_markers: tuple[str, ...] = ()

    def keeps_block(self, block: str) -> bool:
        return any(marker in block for marker in self.kept_markers)


def _added_since(folder: Path, places: PersonsPlaces, since: float) -> tuple[Path, ...]:
    """The entries under *folder* in *places* that appeared or changed after *since* (their status
    time: a copy or an unpack can not set it back)."""
    found = []
    for pattern in places.watch:
        for entry in sorted(folder.glob(pattern)):
            try:
                if entry.lstat().st_ctime > since:
                    found.append(entry)
            except OSError:
                continue
    return tuple(dict.fromkeys(found))


def removal_for(host: tuple[Path, ...], installed_at: float, home: Path) -> HostRemoval:
    """:class:`HostRemoval` for the *host* paths an install listed at *installed_at* (epoch
    seconds) in *home*. Reads only."""
    remove: list[Path] = []
    kept: list[tuple[Path, tuple[Path, ...]]] = []
    markers: list[str] = []
    for path in host:
        places = PERSONS_PLACES.get(path.relative_to(home).as_posix()) if home in path.parents else None
        added = _added_since(path, places, installed_at) if places and path.is_dir() and not path.is_symlink() else ()
        if not added:
            remove.append(path)
            continue
        kept.append((path, added))
        markers += [places.startup_marker] if places.startup_marker else []
        for unit in sorted(path.glob(places.units)) if places.units else []:
            ours = unit.lstat().st_ctime <= installed_at
            if ours and not any(unit == entry or unit in entry.parents for entry in added):
                remove.append(unit)   # the installer's own Node version, holding nothing of the person's
    return HostRemoval(tuple(remove), tuple(kept), tuple(markers))


__all__ = ["PERSONS_PLACES", "HostRemoval", "PersonsPlaces", "removal_for"]
