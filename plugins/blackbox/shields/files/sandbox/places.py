"""What an agent sandbox refuses, worked out once for every operating system (no OS calls here).

:class:`Places` is the policy a platform module (``platform/<os>.py``) renders into its own
sandbox language — Seatbelt on macOS today. Every path is the CANONICAL one (LES-105: links
resolved, ``..`` folded), because a kernel sandbox matches the path the kernel sees.

* the person's File Shield items — no read, no change, no link (a folder: everything inside);
* Blackbox's keys (``detection.blackbox_key_patterns``: the helper's key folder, key files in
  Blackbox's data folders) — the same;
* Blackbox's own places (its data folder, the plugin, every add-on folder beside it and the places
  add-ons declare) — readable, never changed, so an agent in the sandbox can not rewrite its own
  sandbox, switch Blackbox off or change an add-on; and every add-on MANIFEST, existing or not
  (``<plugins>/*/blackbox-addon.json``) — never written, so none is planted or removed;
* every folder ABOVE a protected item — never renamed or removed (``mv ~/Documents ~/D2`` would
  otherwise walk the item out from under its rule; files inside those folders stay writable);
* the shell startup files (``~/.zshrc`` …) — never written: the block that puts Blackbox's agent
  launchers first on PATH lives there, and an agent that removed it would send every later agent
  outside the sandbox (KI-535). Named as given AND resolved (a dotfiles link is closed at both ends);
* the places something starts from by itself, or the person runs from later (launchd jobs, login
  items, cron, OpenSSH's login files, Homebrew's prefix — named by the platform module,
  ``platform.startup_places``) — never written: a job an agent left there would run OUTSIDE the
  sandbox (security round 4);
* the canary — a file only a sandboxed process can not read: the proof a session really is
  inside (an agent can not fake it by setting a variable).

Usage::

    places = build(["~/Documents/Taxes"], key_patterns, own=["/Users/me/.hermes/blackbox"], canary=…)
    places.denied_folders     # ("/Users/me/Documents/Taxes",)
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class Places:
    """The sandbox's policy, canonical absolute paths throughout (see the module doc)."""

    denied_folders: tuple[str, ...]
    denied_files: tuple[str, ...]
    #: ``<folder>/<glob>`` — a key file named by its pattern (``…/blackbox/*.pem``).
    denied_globs: tuple[str, ...]
    no_write: tuple[str, ...]
    no_rename: tuple[str, ...]
    canary: str
    #: Files never written, created, renamed or removed (the shell startup files).
    no_write_files: tuple[str, ...] = ()
    #: ``*`` patterns never written, created, renamed or removed (every add-on's manifest).
    no_write_globs: tuple[str, ...] = ()
    #: Startup and PATH places (folders, files, ``*`` patterns) never written: see the module doc.
    startup_folders: tuple[str, ...] = ()
    startup_files: tuple[str, ...] = ()
    startup_globs: tuple[str, ...] = ()

    def watched(self) -> tuple[str, ...]:
        """Every refused place (a denial naming one of these is a File Shield hit)."""
        return self.denied_folders + self.denied_files


def canonical(path: str) -> str:
    """*path* as the kernel sees it: ``~`` expanded, links resolved, ``..`` folded."""
    return os.path.realpath(os.path.expanduser(path))


def _ancestors(path: str) -> list[str]:
    out = []
    parent = os.path.dirname(path)
    while parent and parent != "/":
        out.append(parent)
        parent = os.path.dirname(parent)
    return out


def _unique(values: Iterable[str]) -> tuple[str, ...]:
    """*values* in order, without repeats."""
    return tuple(dict.fromkeys(values))


def _canonical_glob(pattern: str) -> str:
    """*pattern* with the part before its first wildcard made canonical (the kernel matches real paths)."""
    parts = pattern.split(os.sep)
    fixed = next((index for index, part in enumerate(parts) if any(mark in part for mark in "*?[")), len(parts))
    head = os.sep.join(parts[:fixed]) or os.sep
    return os.path.join(canonical(head), *parts[fixed:])


def build(items: Iterable[str], key_patterns: Iterable[str], own: Iterable[str], canary: str,
          is_folder=os.path.isdir, startup_files: Iterable[str] = (), keep_in_place: Iterable[str] = (),
          no_write_globs: Iterable[str] = (),
          startup: tuple[Iterable[str], Iterable[str], Iterable[str]] = ((), (), ())) -> Places:
    """The policy for the person's *items* (as File Shield stores them), Blackbox's *key_patterns*
    (folders, or ``folder/glob``), Blackbox's *own* places, the *canary* file and the shell
    *startup_files* (absolute; they need not exist — every agent's hook config is passed here too:
    closed to writes the same way), and *keep_in_place* (folders never renamed or removed: the
    folders holding those configs, so ``mv ~/.claude …`` can not take the hook away), and
    *no_write_globs* (absolute ``*`` patterns never written: every add-on's manifest), *startup*
    (``(folders, files, globs)`` of the startup and PATH places, absolute). *is_folder* decides an item's kind (File
    Shield's own rule, so a not-yet-existing folder is a folder)."""
    startup_folders, startup_paths, startup_globs = startup
    folders: list[str] = []
    files: list[str] = []
    for item in items:
        (folders if is_folder(item) else files).append(canonical(item))
    globs: list[str] = []
    for pattern in key_patterns:
        if any(mark in os.path.basename(pattern) for mark in "*?["):
            globs.append(os.path.join(canonical(os.path.dirname(pattern)), os.path.basename(pattern)))
        else:
            folders.append(canonical(pattern))
    canary_path = canonical(canary)
    refused = folders + files + [os.path.dirname(glob) for glob in globs]
    above = [parent for place in refused for parent in _ancestors(place)]
    startup = [form for path in startup_files for form in (os.path.normpath(os.path.expanduser(path)), canonical(path))]
    return Places(denied_folders=_unique(folders), denied_files=_unique(files + [canary_path]), denied_globs=_unique(globs),
                  no_write=_unique(canonical(place) for place in own),
                  no_rename=_unique(above + [form for path in keep_in_place for form in (os.path.normpath(os.path.expanduser(path)),
                                                                                         canonical(path))]), canary=canary_path,
                  no_write_files=_unique(startup), no_write_globs=_unique(_canonical_glob(os.path.expanduser(g)) for g in no_write_globs),
                  startup_folders=_unique(form for path in startup_folders for form in (os.path.normpath(path), canonical(path))),
                  startup_files=_unique(form for path in startup_paths for form in (os.path.normpath(path), canonical(path))),
                  startup_globs=_unique(_canonical_glob(glob) for glob in startup_globs))
