"""Which file an install reads, which reader reads it, and the cache that makes a repeat free (KI-595).

The readers are Strategies chosen by file name (:data:`READERS`); :func:`files_for` names the
files an :class:`~.commands.InstallSite` installs from, in the order its manager prefers them
(a lockfile before its manifest); :func:`read` reads one through ``kernel.bounded_files`` (a
non-blocking open, a regular-file check, :data:`MAX_FILE_BYTES`, no symlink at the last part).

The cache is keyed by the file's path and its ``(size, mtime, inode, ctime)``: an unchanged file
answers from memory without being opened (microseconds). A file whose stamp moved is read and
hashed; when its content hash is the one cached it is not parsed again. Every failure — missing,
unreadable, too large, unparsable, a format no reader knows — is a :class:`FileRead` with a
``note`` saying so, never an exception and never silence.

Usage::

    found = read("/app/package-lock.json")
    found.graph, found.note          # DependencyGraph | None, "" | "package-lock.json is larger than 25 MB"
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import tomllib
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable, Optional

from ...kernel.bounded_files import read_small_text
from . import cargo_gem, npm_json, npm_text, python_files
from .commands import InstallSite
from .model import DependencyGraph

#: The largest dependency file read (a big monorepo lockfile is ~10 MB); a larger one is a note.
MAX_FILE_BYTES = 25 * 1024 * 1024
#: How deep ``-r`` includes are followed, and how many files one install may read.
MAX_INCLUDE_DEPTH = 5
MAX_FILES = 20
#: How many parsed files are kept in memory.
CACHE_ENTRIES = 64

Reader = Callable[[str, str], DependencyGraph]

READERS: dict[str, Reader] = {
    "package-lock.json": npm_json.read_package_lock,
    "npm-shrinkwrap.json": npm_json.read_package_lock,
    ".package-lock.json": npm_json.read_package_lock,
    "package.json": npm_json.read_package_json,
    "pnpm-lock.yaml": npm_text.read_pnpm_lock,
    "yarn.lock": npm_text.read_yarn_lock,
    "bun.lock": npm_text.read_bun_lock,
    "uv.lock": python_files.read_uv_lock,
    "poetry.lock": python_files.read_poetry_lock,
    "Pipfile.lock": python_files.read_pipfile_lock,
    "Pipfile": python_files.read_pipfile,
    "pyproject.toml": python_files.read_pyproject,
    "Cargo.lock": cargo_gem.read_cargo_lock,
    "Gemfile.lock": cargo_gem.read_gemfile_lock,
}
_REQUIREMENTS_NAME = re.compile(r"^(?:requirements|constraints)[\w.-]*\.(?:txt|in)$", re.IGNORECASE)

#: Files a manager may install from that no reader reads, with what to tell the person.
UNSUPPORTED = {
    "bun.lockb": "bun.lockb is bun's binary lockfile and is not read (bun writes a text bun.lock "
                 "with `bun install --save-text-lockfile`)",
    "Cargo.toml": "Cargo.toml's version requirements resolve only when cargo runs; with no Cargo.lock "
                  "the crates are checked after the build writes one",
    "Gemfile": "a Gemfile without Gemfile.lock is not read; its gems are checked once bundler writes the lock",
    "setup.py": "setup.py is code, not data — its dependencies are not read",
}

#: The files each manager installs from, most authoritative first; the first that exists is read.
LOCKFILES: dict[str, tuple[str, ...]] = {
    "npm": ("npm-shrinkwrap.json", "package-lock.json", "node_modules/.package-lock.json"),
    "pnpm": ("pnpm-lock.yaml",), "yarn": ("yarn.lock",), "bun": ("bun.lock",),
    "uv": ("uv.lock",), "poetry": ("poetry.lock",), "pipenv": ("Pipfile.lock",),
    "cargo": ("Cargo.lock",), "bundle": ("Gemfile.lock",),
}
_MANIFESTS: dict[str, tuple[str, ...]] = {
    "npm": ("package.json",), "pnpm": ("package.json",), "yarn": ("package.json",), "bun": ("bun.lockb", "package.json"),
    "uv": ("pyproject.toml",), "poetry": ("pyproject.toml",), "pipenv": ("Pipfile",),
    "cargo": ("Cargo.toml",), "bundle": ("Gemfile",), "pip": ("pyproject.toml", "setup.py"),
    "uv-pip": ("pyproject.toml", "setup.py"),
}
_PARSE_ERRORS = (ValueError, TypeError, KeyError, AttributeError, IndexError, tomllib.TOMLDecodeError,
                 json.JSONDecodeError, RecursionError)


@dataclass(frozen=True)
class FileRead:
    """One file's packages (*graph*) or why there are none (*note*; "" when read)."""

    path: str
    graph: Optional[DependencyGraph]
    note: str = ""


def reader_for(name: str, explicit: bool = False) -> Optional[Reader]:
    """The reader for a file called *name*; a requirements file named on the command line
    (*explicit*) is read as one whatever it is called."""
    found = READERS.get(name)
    if found is None and (explicit or _REQUIREMENTS_NAME.match(name)):
        return python_files.read_requirements
    return found


@dataclass
class _Entry:
    stamp: tuple[int, int, int, int]
    digest: str
    graph: DependencyGraph


class _ParsedFiles:
    """The parsed-file cache (see the module doc). Thread-safe; at most :data:`CACHE_ENTRIES`."""

    def __init__(self) -> None:
        self._entries: OrderedDict[str, _Entry] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, path: str, stamp: tuple[int, int, int, int]) -> Optional[_Entry]:
        with self._lock:
            entry = self._entries.get(path)
            if entry is not None:
                self._entries.move_to_end(path)
            return entry if entry is not None and entry.stamp == stamp else None

    def by_digest(self, path: str, digest: str) -> Optional[_Entry]:
        with self._lock:
            entry = self._entries.get(path)
            return entry if entry is not None and entry.digest == digest else None

    def put(self, path: str, entry: _Entry) -> None:
        with self._lock:
            self._entries[path] = entry
            self._entries.move_to_end(path)
            while len(self._entries) > CACHE_ENTRIES:
                self._entries.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


PARSED = _ParsedFiles()


def parse_text(text: str, name: str, explicit: bool = False) -> FileRead:
    """*text* read as the file *name* would be (for a write's new content); never raises."""
    reader = reader_for(name, explicit)
    if reader is None:
        return FileRead(name, None, f"{name}: {UNSUPPORTED.get(name, 'no reader for this file')}")
    try:
        return FileRead(name, reader(text, name))
    except _PARSE_ERRORS as exc:
        return FileRead(name, None, f"{name} could not be parsed ({type(exc).__name__})")


def read(path: str, explicit: bool = False) -> FileRead:
    """The packages of the file at *path* (absolute), through the cache; never raises."""
    name = os.path.basename(path)
    if reader_for(name, explicit) is None:
        return FileRead(path, None, f"{name}: {UNSUPPORTED.get(name, 'no reader for this file')}")
    try:
        info = os.lstat(path)
    except OSError:
        return FileRead(path, None, f"{name} is missing")
    if info.st_size > MAX_FILE_BYTES:
        return FileRead(path, None, f"{name} is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB")
    stamp = (info.st_size, info.st_mtime_ns, info.st_ino, info.st_ctime_ns)
    cached = PARSED.get(path, stamp)
    if cached is not None:
        return FileRead(path, cached.graph)
    text = read_small_text(path, MAX_FILE_BYTES, nofollow=True)
    if text is None:
        return FileRead(path, None, f"{name} could not be read (not a regular file, a symlink, or unreadable)")
    digest = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
    same = PARSED.by_digest(path, digest)
    if same is not None:
        PARSED.put(path, _Entry(stamp, digest, same.graph))
        return FileRead(path, same.graph)
    parsed = parse_text(text, name, explicit)
    if parsed.graph is not None:
        PARSED.put(path, _Entry(stamp, digest, parsed.graph))
    return FileRead(path, parsed.graph, parsed.note)


def first_existing(folder: str, names: tuple[str, ...]) -> str:
    """The first of *names* that exists in *folder* ("" when none does)."""
    for name in names:
        path = os.path.join(folder, name)
        if os.path.lexists(path):
            return path
    return ""


def _requirements(paths: tuple[str, ...]) -> list[FileRead]:
    """Requirements files and their ``-r`` / ``-c`` includes, :data:`MAX_INCLUDE_DEPTH` deep, at most :data:`MAX_FILES`."""
    found: list[FileRead] = []
    seen: set[str] = set()
    pending = [(path, 0) for path in paths]
    while pending and len(found) < MAX_FILES:
        path, depth = pending.pop(0)
        if path in seen:
            continue
        seen.add(path)
        current = read(path, explicit=True)
        found.append(current)
        if current.graph is None:
            continue
        for include in current.graph.includes:
            target = os.path.normpath(os.path.join(os.path.dirname(path), os.path.expanduser(include)))
            if depth + 1 > MAX_INCLUDE_DEPTH:
                found.append(FileRead(target, None, f"{os.path.basename(target)}: included more than "
                                                    f"{MAX_INCLUDE_DEPTH} files deep — not read"))
            else:
                pending.append((target, depth + 1))
    if pending:
        found.append(FileRead("", None, f"more than {MAX_FILES} requirements files — the rest were not read"))
    return found


def files_for(site: InstallSite) -> list[FileRead]:
    """What a manifest install *site* installs from, read: its requirements files, else its lockfile,
    else its manifest (ranges) — or one :class:`FileRead` whose note says why nothing could be read."""
    if site.files:
        return _requirements(site.files)
    if not site.folder:
        return [FileRead("", None, "the folder the install runs in is not known")]
    if not site.project:
        lockfile = first_existing(site.folder, LOCKFILES.get(site.manager, ()))
        if lockfile:
            return [read(lockfile)]
        if site.strict:
            return [FileRead("", None, "npm ci found no package-lock.json or npm-shrinkwrap.json")]
    manifest = first_existing(site.folder, _MANIFESTS.get(site.manager, ()))
    if not manifest:
        return [FileRead("", None, f"no lockfile or manifest for {site.manager} in the install's folder")]
    return [read(manifest)]


#: The lockfile a manager writes when there is none yet (the others have only one).
_WRITES = {"npm": "package-lock.json"}


def lockfile_for(site: InstallSite) -> str:
    """The lockfile the manager of *site* uses or writes in its folder ("" for pip, which writes none)."""
    names = LOCKFILES.get(site.manager, ())
    if not names or not site.folder:
        return ""
    return first_existing(site.folder, names) or os.path.join(site.folder, _WRITES.get(site.manager, names[0]))
