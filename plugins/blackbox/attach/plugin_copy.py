"""Copying the plugin into an agent home, and finding where it came from.

:func:`_plugin_source_dir` resolves the checkout to copy from (an installed
copy points back to its source via ``.blackbox-source-root``);
:func:`copy_plugin_tree` copies it (minus caches/tests) and bundles the OpenClaw
JS plugin under ``_openclaw/``; :func:`_needs_copy` decides when an installed
copy is stale (version change or any newer shipped file).
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import shutil
import time
import uuid
from pathlib import Path
from typing import Optional
from ..kernel import constants, os_layout
from . import serial

logger = logging.getLogger(__name__)

_SOURCE_ROOT_MARKER = ".blackbox-source-root"
_INSTALL_STAMP_MARKER = ".blackbox-install-stamp"


# Files/dirs never copied into a target home's plugins/blackbox/ — build
# artifacts and the plugin's own tests have no business in a runtime home.
_COPY_EXCLUDE_DIRS = {"__pycache__", "tests", ".pytest_cache", "node_modules", "target"}   # target: the helper crate's build output
_COPY_EXCLUDE_SUFFIXES = (".pyc", ".pyo")

# The OpenClaw JS plugin is bundled inside an installed copy under this name so
# OpenClaw always has something to load, even when Blackbox was copied into a
# user home with no sibling ``integrations/`` (see ``_openclaw_plugin_source``).
_BUNDLED_OPENCLAW_DIRNAME = "_openclaw"

#: Where a copy is built and the previous one set aside: beside ``plugins/``, never inside it
#: (Hermes would scan it as a plugin).
_ASIDE_DIRNAME = ".blackbox-attach-copy"
#: A staging folder older than this was left by a writer that died mid-copy; the next copy removes it.
_STALE_STAGING_S = 3600.0
#: How often the swap is tried when another process puts its copy in place between our two renames.
_SWAP_ATTEMPTS = 3


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def _plugin_source_dir() -> Path:
    """Absolute path to this plugin's copy source.

    Installed copies carry ``.blackbox-source-root`` pointing back to the
    checkout that produced them. Prefer that checkout when it still exists so a
    re-run of ``hermes blackbox attach`` refreshes stale user-plugin files from
    the repo instead of copying the installed copy onto itself.
    """
    # this file is plugins/blackbox/attach/plugin_copy.py -> the plugin root is two up
    own = Path(__file__).resolve().parents[1]
    marker = own / _SOURCE_ROOT_MARKER
    try:
        if marker.exists():
            root = Path(marker.read_text(encoding="utf-8-sig").strip()).expanduser()
            candidate = (root / "plugins" / "blackbox").resolve()
            if candidate.is_dir() and candidate != own:
                return candidate
    except Exception:
        pass
    return own


def repo_root() -> Path:
    """Best-effort repo root: ``<repo>/plugins/blackbox`` → ``<repo>``."""
    return _plugin_source_dir().parents[1]


# ---------------------------------------------------------------------------
# Plugin file copy (dedup, version-aware)
# ---------------------------------------------------------------------------


def _installed_plugin_version(dest: Path) -> Optional[str]:
    """Read ``__version__`` from an installed copy's ``kernel/constants.py`` (cheap parse).

    An install made before the kernel/ layout has no such file, so it reads as
    ``None`` — a version mismatch — and is replaced by a fresh copy.
    """
    const_path = dest / "kernel" / "constants.py"
    if not const_path.exists():
        return None
    try:
        for line in const_path.read_text(encoding="utf-8-sig").splitlines():
            stripped = line.strip()
            if stripped.startswith("__version__"):
                _, _, rhs = stripped.partition("=")
                return rhs.strip().strip("'\"")
    except Exception:
        return None
    return None


def _needs_copy(dest: Path) -> bool:
    """True when the plugin should be (re)copied: missing, version bump, or a
    same-version in-place source edit (so dev iteration propagates without a
    manual version bump)."""
    init = dest / "__init__.py"
    if not init.exists():
        return True
    if _installed_plugin_version(dest) != constants.__version__:
        return True
    try:
        src_dir = _plugin_source_dir()
        if not _is_openclaw_plugin_dir(dest / _BUNDLED_OPENCLAW_DIRNAME):
            checkout = _source_checkout_root(src_dir)
            candidates = [src_dir / _BUNDLED_OPENCLAW_DIRNAME]
            if checkout is not None:
                candidates.append(checkout / "integrations" / "openclaw")
            if any(_is_openclaw_plugin_dir(candidate) for candidate in candidates):
                return True
        stamp = dest / _INSTALL_STAMP_MARKER
        installed_at = stamp.stat().st_mtime if stamp.exists() else init.stat().st_mtime
        # Every file the copy ships counts, not just *.py: a dashboard-only
        # change (static/index.html) must refresh the installed copy too, or
        # existing installs keep serving the old page indefinitely.
        newest_src = max(
            p.stat().st_mtime
            for p in src_dir.rglob("*")
            if p.is_file()
            and not _COPY_EXCLUDE_DIRS.intersection(p.relative_to(src_dir).parts)
            and not p.name.endswith(_COPY_EXCLUDE_SUFFIXES)
        )
        return newest_src > installed_at
    except Exception:  # pragma: no cover - best effort
        return False


def _copy_ignore(folder: str, names: list[str]) -> list[str]:
    # Another operating system's platform/ modules are left out too (kernel.os_layout): a Mac's
    # copy holds no Windows or Linux files.
    skipped = [n for n in names if n in _COPY_EXCLUDE_DIRS or n.endswith(_COPY_EXCLUDE_SUFFIXES)]
    return skipped + [n for n in os_layout.other_os_entries(folder, names) if n not in skipped]


@serial.serialized
def copy_plugin_tree(src: Path, dest: Path) -> None:
    """Copy the plugin tree from *src* to *dest*, excluding pycache/tests and other operating
    systems' platform modules.

    Replaces any existing copy so a version bump fully refreshes the files, and
    bundles the OpenClaw JS plugin so an installed copy can still point OpenClaw
    at it (an installed ``plugins/blackbox`` has no sibling ``integrations/``).
    Raises ``OSError`` when the copy cannot be made; *dest* then still holds the previous copy.
    """
    # Built beside, then swapped in by two renames — the installer's own refresh (KI-644). WHY here
    # too (fix wave W12, macOS VM: an upgrade over a running install failed in `blackbox attach` with
    # "[Errno 17] File exists: …/plugins/blackbox/shields"): the running dashboard and hooks import
    # from the copy and write fresh __pycache__ folders while rmtree + copytree replace it in place.
    # A rename is atomic and does not care what runs from the folder.
    # WHY a unique staging name per call, and only our own removed (review 2026-11-26, LES-167): two
    # writers shared "new-<pid>" and the last step removed the whole aside folder — another writer's
    # half-built copy with it — and an agent's plugin folder was left missing.
    aside = dest.parent.parent / _ASIDE_DIRNAME
    aside.mkdir(parents=True, exist_ok=True)
    _remove_stale_staging(aside)
    token = f"{os.getpid()}-{uuid.uuid4().hex}"
    staged, old_copy = aside / f"new-{token}", aside / f"old-{token}"
    try:
        shutil.copytree(src, staged, ignore=_copy_ignore)
        _bundle_openclaw_plugin(src, staged)
        (staged / _INSTALL_STAMP_MARKER).write_text(constants.__version__, encoding="utf-8")
        source_root = _source_checkout_root(src)
        if source_root is not None:
            try:
                (staged / _SOURCE_ROOT_MARKER).write_text(str(source_root), encoding="utf-8")
            except OSError:
                pass
        dest.parent.mkdir(parents=True, exist_ok=True)
        _swap_in(staged, dest, old_copy)
    finally:
        _remove(staged)
        if dest.exists():   # WHY the check: when the swap and its roll-back both failed, old_copy is the only copy
            _remove(old_copy)
        with contextlib.suppress(OSError):
            aside.rmdir()   # only when empty: another writer may be staging there


def _swap_in(staged: Path, dest: Path, old_copy: Path) -> None:
    """Put *staged* at *dest* by renames, the previous copy set aside at *old_copy*. On a failure
    the previous copy is put back and the error raised. When another process swaps its own copy in
    between our two renames, the swap is tried again (at most :data:`_SWAP_ATTEMPTS` times)."""
    for attempt in range(_SWAP_ATTEMPTS):
        moved = False
        if dest.exists() or dest.is_symlink():
            _remove(old_copy)   # a retry: the copy set aside first is older than the one there now
            os.rename(dest, old_copy)
            moved = True
        try:
            os.rename(staged, dest)
            return
        except OSError:
            if dest.exists() or dest.is_symlink():   # another writer's copy landed meanwhile
                if attempt + 1 < _SWAP_ATTEMPTS:
                    continue
                raise
            if moved:
                os.rename(old_copy, dest)
            raise


def _remove(path: Path) -> None:
    """Remove a folder or a link to one; a missing path is fine."""
    if path.is_symlink():
        with contextlib.suppress(OSError):
            path.unlink()
    else:
        shutil.rmtree(path, ignore_errors=True)


def _remove_stale_staging(aside: Path) -> None:
    """Remove staging folders a writer that died mid-copy left behind (older than :data:`_STALE_STAGING_S`)."""
    cutoff = time.time() - _STALE_STAGING_S
    try:
        entries = list(aside.iterdir())
    except OSError:
        return
    for entry in entries:
        try:
            if entry.lstat().st_mtime < cutoff:
                _remove(entry)
        except OSError:
            continue


def _source_checkout_root(src: Path) -> Optional[Path]:
    try:
        resolved = src.resolve()
        root = resolved.parents[1]
        if (root / ".git").exists() and (root / "plugins" / "blackbox").resolve() == resolved:
            return root
    except Exception:
        return None
    return None


def _bundle_openclaw_plugin(src: Path, dest: Path) -> None:
    """Ensure the OpenClaw JS plugin lives at ``dest/_openclaw``.

    Sourced from the source copy's own bundle (a re-copy from another installed
    copy) or the repo checkout (the first copy from ``integrations/openclaw``).
    Best-effort: bundling must never break the Hermes/Python attach, so any
    failure is logged and swallowed — OpenClaw attach then reports itself
    unprotected via ``_openclaw_load_paths_entry`` rather than crashing.
    """
    dest_bundle = dest / _BUNDLED_OPENCLAW_DIRNAME
    if _is_openclaw_plugin_dir(dest_bundle):
        return  # copytree already carried a valid bundle over from *src*
    checkout = _source_checkout_root(src)
    checkout_integration = checkout / "integrations" / "openclaw" if checkout is not None else None
    for candidate in (src / _BUNDLED_OPENCLAW_DIRNAME, checkout_integration, _repo_openclaw_dir()):
        if candidate is None:
            continue
        if not _is_openclaw_plugin_dir(candidate):
            continue
        try:
            if dest_bundle.exists():
                shutil.rmtree(dest_bundle)
            shutil.copytree(candidate, dest_bundle, ignore=_openclaw_ignore)
        except Exception as exc:  # pragma: no cover - best effort
            logger.debug("blackbox.attach: bundling OpenClaw plugin failed: %s", exc)
        return


def _openclaw_ignore(_dir: str, names: list[str]) -> list[str]:
    """Exclude deps/test dirs from the bundled OpenClaw plugin. ``dist`` is KEPT: since
    2026-11-20 it holds the one file OpenClaw loads (``dist/index.js``, built from ``src/``)."""
    skip = {"node_modules", ".turbo", "test", "tests", "__pycache__"}
    return [n for n in names if n in skip or n.endswith((".pyc", ".log", ".tsbuildinfo"))]


# ---------------------------------------------------------------------------
# OpenClaw attach / detach
# ---------------------------------------------------------------------------


def _repo_openclaw_dir() -> Path:
    """The OpenClaw JS plugin in a repo checkout (sibling ``integrations/``)."""
    return repo_root() / "integrations" / "openclaw"


def _bundled_openclaw_dir() -> Path:
    """The OpenClaw JS plugin bundled inside this (possibly installed) copy."""
    return _plugin_source_dir() / _BUNDLED_OPENCLAW_DIRNAME


def _is_openclaw_plugin_dir(path: Path) -> bool:
    """True when *path* is the OpenClaw plugin (identified by its manifest) AND every entry
    file its ``package.json`` names is there — a copy without its entry (one made before
    ``dist`` was shipped) would be wired into OpenClaw only to fail there, and OpenClaw then
    refuses to run the agent; better reported as "OpenClaw not protected"."""
    try:
        if not (path / "openclaw.plugin.json").is_file():
            return False
        package = path / "package.json"
        if not package.is_file():
            return True
        entries = (json.loads(package.read_text(encoding="utf-8-sig")).get("openclaw") or {}).get("extensions") or []
        return all((path / str(entry)).is_file() for entry in entries)
    except Exception:
        return False
