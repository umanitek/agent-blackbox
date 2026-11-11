"""Trader Shield's ``desktop-app`` and ``cli-key-file`` kinds: wallets that live in an app's own folder.

A browser wallet hides in extension storage (:mod:`.browser_extension`); these keep
their keys in a fixed folder or file of their own, named by each supported pack's
``places`` (``wallets/<id>/wallet.json``). The places were found by installing the
real software and looking (bench bb-trader-1, Ubuntu 24.04, 2026-10-13): Exodus's
``exodus.wallet`` folder, Electrum's ``wallets`` folders, the Solana CLI's
``~/.config/solana/*.json`` key files. Everything inside a place is protected.

A ``cli-key-file`` pack may also carry a ``pointer``: a settings file whose
``<key>: value`` line names the key file in use, which may be anywhere (the Solana
CLI's ``cli/config.yml`` and its ``keypair_path``). :class:`PointerFiles` reads that
one file through the kernel's bounded reader with the manifest's ``max_bytes``,
takes only the line that starts with the literal ``<key>:`` (the key is never made
into a regular expression — a manifest supplies no pattern) and protects the file
it names. Only the settings file is opened, never the key.

Paths are compared lower-cased on both sides (macOS and Windows file names ignore
case); a template is expanded from the environment at the time of the check, so
``$XDG_CONFIG_HOME`` and ``%APPDATA%`` follow the machine. Place matching compares
path segments: a ``*`` in a template stands for one or more characters inside one
segment — no regular expression is built from manifest text.

Moved here from ``detection/app_wallets.py`` (since deleted), built from packs instead of
its ``APP_WALLETS`` rows.

Pattern: Specification — a pack is data (places, pointer); one matcher serves every pack.

Usage::

    matcher = AppFolderMatcher(mode.wallet_packs())
    matcher.owner(normalize_path("~/.electrum/wallets/default_wallet"))   # -> Owner("electrum", "Electrum")
    matcher.existing()   # -> [("/home/u/.config/exodus/exodus.wallet", Owner("exodus", "Exodus")), ...]
"""

from __future__ import annotations

import glob
import os
import re
import threading
from typing import Any, Iterable, Mapping, Optional

from ....kernel.bounded_files import read_small_text
from ...contract import Pack
from ...packs import COMMON_FIELDS, MANIFEST_MAX_BYTES
from .browser_extension import Owner

#: The pack kinds this module serves (their kind-block validator is :func:`validate_pack`).
KINDS = ("desktop-app", "cli-key-file")
_FIELDS = frozenset({"places", "pointer", "label"})
_QUOTES = ("'", '"')


def validate_pack(manifest: Mapping[str, Any]) -> Optional[str]:
    """The first problem with an app-folder pack's kind block, or None. The loader has
    already checked each ``places`` template and the ``pointer`` itself."""
    unknown = sorted(set(manifest) - COMMON_FIELDS - _FIELDS)
    if unknown:
        return f"a {manifest.get('kind')} pack has no field {unknown[0]!r}"
    if not manifest.get("places"):
        return "places must name at least one path template"
    if not isinstance(manifest.get("label"), str) or not manifest["label"].strip():
        return "label must say what the dashboard calls this wallet"
    return None


def expand_template(template: str, *, keep_unset: bool = False) -> str:
    """A pack path template (``$XDG_CONFIG_HOME/google-chrome*``, ``%APPDATA%/Exodus``) or a
    path read from a wallet's config, as a path on this machine now: ``/`` separators, case kept.

    The ONE rule for where a wallet keeps its files. A root comes from the environment, and an
    empty variable counts as unset (the XDG spec; an empty value would make the glob relative to
    the current folder). An unset root is its default (``$XDG_CONFIG_HOME`` → ``~/.config``,
    ``%APPDATA%`` → ``~/AppData/Roaming``, ``%LOCALAPPDATA%`` → ``~/AppData/Local``), except
    that with *keep_unset* a ``%VAR%`` stays literal: the app-place matcher then still matches a
    command that names it the same way, and never looks for it on disk.

    Paths an AGENT hands in are read by ``browser_extension.normalize_path`` instead, on
    purpose: that one asks what the shell would open, so an unset variable stays as written."""
    home = os.path.expanduser("~")
    defaults = {"XDG_CONFIG_HOME": os.path.join(home, ".config"), "APPDATA": os.path.join(home, "AppData", "Roaming"),
                "LOCALAPPDATA": os.path.join(home, "AppData", "Local")}

    def root(name: str, written: str) -> str:
        value = os.environ.get(name) or ("" if keep_unset and written.startswith("%") else defaults.get(name, ""))
        return value or written

    text = template.replace("$XDG_CONFIG_HOME", root("XDG_CONFIG_HOME", "$XDG_CONFIG_HOME"))
    text = re.sub(r"%([A-Za-z_]+)%", lambda m: root(m.group(1), m.group(0)), text)
    return os.path.normpath(os.path.expanduser(text)).replace("\\", "/")


def _absolute(place: str) -> str:
    """:func:`expand_template` (unset ``%VAR%`` kept), lower-cased — how wallet paths are
    compared (macOS and Windows file names ignore case)."""
    return expand_template(place, keep_unset=True).lower()


def _segment_matches(template_segment: str, segment: str) -> bool:
    """Whether one path *segment* fits one template segment, where each ``*`` stands for
    one or more characters (the literal pieces must appear in order, nothing else)."""
    if "*" not in template_segment:
        return template_segment == segment
    first, *middle, last = template_segment.split("*")
    if not (segment.startswith(first) and segment.endswith(last)):
        return False
    position, end = len(first), len(segment) - len(last)
    for piece in middle:
        found = segment.find(piece, position + 1)
        if found < 0:
            return False
        position = found + len(piece)
    return end - position >= 1


def _inside_place(normalized: str, place: str) -> bool:
    """Whether the *normalized* path is the place (a template, expanded now) or lies inside it."""
    wanted = _absolute(place).split("/")
    parts = normalized.split("/")
    return len(parts) >= len(wanted) and all(map(_segment_matches, wanted, parts))


def _pointer_value(line: str, prefix: str) -> Optional[str]:
    """The path a ``<key>: value`` *line* names (one pair of surrounding quotes dropped),
    or None when the line does not start with *prefix* or its value is empty or quoted oddly."""
    if not line.startswith(prefix):
        return None
    value = line[len(prefix):].strip()
    if value[:1] in _QUOTES:
        value = value[1:]
    if value[-1:] in _QUOTES:
        value = value[:-1]
    value = value.strip()
    return value if value and not any(quote in value for quote in _QUOTES) else None


class PointerFiles:
    """The key file each pack's ``pointer`` config names, re-read only when the config's
    path or modification time changes. One lock. None when there is no config, it is not
    a small regular file, or it names none."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cache: dict[str, tuple[str, float, Optional[str]]] = {}

    def get(self, pack: Pack) -> Optional[str]:
        """The normalized path of the key file *pack*'s pointer names now, or None."""
        pointer = pack.data.get("pointer")
        if not isinstance(pointer, dict):
            return None
        max_bytes = pointer.get("max_bytes", MANIFEST_MAX_BYTES)   # the loader checked it: 1..64 KB
        if not isinstance(max_bytes, int):
            return None
        config_path = expand_template(str(pointer["config"]), keep_unset=True)
        try:
            mtime = os.path.getmtime(config_path)
        except OSError:
            return None
        with self._lock:
            cached = self._cache.get(pack.id)
            if cached and cached[:2] == (config_path, mtime):
                return cached[2]
        path = self._read(config_path, str(pointer["key"]), max_bytes)
        with self._lock:
            self._cache[pack.id] = (config_path, mtime, path)
        return path

    @staticmethod
    def _read(config_path: str, key: str, max_bytes: int) -> Optional[str]:
        text = read_small_text(config_path, max_bytes)
        if text is None:
            return None
        prefix = key + ":"
        for line in text.splitlines():
            value = _pointer_value(line, prefix)
            if value:
                return _absolute(value)
        return None

    def reset(self) -> None:
        with self._lock:
            self._cache.clear()


POINTER_FILES = PointerFiles()


def _places(pack: Pack) -> tuple[str, ...]:
    places = pack.data.get("places")
    return tuple(str(place) for place in places) if isinstance(places, list) else ()


class AppFolderMatcher:
    """Every supported ``desktop-app`` / ``cli-key-file`` pack in *packs* (other kinds and
    statuses are skipped), matched by its ``places`` and its ``pointer``."""

    def __init__(self, packs: Iterable[Pack]) -> None:
        self.packs = tuple(pack for pack in packs if pack.status == "supported" and pack.kind in KINDS)
        self._places = tuple((Owner(pack.id, pack.name), _places(pack)) for pack in self.packs)

    def owner(self, normalized: str) -> Optional[Owner]:
        """The pack whose keys the *normalized* path (``normalize_path``) lies inside, or None."""
        if not normalized:
            return None
        for owner, places in self._places:
            if any(_inside_place(normalized, place) for place in places):
                return owner
        for pack in self.packs:
            configured = POINTER_FILES.get(pack)
            if configured and normalized == configured:
                return Owner(pack.id, pack.name)
        return None

    def existing(self) -> list[tuple[str, Owner]]:
        """``[(place as it is on disk, owner)]`` for every place present on this machine (a
        bounded glob over the packs' places; nothing inside is opened), then each pointer's key
        file. Case is kept: callers that match lower-case it (``normalize_path``)."""
        found: list[tuple[str, Owner]] = []
        for owner, places in self._places:
            for place in places:
                pattern = expand_template(place, keep_unset=True)
                if "%" in pattern:
                    continue
                for match in glob.glob(pattern):
                    found.append((match.replace("\\", "/"), owner))
        for pack in self.packs:
            configured = POINTER_FILES.get(pack)
            if configured and os.path.exists(configured) and \
                    all(configured != place.lower() for place, _ in found):
                found.append((configured, Owner(pack.id, pack.name)))
        return found
