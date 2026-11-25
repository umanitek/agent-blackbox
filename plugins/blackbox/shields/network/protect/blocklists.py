"""Network Shield's public block lists: the ``dns-blocklist`` pack kind and its downloader.

A list is DATA, one folder per list (``lists/hagezi-multi/list.json``), loaded and validated by
the shared pack loader (``shields/packs.py``) with :func:`validate_pack` as this kind's own
check. Adding a list is adding a folder. A supported list names:

* ``list.url`` — HTTPS on a host in :data:`ALLOWED_HOSTS` (a typo can never point the Shield at
  an arbitrary server);
* ``list.format`` — ``domains`` (one per line) or ``hosts`` (``0.0.0.0 name`` lines);
* ``list.licence`` — the terms it is used under (downloaded at run time, never bundled).

:func:`domains` downloads a chosen list once a day into Blackbox's own folder, capped at
:data:`MAX_LIST_BYTES`, and keeps the last good copy when a download fails. A list that cannot
be read contributes nothing — it never blocks everything. A redirect may only lead to HTTPS on
another :data:`ALLOWED_HOSTS` host (:class:`_StayOnAllowedHosts`; review 2026-11-21, finding 13):
otherwise a compromised or hijacked list host could hand the Shield any server's content. What a
list asks for is still held to ``never_block`` when the plan is built.

Usage::

    domains(pack)          # frozenset of normalised names, from cache when it is fresh
    cached_domains(pack)   # the same, from memory or disk only (the guard's hot path)

**Undo:** changes no system state — lists are downloaded into Blackbox's own data folder and
only reach DNS Shield through the plan; a list switched off leaves the next plan.
"""

from __future__ import annotations

import ipaddress
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Mapping, Optional

from ....kernel import constants
from ....kernel.bounded_files import atomic_write, read_small_text
from ....shields.contract import Pack
from ....shields.network.mode import normalise_entry

logger = logging.getLogger(__name__)

KINDS = ("dns-blocklist",)
FORMATS = ("domains", "hosts")
#: Where a list may be downloaded from.
ALLOWED_HOSTS = frozenset({"raw.githubusercontent.com", "small.oisd.nl", "big.oisd.nl"})
#: The largest list accepted (HaGeZi Multi is ~5 MB).
MAX_LIST_BYTES = 40 * 1024 * 1024
#: Most domains one list contributes.
MAX_DOMAINS = 1_500_000
#: How long a downloaded list is used before it is fetched again.
FRESH_SECONDS = 24 * 60 * 60
TIMEOUT_SECONDS = 60
#: Names a hosts file lists for itself; never blocked.
_NEVER_BLOCKED = frozenset({"localhost.localdomain", "local.host", "broadcasthost.local"})
_memory: dict[str, tuple[float, frozenset[str]]] = {}


def validate_pack(manifest: Mapping[str, Any]) -> Optional[str]:
    """The first problem with a supported list's ``list`` block, or None."""
    block = manifest.get("list")
    if not isinstance(block, dict):
        return "a block list names its list (url, format, licence)"
    url = urllib.parse.urlsplit(str(block.get("url") or ""))
    if url.scheme != "https" or url.hostname not in ALLOWED_HOSTS or url.username or url.password:
        return f"list.url must be https on one of: {', '.join(sorted(ALLOWED_HOSTS))}"
    if block.get("format") not in FORMATS:
        return f"list.format must be one of: {', '.join(FORMATS)}"
    if not isinstance(block.get("licence"), str) or not block["licence"].strip():
        return "list.licence must say the terms the list is used under"
    return None


def parse(text: str) -> frozenset[str]:
    """Names from a ``domains`` or ``hosts`` list (``#`` comments, blank lines and bad names skipped)."""
    names: set[str] = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        candidate = parts[1] if len(parts) == 2 and parts[0] in ("0.0.0.0", "127.0.0.1") else parts[0]
        name = normalise_entry(candidate.lstrip("*."))
        if name and not _is_ip(name) and name not in _NEVER_BLOCKED:
            names.add(name)
            if len(names) >= MAX_DOMAINS:
                break
    return frozenset(names)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _cache_path(pack: Pack) -> Path:
    return constants.blackbox_home() / "network-shield" / "lists" / f"{pack.id}.txt"


def domains(pack: Pack, now: Optional[float] = None) -> frozenset[str]:
    """The names list *pack* blocks: fresh from memory or disk, else downloaded; the last good
    copy when a download fails; empty when there has never been one."""
    now = time.time() if now is None else now
    cached = _memory.get(pack.id)
    if cached and now - cached[0] < FRESH_SECONDS:
        return cached[1]
    path = _cache_path(pack)
    try:
        age = now - path.stat().st_mtime
    except OSError:
        age = None
    if age is None or age >= FRESH_SECONDS:
        if _download(pack, path):
            age = 0
    text = read_small_text(str(path), MAX_LIST_BYTES, nofollow=True) if age is not None else None
    names = parse(text) if text else frozenset()
    _memory[pack.id] = (now, names)
    return names


def version(pack_id: str) -> float:
    """When the in-memory copy of list *pack_id* was loaded (0 when never): a plan built from
    the lists is rebuilt when this changes."""
    cached = _memory.get(pack_id)
    return cached[0] if cached else 0.0


def cached_domains(pack: Pack) -> frozenset[str]:
    """The names list *pack* blocks from memory or disk ONLY — never a download. For the guard's
    hot path (every tool call): a list that was never downloaded contributes nothing there."""
    cached = _memory.get(pack.id)
    if cached:
        return cached[1]
    text = read_small_text(str(_cache_path(pack)), MAX_LIST_BYTES, nofollow=True)
    names = parse(text) if text else frozenset()
    if names:
        _memory[pack.id] = (0.0, names)   # used on the hot path; :func:`domains` still refreshes it
    return names


class _StayOnAllowedHosts(urllib.request.HTTPRedirectHandler):
    """Follows a redirect only to HTTPS on an :data:`ALLOWED_HOSTS` host; refuses any other."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        target = urllib.parse.urlparse(newurl)
        if target.scheme != "https" or target.hostname not in ALLOWED_HOSTS or target.username or target.password:
            raise urllib.error.HTTPError(newurl, code, f"redirect off the allowed list hosts refused: {target.hostname}", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_StayOnAllowedHosts)


def _download(pack: Pack, path: Path) -> bool:
    url = str((pack.data.get("list") or {}).get("url") or "")   # type: ignore[union-attr]
    if validate_pack(pack.data) is not None:
        return False
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "Blackbox-Network-Shield"})
        with _OPENER.open(request, timeout=TIMEOUT_SECONDS) as response:
            body = response.read(MAX_LIST_BYTES + 1)
    except OSError as exc:
        logger.info("blackbox network shield: list %s not downloaded: %s", pack.id, exc)
        return False
    if len(body) > MAX_LIST_BYTES:
        logger.warning("blackbox network shield: list %s is over %d bytes; not used", pack.id, MAX_LIST_BYTES)
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(path, body)
    return True
