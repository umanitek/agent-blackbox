"""Legacy anchors — what the verified graph held before curator envelopes.

The legacy asset list (trust-and-threat-lab §03.4, D24): the release file
``legacy_assets.txt`` beside this module names the assets confirmed before
curator manifest v1; :func:`verified_legacy_assets` hands it out only when its
hash equals the trusted manifest's ``legacy_assets_hash`` pin. (The proof-era
anchor hashes that once lived here had no caller and were removed 2026-11-11.)

Usage::

    legacy = verified_legacy_assets(manifest.legacy_assets_hash)
    if legacy.uals is not None: ...   # the list may be trusted this refresh
    elif legacy.refused: ...          # SECURITY alarm: keep the last-good tiers
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from ..kernel.signing import key_manifest

logger = logging.getLogger(__name__)

#: The shipped legacy asset list: one UAL per line, ``#`` comments and blank lines ignored.
LEGACY_ASSETS_FILE = Path(__file__).with_name("legacy_assets.txt")

# ---------------------------------------------------------------------------
# The legacy asset list (D24)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LegacyAssets:
    """The legacy list as one refresh may use it. ``uals`` — the verified list
    (None: not usable this refresh); ``refused`` — why a pinned list was refused
    ("" when it matched, or when no trusted manifest pins one)."""

    uals: Optional[frozenset[str]] = None
    refused: str = ""


def load_legacy_assets(path: Optional[Path] = None) -> Optional[frozenset[str]]:
    """The UALs in the list file (default :data:`LEGACY_ASSETS_FILE`); None when it cannot be read."""
    try:
        text = (path or LEGACY_ASSETS_FILE).read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        logger.warning("blackbox: legacy asset list not readable: %s", exc)
        return None
    return frozenset(line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#"))


def legacy_list_hash(uals: Iterable[str]) -> str:
    """The list's pin — the same sha256 the manifest signs (:func:`key_manifest.legacy_assets_hash`)."""
    return key_manifest.legacy_assets_hash(uals)


def verified_legacy_assets(pinned_hash: str, path: Optional[Path] = None) -> LegacyAssets:
    """The list file, read now, checked against *pinned_hash* (the trusted
    manifest's ``legacy_assets_hash``; "" = no trusted manifest, nothing to check
    against, so the list is not used and nothing is wrong). A list that is
    missing or whose hash differs is REFUSED — the caller keeps the last-good
    tiers and raises the alarm; it never treats the corpus as unlisted."""
    if not pinned_hash:
        return LegacyAssets()
    uals = load_legacy_assets(path)
    if uals is None:
        return LegacyAssets(refused="the shipped legacy asset list could not be read")
    if legacy_list_hash(uals) != pinned_hash:
        logger.warning("blackbox: SECURITY — the shipped legacy asset list does not match the curator "
                       "manifest's pin; the last-good asset tiers stay in force")
        return LegacyAssets(refused="the shipped legacy asset list does not match the curator manifest's pin")
    return LegacyAssets(uals=uals)
