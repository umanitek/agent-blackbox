"""Source API keys (abuse.ch Auth-Key, PhishTank app key…) for the curator node only (§03.3, F-005).

Read from ``<curate home>/sources/credentials.json`` — a JSON object of
``{source name: key}`` — which must be mode 0600: a file any other user can
read is REFUSED, never used. Curate-only, never ``kernel/config.py``; key
values never appear in an error message or a log.

Usage::

    key = load_credentials().get("urlhaus")   # None → that source answers UNAVAILABLE
"""

from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Callable, Mapping, Optional

from .. import keys

_FILE = "credentials.json"


class CredentialsError(Exception):
    """The credentials file exists but may not be used (too open, or malformed)."""


def credentials_path() -> Path:
    return keys.curate_home() / "sources" / _FILE


def load_credentials(path: Optional[Path] = None) -> Mapping[str, str]:
    """The source keys, or an empty mapping when no file exists. Raises
    :class:`CredentialsError` when group or others have any access to the file,
    or it is not a JSON object of string keys to string values."""
    path = path or credentials_path()
    try:
        mode = path.stat().st_mode
    except FileNotFoundError:
        return {}
    if not stat.S_ISREG(mode):
        raise CredentialsError(f"{path} is not a regular file")
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise CredentialsError(f"{path} is mode {stat.S_IMODE(mode):04o}; run: chmod 600 {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        raise CredentialsError(f"{path} is not readable JSON") from exc
    if not isinstance(data, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in data.items()):
        raise CredentialsError(f"{path} must be a JSON object of source name to key")
    return dict(data)


def key_for(name: str) -> Callable[[], Optional[str]]:
    """A source's default key lookup: *name* from the credentials file, read when asked. A file
    that may not be used (too open, malformed) gives no key — the source then answers "could
    not tell", never a guess. Usage: ``_default_key = credentials.key_for("URLSCAN_API_KEY")``."""
    def lookup() -> Optional[str]:
        try:
            return load_credentials().get(name)
        except CredentialsError:
            return None
    return lookup
