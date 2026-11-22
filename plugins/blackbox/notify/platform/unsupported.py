"""An operating system without a notifier yet: nothing is shown, and that is said plainly."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from ..model import NotifierStatus

_NONE = NotifierStatus("none", False, "unknown", "Blackbox has no native notifier for this system yet; the dashboard shows every notification.")


def send(title: str, body: str, level: str, ident: str) -> bool:
    return False


def status() -> NotifierStatus:
    return _NONE


def install(source: Optional[Path] = None, sha256: str = "") -> NotifierStatus:
    return _NONE


def remove() -> None:
    return None
