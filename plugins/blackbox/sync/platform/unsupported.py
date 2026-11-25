"""Any other system (Windows: the node's sign-in task is the installer's alone): no service this
module can find or restart, so the caller runs the node itself."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from ...kernel.config import BlackboxConfig
from .model import NodeService


def registered(_cfg: BlackboxConfig, _home: Path) -> Optional[NodeService]:
    return None


def service_for_unit(_unit: str) -> Optional[NodeService]:
    return None


__all__ = ["registered", "service_for_unit"]
