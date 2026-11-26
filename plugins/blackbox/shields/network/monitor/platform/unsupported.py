"""An operating system without a port yet: nothing is run and nothing is seen; the traffic
monitor says why, in one sentence for a person. A port adds ``windows.py``."""

from __future__ import annotations

from typing import Optional

TIMEOUT_SECONDS = 5.0


def traffic_unavailable() -> Optional[str]:
    return "The network monitor reads macOS and Linux for now; Windows is coming."


def connection_table() -> Optional[str]:
    return None


def listening_table() -> str:
    return ""


def routing_table() -> str:
    return ""


def process_table() -> Optional[str]:
    return None


def process_paths(timeout: float = TIMEOUT_SECONDS) -> str:
    return ""


def code_signature(path: str) -> Optional[str]:
    return None


def tailscale_status() -> Optional[str]:
    return None
