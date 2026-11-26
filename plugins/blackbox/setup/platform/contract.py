"""What every ``setup/platform/<os>`` module is given: the runner it reaches the system through
(the caller's, so tests pass a fake) and the names of Blackbox's login services on each system
(owned by ``sync``: one place to rename them)."""

from __future__ import annotations

from typing import Callable, NamedTuple, Sequence

Runner = Callable[[Sequence[str]], int]


class ServiceNames(NamedTuple):
    """Blackbox's login services: launchd labels (macOS), systemd unit files (Linux), Scheduled
    Task names (Windows)."""

    launchd_labels: tuple[str, ...]
    systemd_units: tuple[str, ...]
    windows_tasks: tuple[str, ...]


__all__ = ["Runner", "ServiceNames"]
