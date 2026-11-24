"""The shims first on the sandboxed PATH on Linux: ``brew`` (Linuxbrew) and the package managers —
the POSIX ports' shared ones (``platform/posix_scripts.py``) — and the broker's Homebrew run.
The link and app openers (``xdg-open``, ``gio open`` …) follow with the Linux brokers.

Usage::

    brew_shim(tools, python, dashboard_url)
    manager_shims(tools, python, dashboard_url)
"""

from __future__ import annotations

from ..posix_scripts import BREW_READ_ONLY, MANAGER_PROGRAMS, brew_shim, manager_shims, spawn_brew, stop_group


def open_shim(_tools: str, _python: str, _dashboard_url: str) -> str:
    """No ``open`` on Linux (its openers are ``xdg-open`` and ``gio``: :func:`broker_shims`)."""
    return ""


def osascript_shim(_tools: str, _python: str, _dashboard_url: str) -> str:
    """No AppleScript on Linux."""
    return ""


def broker_shims(_tools: str, _python: str, _dashboard_url: str) -> dict[str, str]:
    """``{program: stand-in}`` for the brokered actions (none yet on Linux)."""
    return {}


__all__ = ["BREW_READ_ONLY", "MANAGER_PROGRAMS", "brew_shim", "broker_shims", "manager_shims", "open_shim", "osascript_shim",
           "spawn_brew", "stop_group"]
