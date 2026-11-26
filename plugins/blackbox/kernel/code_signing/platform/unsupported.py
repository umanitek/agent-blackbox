"""Any system but macOS: there is no ``codesign`` to ask, so nothing is run and every answer is
"could not check" (None) — the shared code then shows the signer as unknown, never as verified."""

from __future__ import annotations

from typing import Optional


def intact_command(path: str) -> list[str]:
    return []


def requirement_command(path: str, requirement: str) -> list[str]:
    return []


def notarisation_command(bundle: str) -> list[str]:
    return []


def entitlements_command(path: str) -> list[str]:
    return []


def display_command(path: str) -> list[str]:
    return []


def run(command: list[str]) -> Optional[tuple[int, str]]:
    """Nothing to run here: always None."""
    return None


__all__ = ["display_command", "entitlements_command", "intact_command", "notarisation_command", "requirement_command", "run"]
