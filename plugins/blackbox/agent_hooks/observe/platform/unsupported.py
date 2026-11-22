"""An operating system without a port yet: no process can be read, so nothing is observed."""

from __future__ import annotations


def process_table() -> str:
    return ""


def process_environment(pid: int) -> str:
    return ""
