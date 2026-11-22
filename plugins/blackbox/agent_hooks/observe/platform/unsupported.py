"""An operating system without a port yet: no process can be read, so nothing is observed."""

from __future__ import annotations


def process_table() -> str:
    return ""


def process_users() -> str:
    return ""


def process_environment(pid: int) -> str:
    return ""


def process_variable(pid: int, name: str) -> str:
    return ""


def process_ancestry(pid: int, limit: int) -> list[tuple[int, int, float, str]] | None:
    return None   # cannot be asked this way: callers read the whole process list


def process_cwd(pid: int) -> str:
    return ""
