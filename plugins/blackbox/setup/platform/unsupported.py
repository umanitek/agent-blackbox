"""What a system does not have: no Keychain or preferences domains, no systemd lingering, no
per-user PATH in the registry — nothing to remove there. The other modules take the functions
they have no use for from here.

Usage::

    delete_keychain_item("com.example.app", "token", run)   # False: not on this system
"""

from __future__ import annotations

from typing import Callable, Sequence

Runner = Callable[[Sequence[str]], int]


def delete_keychain_item(_service: str, _account: str, _run: Runner) -> bool:
    return False


def delete_preferences(_domain: str, _run: Runner) -> bool:
    return False


def disable_linger(_user: str, _run: Runner) -> bool:
    return False


def remove_user_path_entry(_folder: str) -> bool:
    return False


__all__ = ["delete_keychain_item", "delete_preferences", "disable_linger", "remove_user_path_entry"]
