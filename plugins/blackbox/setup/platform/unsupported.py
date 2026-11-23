"""Systems with no Keychain or preferences domains of their own: nothing to remove there.

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


__all__ = ["delete_keychain_item", "delete_preferences"]
