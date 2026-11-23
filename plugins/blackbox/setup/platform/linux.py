"""Linux: systemd lingering turned off again for the person (``loginctl disable-linger``) when
Blackbox's installer turned it on (``ensure_user_lingering``, recorded in the install manifest) —
a fixed argv, never a shell, through the caller's runner (``uninstall``'s, so tests pass a fake).

Usage::

    disable_linger("alice", run)   # True when loginctl said yes
"""

from __future__ import annotations

from typing import Callable, Sequence

from .unsupported import delete_keychain_item, delete_preferences, remove_user_path_entry

LOGINCTL = "loginctl"
Runner = Callable[[Sequence[str]], int]


def disable_linger(user: str, run: Runner) -> bool:
    """Lingering off for *user*: their services stop at logout again, as before the install."""
    return run([LOGINCTL, "disable-linger", user]) == 0


__all__ = ["delete_keychain_item", "delete_preferences", "disable_linger", "remove_user_path_entry"]
