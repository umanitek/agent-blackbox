"""Allow once, for a permission a BROKER enforces: a grant bound to one permission, one scope and
the exact request (its digest), used at most once within :data:`ONCE_SECONDS`.

(A permission the profile enforces is allowed once differently: a one-launch profile the
launcher takes — ``profiles.write_once``.)

Usage::

    grant(OnceGrant("homebrew", scope, digest, time.time() + ONCE_SECONDS))
    use("homebrew", scope, digest)    # True the first time, False after
"""

from __future__ import annotations

import threading
import time
from typing import Optional

from .model import OnceGrant, Scope

ONCE_SECONDS = 120.0
MAX_GRANTS = 50
_lock = threading.Lock()
_grants: list[OnceGrant] = []


def grant(once: OnceGrant) -> None:
    with _lock:
        _grants[:] = [each for each in _grants if each.expires > time.time()][-(MAX_GRANTS - 1):] + [once]


def use(permission: str, scope: Scope, digest: str, now: Optional[float] = None) -> bool:
    """True, and the grant spent, when an unexpired grant matches exactly; False otherwise."""
    now = time.time() if now is None else now
    with _lock:
        for index, each in enumerate(_grants):
            if (each.permission, each.scope, each.digest) == (permission, scope, digest) and each.expires > now:
                del _grants[index]
                return True
    return False


def reset() -> None:
    with _lock:
        _grants.clear()


__all__ = ["MAX_GRANTS", "ONCE_SECONDS", "grant", "reset", "use"]
