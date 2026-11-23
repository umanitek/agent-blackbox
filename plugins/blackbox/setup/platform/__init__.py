"""The operating-system seam of ``blackbox uninstall``: what only the system's own tools can remove
— a Keychain item, a preferences domain — one module per OS (per-OS structure, Amos 2026-11-21):
``macos.py`` today, ``unsupported.py`` elsewhere. Only this machine's module is imported or copied
(``kernel.os_layout``).

Pattern: **Strategy** (one module per OS) behind a **Facade** (this module).

Usage::

    from . import platform
    platform.delete_keychain_item("com.example.app", "token", run)   # True when removed
    platform.delete_preferences("com.example.app", run)
"""

from __future__ import annotations

import sys

if sys.platform == "darwin":
    from .macos import delete_keychain_item, delete_preferences
else:
    from .unsupported import delete_keychain_item, delete_preferences

__all__ = ["delete_keychain_item", "delete_preferences"]
