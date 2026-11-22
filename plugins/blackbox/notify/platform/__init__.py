"""The operating-system seam of the notifier: how a notice reaches the system's own notification
centre is decided here, one module (or folder) per operating system (per-OS structure, 2026-11-21).

The contract — every OS module offers the same four functions:

* ``send(title, body, level, ident) -> bool`` — show one notification; False when it could not
  be shown (never raises);
* ``status() -> NotifierStatus`` — what is installed and whether the person allowed it;
* ``install(source, sha256) -> NotifierStatus`` — put Blackbox's own notifier in place from a
  verified archive (macOS: the ``Blackbox.app`` bundle) and ask the person's permission once;
* ``remove() -> None`` — take it out again (uninstall).

Pattern: **Strategy** (one module per OS) behind a **Facade** (this module).

Usage::

    from . import platform
    platform.send("Blackbox stopped Claude Code", "…", "critical", "finding:…")
"""

from __future__ import annotations

import sys

if sys.platform == "darwin":
    from .macos import install, remove, send, status
elif sys.platform.startswith("linux"):
    from .linux import install, remove, send, status
else:
    from .unsupported import install, remove, send, status

__all__ = ["install", "remove", "send", "status"]
