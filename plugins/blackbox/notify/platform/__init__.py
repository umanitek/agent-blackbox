"""The operating-system seam of the notifier: how a notice reaches the system's own notification
centre is decided here, one module (or folder) per operating system (per-OS structure, 2026-11-21).

The contract — every OS module offers the same six functions:

* ``send(title, body, level, ident) -> Delivery`` — hand one notification to the system and say
  honestly what became of it (delivered, through the fallback, or not shown — never raises);
* ``status() -> NotifierStatus`` — what is installed, whether the person allowed it, and the
  link to change that;
* ``request() -> NotifierStatus`` — ask the person's permission now (they clicked; macOS asks
  only someone at the desktop — KI-PENDING-411cdb);
* ``open_settings() -> bool`` — open the system's notification settings for Blackbox;
* ``install(source, sha256) -> NotifierStatus`` — put Blackbox's own notifier in place from a
  verified archive (macOS: the ``Blackbox.app`` bundle); asks permission only when the person is
  at the desktop, else the question waits for them;
* ``remove() -> None`` — take it out again (uninstall).

Pattern: **Strategy** (one module per OS) behind a **Facade** (this module).

Usage::

    from . import platform
    platform.send("Blackbox stopped Claude Code", "…", "critical", "finding:…")
"""

from __future__ import annotations

import sys

if sys.platform == "darwin":
    from .macos import install, open_settings, remove, request, send, status
elif sys.platform.startswith("linux"):
    from .linux import install, open_settings, remove, request, send, status
else:
    from .unsupported import install, open_settings, remove, request, send, status

__all__ = ["install", "open_settings", "remove", "request", "send", "status"]
