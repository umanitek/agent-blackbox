"""The operating-system seam of :mod:`kernel.code_signing`: the commands that ask the system who
signed a program, and the one way they are run — one module per OS (per-OS structure, KI-628):
``macos.py`` (``codesign`` / ``spctl``), ``unsupported.py`` elsewhere (no such tools: every
answer is "could not check"). Only this machine's module is imported or copied (``kernel.os_layout``).

Pattern: **Strategy** (one module per OS) behind a **Facade** (this module).

Usage::

    from . import platform
    platform.run(platform.intact_command("/usr/bin/true"))   # (exit status, output) or None
"""

from __future__ import annotations

import sys

if sys.platform == "darwin":
    from .macos import (display_command, entitlements_command, intact_command, notarisation_command,
                        requirement_command, run)
else:
    from .unsupported import (display_command, entitlements_command, intact_command, notarisation_command,
                              requirement_command, run)

__all__ = ["display_command", "entitlements_command", "intact_command", "notarisation_command", "requirement_command", "run"]
