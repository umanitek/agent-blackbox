"""Brokered actions: what a sandboxed agent may ask Blackbox to do OUTSIDE the sandbox, each under
its sandbox permission (block / ask / allow; ``sandbox.permissions``) — opening a web link
(``open-links``), opening a file in an app (``open-apps``) and stopping a program the agent may
not signal itself (``stop-processes``, :mod:`.stop`: from the refusal the hook saw) and running one
AppleScript the person has read (``applescript``, :mod:`.applescript`: ask, once only).

Pattern: **Broker** — the agent's stand-in (``open`` first on the sandboxed PATH,
``platform.open_shim``) sends the request; the dashboard process, outside the sandbox, checks who
asked (:mod:`.asking`), the permission, the request itself and the threat graph, then does it
with a fixed argv and records it.

Usage::

    install_shims(tools_folder)          # the ``open`` stand-in, at each sandbox sync
    API_WRITES["open-link"](context, {"argv": ["https://…"]})
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from .....kernel.bounded_files import atomic_write, read_small_text
from .....kernel.config import load_blackbox_config
from .. import platform
from . import applescript, stop
from .asking import WAITING, Asking, decide
from .open_apps import open_app
from .open_links import open_link

API_WRITES = {"open-link": open_link, "open-app": open_app, "applescript": applescript.run}


def install_shims(tools: Path, dashboard_url: str = "") -> None:
    """The brokered actions' stand-ins in the sandbox's tools folder (first on the sandboxed PATH only)."""
    url = dashboard_url or f"http://127.0.0.1:{load_blackbox_config().dashboard_port}"
    for name, shim in platform.broker_shims(str(tools), sys.executable, url).items():
        path = tools / name
        if shim and tools.is_dir() and (read_small_text(str(path), 256 * 1024) != shim or not os.access(path, os.X_OK)):
            atomic_write(path, shim, mode=0o755)


__all__ = ["API_WRITES", "WAITING", "Asking", "applescript", "decide", "install_shims", "stop"]
