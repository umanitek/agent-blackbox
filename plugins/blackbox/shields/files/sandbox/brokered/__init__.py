"""Brokered actions: what a sandboxed agent may ask Blackbox to do OUTSIDE the sandbox, each under
its sandbox permission (block / ask / allow; ``sandbox.permissions``) — opening a web link
(``open-links``), opening a file in an app (``open-apps``) and stopping a program the agent may
not signal itself (``stop-processes``, :mod:`.stop`: from the refusal the hook saw) and running one
AppleScript the person has read (``applescript``, :mod:`.applescript`: ask, once only).

Pattern: **Broker** — the agent's stand-in (``open`` first on the sandboxed PATH,
``platform.open_shim``) sends the request; the dashboard process, outside the sandbox, checks the
request, who asked (:mod:`.asking`) and the permission, and answers with a JOB at once
(``packages.jobs.start_action``). The threat check (a link) and the action itself run in that job,
failing closed; the client follows it (``GET …/action-job``, ``packages.client``) and waits on a busy
Blackbox up to 120 s, saying why when it gives up. WHY (KI-632, LES-143): checks and work done
before the answer held the agent's request past the client's 10 s timeout during the first sync,
and an AppleScript can run longer than any one request should wait. Stopping a process
(:mod:`.stop`) is not asked through a request: the hook's refusal reaches it in the background.

Usage::

    install_shims(tools_folder)          # the ``open`` stand-in, at each sandbox sync
    API_WRITES["open-link"](context, {"argv": ["https://…"]})   # {"job": "…", "command": "open https://…"}
    API_READS["action-job"](context, {"job": "…", "from": "0"})
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Callable, Mapping

from .....kernel.bounded_files import atomic_write, read_small_text
from .....kernel.config import load_blackbox_config
from ....shield_api import ShieldContext
from .. import platform
from ..packages import job_read, jobs
from . import applescript, stop
from .asking import WAITING, Asking, Planned, decide
from .open_apps import open_app
from .open_links import open_link


def _answered_at_once(door: Callable[[ShieldContext, Mapping[str, Any]], Planned]) -> Callable[[ShieldContext, Mapping[str, Any]], dict[str, Any]]:
    """The endpoint of an action: its *door* (raises when refused or waiting), then the job started."""
    def endpoint(context: ShieldContext, body: Mapping[str, Any]) -> dict[str, Any]:
        planned = door(context, body)
        job = jobs.start_action(jobs.ActionRequest(planned.tool, planned.command), work=planned.work,
                                owner=planned.asked.owner, check=planned.check)
        return {"job": job.id, "command": planned.command}
    return endpoint


API_WRITES = {"open-link": _answered_at_once(open_link), "open-app": _answered_at_once(open_app),
              "applescript": _answered_at_once(applescript.run)}
API_READS = {"action-job": job_read}


def install_shims(tools: Path, dashboard_url: str = "") -> None:
    """The brokered actions' stand-ins in the sandbox's tools folder (first on the sandboxed PATH only)."""
    url = dashboard_url or f"http://127.0.0.1:{load_blackbox_config().dashboard_port}"
    for name, shim in platform.broker_shims(str(tools), sys.executable, url).items():
        path = tools / name
        if shim and tools.is_dir() and (read_small_text(str(path), 256 * 1024) != shim or not os.access(path, os.X_OK)):
            atomic_write(path, shim, mode=0o755)


__all__ = ["API_READS", "API_WRITES", "WAITING", "Asking", "Planned", "applescript", "decide", "install_shims", "stop"]
