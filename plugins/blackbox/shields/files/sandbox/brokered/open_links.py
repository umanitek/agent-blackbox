"""``open-link``: a sandboxed agent's ``open https://…`` (sandbox permission ``open-links``; a
sign-in such as ``gh auth login --web``). Only an http or https address, without control
characters or a user name, at most :data:`MAX_URL_CHARS`; checked against the threat graph (a
listed domain is refused, and every link when the verdict can not be asked); then opened by
``/usr/bin/open`` outside the sandbox. ``file://`` and every other scheme are refused.

**Security cost:** the page loads outside the sandbox, and a link can carry data out in its address.

Usage::

    API_WRITES["open-link"](context, {"argv": ["https://github.com/login/device"], "pid": 4242})
"""

from __future__ import annotations

from typing import Any, Mapping
from urllib.parse import urlsplit

from ..... import audit
from ....shield_api import ShieldApiError, ShieldContext
from .....kernel.os_layout import machine_words
from .. import platform
from .asking import Asking, Planned, decide

PERMISSION = "open-links"
MAX_URL_CHARS = 2048
LISTED = "a threat rule lists this address (or it could not be checked), so Blackbox will not open it"


def parse(argv: Any) -> str:
    """The one link in *argv*; raises ShieldApiError(400) for anything else."""
    if not isinstance(argv, list) or len(argv) != 1 or not isinstance(argv[0], str):
        raise ShieldApiError(400, "Blackbox opens one web link: open https://…")
    url = argv[0]
    parts = urlsplit(url)
    if len(url) > MAX_URL_CHARS or any(ord(char) < 33 for char in url) or parts.scheme not in ("http", "https") \
            or not parts.hostname or parts.username or parts.password:
        raise ShieldApiError(400, "Blackbox opens only http and https links (no file://, no other scheme, no user name)")
    return url


def listed(context: ShieldContext, url: str) -> bool:
    """True when a threat rule lists the link's address, or the verdict can not be asked (fail closed)."""
    judge = context.tool_call_verdict
    if judge is None:
        return True
    try:
        verdict = judge("terminal", {"command": f"curl {url}"})
    except Exception:   # health: allow BLE001 -- the verdict could not be asked: fail closed
        return True
    return verdict.get("decision") == "block" or any(found.get("source") != "heuristic" for found in verdict.get("findings") or [])


def open_link(context: ShieldContext, body: Mapping[str, Any]) -> Planned:
    """The door: the link checked, the asker found and the permission decided (raises when not
    allowed); the threat check and the opening run in the job (``brokered``)."""
    if set(body) - {"argv", "pid", "cwd"}:
        raise ShieldApiError(400, "a request carries the link only")
    url = parse(body.get("argv"))
    asked = Asking.of(context, body)
    decide(PERMISSION, asked, f"open {urlsplit(url).scheme}://{urlsplit(url).hostname}")

    def work() -> tuple[int, str]:
        code = platform.open_url(url)
        audit.record_for(audit.SANDBOX_RECORDER, event="brokered_open", workspace=asked.folder,
                         detail={"what": "link", "host": urlsplit(url).hostname or "", "agent": asked.agent, "exit": code})
        return code, "Opened in your browser." if code == 0 else f"{machine_words().capitalize()} could not open it."
    return Planned("open-link", f"open {url}", asked, work, check=lambda: LISTED if listed(context, url) else "")


__all__ = ["LISTED", "MAX_URL_CHARS", "PERMISSION", "listed", "open_link", "parse"]
