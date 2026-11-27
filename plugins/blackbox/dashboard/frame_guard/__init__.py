"""No other page may show the dashboard inside a frame (clickjacking; review 2026-11-26, MED).

The dashboard's buttons change protection (Audit / Block, an agent switched off, a shield's
settings). A hostile page could load the dashboard in an invisible frame over its own buttons and
have the person click through to it. Every answer therefore carries ``X-Frame-Options: DENY`` and a
``Content-Security-Policy`` with ``frame-ancestors 'none'`` — added to a route's own policy (a pack
logo's ``default-src 'none'; …; sandbox``) rather than replacing it.

Nothing in this repository frames the dashboard: the Hermes Desktop page draws its panels natively
from the dashboard's JSON (``desktop.dashboard_link``), and a companion app opens it as a page of
its own, never inside a frame.

Pattern: **Decorator** (ASGI middleware around the whole app), placed outermost so a refusal by the
browser boundary carries the headers too.

Usage::

    frame_guard.install(app)        # once, while building the app
"""

from typing import Any, Awaitable, Callable

#: The policy directive that forbids every framing page.
FRAME_ANCESTORS = b"frame-ancestors 'none'"
_CSP = b"content-security-policy"
_XFO = b"x-frame-options"

Scope = dict[str, Any]
Message = dict[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]


def framed_headers(headers: list[tuple[bytes, bytes]]) -> list[tuple[bytes, bytes]]:
    """*headers* (ASGI byte pairs) with framing forbidden: a route's own policy keeps every
    directive and gains ``frame-ancestors 'none'`` unless it already names its frame ancestors."""
    out: list[tuple[bytes, bytes]] = []
    has_policy = False
    for name, value in headers:
        lowered = name.lower()
        if lowered == _XFO:
            continue
        if lowered == _CSP:
            has_policy = True
            if b"frame-ancestors" not in value.lower():
                value = value.rstrip(b"; ") + b"; " + FRAME_ANCESTORS
        out.append((name, value))
    if not has_policy:
        out.append((_CSP, FRAME_ANCESTORS))
    out.append((_XFO, b"DENY"))
    return out


class FrameGuard:
    """``app.add_middleware(FrameGuard)``: adds the no-framing headers to every HTTP answer."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        async def send_framed(message: Message) -> None:
            if message.get("type") == "http.response.start":
                message = {**message, "headers": framed_headers(list(message.get("headers") or []))}
            await send(message)

        await self.app(scope, receive, send_framed)


def install(app: Any) -> None:
    """Wrap *app* (a FastAPI app, before it starts) in :class:`FrameGuard`, outermost."""
    app.add_middleware(FrameGuard)


__all__ = ["FRAME_ANCESTORS", "FrameGuard", "framed_headers", "install"]
