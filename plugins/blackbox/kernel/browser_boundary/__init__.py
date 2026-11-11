"""The browser boundary two web apps share (KI-028 / LES-006).

Binding a web app to loopback (or to a tailnet name) keeps the network out,
but the operator's BROWSER is on the same side: a malicious webpage can fire
cross-origin POSTs at the app, and DNS rebinding makes an attacker page look
same-origin. Two structural gates, enforced in ONE middleware:

1. Host + Origin allowlist — only the app's genuine host names pass. The
   Host header defeats DNS rebinding; an Origin, when present (cross-site and
   ``fetch()`` requests carry one), must name an allowed host too AND the port
   the request arrived on (KI-390): another server on the same loopback
   (``http://127.0.0.1:8000``, a dev server, a hostile local page) is a
   different origin, not the app. The port compared is the Host header's (the
   browser writes the port it connected to there); a header without one means
   the default port of the Origin's scheme.
2. A change token on every state-changing request (anything but GET, HEAD,
   OPTIONS), read from the ``X-Blackbox-Token`` header and compared in
   constant time.

Pattern: Strategy for the token source. ``token_for(request)`` returns the
token the request must carry: the dashboard passes a per-process lookup
(one token minted at start-up, handed to the UI by ``/api/session``); the
curator key console passes a per-session lookup (the token bound to the
request's session cookie). A lookup that returns no token fails closed —
the change is refused.

Usage::

    token = secrets.token_urlsafe(32)
    BrowserBoundary({"127.0.0.1", "localhost", "[::1]"}, lambda request: token).install(app)

    # per session, on a MagicDNS host:
    BrowserBoundary({"node.tailnet.ts.net"}, sessions.token_for_request).install(app)

Host names are compared case-insensitively; IPv6 literals are listed in
brackets (``[::1]``), as they appear in a Host header. The allowlist holds
names only — the port check compares an Origin with the Host header.
"""

from __future__ import annotations

import secrets
from typing import Any, Callable, Iterable, Optional
from urllib.parse import urlsplit

TOKEN_HEADER = "x-blackbox-token"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

_DEFAULT_PORTS = {"http": "80", "https": "443"}


def _split_authority(value: str) -> tuple[str, str]:
    """``(host, port)`` of a ``host[:port]`` authority, host lower-case; an IPv6 literal
    keeps its brackets (``[::1]``) as Host headers write it; port ``""`` when absent."""
    value = (value or "").strip().lower()
    if value.startswith("["):
        host, _, rest = value.partition("]")
        return host + "]", rest[1:] if rest.startswith(":") else ""
    host, _, port = value.partition(":")
    return host, port


TokenLookup = Callable[[Any], Optional[str]]
"""``token_for(request) -> expected token``, or None/"" when the request has none."""


class BrowserBoundary:
    """The Host + Origin allowlist and change-token gate for one FastAPI app.

    ``allowed_hosts`` — host names (no port) the app answers to.
    ``token_for`` — the token-source Strategy, called per state-changing request.
    """

    def __init__(self, allowed_hosts: Iterable[str], token_for: TokenLookup) -> None:
        self._allowed_hosts = frozenset(host.strip().lower() for host in allowed_hosts)
        self._token_for = token_for

    def allows_host(self, value: str) -> bool:
        """True when a Host header (or an Origin's netloc) names an allowed host."""
        return _split_authority(value)[0] in self._allowed_hosts

    def allows_origin(self, origin: str, host_header: str) -> bool:
        """True when *origin* names an allowed host on the same port as the request's
        *host_header* — the app's own origin (see the module doc)."""
        parts = urlsplit(origin)
        origin_host, origin_port = _split_authority(parts.netloc)
        if origin_host not in self._allowed_hosts:
            return False
        default = _DEFAULT_PORTS.get(parts.scheme.lower(), "")
        return (origin_port or default) == (_split_authority(host_header)[1] or default)

    def install(self, app: Any) -> None:
        """Register the boundary as HTTP middleware on *app* (a FastAPI app)."""
        from starlette.responses import JSONResponse

        boundary = self

        @app.middleware("http")
        async def _browser_boundary(request, call_next):
            if not boundary.allows_host(request.headers.get("host", "")):
                return JSONResponse({"error": "forbidden host"}, status_code=403)
            origin = request.headers.get("origin", "")
            # Same-origin UI requests carry an allowed origin or none at all.
            if origin and not boundary.allows_origin(origin, request.headers.get("host", "")):
                return JSONResponse({"error": "forbidden origin"}, status_code=403)
            if request.method not in SAFE_METHODS and not boundary._token_matches(request):
                return JSONResponse(
                    {"error": "missing or invalid session token"}, status_code=403
                )
            return await call_next(request)

    def _token_matches(self, request: Any) -> bool:
        expected = self._token_for(request) or ""
        presented = request.headers.get(TOKEN_HEADER, "")
        # An absent expected token never matches, even an absent presented one. Compared as UTF-8
        # bytes: `compare_digest` refuses a str with characters outside ASCII (a header the server
        # decoded as latin-1), which used to escape as a 500 instead of this 403.
        return bool(expected) and secrets.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))


__all__ = ["SAFE_METHODS", "TOKEN_HEADER", "BrowserBoundary", "TokenLookup"]
