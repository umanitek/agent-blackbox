"""The key console web app and its three server-side gates (trust-and-threat-lab C2, §03.1).

Pattern: Facade. The app is HTTP in front of the existing ``curate`` verbs
(the routes arrive with ``routes.py``); this module owns only who may get in.
It binds to :data:`CONSOLE_BIND_HOST` and is reached through
``tailscale serve`` (never Funnel). Every request passes three gates, all
server-side and all default-deny:

1. ``Tailscale-User-Login`` must equal ``settings.tailscale_login`` exactly.
   Serve sets this header and strips any inbound copy, but a local process
   can reach 127.0.0.1 and forge it — so it is necessary, not sufficient.
2. A login session (:class:`.session.ConsoleSessions`): every path except
   :data:`LOGIN_PATH` needs an authenticated session cookie
   (``HttpOnly; Secure; SameSite=Strict``), else 401.
3. The kernel's :class:`BrowserBoundary` with the host set = the node's
   MagicDNS name only (a loopback or rebound Host is refused), Origin
   same-origin, and the session's CSRF token on every change — the login
   POST included, which carries its pending session's token.

Usage::

    app = create_console_app(ConsoleSettings(
        tailscale_login="amos@example.com",
        magic_dns_host="curator-a.tail1234.ts.net",
        login_passphrase_hash=hash_login_passphrase("..."),
    ))
    uvicorn.run(app, host=CONSOLE_BIND_HOST, port=settings.port)

Browser flow: ``GET /login`` → pending session cookie + ``{"csrf"}``;
``POST /login {"passphrase"}`` with ``X-Blackbox-Token: <csrf>`` → a new
authenticated cookie + ``{"csrf"}``; changes carry that token;
``POST /logout`` ends it.
"""

# No ``from __future__ import annotations``: FastAPI resolves the route
# annotations below, and their types are imported inside the factory.
import secrets
from dataclasses import dataclass
from typing import Any, Optional

from ...kernel import local_http
from ...kernel.browser_boundary import BrowserBoundary
from .session import ConsoleSessions

CONSOLE_BIND_HOST = "127.0.0.1"
DEFAULT_CONSOLE_PORT = 9720
TAILSCALE_LOGIN_HEADER = "tailscale-user-login"
#: ``__Host-``: the browser accepts it only Secure, path=/, with no Domain.
SESSION_COOKIE = "__Host-bb_console"
LOGIN_PATH = "/login"
MAX_PASSPHRASE_LENGTH = 1024


@dataclass(frozen=True)
class ConsoleSettings:
    """What the console needs to start.

    ``tailscale_login`` — the one Tailscale login allowed in (gate 1).
    ``magic_dns_host`` — this node's MagicDNS name, the only Host answered (gate 3).
    ``login_passphrase_hash`` — from ``session.hash_login_passphrase`` (gate 2).
    ``port`` — the loopback port ``tailscale serve`` forwards to.
    """

    tailscale_login: str
    magic_dns_host: str
    login_passphrase_hash: str
    port: int = DEFAULT_CONSOLE_PORT

    def __post_init__(self) -> None:
        if not self.tailscale_login.strip():
            raise ValueError("tailscale_login must name the one allowed Tailscale login")
        host = self.magic_dns_host.strip().lower()
        if not host or local_http.is_loopback_host(host) or ":" in host:
            raise ValueError("magic_dns_host must be the node's MagicDNS name (no port, not loopback)")


def create_console_app(settings: ConsoleSettings, sessions: Optional[ConsoleSessions] = None) -> Any:
    """The console FastAPI app behind all three gates.

    *sessions* — injectable for tests (a fake clock); by default one
    :class:`ConsoleSessions` per app, memory only. Exposed as
    ``app.state.console_sessions`` for the routes module.
    """
    from fastapi import FastAPI

    app = FastAPI(title="Blackbox key console", docs_url=None, redoc_url=None, openapi_url=None)
    sessions = sessions or ConsoleSessions(settings.login_passphrase_hash)
    app.state.console_sessions = sessions
    app.state.console_settings = settings
    _install_login_gates(app, settings, sessions)
    # Installed last, so it runs first: Host, Origin and CSRF before anything else.
    BrowserBoundary({settings.magic_dns_host},
                    lambda request: sessions.csrf_token(_session_id(request))).install(app)
    _add_session_routes(app, sessions)
    return app


def _session_id(request: Any) -> str:
    return request.cookies.get(SESSION_COOKIE, "")


def _install_login_gates(app: Any, settings: ConsoleSettings, sessions: ConsoleSessions) -> None:
    """Gates 1 and 2 as one middleware: the Tailscale login, then the session."""
    from starlette.responses import JSONResponse

    allowed_login = settings.tailscale_login.encode("utf-8")

    @app.middleware("http")
    async def _console_login_gates(request, call_next):
        presented = request.headers.get(TAILSCALE_LOGIN_HEADER, "").encode("utf-8")
        if not secrets.compare_digest(presented, allowed_login):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        if request.url.path != LOGIN_PATH and not sessions.is_authenticated(_session_id(request)):
            return JSONResponse({"error": "login required"}, status_code=401)
        return await call_next(request)


def _add_session_routes(app: Any, sessions: ConsoleSessions) -> None:
    from fastapi import Body, Request, Response
    from fastapi.responses import JSONResponse

    @app.get(LOGIN_PATH)
    def login_form(request: Request, response: Response):
        """Start a pending session; the login POST must carry its CSRF token."""
        sessions.logout(_session_id(request))
        session_id, csrf = sessions.begin()
        _set_session_cookie(response, session_id)
        return {"csrf": csrf}

    @app.post(LOGIN_PATH)
    def login(request: Request,
              passphrase: str = Body(..., embed=True, min_length=1, max_length=MAX_PASSPHRASE_LENGTH)):
        session_id = sessions.login(_session_id(request), passphrase)
        if session_id is None:
            return JSONResponse({"error": "login refused"}, status_code=401)
        response = JSONResponse({"csrf": sessions.csrf_token(session_id)})
        _set_session_cookie(response, session_id)
        return response

    @app.post("/logout")
    def logout(request: Request, response: Response):
        sessions.logout(_session_id(request))
        response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="strict")
        return {"ok": True}

    @app.get("/api/session")
    def session(request: Request):
        """The signed-in page's CSRF token (behind all three gates)."""
        return {"csrf": sessions.csrf_token(_session_id(request))}


def _set_session_cookie(response: Any, session_id: str) -> None:
    response.set_cookie(SESSION_COOKIE, session_id, path="/", secure=True, httponly=True, samesite="strict")


__all__ = [
    "CONSOLE_BIND_HOST",
    "DEFAULT_CONSOLE_PORT",
    "LOGIN_PATH",
    "SESSION_COOKIE",
    "TAILSCALE_LOGIN_HEADER",
    "ConsoleSettings",
    "create_console_app",
]
