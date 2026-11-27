"""The Security page: ONE place to see and change how Blackbox protects you, each setting explained
where it is edited.

* ``GET /security`` and ``/security.js`` — the page: the protection mode (Audit / Block and the
  severity that blocks), what agents may do (the sandbox permissions, per agent and per project),
  the threat checks (each detection category on or off and its minimum severity), the limits (the
  hook size limit, when the settings serve it) and what is always on (the self-protection rules
  and the never-list, read-only, each with its reason).
* ``GET /permission-card.js`` — the one drawing of the sandbox permissions, shared with File
  Shield's page (``static/permission_card.js``).

The page has no endpoint of its own: it reads and writes through ``/api/settings`` and File
Shield's permission endpoints (``/api/shields/file-shield/api/…``), so every loosening passes the
same approval gate as anywhere else (``approvals.js`` asks the person and sends it again).

Usage::

    security_routes.register(app, swr)   # from dashboard.server.create_app
"""

# No ``from __future__ import annotations`` here: FastAPI must see the handlers' annotations.
from pathlib import Path
from typing import Any, Callable

NO_CACHE = {"Cache-Control": "no-store"}
STATIC = Path(__file__).resolve().parent.parent / "static"
#: The fixed files this package serves: address -> (file, media type).
FILES = {
    "/security": (STATIC / "security.html", "text/html"),
    "/security.js": (STATIC / "security.js", "application/javascript"),
    "/permission-card.js": (STATIC / "permission_card.js", "application/javascript"),
}

Cache = Callable[..., Any]


def register(app: Any, _swr: Cache = None) -> None:
    """Add the Security page's routes to *app*."""
    from fastapi.responses import FileResponse

    def served(path: Path, media_type: str) -> Callable[[], Any]:
        def answer() -> Any:
            return FileResponse(str(path), media_type=media_type, headers=NO_CACHE)
        return answer

    for address, (path, media_type) in FILES.items():
        app.add_api_route(address, served(path, media_type), methods=["GET"], include_in_schema=False)
