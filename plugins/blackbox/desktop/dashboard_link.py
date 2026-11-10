"""Hermes Desktop's door to the Blackbox dashboard's own API (Proxy pattern).

The Desktop page shows every dashboard panel natively, from the same JSON the dashboard's web
page reads. Rather than copy the dashboard's logic, the Desktop routes (``/api/plugins/blackbox/
dash/<path>``, which Hermes answers only for Desktop's own credential) forward an allowlisted set
of the dashboard's API routes to the dashboard already running on this machine's loopback, and
return its answer unchanged.

The dashboard's browser boundary stays as it is: a loopback request with the dashboard's Host
header and no Origin is the same request its own page makes, and a change carries the
dashboard's per-process change token, read from its ``/api/session`` on loopback (and read again
once when the dashboard restarts and answers 403). Embedding the dashboard page in Desktop instead
would need it to accept an opaque origin, which is what a hostile site's sandboxed frame sends.

Usage::

    link = DashboardLink(port=9700)
    link.forward("GET", "api/graph-status", "")            # -> LinkAnswer(status=200, body={...})
    link.forward("POST", "api/settings", "", {"mode": "block"})
    link.forward("GET", "api/session", "")                 # -> LinkAnswer(status=404, ...): not allowlisted
"""

from __future__ import annotations

import json
import logging
import re
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Optional

from ..kernel import local_http

logger = logging.getLogger(__name__)

#: Dashboard routes the Desktop page may read (GET).
READ_ROUTES = re.compile(
    r"api/(?:agents|attach-targets|audit|community-statements|community-stats|findings|graph|graph-status|health"
    r"|local-activity|playground(?:/(?:graph|local|threat|wallets))?|reports|settings|shields(?:/[a-z0-9_-]{1,40}/events)?"
    r"|threat|threat-proof|trust|verified-sync|docs)"
    r"|shields/[a-z0-9_-]{1,40}/(?:content|attacks|graph)\.json")
#: Dashboard routes the Desktop page may change through (POST).
WRITE_ROUTES = re.compile(r"api/(?:settings|agents/protection|agents/rescan|attach|sync|playground/run|playground/wallets/run|blackbox-chat)")
#: Changes that do real work before they answer: an assistant turn (up to 120 s on the dashboard) and a
#: Playground test (up to ~90 s waiting for its share). Everything else answers within _TIMEOUT_S.
LONG_ROUTES = re.compile(r"api/(?:blackbox-chat|playground/run|playground/wallets/run)")
_TIMEOUT_S = 15.0
_LONG_TIMEOUT_S = 130.0
_MAX_BODY_BYTES = 4_000_000


@dataclass(frozen=True)
class LinkAnswer:
    """The dashboard's answer: its HTTP status and its JSON body (``{"error": ...}`` when there is none)."""

    status: int
    body: Any


class DashboardLink:
    """Forwards allowlisted requests to the dashboard on ``127.0.0.1:<port>``; one lock guards the token."""

    def __init__(self, port: int, host: str = "127.0.0.1") -> None:
        self._base = f"http://{host}:{int(port)}/"
        self._host_header = f"{host}:{int(port)}"
        self._token: Optional[str] = None
        self._lock = threading.Lock()

    @staticmethod
    def allowed(method: str, path: str) -> bool:
        """True when *method* *path* is a dashboard route the Desktop page may use."""
        routes = READ_ROUTES if method == "GET" else WRITE_ROUTES if method == "POST" else None
        return bool(routes and routes.fullmatch(path.strip("/")))

    def forward(self, method: str, path: str, query: str = "", body: Any = None) -> LinkAnswer:
        """Send *method* *path*?*query* (with JSON *body* for POST) to the dashboard and return its answer.

        404 for a route the Desktop page may not use; 503 ``{"dashboardDown": true}`` when no
        dashboard answers on loopback. Never raises."""
        method = method.upper()
        path = path.strip("/")
        if ".." in path or not self.allowed(method, path):
            return LinkAnswer(404, {"error": "not a dashboard route the Desktop page uses"})
        answer = self._send(method, path, query, body)
        if answer.status == 403 and method == "POST":
            with self._lock:
                self._token = None            # the dashboard restarted: its token changed
            answer = self._send(method, path, query, body)
        return answer

    def _token_value(self) -> Optional[str]:
        with self._lock:
            if self._token is None:
                answer = self._request("GET", "api/session", "", None, token=None)
                token = answer.body.get("token") if isinstance(answer.body, dict) else None
                self._token = token if isinstance(token, str) and token else None
            return self._token

    def _send(self, method: str, path: str, query: str, body: Any) -> LinkAnswer:
        token = self._token_value() if method == "POST" else None
        if method == "POST" and token is None:
            return LinkAnswer(503, {"error": "the Blackbox dashboard is not running", "dashboardDown": True})
        return self._request(method, path, query, body, token=token)

    def _request(self, method: str, path: str, query: str, body: Any, *, token: Optional[str]) -> LinkAnswer:
        url = self._base + path + (f"?{query}" if query else "")
        data = json.dumps(body if body is not None else {}).encode() if method == "POST" else None
        headers = {"Host": self._host_header, "Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if token:
            headers["X-Blackbox-Token"] = token
        request = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            timeout = _LONG_TIMEOUT_S if LONG_ROUTES.fullmatch(path) else _TIMEOUT_S
            # Loopback only (the URL is built from 127.0.0.1 and the port), and it carries the session token.
            with local_http.open_direct(request, timeout=timeout) as response:
                return LinkAnswer(response.status, _json(response.read(_MAX_BODY_BYTES)))
        except urllib.error.HTTPError as error:
            return LinkAnswer(error.code, _json(error.read(_MAX_BODY_BYTES)) or {"error": error.reason})
        except (urllib.error.URLError, OSError, TimeoutError) as error:
            logger.debug("blackbox: dashboard not reachable for Desktop: %s", error)
            return LinkAnswer(503, {"error": "the Blackbox dashboard is not running", "dashboardDown": True})


def _json(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8")) if raw else {}
    except (UnicodeDecodeError, ValueError):
        return {"error": "the dashboard sent something that is not JSON"}
