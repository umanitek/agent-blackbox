"""The one HTTP client every outside-source adapter talks through (§03.3).

Pattern: Adapter — a source asks :meth:`HttpClient.post` (or
:meth:`HttpClient.get`) and gets back the publisher's JSON answer, or ``None``. ``None`` means "could not tell"
(network down, timeout, a non-2xx status such as PhishTank's 509, a redirect,
an oversized or non-JSON body) and the adapter must answer UNAVAILABLE —
never CLEAN (LES-011, LES-028). Tests hand adapters a fake with the same
``post`` signature, so no adapter ever sees ``urllib``.

Redirects are never followed: a source that moves its API is a change we want
to notice, and a redirect could carry an API key to another host.

Usage::

    client = UrllibClient()
    answer = client.post("https://…", headers={"Auth-Key": key}, form={"url": url})
    if answer is None: ...   # could not tell
    listing = client.get("https://…/domains.json", headers={}, max_bytes=64_000_000)   # a JSON object or list
"""

from __future__ import annotations

import http.client
import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, List, Mapping, Optional, Protocol

from ...kernel.local_http import RefuseRedirects

logger = logging.getLogger(__name__)

#: Each socket operation waits at most this long; the beat must not stall on one source.
SOURCE_TIMEOUT_SECONDS = 5.0
#: The slowest answer worth waiting for: a body arriving slower than this is given up, so a source
#: that trickles bytes (each read inside the per-operation timeout) cannot hold the beat without end.
MIN_BYTES_PER_SECOND = 256 * 1024
#: The chunk read between deadline checks.
_CHUNK_BYTES = 64 * 1024
#: A source answer larger than this is not read (a look-up answer is a few KB).
MAX_ANSWER_BYTES = 2_000_000
#: Sent on every request; PhishTank requires a descriptive User-Agent.
USER_AGENT = "blackbox-curator/1 (+https://blackboxcommand.com)"

JsonObject = Mapping[str, Any]
#: What :meth:`HttpClient.get` may return: a JSON object or a JSON list.
JsonValue = JsonObject | list[Any]


class HttpClient(Protocol):
    """Sends one request and returns the answer's JSON, or ``None`` when it could not tell."""

    def post(self, url: str, *, headers: Mapping[str, str], form: Optional[Mapping[str, str]] = None,
             json_body: Optional[JsonObject] = None) -> Optional[JsonObject]: ...

    def get(self, url: str, *, headers: Mapping[str, str],
            max_bytes: int = MAX_ANSWER_BYTES) -> Optional[JsonValue]:
        """GETs *url*; the answer's JSON object or list, or ``None`` when it could not tell
        (any non-2xx — urlscan's "still scanning" 404 included — or a body over *max_bytes*)."""


class UrllibClient:
    """The real :class:`HttpClient` — stdlib only, no redirects, bounded reads."""

    def __init__(self, timeout: float = SOURCE_TIMEOUT_SECONDS) -> None:
        self._timeout = timeout
        self._opener = urllib.request.build_opener(RefuseRedirects())

    def post(self, url: str, *, headers: Mapping[str, str], form: Optional[Mapping[str, str]] = None,
             json_body: Optional[JsonObject] = None) -> Optional[JsonObject]:
        if json_body is not None:
            data, content_type = json.dumps(json_body).encode("utf-8"), "application/json"
        else:
            data, content_type = urllib.parse.urlencode(form or {}).encode("utf-8"), "application/x-www-form-urlencoded"
        request = urllib.request.Request(url, data=data, method="POST", headers={
            **headers, "Content-Type": content_type, "Accept": "application/json", "User-Agent": USER_AGENT})
        answer = self._send(request, MAX_ANSWER_BYTES)
        return answer if isinstance(answer, dict) else None

    def get(self, url: str, *, headers: Mapping[str, str],
            max_bytes: int = MAX_ANSWER_BYTES) -> Optional[JsonValue]:
        request = urllib.request.Request(url, method="GET", headers={
            **headers, "Accept": "application/json", "User-Agent": USER_AGENT})
        answer = self._send(request, max_bytes)
        return answer if isinstance(answer, (dict, list)) else None

    def _send(self, request: urllib.request.Request, max_bytes: int) -> Any:
        """The decoded JSON answer, or ``None`` when the request could not tell."""
        deadline = time.monotonic() + self._timeout + max_bytes / MIN_BYTES_PER_SECOND
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                raw = _read_until(response, max_bytes, deadline)
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
            # Never log the request: its headers carry the source's key.
            logger.debug("blackbox: source request to %s failed: %s",
                         urllib.parse.urlsplit(request.full_url).netloc, type(exc).__name__)
            return None
        if raw is None or len(raw) > max_bytes:   # past the deadline, or over the size cap
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except ValueError:
            return None


def _read_until(response: Any, max_bytes: int, deadline: float) -> Optional[bytes]:
    """Up to ``max_bytes + 1`` bytes of *response*, read in chunks; None once *deadline*
    (``time.monotonic()``) passes. Each read still waits at most the socket timeout, so the
    whole read ends within the deadline plus one timeout."""
    chunks: list[bytes] = []
    size = 0
    while size <= max_bytes:
        if time.monotonic() > deadline:
            return None
        chunk = response.read(min(_CHUNK_BYTES, max_bytes + 1 - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    return b"".join(chunks)
