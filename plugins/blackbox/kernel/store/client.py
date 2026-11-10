"""The read-only SPARQL client for the node's local store.

Pattern: Adapter — the SPARQL 1.1 protocol (form-encoded ``query=`` POST,
``application/sparql-results+json`` back) behind one method, so the rest of
the plugin never sees HTTP. Every call has three outcomes (LES-011):

* rows came back (possibly none) — :attr:`StoreAnswer.rows` is a list;
* the store could not be asked or did not answer in time —
  :attr:`StoreAnswer.rows` is ``None`` and :attr:`StoreAnswer.reason` says why.

A caller must never read the second outcome as "nothing matched".

Only a loopback endpoint is accepted: the store has no authentication of its
own, and a lookup carries what the agent is doing (package names, addresses),
which must not leave the machine.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .. import local_http

logger = logging.getLogger(__name__)

#: A lookup on the hot path waits at most this long. Bench p95 was 5 ms on a
#: node busy downloading the graph; anything near this bound is a store in
#: trouble, and the caller's answer is "could not tell", not "clean".
LOOKUP_TIMEOUT_SECONDS = 2.0

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})


@dataclass(frozen=True)
class StoreAnswer:
    """What one query produced.

    ``rows`` — one ``{variable: value}`` dict per solution, values in the
    daemon's term shape (IRIs bare, literals quoted — decode with
    ``sparql_text.extract_binding``); ``None`` when the store could not
    be asked. ``reason`` — why, when ``rows`` is None (``"timeout"``,
    ``"http 500: …"``, ``"no store endpoint"``, …).
    """

    rows: Optional[list[dict[str, str]]]
    reason: str = ""

    @property
    def known(self) -> bool:
        """True when the store answered (even with no rows)."""
        return self.rows is not None


def loopback_store_url(node_status: dict[str, Any]) -> str:
    """The node's local store endpoint from ``GET /api/status``, or ``""``.

    DKG 10.0.2x reports ``storeUrl`` (``http://127.0.0.1:7878/query`` for the
    managed Oxigraph). Anything not on this machine is refused.
    """
    url = str(node_status.get("storeUrl") or "").strip()
    if not url:
        return ""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or (parsed.hostname or "") not in _LOOPBACK_HOSTS:
        return ""
    return url


class StoreClient:
    """``select(sparql)`` against one store endpoint, with a hard timeout.

    Holds no connection and no state beyond the URL and the timeout, so one
    instance can be shared by every lookup in a process.
    """

    def __init__(self, url: str, timeout: float = LOOKUP_TIMEOUT_SECONDS) -> None:
        self.url = url
        self.timeout = timeout

    def select(self, sparql: str, *, timeout: Optional[float] = None) -> StoreAnswer:
        """Run one SELECT. Never raises: every failure is a :class:`StoreAnswer`
        with ``rows=None``."""
        if not self.url:
            return StoreAnswer(None, "no store endpoint")
        request = urllib.request.Request(
            self.url,
            data=urllib.parse.urlencode({"query": sparql}).encode("utf-8"),
            headers={
                "Accept": "application/sparql-results+json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method="POST",
        )
        try:
            with local_http.open_direct(request, timeout=timeout or self.timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            return StoreAnswer(None, f"http {exc.code}")
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            return StoreAnswer(None, "timeout" if "timed out" in str(exc) else f"transport: {exc}")
        return _parse_results(raw)


def _parse_results(raw: bytes) -> StoreAnswer:
    """SPARQL-JSON results to rows in the daemon's term shape; a malformed body
    is could-not-tell."""
    try:
        payload = json.loads(raw.decode("utf-8"))
        bindings = payload["results"]["bindings"]
    except (ValueError, KeyError, TypeError, AttributeError):
        return StoreAnswer(None, "malformed results")
    if not isinstance(bindings, list):
        return StoreAnswer(None, "malformed results")
    rows: list[dict[str, str]] = []
    for binding in bindings:
        if isinstance(binding, dict):
            rows.append({name: _term(cell) for name, cell in binding.items() if isinstance(cell, dict)})
    return StoreAnswer(rows)


def _term(cell: dict[str, Any]) -> str:
    """One SPARQL-JSON cell as the N-Triples term the DKG node's own API
    returns — IRIs bare, blank nodes ``_:x``, literals quoted and escaped —
    so every reader keeps decoding cells with ``sparql_text.extract_binding``
    and a value that itself starts with a quote survives the round trip."""
    value = str(cell.get("value", ""))
    kind = cell.get("type")
    if kind == "uri":
        return value
    if kind == "bnode":
        return f"_:{value}"
    escaped = (value.replace("\\", "\\\\").replace('"', '\\"')
               .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t"))
    term = f'"{escaped}"'
    if cell.get("xml:lang"):
        return f'{term}@{cell["xml:lang"]}'
    if cell.get("datatype"):
        return f'{term}^^<{cell["datatype"]}>'
    return term
