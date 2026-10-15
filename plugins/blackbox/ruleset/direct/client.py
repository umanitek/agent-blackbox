"""Local-only DKG transport for security decisions. No proxy, redirect or silent empty fallback."""
from __future__ import annotations

import ipaddress
import json
import re
import time
import http.client
import urllib.parse

from ...kernel.dkg_client import DkgClient, DkgError, signed_request_headers

MAX_RESPONSE_BYTES = 1024 * 1024 + 4096


class GraphReadUnavailable(DkgError):
    """The graph could not answer; this is never a clean negative detection."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def local_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise GraphReadUnavailable("LOCAL_DKG_REQUIRED")
    host = parsed.hostname
    if host == "localhost":
        host = "127.0.0.1"  # no DNS resolution for action-derived query data
    try:
        if not ipaddress.ip_address(host or "").is_loopback:
            raise ValueError
        port = parsed.port
    except ValueError:
        raise GraphReadUnavailable("LOCAL_DKG_REQUIRED") from None
    authority = f"[{host}]" if ":" in host else host
    return f"{parsed.scheme}://{authority}" + (f":{port}" if port else "")


class LocalGraphClient(DkgClient):
    def __init__(self, cfg, *, budget_s: float = 2.5):
        super().__init__(url=local_url(cfg.dkg_url), dkg_home=cfg.dkg_home)
        self.deadline = time.monotonic() + budget_s
        self.failure_code = ""
        self.rows_left = 8192

    def request(self, method, path, body=None, timeout=None):
        try:
            return self._request(method, path, body, timeout)
        except GraphReadUnavailable as exc:
            self.failure_code = exc.code
            raise

    def _request(self, method, path, body=None, timeout=None):
        if not ((method == "GET" and path in {"/api/status", "/api/info", "/api/context-graphs", "/api/query/bounded"})
                or (method == "POST" and path == "/api/query/bounded")):
            raise GraphReadUnavailable("LOCAL_READ_ONLY_REQUIRED")
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise GraphReadUnavailable("QUERY_DEADLINE_EXCEEDED")
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
            headers.update(signed_request_headers(self.token, method, path, data))
        from .transport import request
        try:
            status, raw = request(self.url, method, path, data, headers,
                                  deadline=min(self.deadline, time.monotonic() + (timeout or remaining)),
                                  max_bytes=MAX_RESPONSE_BYTES)
            if 300 <= status < 400:
                raise GraphReadUnavailable("LOCAL_DKG_REDIRECT_REFUSED")
            if len(raw) > MAX_RESPONSE_BYTES:
                raise GraphReadUnavailable("QUERY_RESULT_TOO_LARGE")
            if status >= 400:
                code = "DKG_UPGRADE_REQUIRED" if status == 404 else "QUERY_UNAVAILABLE"
                try:
                    error = json.loads(raw)
                    if isinstance(error, dict) and error.get("code") in {"QUERY_RESULT_TOO_LARGE", "QUERY_DEADLINE_EXCEEDED", "QUERY_ACCESS_DENIED"}:
                        code = error["code"]
                except ValueError:
                    pass
                raise GraphReadUnavailable(code)
            result = json.loads(raw)
            if not isinstance(result, dict):
                raise ValueError
            return result
        except TimeoutError:
            raise GraphReadUnavailable("QUERY_DEADLINE_EXCEEDED") from None
        except (OSError, http.client.HTTPException):
            raise GraphReadUnavailable("QUERY_UNAVAILABLE") from None
        except ValueError:
            raise GraphReadUnavailable("QUERY_MALFORMED_RESPONSE") from None

    def bounded(self, sparql: str, cg_id: str, *, max_rows: int = 8192, view=None):
        return self._select(sparql, cg_id, max_rows=max_rows, view=view)

    def page(self, sparql: str, cg_id: str, *, limit: int = 100, offset: int = 0):
        return self._select(sparql, cg_id, max_rows=limit, mode="page", offset=offset)

    def _select(self, sparql, cg_id, *, max_rows, view=None, mode="complete", offset=0):
        if self.rows_left < 1:
            raise GraphReadUnavailable("QUERY_RESULT_TOO_LARGE")
        max_rows = min(max_rows, self.rows_left)
        timeout_ms = min(2000, int((self.deadline - time.monotonic()) * 1000))
        if timeout_ms < 1:
            raise GraphReadUnavailable("QUERY_DEADLINE_EXCEEDED")
        body = {"version": 1, "sparql": sparql, "contextGraphId": cg_id,
                "maxRows": max_rows, "timeoutMs": timeout_ms, "includeContextGraphPartitions": True,
                "mode": mode, "offset": offset}
        if view is not None:
            body["view"] = view
        reply = self.request("POST", "/api/query/bounded", body)
        result = reply.get("result", {})
        complete = reply.get("resultComplete") is True if mode == "complete" else (
            reply.get("mode") == "page" and reply.get("resultComplete") is False
            and reply.get("pageComplete") is True and isinstance(reply.get("hasMore"), bool)
            and reply.get("offset") == offset and type(reply.get("nextOffset")) is int)
        if (reply.get("version") != 1 or not complete
                or reply.get("coverage") != "local-only" or reply.get("contextGraphId") != cg_id
                or not reply.get("queryId") or not reply.get("observedAt")
                or not isinstance(result, dict) or result.get("type") != "bindings"
                or not isinstance(result.get("bindings"), list) or len(result["bindings"]) > max_rows
                or any(not isinstance(row, dict) for row in result["bindings"])):
            raise GraphReadUnavailable("QUERY_MALFORMED_RESPONSE")
        if mode == "page" and (reply["nextOffset"] != offset + len(result["bindings"])
                               or (reply["hasMore"] and len(result["bindings"]) != max_rows)):
            raise GraphReadUnavailable("QUERY_MALFORMED_RESPONSE")
        self.rows_left -= len(result["bindings"])
        return reply

    def status(self, timeout=None):
        status = self.request("GET", "/api/status", timeout=timeout)
        if not isinstance(status.get("networkId"), str) or not status["networkId"]:
            self.failure_code = "QUERY_AUTHORITY_UNAVAILABLE"
            raise GraphReadUnavailable(self.failure_code)
        return status

    def query(self, sparql, cg_id, view=None, on_error=None, agent_address=None, timeout=None):
        """Keep signed curator readers on the same bounded local contract.

        Their existing pages use LIMIT; the outer SELECT bounds each page and
        the shared client budget bounds the whole decision. Failures are both
        returned to legacy tri-state readers and retained for the decision audit.
        """
        try:
            if agent_address:
                raise GraphReadUnavailable("QUERY_UNSUPPORTED_SCOPE")
            # Only move the lexical PREFIX/BASE prologue, never rewrite query data.
            prologue = re.match(r"(?is)\s*(?:(?:PREFIX\s+[\w-]*:\s*<[^>]+>|BASE\s*<[^>]+>)\s*)*", sparql)
            prefix, body = sparql[:prologue.end()], sparql[prologue.end():]
            reply = self.bounded(prefix + "SELECT * WHERE { { " + body + "\n} }", cg_id, view=view)
            return reply["result"]["bindings"]
        except GraphReadUnavailable as exc:
            self.failure_code = exc.code
            return [] if on_error is None else on_error
