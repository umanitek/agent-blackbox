"""The link to the lab — a small HTTP client over the SSH tunnel's loopback port
(proposal §03.5, D28/D29).

Pattern: Adapter — the lab's job API behind three methods, so the controller
never sees HTTP. Every call has exactly three outcomes (LES-011, the discipline
of ``kernel/store``):

* ``OK`` — the lab answered; :attr:`LabAnswer.body` is its JSON object;
* ``REFUSED`` — the lab answered NO (a 4xx other than 429: an unknown job, a
  job it will not run) — a definite answer;
* ``UNAVAILABLE`` — the lab could not be asked or did not answer within the
  ONE hard timeout (connection refused, timeout, 429/5xx, a malformed or
  oversized body). This is "could not tell", never "no".

The lab job API (the lab runner, ``integrations/threat-lab/``, serves it on
the tunnel's loopback port only)::

    POST /jobs               {"key", "identifier", "level"} -> 2xx {"key"}
    GET  /jobs/<key>         -> {"state": "queued" | "running" | "done" | "failed"}
    GET  /jobs/<key>/output  -> the raw output object the extractor reads

Only a loopback endpoint is accepted: the tunnel ends on this machine, and a
request names what is being tested. Proxies and redirects are never followed
for the same reason (a 3xx is UNAVAILABLE).

Usage::

    transport = LabTransport("http://127.0.0.1:7801")
    answer = transport.submit(job)
    if answer.outcome is LabOutcome.UNAVAILABLE: ...   # try again later; never read as "no"
"""

from __future__ import annotations

import http.client
import json
import socket
import threading
import time
import urllib.parse
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

from ...kernel.local_http import is_loopback_url
from .jobs import LabJob

#: Every call waits at most this long, start to finish — the ONE hard timeout.
LAB_TIMEOUT_SECONDS = 10.0
#: A lab answer larger than this is not read (raw output is summarised on the lab).
MAX_ANSWER_BYTES = 1_000_000
#: Lab statuses that mean "busy, ask later" rather than "no".
_BUSY_STATUSES = frozenset({429})


class LabOutcome(Enum):
    OK = "ok"
    UNAVAILABLE = "unavailable"
    REFUSED = "refused"


@dataclass(frozen=True)
class LabAnswer:
    """What one call produced: ``body`` — the lab's JSON object when ``OK``,
    else None; ``reason`` — why, when not ``OK`` (``"timeout"``, ``"http 404"`` …)."""

    outcome: LabOutcome
    body: Optional[dict[str, Any]] = None
    reason: str = ""


class LabTransport:
    """The lab job API at *url* (the tunnel's loopback end), with one hard timeout.

    Holds no connection and no state beyond the URL and the timeout. A
    non-loopback *url* is refused at construction (``ValueError``)."""

    def __init__(self, url: str, timeout: float = LAB_TIMEOUT_SECONDS) -> None:
        if not is_loopback_url(url):
            raise ValueError("the lab is reached only through the tunnel's loopback port")
        parsed = urllib.parse.urlsplit(url)
        # http.client directly, not urllib: no proxy and no redirect is ever
        # followed — either could carry the request off this machine.
        self._connection_class = (http.client.HTTPSConnection if parsed.scheme == "https"
                                  else http.client.HTTPConnection)
        self._host = parsed.hostname or ""
        self._port = parsed.port
        self._path_prefix = parsed.path.rstrip("/")
        self._timeout = timeout

    def submit(self, job: LabJob) -> LabAnswer:
        """Ask the lab to run *job* (idempotent on the lab side by ``job.key``)."""
        return self._call("POST", "/jobs", {"key": job.key, "identifier": job.identifier, "level": job.level})

    def status(self, key: str) -> LabAnswer:
        """Where the lab's run of *key* stands (``body["state"]``)."""
        return self._call("GET", f"/jobs/{_quoted(key)}")

    def output(self, key: str) -> LabAnswer:
        """The raw output of a finished run of *key*."""
        return self._call("GET", f"/jobs/{_quoted(key)}/output")

    def _call(self, method: str, path: str, body: Optional[dict[str, Any]] = None) -> LabAnswer:
        """One request. Never raises: every failure is an answer."""
        deadline = time.monotonic() + self._timeout
        connection = self._connection_class(self._host, self._port, timeout=self._timeout)
        watchdog: Optional[threading.Timer] = None
        cut = threading.Event()
        try:
            connection.connect()                            # bounded by the socket timeout
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return LabAnswer(LabOutcome.UNAVAILABLE, reason="timeout")
            # A per-read socket timeout does not bound a lab trickling bytes; the
            # watchdog shuts the socket at the deadline, whatever is being read.
            watchdog = threading.Timer(remaining, _cut_off, args=(connection, cut))
            watchdog.daemon = True
            watchdog.start()
            connection.request(method, self._path_prefix + path,
                               body=json.dumps(body).encode("utf-8") if body is not None else None,
                               headers={"Accept": "application/json", "Content-Type": "application/json"})
            response = connection.getresponse()
            if not 200 <= response.status < 300:
                return _status_answer(response.status)
            raw = response.read(MAX_ANSWER_BYTES + 1)
            # A body cut short (connection closed early) is not an answer.
            complete = not response.length
        except (OSError, http.client.HTTPException) as exc:
            timed_out = cut.is_set() or "timed out" in str(exc)
            return LabAnswer(LabOutcome.UNAVAILABLE, reason="timeout" if timed_out else "unreachable")
        finally:
            if watchdog is not None:
                watchdog.cancel()
            connection.close()
        if cut.is_set():
            return LabAnswer(LabOutcome.UNAVAILABLE, reason="timeout")
        if len(raw) > MAX_ANSWER_BYTES or not complete:
            return LabAnswer(LabOutcome.UNAVAILABLE, reason="oversized or truncated answer")
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except ValueError:
            return LabAnswer(LabOutcome.UNAVAILABLE, reason="malformed answer")
        if not isinstance(parsed, dict):
            return LabAnswer(LabOutcome.UNAVAILABLE, reason="malformed answer")
        return LabAnswer(LabOutcome.OK, parsed)


def _status_answer(status: int) -> LabAnswer:
    """A non-2xx status: a 4xx (not 429) is the lab's definite no; anything else —
    busy, broken, or a redirect (never followed: it could lead off this machine) —
    is could-not-tell."""
    refused = 400 <= status < 500 and status not in _BUSY_STATUSES
    return LabAnswer(LabOutcome.REFUSED if refused else LabOutcome.UNAVAILABLE, reason=f"http {status}")


def _cut_off(connection: http.client.HTTPConnection, cut: threading.Event) -> None:
    """The deadline passed: wake any blocked read by shutting the socket."""
    cut.set()
    sock = connection.sock
    if sock is not None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


def _quoted(key: str) -> str:
    return urllib.parse.quote(key, safe="")
