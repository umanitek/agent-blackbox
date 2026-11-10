"""Blackbox's HTTP transport rules, in one place.

* :func:`open_direct` — how Blackbox talks to its OWN services (the DKG node, the node's
  store, the dashboard): straight to the address given, never through a proxy named in the
  environment (``HTTP_PROXY`` would be handed the bearer token, the request signature and
  every lookup — KI-497), and never following a redirect.
* :class:`RefuseRedirects` — the redirect rule alone, for clients of outside services that
  may legitimately use the operator's proxy.
* :func:`request` — a bounded read with an absolute deadline, including response headers.

Usage::

    with local_http.open_direct(urllib.request.Request(url, headers=headers), timeout=5) as response:
        raw = response.read()
"""
from __future__ import annotations

import http.client
import socket
import threading
import time
import urllib.parse
import urllib.request


def request(url, method, path, data, headers, *, deadline, max_bytes):
    target = urllib.parse.urlsplit(url)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    connection_type = http.client.HTTPSConnection if target.scheme == "https" else http.client.HTTPConnection
    connection = connection_type(target.hostname, target.port, timeout=remaining)
    timer = None
    try:
        # The caller permits only IP literals. Connect/TLS gets the remaining
        # socket budget; after connection, shutdown also interrupts slow headers.
        connection.connect()
        sock = connection.sock
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError

        def cancel():
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass  # the peer may already have closed the connection

        timer = threading.Timer(remaining, cancel)
        timer.daemon = True
        timer.start()
        connection.request(method, path, body=data, headers=headers)
        response = connection.getresponse()
        raw = response.read(max_bytes + 1)
        if time.monotonic() >= deadline:
            raise TimeoutError
        return response.status, raw
    except (OSError, http.client.HTTPException):
        if time.monotonic() >= deadline:
            raise TimeoutError from None
        raise
    finally:
        if timer is not None:
            timer.cancel()
            timer.join()
        connection.close()


class RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: the answer comes from the address asked, or it is an error."""

    def redirect_request(self, *args, **kwargs):
        return None


#: No environment proxy, no redirects. Built once; an opener is safe to share between threads.
_DIRECT = urllib.request.build_opener(urllib.request.ProxyHandler({}), RefuseRedirects())


def open_direct(http_request: urllib.request.Request, timeout: float):
    """Send *http_request* straight to its address and return the response (a context manager).

    Raises what ``urllib.request.urlopen`` raises (``HTTPError``, ``URLError``, ``OSError``);
    a redirect arrives as its ``HTTPError`` (3xx) instead of being followed.
    """
    return _DIRECT.open(http_request, timeout=timeout)


__all__ = ["RefuseRedirects", "open_direct", "request"]
