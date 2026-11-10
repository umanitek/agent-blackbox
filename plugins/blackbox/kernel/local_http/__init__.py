"""Blackbox's HTTP transport rules, in one place.

* :func:`open_direct` — how Blackbox talks to its OWN services (the DKG node, the node's
  store, the dashboard): straight to the address given, never through a proxy named in the
  environment (``HTTP_PROXY`` would be handed the bearer token, the request signature and
  every lookup — KI-497), and never following a redirect.
* :class:`RefuseRedirects` — the redirect rule alone, for clients of outside services that
  may legitimately use the operator's proxy.
* :func:`request` — a bounded read with an absolute deadline, including response headers.
* :func:`is_loopback_host` / :func:`is_loopback_url` — THE answer to "is this address on this
  machine?". Four modules each kept their own and disagreed (``127.0.0.2`` was local to one
  and remote to three; one took an unparseable URL as local). The rule: the name
  ``localhost`` or an IP address in a loopback range — decided from the text, never by a
  DNS lookup.

Usage::

    with local_http.open_direct(urllib.request.Request(url, headers=headers), timeout=5) as response:
        raw = response.read()
"""
from __future__ import annotations

import http.client
import ipaddress
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


def is_loopback_host(host: str) -> bool:
    """Whether *host* (a URL's host name, without brackets) is this machine: ``localhost`` in
    any letter case, or an IP address in a loopback range (``127.0.0.0/8``, ``::1``, and the
    IPv4 loopbacks written as IPv6). No name is looked up: any other name is not local."""
    host = (host or "").strip().lower().strip("[]")
    if host == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    mapped = getattr(address, "ipv4_mapped", None)   # ::ffff:127.0.0.1 — spelled the same on every Python
    return (mapped or address).is_loopback


def is_loopback_url(url: str) -> bool:
    """Whether *url* is an http(s) URL whose host is this machine (:func:`is_loopback_host`).
    Anything that does not parse as such a URL is not local."""
    try:
        parsed = urllib.parse.urlsplit(url or "")
        host = parsed.hostname or ""
    except ValueError:
        return False
    return parsed.scheme in ("http", "https") and is_loopback_host(host)


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


__all__ = ["RefuseRedirects", "is_loopback_host", "is_loopback_url", "open_direct", "request"]
