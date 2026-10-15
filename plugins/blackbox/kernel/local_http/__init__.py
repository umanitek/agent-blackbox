"""Bounded HTTP reads with an absolute deadline, including response headers."""
from __future__ import annotations

import http.client
import socket
import threading
import time
import urllib.parse


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
