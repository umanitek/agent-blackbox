"""Tailnet-only HTTP download endpoint for immutable approval bundles."""

from __future__ import annotations

import hmac
import re
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping

from .core import State
from .pipeline import bundle_export_bytes


_DOWNLOAD = re.compile(r"^/(?:blackbox-review/)?bundles/(bundle-[A-Za-z0-9T.+-]+)\.json$")


def bundle_download_url(config: Mapping[str, Any], row: Mapping[str, Any]) -> str:
    base = str(config["slack"].get("download_base_url") or "").rstrip("/")
    if not base:
        raise RuntimeError("slack.download_base_url is not configured")
    bundle_id = urllib.parse.quote(str(row["bundle_id"]), safe="")
    manifest = urllib.parse.quote(str(row["manifest_sha256"]), safe="")
    return f"{base}/bundles/{bundle_id}.json?manifest={manifest}"


class BundleDownloadHandler(BaseHTTPRequestHandler):
    server: "BundleDownloadServer"

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/healthz":
            self._reply(200, b"ok\n", "text/plain; charset=utf-8")
            return
        if not self.headers.get("Tailscale-User-Login"):
            self._reply(403, b"tailnet identity required\n", "text/plain; charset=utf-8")
            return
        match = _DOWNLOAD.fullmatch(parsed.path)
        manifest = (urllib.parse.parse_qs(parsed.query).get("manifest") or [""])[0]
        if not match or not re.fullmatch(r"[0-9a-f]{64}", manifest):
            self._reply(404, b"not found\n", "text/plain; charset=utf-8")
            return
        bundle_id = match.group(1)
        state = State(self.server.state_path)
        try:
            row = state.bundle_row(bundle_id)
            if not hmac.compare_digest(str(row["manifest_sha256"]), manifest):
                self._reply(404, b"not found\n", "text/plain; charset=utf-8")
                return
            payload = bundle_export_bytes(self.server.config, state, bundle_id)
        except (KeyError, FileNotFoundError, RuntimeError, ValueError):
            self._reply(404, b"not found\n", "text/plain; charset=utf-8")
            return
        finally:
            state.close()
        filename = f"{bundle_id}-threats.json"
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "private, no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(payload)

    def _reply(self, status: int, payload: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: Any) -> None:
        # Do not log manifest-bearing URLs. systemd already records lifecycle.
        return


class BundleDownloadServer(ThreadingHTTPServer):
    def __init__(self, address, config: Mapping[str, Any], state_path: Path):
        super().__init__(address, BundleDownloadHandler)
        self.config = config
        self.state_path = state_path


def serve_downloads(config: Mapping[str, Any]) -> None:
    settings = config.get("downloads") or {}
    host = str(settings.get("host", "127.0.0.1"))
    port = int(settings.get("port", 8791))
    state_path = Path(str(config["paths"]["state_dir"])) / "pipeline.sqlite3"
    BundleDownloadServer((host, port), config, state_path).serve_forever()
