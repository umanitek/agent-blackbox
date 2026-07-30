#!/usr/bin/env python3
"""Compute and atomically record the DKG runtime loaded by Blackbox.

The installer uses this durable fingerprint to distinguish a daemon that has
actually been restarted onto the current checkout and config from files that
were updated on disk after an interrupted install.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


class FingerprintError(RuntimeError):
    """Raised when the installed runtime cannot be fingerprinted safely."""


_CGROUP_MEMORY_LIMIT_PATHS = (
    Path("/sys/fs/cgroup/memory.max"),
    Path("/sys/fs/cgroup/memory/memory.limit_in_bytes"),
)
_UNLIMITED_MEMORY_THRESHOLD = 1 << 50
_V8_HEAP_OPTION_RE = re.compile(
    r"(?:^|\s)--max[-_]old[-_]space[-_]size(?:=|\s)",
    re.IGNORECASE,
)


def read_cgroup_memory_limit() -> int | None:
    """Return the active cgroup memory ceiling, if it is finite."""
    for path in _CGROUP_MEMORY_LIMIT_PATHS:
        try:
            raw = path.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError):
            continue
        if raw == "max":
            return None
        if not raw:
            continue
        try:
            limit = int(raw)
        except ValueError:
            continue
        if limit >= _UNLIMITED_MEMORY_THRESHOLD:
            return None
        if limit > 0:
            return limit
    return None


def read_physical_memory() -> int | None:
    """Return physical RAM in bytes using only the standard library."""
    try:
        pages = int(os.sysconf("SC_PHYS_PAGES"))
        page_size = int(os.sysconf("SC_PAGE_SIZE"))
        if pages > 0 and page_size > 0:
            return pages * page_size
    except (AttributeError, OSError, TypeError, ValueError):
        pass

    if sys.platform == "win32":
        try:
            import ctypes

            class MemoryStatus(ctypes.Structure):
                _fields_ = [
                    ("length", ctypes.c_ulong),
                    ("memory_load", ctypes.c_ulong),
                    ("total_physical", ctypes.c_ulonglong),
                    ("available_physical", ctypes.c_ulonglong),
                    ("total_page_file", ctypes.c_ulonglong),
                    ("available_page_file", ctypes.c_ulonglong),
                    ("total_virtual", ctypes.c_ulonglong),
                    ("available_virtual", ctypes.c_ulonglong),
                    ("available_extended_virtual", ctypes.c_ulonglong),
                ]

            status = MemoryStatus()
            status.length = ctypes.sizeof(status)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return int(status.total_physical)
        except (AttributeError, OSError, TypeError, ValueError):
            pass
    return None


def resolve_dkg_heap_mb(default_mb: int = 8192) -> int:
    """Choose a V8 heap cap that fits both the host and its cgroup.

    DKG snapshot recovery retains complete RDF phases in memory.  Node's
    roughly 4 GiB default old-space cap is too small for the Blackbox graph,
    while an unconditional 8 GiB cap is unsafe in a smaller container.  Use at
    most 75% of the effective memory ceiling and never exceed ``default_mb``.
    """
    if default_mb <= 0:
        raise FingerprintError("default DKG heap must be positive")
    limits = [
        value
        for value in (read_cgroup_memory_limit(), read_physical_memory())
        if value and 0 < value < _UNLIMITED_MEMORY_THRESHOLD
    ]
    if not limits:
        return default_mb
    limit_mb = min(limits) // (1024 * 1024)
    sized = int(limit_mb * 0.75)
    if sized <= 0:
        raise FingerprintError("effective memory limit is too small for DKG")
    return min(default_mb, sized)


def merge_node_options(node_options: str, heap_mb: int) -> str:
    """Add a DKG heap cap while preserving explicit Node options."""
    existing = str(node_options or "").strip()
    if _V8_HEAP_OPTION_RE.search(existing):
        return existing
    heap = int(heap_mb)
    if heap <= 0:
        raise FingerprintError("DKG heap must be positive")
    option = f"--max-old-space-size={heap}"
    return f"{existing} {option}".strip()


def _add_bytes(digest: "hashlib._Hash", label: str, data: bytes) -> None:
    label_bytes = label.encode("utf-8")
    digest.update(len(label_bytes).to_bytes(8, "big"))
    digest.update(label_bytes)
    digest.update(len(data).to_bytes(8, "big"))
    digest.update(data)


def _runtime_files(cli_dir: Path, dkg_home: Path, dkg_bin: Path) -> list[Path]:
    monorepo_cli = cli_dir / "packages" / "cli"
    cli_package = (
        monorepo_cli
        if (monorepo_cli / "package.json").is_file()
        else cli_dir / "node_modules" / "@origintrail-official" / "dkg"
    )
    config = dkg_home / "config.json"
    required = [config, cli_package / "package.json", dkg_bin]
    missing = [path for path in required if not path.is_file()]
    if missing:
        raise FingerprintError(f"required runtime file is missing: {missing[0]}")

    agent_dists = []
    monorepo_agent_dist = cli_dir / "packages" / "agent" / "dist"
    if monorepo_agent_dist.is_dir():
        agent_dists.append(monorepo_agent_dist)
    agent_dists.extend(sorted(cli_dir.glob("node_modules/**/dkg-agent/dist")))
    if not agent_dists:
        raise FingerprintError(f"dkg-agent dist not found under {cli_dir}")

    files = set(required)
    files.update((cli_package / "dist").rglob("*.js"))
    for dist in agent_dists:
        package_json = dist.parent / "package.json"
        if not package_json.is_file():
            raise FingerprintError(f"dkg-agent package metadata is missing: {package_json}")
        files.add(package_json)
        files.update(dist.rglob("*.js"))
    return sorted(files, key=lambda path: str(path.resolve()))


def compute_fingerprint(
    cli_dir: Path,
    dkg_home: Path,
    node_bin: Path,
    dkg_bin: Path,
    store_queue_limit: str = "512",
    list_context_graphs_projection: str = "1",
    sync_global_max_inflight: str = "1",
    node_options: str = "--max-old-space-size=8192",
    catchup_max_concurrent_peers: str = "1",
    store_queue_wait_timeout_ms: str = "300000",
) -> str:
    cli_dir = cli_dir.expanduser().resolve()
    dkg_home = dkg_home.expanduser().resolve()
    node_bin = node_bin.expanduser().resolve()
    dkg_bin = dkg_bin.expanduser().resolve()
    if not node_bin.is_file():
        raise FingerprintError(f"Node.js executable is missing: {node_bin}")
    try:
        node_version = subprocess.run(
            [str(node_bin), "--version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise FingerprintError(f"could not identify Node.js runtime: {exc}") from exc
    if not node_version:
        raise FingerprintError("Node.js returned an empty version")

    digest = hashlib.sha256()
    _add_bytes(digest, "format", b"blackbox-dkg-runtime-v3")
    _add_bytes(digest, "node-path", str(node_bin).encode("utf-8"))
    _add_bytes(digest, "node-version", node_version.encode("utf-8"))
    _add_bytes(digest, "store-queue-limit", str(store_queue_limit).encode("utf-8"))
    _add_bytes(
        digest,
        "list-context-graphs-projection",
        str(list_context_graphs_projection).encode("utf-8"),
    )
    _add_bytes(
        digest,
        "sync-global-max-inflight",
        str(sync_global_max_inflight).encode("utf-8"),
    )
    _add_bytes(digest, "node-options", str(node_options).encode("utf-8"))
    _add_bytes(
        digest,
        "catchup-max-concurrent-peers",
        str(catchup_max_concurrent_peers).encode("utf-8"),
    )
    _add_bytes(
        digest,
        "store-queue-wait-timeout-ms",
        str(store_queue_wait_timeout_ms).encode("utf-8"),
    )
    for path in _runtime_files(cli_dir, dkg_home, dkg_bin):
        _add_bytes(digest, f"file:{path.resolve()}", path.read_bytes())
    return digest.hexdigest()


def installed_commit(cli_dir: Path) -> str:
    """Return the build commit advertised by the installed DKG package."""
    cli_dir = cli_dir.expanduser().resolve()
    package_roots = (
        cli_dir / "node_modules" / "@origintrail-official" / "dkg",
        cli_dir / "packages" / "cli",
    )
    for package_root in package_roots:
        build_info = package_root / "build-info.json"
        if not build_info.is_file():
            continue
        try:
            payload = json.loads(build_info.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise FingerprintError(f"could not read DKG build metadata: {exc}") from exc
        commit = str(payload.get("commit") or "").strip().lower()
        if len(commit) >= 7 and all(ch in "0123456789abcdef" for ch in commit):
            return commit
        raise FingerprintError(f"invalid DKG build commit in {build_info}")
    raise FingerprintError(f"DKG build-info.json not found under {cli_dir}")


def record_fingerprint(marker: Path, fingerprint: str) -> None:
    normalized = fingerprint.strip().lower()
    if len(normalized) != 64 or any(ch not in "0123456789abcdef" for ch in normalized):
        raise FingerprintError("runtime fingerprint must be a 64-character SHA-256 value")
    marker = marker.expanduser().resolve()
    marker.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{marker.name}.", dir=marker.parent)
    temporary_path = Path(temporary)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(normalized + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, marker)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        temporary_path.unlink(missing_ok=True)
        raise


def wait_for_runtime(
    daemon_url: str,
    expected_commit: str,
    timeout_seconds: float,
) -> dict[str, object]:
    """Wait until the daemon API serves the checkout that was just built."""
    expected = expected_commit.strip().lower()
    if len(expected) < 7 or any(ch not in "0123456789abcdef" for ch in expected):
        raise FingerprintError("expected commit must be a Git hexadecimal revision")
    if timeout_seconds <= 0:
        raise FingerprintError("runtime wait timeout must be positive")

    status_url = daemon_url.rstrip("/") + "/api/status"
    deadline = time.monotonic() + timeout_seconds
    last_detail = "daemon API has not responded"
    while time.monotonic() < deadline:
        try:
            request = urllib.request.Request(
                status_url,
                headers={"Accept": "application/json"},
            )
            with urllib.request.urlopen(request, timeout=min(3.0, timeout_seconds)) as response:
                payload = json.loads(response.read().decode("utf-8"))
            actual = str(
                payload.get("commit") or payload.get("commitShort") or ""
            ).strip().lower()
            if actual and (expected.startswith(actual) or actual.startswith(expected)):
                return payload
            last_detail = f"daemon serves commit {actual or 'unknown'}, expected {expected[:12]}"
        except (OSError, UnicodeError, json.JSONDecodeError, urllib.error.URLError) as exc:
            last_detail = str(exc)
        time.sleep(0.5)
    raise FingerprintError(
        f"DKG runtime did not become ready at {status_url} within "
        f"{timeout_seconds:g}s ({last_detail})"
    )


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        if len(args) in (5, 7, 9, 11) and args[0] == "compute":
            paths = [Path(value) for value in args[1:5]]
            print(compute_fingerprint(*paths, *args[5:]))
            return 0
        if len(args) in (1, 2) and args[0] == "heap":
            default_mb = int(args[1]) if len(args) == 2 else 8192
            print(resolve_dkg_heap_mb(default_mb))
            return 0
        if len(args) in (2, 3) and args[0] == "node-options":
            existing = args[2] if len(args) == 3 else ""
            print(merge_node_options(existing, int(args[1])))
            return 0
        if len(args) == 2 and args[0] == "commit":
            print(installed_commit(Path(args[1])))
            return 0
        if len(args) == 3 and args[0] == "record":
            record_fingerprint(Path(args[1]), args[2])
            return 0
        if len(args) == 4 and args[0] == "wait":
            payload = wait_for_runtime(args[1], args[2], float(args[3]))
            actual = str(payload.get("commit") or payload.get("commitShort") or "")
            print(actual)
            return 0
    except (OSError, ValueError, FingerprintError) as exc:
        print(f"blackbox-dkg-runtime-fingerprint: {exc}", file=sys.stderr)
        return 1
    print(
        f"usage: {Path(sys.argv[0]).name} compute <dkg-cli-dir> <dkg-home> "
        "<node-bin> <dkg-bin> [<store-queue-limit> <list-context-graphs-projection> "
        "[<sync-global-max-inflight> <node-options> "
        "[<catchup-max-concurrent-peers> <store-queue-wait-timeout-ms>]]]\n"
        f"       {Path(sys.argv[0]).name} heap [<default-mb>]\n"
        f"       {Path(sys.argv[0]).name} node-options <heap-mb> [<existing-options>]\n"
        f"       {Path(sys.argv[0]).name} commit <dkg-cli-dir>\n"
        f"       {Path(sys.argv[0]).name} record <marker> <sha256>\n"
        f"       {Path(sys.argv[0]).name} wait <daemon-url> <expected-commit> <timeout-seconds>",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
