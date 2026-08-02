#!/usr/bin/env python3
"""Alert-only health monitor for the Blackbox DKG publisher node.

This is an external observer. It never mutates or restarts DKG.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


SERVICE = "dkg-node.service"
STATE_PATH = Path(os.getenv("MONITOR_STATE_PATH", "/var/lib/blackbox-dkg-monitor/state.json"))
HOST_LABEL = os.getenv("MONITOR_HOST_LABEL", "blackbox-publisher-node")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
DRY_RUN = os.getenv("MONITOR_DRY_RUN", "").lower() in {"1", "true", "yes"}

# A busy Blazegraph can miss one five-second probe while successfully promoting
# an asset. Alert only after three consecutive failed minute probes, and require
# two healthy probes before announcing recovery, so Slack reflects outages
# instead of normal publication latency.
FAILURE_THRESHOLDS = {"blazegraph": 3}
RECOVERY_THRESHOLDS = {"blazegraph": 2}


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, text=True, capture_output=True, check=False, timeout=15)


def recent_logs(since: str = "6 minutes ago") -> str:
    result = run("journalctl", "-u", SERVICE, "--since", since, "--no-pager", "-o", "cat")
    return result.stdout if result.returncode == 0 else ""


def service_invocation() -> str:
    result = run("systemctl", "show", SERVICE, "--property=InvocationID", "--value")
    return result.stdout.strip() if result.returncode == 0 else ""


def load_state() -> dict[str, Any]:
    try:
        value = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(value: Mapping[str, Any]) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix="state.", dir=STATE_PATH.parent)
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(value, handle, sort_keys=True)
            handle.write("\n")
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, STATE_PATH)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


def health_issues() -> dict[str, str]:
    issues: dict[str, str] = {}

    active = run("systemctl", "is-active", SERVICE)
    if active.stdout.strip() != "active":
        issues["service"] = f"{SERVICE} is {active.stdout.strip() or 'not active'}"

    try:
        request = urllib.request.Request("http://127.0.0.1:9999/bigdata/status")
        with urllib.request.urlopen(request, timeout=5) as response:
            if response.status != 200:
                issues["blazegraph"] = f"Blazegraph health endpoint returned HTTP {response.status}"
    except (OSError, urllib.error.URLError) as exc:
        issues["blazegraph"] = f"Blazegraph health endpoint failed: {exc}"

    logs = recent_logs()
    heartbeat_count = logs.count("Peer health ping:")
    if active.stdout.strip() == "active" and heartbeat_count == 0:
        issues["heartbeat"] = "No DKG peer-health heartbeat logged in the last 6 minutes"

    queue_failures = sum(
        logs.count(pattern)
        for pattern in ("Store scheduler queue wait timeout", "Store scheduler queue full")
    )
    if queue_failures >= 10:
        issues["store_queue"] = (
            f"{queue_failures} DKG store-queue timeout/full errors in the last 6 minutes"
        )

    usage = shutil.disk_usage("/")
    disk_pct = round(100 * usage.used / usage.total)
    if disk_pct >= 85:
        issues["disk"] = f"Root filesystem usage is {disk_pct}%"

    try:
        meminfo = {}
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            key, value = line.split(":", 1)
            meminfo[key] = int(value.strip().split()[0])
        available_pct = round(100 * meminfo["MemAvailable"] / meminfo["MemTotal"])
        if available_pct <= 10:
            issues["memory"] = f"Available memory is {available_pct}%"
    except (OSError, KeyError, ValueError):
        pass

    return issues


def stabilize_issues(
    state: Mapping[str, Any], observed: Mapping[str, str],
) -> tuple[dict[str, str], dict[str, int], dict[str, int]]:
    """Debounce selected probes while preserving immediate critical alerts."""
    previous = dict(state.get("issues") or {})
    failure_counts = {
        str(key): int(value)
        for key, value in dict(state.get("failure_counts") or {}).items()
    }
    recovery_counts = {
        str(key): int(value)
        for key, value in dict(state.get("recovery_counts") or {}).items()
    }
    current = dict(previous)

    for key, detail in observed.items():
        failure_counts[key] = failure_counts.get(key, 0) + 1
        recovery_counts.pop(key, None)
        if key in previous or failure_counts[key] >= FAILURE_THRESHOLDS.get(key, 1):
            current[key] = detail

    for key in set(previous) - set(observed):
        failure_counts.pop(key, None)
        recovery_counts[key] = recovery_counts.get(key, 0) + 1
        if recovery_counts[key] >= RECOVERY_THRESHOLDS.get(key, 1):
            current.pop(key, None)
            recovery_counts.pop(key, None)

    for key in set(failure_counts) - set(observed):
        failure_counts.pop(key, None)

    return current, failure_counts, recovery_counts


def post_slack(text: str) -> None:
    if DRY_RUN:
        print(text)
        return
    if not SLACK_WEBHOOK_URL:
        raise RuntimeError("SLACK_WEBHOOK_URL is not configured")
    body = json.dumps({"text": text}).encode()
    request = urllib.request.Request(
        SLACK_WEBHOOK_URL,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        response_body = response.read().decode(errors="replace")
        if response.status != 200 or response_body.strip() != "ok":
            raise RuntimeError(f"Slack returned HTTP {response.status}: {response_body[:200]}")


def main() -> int:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    state = load_state()
    previous = dict(state.get("issues") or {})
    observed = health_issues()
    current, failure_counts, recovery_counts = stabilize_issues(state, observed)
    invocation = service_invocation()
    previous_invocation = state.get("service_invocation", "")
    new_keys = sorted(set(current) - set(previous))
    recovered_keys = sorted(set(previous) - set(current))

    messages = []
    if previous_invocation and invocation and invocation != previous_invocation:
        messages.append(
            f":warning: *DKG SERVICE RESTARTED — {HOST_LABEL}*\n"
            f"The systemd invocation changed since the previous check.\n_{now}_"
        )
    if new_keys:
        details = "\n".join(f"• {current[key]}" for key in new_keys)
        messages.append(f":rotating_light: *DKG ALERT — {HOST_LABEL}*\n{details}\n_{now}_")
    if recovered_keys:
        details = "\n".join(f"• Recovered: {previous[key]}" for key in recovered_keys)
        messages.append(f":white_check_mark: *DKG RECOVERY — {HOST_LABEL}*\n{details}\n_{now}_")

    try:
        for message in messages:
            post_slack(message)
    except Exception as exc:
        print(f"alert delivery failed: {exc}", file=sys.stderr)
        return 1

    save_state({
        "issues": current,
        "observed_issues": observed,
        "failure_counts": failure_counts,
        "recovery_counts": recovery_counts,
        "last_check": now,
        "service_invocation": invocation,
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
