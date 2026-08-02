"""Portable development fallback for the generated Blackbox hook command.

The installer replaces the bundled command with absolute paths to its managed
Python and runtime. This locator keeps a manually installed checkout plugin
useful without duplicating the Blackbox detection engine in this integration.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _runtime() -> Path | None:
    plugin_root = Path(os.environ.get("PLUGIN_ROOT") or os.environ.get("CLAUDE_PLUGIN_ROOT") or __file__).resolve()
    if plugin_root.is_file():
        plugin_root = plugin_root.parent.parent
    candidates = [
        plugin_root.parents[1] / "plugins" / "blackbox" / "external_hook.py"
        if len(plugin_root.parents) > 1
        else plugin_root / "missing",
        Path.home() / ".hermes" / "plugins" / "blackbox" / "external_hook.py",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def main() -> int:
    runtime = _runtime()
    if runtime is None:
        return 0
    raw = sys.stdin.buffer.read()
    # The managed installer command passes the framework explicitly. For a
    # manually installed portable plugin, infer Codex from its extension fields.
    try:
        payload = json.loads(raw.decode("utf-8")) if raw.strip() else {}
    except Exception:
        payload = {}
    framework = "codex" if isinstance(payload, dict) and (
        payload.get("model") is not None or payload.get("turn_id") is not None
    ) else "claude-code"
    completed = subprocess.run(
        [sys.executable, str(runtime), "--framework", framework],
        input=raw,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if completed.stdout:
        sys.stdout.buffer.write(completed.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
