"""A hook's own process reads Blackbox's settings without importing Hermes's config module — and
never reads settings other than the ones Hermes would merge (``kernel/config_values/entry_snapshot``).

Linux round L8 (BB-LINUX-PENDING-7582d0, the hook budget): with the dashboard stopped the hook
runner judged each call in a fresh process in 5.0-6.6 s (p50) at load 12 on the 4-CPU VM, over
its 6.5 s budget. Profiled there, importing ``hermes_cli.config`` only to read Blackbox's entry was
the largest single cost: 272 ms of 986 ms of imports. The entry Hermes merged is kept beside
Blackbox's data, keyed on Hermes's own change key of the files it merged; any change sends the
reader back to Hermes.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
READ = ("import json, sys; from plugins.blackbox.kernel.config_values import saved_entry; "
        "print(json.dumps({'entry': saved_entry.read(), 'hermes_config': 'hermes_cli.config' in sys.modules}))")
BLOCK = "plugins:\n  enabled: [blackbox]\n  entries:\n    blackbox:\n      mode: block\n"


@pytest.fixture
def machine(tmp_path):
    hermes = tmp_path / ".hermes"
    hermes.mkdir()
    (tmp_path / "bb").mkdir()
    (hermes / "config.yaml").write_text(BLOCK, encoding="utf-8")
    env = {**os.environ, "HOME": str(tmp_path), "HERMES_HOME": str(hermes), "BLACKBOX_HOME": str(tmp_path / "bb"),
           "PYTHONDONTWRITEBYTECODE": "1"}
    env.pop("HERMES_MANAGED_DIR", None)
    return tmp_path, env


def _read(env: dict, code: str = READ) -> dict:
    out = subprocess.run([sys.executable, "-c", code], cwd=REPO, env=env, capture_output=True, text=True, timeout=120, check=True)
    return json.loads(out.stdout.strip().splitlines()[-1])


def _through_hermes(env: dict) -> dict:
    """A process that has Hermes's config loaded (the dashboard, Hermes): it reads through Hermes and keeps the snapshot."""
    return _read(env, "import hermes_cli.config; " + READ)


def test_a_fresh_process_reads_the_entry_hermes_merged_without_importing_its_config(machine):
    home, env = machine
    assert _through_hermes(env)["entry"] == {"mode": "block"}
    assert (home / "bb" / "settings-snapshot.json").is_file()
    fresh = _read(env)
    assert fresh == {"entry": {"mode": "block"}, "hermes_config": False}


def test_any_change_to_the_config_is_read_through_hermes_again(machine):
    home, env = machine
    _through_hermes(env)
    config = home / ".hermes" / "config.yaml"
    stat = config.stat()
    config.write_text(BLOCK.replace("block", "audt"), encoding="utf-8")       # same size …
    os.utime(config, ns=(stat.st_atime_ns, stat.st_mtime_ns))                 # … and the old time put back
    fresh = _read(env)
    assert fresh == {"entry": {"mode": "audt"}, "hermes_config": True}


def test_a_config_whose_values_hermes_expands_is_never_kept(machine):
    home, env = machine
    (home / ".hermes" / "config.yaml").write_text(BLOCK.replace("mode: block", "mode: ${BB_MODE}"), encoding="utf-8")
    _through_hermes({**env, "BB_MODE": "block"})
    assert not (home / "bb" / "settings-snapshot.json").exists()
    assert _read({**env, "BB_MODE": "audit"})["hermes_config"] is True   # each process expands its own environment


def test_no_snapshot_is_made_without_a_blackbox_home(machine):
    home, env = machine
    (home / "bb").rmdir()
    _through_hermes(env)
    assert not (home / "bb").exists()
