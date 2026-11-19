"""One Blackbox protects every Hermes profile on the machine (2026-11-19).

Found on a fresh Mac: Blackbox's own assistant (Hermes profile ``agent-blackbox``) kept a
private Blackbox folder — no compiled verified rules (only the general patterns fired), its own
copy of the settings, and logs the dashboard never read. Every named profile was the same.
These tests hold the one folder, the one set of settings, the main config guarded from a
profile's agent, and the old per-profile logs folded into the shared ones.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

import pytest

from plugins.blackbox.audit import profile_logs
from plugins.blackbox.detection.paths import guard_settings
from plugins.blackbox.kernel import config as bb_config
from plugins.blackbox.kernel import constants, settings

INSTALL_SH = Path(__file__).resolve().parents[2] / "scripts" / "blackbox-install.sh"


@pytest.fixture
def in_profile(tmp_path, monkeypatch):
    """A machine whose main Hermes home is *root*, running the named profile ``agent-blackbox``."""
    root = tmp_path / "hermes-root"
    profile = root / "profiles" / "agent-blackbox"
    profile.mkdir(parents=True)
    monkeypatch.delenv("BLACKBOX_HOME", raising=False)
    monkeypatch.setenv("HERMES_HOME", str(profile))
    return root, profile


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_a_profile_uses_the_main_blackbox_folder(in_profile):
    root, profile = in_profile
    assert constants.hermes_home() == profile
    assert constants.hermes_root() == root
    assert constants.blackbox_home() == root / "blackbox"


def test_an_explicit_blackbox_home_still_wins(in_profile, tmp_path, monkeypatch):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "elsewhere"))
    assert constants.blackbox_home() == tmp_path / "elsewhere"


def test_the_main_home_is_its_own_root(tmp_path, monkeypatch):
    monkeypatch.delenv("BLACKBOX_HOME", raising=False)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "main"))
    assert constants.blackbox_home() == tmp_path / "main" / "blackbox"   # unchanged for the main profile


def test_a_profile_reads_the_main_settings(in_profile):
    root, profile = in_profile
    _write(root / "config.yaml", "plugins:\n  entries:\n    blackbox:\n      mode: block\n")
    _write(profile / "config.yaml", "plugins:\n  entries:\n    blackbox:\n      mode: audit\n")   # the copy made once
    assert bb_config.load_blackbox_config().mode == "block"


def test_a_save_made_in_a_profile_reaches_the_main_settings(in_profile):
    root, profile = in_profile
    _write(root / "config.yaml", "plugins:\n  entries:\n    blackbox:\n      mode: audit\n")
    _write(profile / "config.yaml", "plugins:\n  entries:\n    blackbox:\n      mode: audit\n")
    assert settings._persist_locked({"mode": "block"}) is True
    assert "mode: block" in (root / "config.yaml").read_text(encoding="utf-8")
    assert "mode: audit" in (profile / "config.yaml").read_text(encoding="utf-8")


def test_an_agent_in_a_profile_cannot_write_the_main_config(in_profile):
    root, _profile = in_profile
    places = guard_settings._guarded_places()
    assert str(root / "config.yaml") in places
    assert str(root / "blackbox") in places


# --------------------------------------------------------------------- the old per-profile logs
def _rows(*stamps: float, mark: str) -> str:
    return "".join(json.dumps({"ts": ts, "event": "flagged", "mark": mark}) + "\n" for ts in stamps)


def test_old_profile_logs_join_the_shared_logs_in_time_order(in_profile):
    root, profile = in_profile
    _write(root / "blackbox" / "findings.jsonl", _rows(10.0, 30.0, mark="main"))
    _write(profile / "blackbox" / "findings.jsonl", _rows(20.0, mark="assistant"))
    _write(profile / "blackbox" / "audit.jsonl", _rows(5.0, mark="assistant"))

    assert profile_logs.fold_profile_logs(root) == 2
    merged = [json.loads(line) for line in (root / "blackbox" / "findings.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [row["ts"] for row in merged] == [10.0, 20.0, 30.0]
    assert (root / "blackbox" / "audit.jsonl").read_text(encoding="utf-8").count('"assistant"') == 1
    assert not (profile / "blackbox").exists()
    assert [p.name.startswith("blackbox.folded-") for p in profile.iterdir()] == [True]   # kept, never deleted
    assert profile_logs.fold_profile_logs(root) == 0   # folded once


def test_folding_leaves_the_shared_folder_alone(in_profile):
    root, _profile = in_profile
    _write(root / "blackbox" / "findings.jsonl", _rows(1.0, mark="main"))
    assert profile_logs.fold_profile_logs(root) == 0
    assert (root / "blackbox" / "findings.jsonl").exists()


# --------------------------------------------------------------------- the installer asks about Block mode
def _function(name: str) -> str:
    match = re.search(rf"^{name}\(\)\s*\{{.*?^\}}\n", INSTALL_SH.read_text(encoding="utf-8"), re.MULTILINE | re.DOTALL)
    assert match is not None
    return match.group(0)


def test_without_a_terminal_the_install_stays_in_audit_mode(tmp_path):
    script = 'step() { :; }\n' + _function("ask_block_mode") + 'ask_block_mode && echo BLOCK || echo AUDIT\n'
    done = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, timeout=30,
                          env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(tmp_path)},
                          start_new_session=True, stdin=subprocess.DEVNULL, check=False)
    assert done.stdout.strip() == "AUDIT"


def test_the_block_question_is_only_asked_when_no_mode_was_given():
    body = _function("configure_blackbox_mode")
    assert '[ -z "$requested" ] && [ "$BLACKBOX_SELECTED_MODE" = audit ] && ask_block_mode' in body
