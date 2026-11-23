"""Inside the agent sandbox Blackbox's settings can not be written, and Blackbox's home can not be
moved away.

Design review 2026-11-23, P0 (recorded as a private security finding): ``<hermes_root>/config.yaml``
holds EVERY Blackbox setting (``blackbox: mode``, ``shields: file-shield: enabled``, the sandboxed
agents) and was not among the sandbox profile's closed places. A sandboxed script the hook can not
read could have switched File Shield off or emptied the sandboxed list. Also checked: whether
``~/.hermes`` itself (the folder above Blackbox's home) could be renamed from inside — Blackbox's
home would move away and every launcher fall back to hooks only.

Proven with the REAL Seatbelt sandbox, in a temporary home (never the real one).
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

from plugins.blackbox.shields.files import changes, mode as files_mode, sandbox
from plugins.blackbox.shields.files.sandbox import platform

REAL = pytest.mark.skipif(sys.platform != "darwin" or not os.access("/usr/bin/sandbox-exec", os.X_OK),
                          reason="a real Seatbelt sandbox needs macOS")
CONFIG = "plugins:\n  enabled:\n    - blackbox\nblackbox:\n  mode: block\n"


@pytest.fixture
def home(tmp_path, monkeypatch):
    real = tmp_path.resolve()
    hermes = real / ".hermes"
    (hermes / "blackbox").mkdir(parents=True)
    (hermes / "profiles" / "work").mkdir(parents=True)
    for config in (hermes / "config.yaml", hermes / "profiles" / "work" / "config.yaml"):
        config.write_text(CONFIG, encoding="utf-8")
    (hermes / ".env").write_text("OPENAI_API_KEY=x\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(real))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    monkeypatch.delenv("BLACKBOX_HOME", raising=False)
    monkeypatch.setattr(platform, "startup_places", lambda folder: ([], [], []))
    changes.reset()
    yield real
    changes.reset()


def _run(script: str) -> dict[str, str]:
    done = subprocess.run(["/usr/bin/sandbox-exec", "-f", str(sandbox.profile_path()), "/bin/sh", "-c", script],
                          capture_output=True, text=True, timeout=30, check=False)
    return dict(line.split("=", 1) for line in done.stdout.split() if "=" in line)


def _sync():
    sandbox.sync(files_mode.build(enabled=True, protected=("~/Documents/Vault",), sandboxed=("claude-code",)))


@REAL
def test_blackboxs_settings_in_hermes_config_can_not_be_changed_from_inside(home):
    _sync()
    hermes = home / ".hermes"
    lines = _run(f"""
printf 'shields:\\n  file-shield:\\n    enabled: false\\n' >> '{hermes}/config.yaml' 2>/dev/null; echo append=$?
echo x > '{hermes}/config.yaml' 2>/dev/null; echo overwrite=$?
mv '{hermes}/config.yaml' '{hermes}/config.old' 2>/dev/null; echo rename=$?
rm -f '{hermes}/config.yaml' 2>/dev/null; echo remove=$?
echo BLACKBOX_MODE=audit >> '{hermes}/.env' 2>/dev/null; echo env=$?
echo x >> '{hermes}/profiles/work/config.yaml' 2>/dev/null; echo profile=$?
echo x > '{hermes}/profiles/new/config.yaml' 2>/dev/null; echo new_profile=$?
cat '{hermes}/config.yaml' >/dev/null 2>&1; echo read=$?
echo x > '{hermes}/notes.txt' 2>/dev/null; echo sibling=$?
""")
    assert lines == {"append": "1", "overwrite": "1", "rename": "1", "remove": "1", "env": "1", "profile": "1",
                     "new_profile": "1", "read": "0", "sibling": "0"}, lines
    assert (hermes / "config.yaml").read_text(encoding="utf-8") == CONFIG


@REAL
def test_blackboxs_home_can_not_be_moved_away_from_inside(home):
    _sync()
    hermes = home / ".hermes"
    lines = _run(f"""
mv '{hermes}' '{home}/.hermes-moved' 2>/dev/null; echo hermes=$?
mv '{hermes}/blackbox' '{hermes}/blackbox-moved' 2>/dev/null; echo blackbox=$?
mkdir '{hermes}/scratch' && rmdir '{hermes}/scratch'; echo own_folder_inside=$?
""")
    assert lines == {"hermes": "1", "blackbox": "1", "own_folder_inside": "0"}, lines
    assert (hermes / "blackbox").is_dir()


def test_the_policy_names_the_settings_files_and_every_folder_above_blackboxs_places(home):
    places = sandbox.policy(files_mode.build(enabled=True, sandboxed=("claude-code",)))
    hermes = str(home / ".hermes")
    assert {hermes + "/config.yaml", hermes + "/.env"} <= set(places.no_write_files)
    assert hermes + "/profiles/*/config.yaml" in places.no_write_globs
    assert {hermes, str(home)} <= set(places.no_rename)


@REAL
def test_the_canary_is_still_refused_inside_but_never_reported(home):
    """KI-600 (round 5): every hook call probes the canary; each probe was a kernel log line (~30 in
    36 s) and the real refusal after them never reached the log the helper reads. The canary is now
    refused without a report — still the proof a session is inside."""
    _sync()
    canary = sandbox.canary_path()
    assert _run(f"cat '{canary}' >/dev/null 2>&1; echo canary=$?") == {"canary": "1"}
    profile = sandbox.profile_path().read_text(encoding="utf-8")
    [line] = [each for each in profile.splitlines() if str(canary.resolve()) in each]
    assert line.startswith("(deny file-read*") and line.endswith("(with no-report))")
