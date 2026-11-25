"""Reading a program's signature or a file's extended attributes is not changing Blackbox (KI-608).

Security round 4, system-level day (REAL, Claude Code haiku, both modes): ``codesign -dv`` on two
apps — one of them the companion app, which Blackbox guards as an add-on place — was refused by the
hook as "Change to Blackbox's own settings"; ``spctl -a`` and an ``xattr`` round-trip passed.
``codesign -d``/``--verify``, ``spctl --assess`` and ``xattr -l``/``-p`` only read; signing,
re-signing, stripping a signature, a security-policy change and writing or deleting an attribute
on a guarded place stay refused.
"""

from __future__ import annotations

import pytest

from _blackbox_loader import load_blackbox

guard_settings = load_blackbox("detection.paths.guard_settings")


@pytest.fixture
def home(tmp_path, monkeypatch):
    for folder in (".hermes/blackbox", ".hermes/plugins/blackbox"):
        (tmp_path / folder).mkdir(parents=True)
    (tmp_path / ".hermes" / "config.yaml").write_text("plugins:\n  enabled:\n    - blackbox\n", encoding="utf-8")
    (tmp_path / ".hermes" / "plugins" / "blackbox" / "plugin.yaml").write_text("name: blackbox\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
    monkeypatch.delenv("BLACKBOX_HOME", raising=False)
    return tmp_path


def _refused(command: str) -> bool:
    return bool(guard_settings.detect_guard_tamper("terminal", {"command": command}))


@pytest.mark.parametrize("command", [
    "codesign -dv ~/.hermes/plugins/blackbox",
    "codesign -dvvv --entitlements - ~/.hermes/plugins/blackbox/plugin.yaml",
    "codesign --verify --deep --strict ~/.hermes/plugins/blackbox",
    "codesign -dv /Applications/Safari.app ~/.hermes/plugins/blackbox 2>&1 | head -5",
    "spctl -a -vv ~/.hermes/plugins/blackbox",
    "spctl --assess --type execute ~/.hermes/plugins/blackbox",
    "xattr -l ~/.hermes/plugins/blackbox/plugin.yaml",
    "xattr -p com.apple.quarantine ~/.hermes/plugins/blackbox/plugin.yaml",
])
def test_reading_a_signature_or_an_attribute_is_allowed(home, command):
    assert not _refused(command), command


@pytest.mark.parametrize("command", [
    "codesign -s - --force ~/.hermes/plugins/blackbox/plugin.yaml",
    "codesign -fs - ~/.hermes/plugins/blackbox/plugin.yaml",
    "codesign --remove-signature ~/.hermes/plugins/blackbox/plugin.yaml",
    "xattr -d com.apple.quarantine ~/.hermes/plugins/blackbox/plugin.yaml",
    "xattr -w user.x 1 ~/.hermes/plugins/blackbox/plugin.yaml",
    "xattr -c ~/.hermes/plugins/blackbox/plugin.yaml",
    "spctl --add ~/.hermes/plugins/blackbox",
    "rm -rf ~/.hermes/plugins/blackbox",
])
def test_changing_a_signature_or_an_attribute_stays_refused(home, command):
    assert _refused(command), command
