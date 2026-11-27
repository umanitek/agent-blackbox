"""The machine every self-protection test judges on, shared by the topic files that split
test_blackbox_self_protection.py (KI-691: one file ran 294 s of the 300 s per-file limit).

``make_machine(monkeypatch, tmp_path)`` (each file's ``machine`` fixture calls it): a home folder with Hermes (main + one profile), two OpenClaw profiles and
Blackbox's data folder; it returns ``use(mode)``. ``attack_cases(*surfaces)``: the red-team
catalogue's cases of those surfaces as pytest params; ``refused_in_every_mode(use, mode, tool,
args)``: the one assertion every attack case makes. ``here(value)``: ``@SRC@`` filled in.
"""

from __future__ import annotations

import json
import shlex
from pathlib import Path

import pytest

from _blackbox_loader import load_blackbox
from _blackbox_self_protection_cases import ATTACKS

guard = load_blackbox("guard")
hooks = load_blackbox("guard.hooks")
guard_background = load_blackbox("guard.background")
config_mod = load_blackbox("kernel.config")
ruleset_mod = load_blackbox("ruleset")

REPO = str(Path(__file__).resolve().parents[2])
OWN_RULE = "blackbox-settings"
CONFIG = "plugins:\n  enabled:\n    - blackbox\n  entries:\n    blackbox:\n      mode: block\n      block_severity: critical\n"
OPENCLAW = {"plugins": {"allow": ["blackbox"], "entries": {"blackbox": {"enabled": True, "config": {"mode": "block"}}}}}


def here(value, *, in_command: bool = False):
    """*value* with ``@SRC@`` replaced by this checkout, through strings, lists and dicts. Inside a
    shell command the checkout is shell-quoted, as a working attack must write it: a checkout whose
    path holds a space (``~/Library/Application Support/…``) is two words unquoted, and neither is
    the checkout, so the shell never reaches it."""
    if isinstance(value, str):
        return value.replace("@SRC@", shlex.quote(REPO) if in_command else REPO)
    if isinstance(value, dict):
        return {key: here(item, in_command=in_command or key == "command") for key, item in value.items()}
    return [here(item, in_command=in_command) for item in value] if isinstance(value, list) else value


def make_machine(monkeypatch, tmp_path):
    """A home folder with Hermes (main + one profile), two OpenClaw profiles and Blackbox's data
    folder; returns ``use(mode)`` which sets the mode the hook judges in."""
    hermes = tmp_path / ".hermes"
    for folder in (hermes / "blackbox", hermes / "plugins" / "blackbox" / "guard", hermes / "profiles" / "coder"):
        folder.mkdir(parents=True)
    for config in (hermes / "config.yaml", hermes / "profiles" / "coder" / "config.yaml"):
        config.write_text(CONFIG, encoding="utf-8")
    for profile in (".openclaw", ".openclaw-work"):
        (tmp_path / profile).mkdir()
        (tmp_path / profile / "openclaw.json").write_text(json.dumps(OPENCLAW), encoding="utf-8")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    monkeypatch.delenv("BLACKBOX_HOME", raising=False)
    monkeypatch.delenv("OPENCLAW_CONFIG_PATH", raising=False)
    monkeypatch.setattr(ruleset_mod, "get", lambda cfg=None: ruleset_mod.Ruleset())
    monkeypatch.setattr(guard_background, "_spawn_llm_review", lambda *a, **k: None)

    def use(mode: str) -> None:
        monkeypatch.setattr(hooks, "_config", lambda: config_mod.BlackboxConfig(mode=mode, report=False))
    return use


def own_findings(verdict) -> list[str]:
    return [finding["identifier"] for finding in verdict["findings"] if finding["matched"] == OWN_RULE]




def attack_cases(*surfaces: str) -> list:
    """The catalogue's attacks of *surfaces*, one pytest param each (id ``<surface>-<n>``)."""
    return [pytest.param(tool, args, id=f"{surface}-{number}")
            for surface in surfaces for number, (tool, args) in enumerate(ATTACKS[surface])]


def refused_in_every_mode(use, mode: str, tool: str, args) -> None:
    """The contract every attack case holds: refused, by self-protection, in *mode*."""
    use(mode)
    verdict = guard.tool_call_verdict(tool, here(args))
    assert verdict["decision"] == "block", verdict
    assert set(own_findings(verdict)) <= set(verdict["blocked"]) and own_findings(verdict)
    assert "Blackbox blocked" in verdict["message"]
