"""A publisher-wide kill and installs whose publisher no registry confirmed (``killlist.check``;
owner decision 2026-11-27).

While a curator-signed publisher-wide DISABLE is in force for a registry, an install there that
names no publisher (and none a registry confirms) is a critical finding matched ``unnamed-publisher``, decided by the person's
``unnamed-publisher`` permission (blocked in Block mode by default, a flag when allowed). Naming the
killed publisher is still the kill itself. With no publisher kill in force nothing changes.
"""

from __future__ import annotations

import pytest

from plugins.blackbox import killlist
from plugins.blackbox.guard import hooks
from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.kernel.config import BlackboxConfig

DAY = "2026-11-27"
UNNAMED = "unnamed-publisher"


@pytest.fixture
def entry(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    state: dict = {"mode": "block"}
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: state)
    return state


def _list(*entries: killlist.KillEntry) -> killlist.KillList:
    return killlist.KillList(version=3, day=DAY, entries=entries)


PUBLISHER_KILL = killlist.KillEntry("skill", "*", killlist.KillAction.DISABLE, publisher="EvilCorp")


def _install(**extra: str) -> dict:
    return {"name": "handy-tool", "version": "1.2.0", "code": "print('hi')", **extra}


@pytest.mark.parametrize("args", [_install(), _install(author=""), _install(publisher="  ")], ids=["none", "empty", "blank"])
def test_an_install_naming_no_publisher_under_a_publisher_kill_is_critical(args):
    found = killlist.finding_for(_list(PUBLISHER_KILL), "skill_install", args)
    assert found is not None and found.matched == UNNAMED and found.severity == "critical"
    assert found.source == "custom" and "EvilCorp" in found.title


def test_an_install_naming_another_publisher_is_not_refused_for_it():
    """The owner's interim line (2026-11-27): only an install naming NO publisher is refused."""
    assert killlist.finding_for(_list(PUBLISHER_KILL), "skill_install", _install(publisher="GoodCorp")) is None


def test_naming_the_killed_publisher_is_still_the_kill():
    found = killlist.finding_for(_list(PUBLISHER_KILL), "skill_install", _install(publisher="evilcorp"))
    assert found is not None and found.matched == "EvilCorp" and found.kind == "malware"


@pytest.mark.parametrize("kills", [(), (killlist.KillEntry("skill", "evil-skill", killlist.KillAction.DISABLE),),
                                   (killlist.KillEntry("skill", "*", killlist.KillAction.WARN, publisher="EvilCorp"),)],
                         ids=["no-list", "name-kill-only", "publisher-warn-only"])
def test_with_no_publisher_kill_in_force_nothing_changes(kills):
    assert killlist.finding_for(_list(*kills) if kills else None, "skill_install", _install()) is None


def test_a_call_that_installs_nothing_is_untouched():
    assert killlist.finding_for(_list(PUBLISHER_KILL), "terminal", {"command": "ls"}) is None


def test_the_unnamed_publisher_permission_decides_it(entry):
    found = killlist.finding_for(_list(PUBLISHER_KILL), "skill_install", _install())
    assert hooks._would_block(BlackboxConfig(mode="block"), [found]) == [found]     # the default: blocked in Block mode
    assert hooks._would_block(BlackboxConfig(mode="audit"), [found]) == []          # a flag in Audit mode
    entry["agent_sandbox"] = {"permissions": [{"permission": "unnamed-publisher", "mode": "allow"}]}
    assert hooks._would_block(BlackboxConfig(mode="block"), [found]) == []
    assert found.fields["allowed_by_permission"] == "unnamed-publisher"
