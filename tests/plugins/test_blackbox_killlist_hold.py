"""The kill list's 24 h hold releases its entries, and a publisher-wide kill matches the publisher
however the call spells it (``killlist.gates`` / ``.store`` / ``.check``; review findings of 2026-11-26).

* An entry still inside its hold was left out of the saved list; the next refresh then refused
  the SAME version as "not newer", so the held kill was never applied. The held entries are now
  kept beside the applied ones and admitted when the hold ends.
* A publisher-wide kill compared the call's ``publisher`` text as sent: a trailing space or other
  case missed it. Both sides are canonical (trimmed, case-folded) now.
"""

from __future__ import annotations

import time

import pytest

from plugins.blackbox import killlist

DAY = "2026-10-02"
SIGNED = time.mktime(time.strptime(DAY, "%Y-%m-%d")) - time.timezone


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))


def _entry(identifier, version="1.0.0", **kw):
    return killlist.KillEntry(registry="skill", identifier=identifier, action=killlist.KillAction.DISABLE, version=version, **kw)


def _cycle(store, kill_list, now):
    """One refresh as the ruleset runs it: admit against the last-good list, remember what passed."""
    decision = killlist.admit(kill_list, signers={"a", "b"}, root_signers={"root"}, previous=store.current(),
                              now=now, is_popular=lambda e: e.identifier == "popular-skill")
    store.remember(decision, kill_list.day)
    return decision


def test_an_entry_held_for_a_day_is_applied_when_the_hold_ends(tmp_path):
    store = killlist.LastGoodStore(tmp_path / "kill_list.json")
    pinned, popular = _entry("evil-skill"), _entry("popular-skill")
    kill_list = killlist.KillList(version=1, day=DAY, entries=(pinned, popular))
    held = _cycle(store, kill_list, SIGNED + 3600)
    assert held.applied == (pinned,) and held.deferred == (popular,)
    assert store.current().entries == (pinned,)                     # not enforced while it is held
    released = _cycle(store, kill_list, SIGNED + killlist.POPULAR_HOLD_SECONDS + 1)
    assert not released.refused and released.applied == (pinned, popular)
    assert store.current().entries == (pinned, popular)
    again = _cycle(store, kill_list, SIGNED + killlist.POPULAR_HOLD_SECONDS + 7200)
    assert store.current().entries == (pinned, popular) and "not newer" in again.refused


def test_an_older_or_a_different_same_version_list_still_never_replaces_the_held_one(tmp_path):
    store = killlist.LastGoodStore(tmp_path / "kill_list.json")
    kill_list = killlist.KillList(version=2, day=DAY, entries=(_entry("evil-skill"), _entry("popular-skill")))
    _cycle(store, kill_list, SIGNED + 3600)
    other = killlist.KillList(version=2, day=DAY, entries=(_entry("someone-else"),))
    assert "not newer" in _cycle(store, other, SIGNED + killlist.POPULAR_HOLD_SECONDS + 1).refused
    older = killlist.KillList(version=1, day=DAY, entries=kill_list.entries)
    assert "not newer" in _cycle(store, older, SIGNED + killlist.POPULAR_HOLD_SECONDS + 1).refused
    assert [e.identifier for e in store.current().entries] == ["evil-skill"]


@pytest.mark.parametrize("spelled", ["evilcorp ", " EvilCorp", "EVILCORP"])
def test_a_publisher_wide_kill_matches_however_the_publisher_is_spelled(spelled):
    wide = killlist.KillEntry("skill", "*", killlist.KillAction.DISABLE, publisher="EvilCorp")
    call = {"name": "x", "version": "1.0.0", "code": "print(1)", "publisher": spelled}
    assert killlist.match((wide,), "skill_install", call) == wide
