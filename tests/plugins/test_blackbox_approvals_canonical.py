"""The approval gate judges a settings change by the value the writer will SAVE, and fails toward
asking when it can not read what is on now (``approvals.weakening``; review findings of 2026-11-26).

* A category's ``min_severity`` (and ``block_severity``) was ranked on its raw spelling while the
  settings writer trims and lower-cases it: ``"CRITICAL"`` asked nothing and was saved as critical.
* With the current settings unreadable, sending a protected-paths list was not judged weakening,
  although the module promises that an unknown current value makes a possibly weakening change ask.
"""

from __future__ import annotations

import pytest

from plugins.blackbox.approvals import weakening

KNOWN = weakening.Current(settings={"mode": "block", "block_severity": "high", "protected_paths": ["~/.ssh"],
                                    "categories": {"secret": {"enabled": True, "min_severity": "info"}}})


@pytest.fixture(autouse=True)
def _valid(monkeypatch):
    monkeypatch.setattr(weakening, "_invalid", lambda body: False)


@pytest.mark.parametrize("spelled", ["CRITICAL", " critical ", "Critical"])
def test_a_category_floor_is_judged_on_the_value_the_writer_saves(spelled):
    reasons = weakening.reasons("/api/settings", {"categories": {"secret": {"min_severity": spelled}}}, KNOWN)
    assert reasons == ["Flag secret only at critical and above"]


@pytest.mark.parametrize("spelled", ["CRITICAL", " critical "])
def test_the_block_floor_is_judged_on_the_value_the_writer_saves(spelled):
    assert weakening.reasons("/api/settings", {"block_severity": spelled}, KNOWN) == ["Block only critical threats and above"]


def test_a_protected_paths_change_asks_when_the_current_list_can_not_be_read():
    unread = weakening.Current()
    reasons = weakening.reasons("/api/settings", {"protected_paths": ["~/.aws"]}, unread)
    assert reasons and "protected" in reasons[0].lower()
    assert weakening.reasons("/api/settings", {"protected_paths": ["~/.ssh", "~/.aws"]}, KNOWN) == []
