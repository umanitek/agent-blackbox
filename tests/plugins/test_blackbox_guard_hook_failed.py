"""The hook boundary fails open, and says so (2026-10-22, FIX-0160).

A tool input that makes detection raise used to be allowed with one DEBUG line
and no record. Now the failure is a WARNING naming the hook and the exception
class, and a ``guard_error`` audit row so the activity trail shows that the
action passed unchecked.
"""

from __future__ import annotations

import logging

import pytest

from plugins.blackbox import ruleset
from plugins.blackbox.guard import hooks, reporting


@pytest.fixture
def recorded(monkeypatch):
    rows: list[dict] = []
    monkeypatch.setattr(reporting.audit, "record", lambda **kw: rows.append(kw))
    return rows


@pytest.fixture
def broken_ruleset(monkeypatch):
    monkeypatch.setattr(hooks, "_config", lambda: object())

    def explode(cfg):
        raise RuntimeError("boom")
    monkeypatch.setattr(ruleset, "get", explode)


def test_a_raising_pre_tool_call_still_allows_the_action(broken_ruleset, recorded, caplog):
    with caplog.at_level(logging.WARNING, logger="plugins.blackbox.guard.reporting"):
        verdict = hooks.on_pre_tool_call(tool_name="terminal", args={"command": "ls"})

    assert verdict is None
    assert any("pre_tool_call raised RuntimeError" in r.getMessage() and "passed unchecked" in r.getMessage()
               for r in caplog.records)


def test_the_failure_is_written_to_the_audit_trail(broken_ruleset, recorded):
    hooks.on_pre_tool_call(tool_name="terminal", args={"command": "ls"})

    assert [r["event"] for r in recorded] == ["guard_error"]
    detail = recorded[0]["detail"]
    assert (detail["hook"], detail["tool_name"], detail["error"]) == ("pre_tool_call", "terminal", "RuntimeError")


def test_a_raising_pre_api_request_is_recorded_too(monkeypatch, recorded, caplog):
    monkeypatch.setattr(hooks, "_config", lambda: (_ for _ in ()).throw(ValueError("bad config")))
    with caplog.at_level(logging.WARNING, logger="plugins.blackbox.guard.reporting"):
        hooks.on_pre_api_request(user_message="hello")

    assert [r["detail"]["hook"] for r in recorded] == ["pre_api_request"]
    assert any("pre_api_request raised ValueError" in r.getMessage() for r in caplog.records)
