"""The guard never raises on an odd input (2026-11-08 pre-release robustness pass).

The hooks fail OPEN: an exception inside one lets the action through (FIX-0160 records it as a
``guard_error``). So any argument shape that makes detection raise is a gap in protection. These
tests run the REAL hooks — block mode, Trader Shield on, an isolated HOME — over argument shapes a
host or a model can produce (wrong types, nesting, huge or control-character text, empty values)
and require: no hook failure at all, and a protected file read still blocked whatever wraps it.
"""

from __future__ import annotations

import json

import pytest

from plugins.blackbox import ruleset as ruleset_mod
from plugins.blackbox.guard import background as guard_background, hooks, reporting
from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.ruleset import Ruleset
from plugins.blackbox.shields.trader import mode as trader_mode


@pytest.fixture
def guard(tmp_path, monkeypatch):
    """Block mode, Trader Shield on, nothing leaves the temp HOME; returns the hook failures."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    monkeypatch.setattr(hooks, "_config", lambda: config_mod.BlackboxConfig(mode="block", report=False))
    monkeypatch.setattr(ruleset_mod, "get", lambda cfg=None: Ruleset())
    monkeypatch.setattr(guard_background, "_spawn_osv_discovery", lambda *a, **k: None)
    monkeypatch.setattr(trader_mode, "current", lambda: trader_mode.build(enabled=True))
    failures: list[str] = []
    monkeypatch.setattr(reporting, "hook_failed",
                        lambda hook, exc, **kw: failures.append(f"{hook}: {type(exc).__name__}: {exc}"))
    return failures


ODD_ARGS = [
    None, "", "ls -la", 0, 3.5, True, [], ["ls", "-la"], {}, {"command": None}, {"command": 7},
    {"command": ["cat", "notes.txt"]}, {"command": {"nested": "ls"}}, {"path": None}, {"path": ["a", "b"]},
    {"command": "x" * 200_000}, {"command": "echo \x00\x01\x1b[31m‮﻿"}, {"command": "\n" * 5000},
    {"": ""}, {"command": "ls", "extra": [{"deep": [{"deeper": {"x": None}}]}]},
    {"content": b"bytes are not text"}, {"command": "echo " + "\U0001F600" * 1000},
]
TOOLS = ["terminal", "read_file", "write_file", "execute_code", None, 42]


@pytest.mark.parametrize("args", ODD_ARGS, ids=lambda a: type(a).__name__ + ":" + repr(a)[:30])
@pytest.mark.parametrize("tool_name", TOOLS, ids=repr)
def test_the_tool_hooks_never_raise_on_an_odd_input(guard, tool_name, args):
    hooks.on_pre_tool_call(tool_name=tool_name, args=args, session_id="s", task_id="t", tool_call_id="c")
    hooks.on_post_tool_call(tool_name=tool_name, args=args, result=args, session_id="s", task_id="t", tool_call_id="c")
    assert guard == []


@pytest.mark.parametrize("kwargs", [
    {}, {"messages": None}, {"messages": "text"}, {"messages": [None, 1, "x", {"role": "user", "content": None}]},
    {"messages": [{"role": "user", "content": [{"type": "text", "text": None}, {"type": "image_url"}]}]},
    {"input": [{"type": "function_call_output", "output": None}, {"type": "message", "content": 5}]},
    {"input": "plain"}, {"request": {"messages": [{"role": "tool", "content": {"a": [1, 2]}}]}},
    {"messages": [{"role": "user", "content": "x" * 300_000}]},
], ids=lambda k: repr(k)[:40])
def test_the_model_request_hook_never_raises_on_an_odd_payload(guard, kwargs):
    hooks.on_pre_api_request(**kwargs)
    assert guard == []


@pytest.mark.parametrize("args", [
    {"command": "cat ~/.ssh/id_ed25519"},
    json.dumps({"command": "cat ~/.ssh/id_ed25519"}),
    {"command": "cat ~/.ssh/id_ed25519", "extra": [None, {"x": 1}]},
], ids=["dict", "json-string", "with-extra-fields"])
def test_a_protected_key_read_is_blocked_whatever_wraps_it(guard, args):
    decision = hooks.on_pre_tool_call(tool_name="terminal", args=args, session_id="s", task_id="t", tool_call_id="c")
    assert guard == []
    assert isinstance(decision, dict) and decision.get("action") == "block", decision
