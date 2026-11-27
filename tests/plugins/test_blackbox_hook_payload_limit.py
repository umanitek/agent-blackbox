"""The hook runner's pre-tool payload limit is the person's setting ``hook_payload_limit_mb``
(4, 16 or 64 MiB; default 16), read by the stdlib-only runner from the file the plugin writes
beside it (``agent_hooks.protect.judge_here``). Unreadable or not a choice: 16 MiB. Over the limit
stays refused; neither direction is a weakening (``approvals``), since no choice lets a call
through unchecked.
"""

from __future__ import annotations

import json

import pytest

from plugins.blackbox import agent_hooks
from plugins.blackbox.agent_hooks.protect import answers, events, judge_here, runner
from plugins.blackbox.approvals import weakening
from plugins.blackbox.kernel import config as config_mod, settings
from plugins.blackbox.kernel.config_values import schema

DOWN = "http://127.0.0.1:9"
MIB = 1024 * 1024


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes"))
    state: dict = {}
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: state)
    return state


def test_the_runner_keeps_the_same_choices_as_the_setting():
    assert judge_here.PAYLOAD_LIMITS_MB == schema.HOOK_PAYLOAD_LIMITS_MB
    assert judge_here.DEFAULT_PAYLOAD_LIMIT_MB == schema.DEFAULT_HOOK_PAYLOAD_LIMIT_MB == 16
    assert runner.MAX_INPUT_BYTES == 16 * MIB


@pytest.mark.parametrize("raw, saved", [(4, 4), (16, 16), (64, 64), ("64", 64)])
def test_each_choice_is_saved(home, raw, saved):
    updates, errors = settings._validate({"hook_payload_limit_mb": raw})
    assert errors == [] and updates == {"hook_payload_limit_mb": saved}


@pytest.mark.parametrize("raw", [8, 0, 1024, True, "16 MB", None, 16.0])
def test_anything_else_is_refused(home, raw):
    updates, errors = settings._validate({"hook_payload_limit_mb": raw})
    assert updates == {} and errors == [f"invalid hook_payload_limit_mb: {raw!r}"]


@pytest.mark.parametrize("stored, read", [(None, 16), (64, 64), (4, 4), (8, 16), ("lots", 16)])
def test_the_config_reads_a_choice_or_the_default(home, stored, read):
    if stored is not None:
        home["hook_payload_limit_mb"] = stored
    assert config_mod.hook_payload_limit_mb() == read
    assert settings.read_settings()["hook_payload_limit_mb"] == read


@pytest.mark.parametrize("value", [4, 64])
def test_neither_direction_is_a_weakening(home, value):
    current = weakening.Current(settings={"hook_payload_limit_mb": 16})
    assert weakening.reasons("/api/settings", {"hook_payload_limit_mb": value}, current) == []


def test_the_plugin_hands_the_limit_to_the_installed_runner(home):
    home["hook_payload_limit_mb"] = 64
    folder = agent_hooks._runner().parent
    assert json.loads((folder / judge_here.JUDGE_HERE_FILE).read_text(encoding="utf-8"))[judge_here.LIMIT_KEY] == 64
    home["hook_payload_limit_mb"] = 4
    agent_hooks.keep_hooks()   # the hook watch's look carries a changed limit to the runner
    assert json.loads((folder / judge_here.JUDGE_HERE_FILE).read_text(encoding="utf-8"))[judge_here.LIMIT_KEY] == 4


@pytest.mark.parametrize("written, limit", [({judge_here.LIMIT_KEY: 64}, 64), ({judge_here.LIMIT_KEY: 4}, 4), ({}, 16),
                                            ({judge_here.LIMIT_KEY: 1024}, 16), ({judge_here.LIMIT_KEY: "64"}, 16),
                                            ({judge_here.LIMIT_KEY: True}, 16)])
def test_the_runner_reads_only_a_choice_else_sixteen(monkeypatch, written, limit):
    monkeypatch.setattr(judge_here, "_where", lambda: written)
    assert judge_here.payload_limit_bytes() == limit * MIB


def _run(monkeypatch, capsys, size: int) -> tuple[int, str, list]:
    asked: list = []
    monkeypatch.setattr(runner, "process_age", lambda: 0.0)
    monkeypatch.setattr(runner, "answer_in_time", lambda *a, **k: asked.append(a) or runner.Verdict({}))
    events._answered.clear()
    raw = json.dumps({"session_id": "s", "tool_name": "Write", "tool_input": {"file_path": "/tmp/x", "content": "a" * size}}).encode()
    stdin = type("In", (), {"buffer": type("B", (), {"read": lambda self, n=-1: raw if n < 0 else raw[:n]})()})()
    monkeypatch.setattr(runner.sys, "stdin", stdin)
    code = runner.main(["runner.py", "claude-code", "pre_tool", DOWN])
    return code, capsys.readouterr().out, asked


def test_a_payload_over_the_chosen_limit_is_refused_and_one_under_it_is_judged(home, monkeypatch, capsys):
    monkeypatch.setattr(judge_here, "_where", lambda: {judge_here.LIMIT_KEY: 4})
    code, out, asked = _run(monkeypatch, capsys, 5 * MIB)
    assert (out, code) == answers.deny_output("claude-code", runner.NOT_READ) and asked == []
    monkeypatch.setattr(judge_here, "_where", lambda: {judge_here.LIMIT_KEY: 64})
    code, out, asked = _run(monkeypatch, capsys, 20 * MIB)   # over the old fixed 16 MiB: read whole and judged
    assert code == 0 and len(asked) == 1
