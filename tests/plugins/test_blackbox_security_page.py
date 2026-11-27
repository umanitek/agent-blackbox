"""The Security page and the permission read it draws (engine build 2026-11-27, owner requirement:
every setting is explained right where it is edited; plugins/blackbox/dashboard/security_routes/,
static/security.html + security.js + permission_card.js, shields/files/sandbox/permissions/api.py,
shields/files/api.py).

Contracts (red on the base 138eafb5bd: no ``when_blocked``, ``applies_line``, ``always_on`` or
scoped read, no Security page):
* the ``permissions`` read explains every permission three ways (allowed / blocked / if relaxed)
  with its strict default, route and when a change applies, and serves the always-on rules, the
  never-list and what can not be controlled, each with its reason;
* ``?agent=&project=`` answers each mode as it is for that scope (``set_here`` when a rule for
  exactly that scope decides it); an unknown agent or the whole home folder is refused;
* the page draws each explanation next to its control and the always-on list read-only; a change
  for one agent posts that agent's rule; a loosening the gate holds says it waits for approval;
* the mode, a threat check and the hook limit are saved as that one field through
  ``/api/settings``; the limit is drawn only when the settings serve it.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.shields import ShieldApiError
from plugins.blackbox.shields.files import api, sandbox
from plugins.blackbox.shields.files.sandbox.permissions import catalogue

STATIC = Path(__file__).resolve().parents[2] / "plugins" / "blackbox" / "dashboard" / "static"
RENDER = Path(__file__).with_name("security_page_render.mjs")
NODE = shutil.which("node")
API = "/api/shields/file-shield/api/permissions"
SETTINGS = {"mode": "block", "block_severity": "high", "severity_order": ["info", "low", "medium", "high", "critical"],
            "categories": {"injection": {"enabled": True, "min_severity": "info"}, "secret": {"enabled": True, "min_severity": "low"}},
            "category_labels": {"injection": "Prompt injection", "secret": "Secret exposure"}}


@pytest.fixture
def entry(tmp_path, monkeypatch):
    real = tmp_path.resolve()
    monkeypatch.setenv("HOME", str(real))
    monkeypatch.setenv("BLACKBOX_HOME", str(real / "bb"))
    (real / "work" / "shop").mkdir(parents=True)
    monkeypatch.setattr(sandbox.platform, "unavailable", lambda: None)
    state: dict = {"shields": {"file-shield": {"enabled": True, "protected": [], "sandboxed": ["claude-code"]}},
                   "agent_sandbox": {"permissions": [{"permission": "docker", "mode": "allow", "agent": "claude-code"}]}}
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: state)
    return state


def test_every_permission_is_explained_and_the_fixed_lists_carry_their_reasons(entry):
    view = api.API.reads["permissions"](None, {})
    assert [row["id"] for row in view["permissions"]] == [each.id for each in catalogue.PERMISSIONS]
    for row in view["permissions"]:
        assert row["unlocks"] and row["when_blocked"] and row["cost"] and row["applies_line"], row["id"]
        assert row["default"] in row["modes"] and row["route"] in ("profile", "broker", "hook")
    assert next(row for row in view["permissions"] if row["id"] == "docker")["applies_line"].startswith("Applies when the agent starts")
    for key, source in (("always_on", catalogue.ALWAYS_ON), ("never", catalogue.NEVER), ("not_controllable", catalogue.NOT_CONTROLLABLE)):
        assert [(row["name"], row["why"]) for row in view[key]] == [(each.name, each.why) for each in source]
    assert "approval" in view["loosening_note"]


def test_the_every_mode_list_is_the_guards_own(entry):
    """The page's "Refused in Audit mode too" list is what the guard refuses in every mode, served
    from that one definition (``detection.ALWAYS_BLOCKED``), never retyped on the page."""
    from plugins.blackbox import detection

    view = api.API.reads["permissions"](None, {})
    assert [row["name"] for row in view["always_blocked"]] == [rule.name for rule in detection.ALWAYS_BLOCKED]
    assert {rule.matched for rule in detection.ALWAYS_BLOCKED} == detection.ALWAYS_BLOCKED_MATCHES
    relaxable = {row["permission"] for row in view["always_blocked"] if row["permission"]}
    assert relaxable <= {each.id for each in catalogue.PERMISSIONS if each.route.value == "hook"}


def test_a_scoped_read_answers_the_mode_in_force_there(entry):
    everywhere = api.API.reads["permissions"](None, {})
    assert next(row for row in everywhere["permissions"] if row["id"] == "docker")["mode"] == "ask"
    scoped = api.API.reads["permissions"](None, {"agent": "claude-code", "project": "~/work/shop"})
    docker = next(row for row in scoped["permissions"] if row["id"] == "docker")
    assert docker["mode"] == "allow" and docker["set_here"] is False   # decided by the agent-wide rule
    assert next(row for row in api.API.reads["permissions"](None, {"agent": "claude-code"})["permissions"]
                if row["id"] == "docker")["set_here"] is True
    assert scoped["scope"] == {"agent": "claude-code", "project": "~/work/shop", "words": "Claude Code in ~/work/shop"}
    assert {"hermes", "claude-code"} <= {agent["id"] for agent in scoped["scope_agents"]}
    for bad in ({"agent": "nobody"}, {"project": "~"}):
        with pytest.raises(ShieldApiError) as refused:
            api.API.reads["permissions"](None, bad)
        assert refused.value.status == 400


def _render(tmp_path: Path, fixture: dict) -> dict:
    path = tmp_path / "fixture.json"
    path.write_text(json.dumps(fixture), encoding="utf-8")
    done = subprocess.run([NODE, str(RENDER), str(STATIC), str(path)], capture_output=True, text=True, timeout=60, check=False)
    assert done.returncode == 0, done.stderr[-2000:]
    drawn = json.loads(done.stdout)
    assert drawn["errors"] == []
    return drawn


def _flat(outline: list[str]) -> str:
    """The text an outline holds, run together as a person reads it."""
    return "\n".join(line.lstrip().split(" ", 1)[1] for line in outline if " " in line.lstrip())


def _answers(view: dict, settings: dict = SETTINGS) -> list:
    return [["/api/settings", settings], [API, view]]


@pytest.mark.skipif(NODE is None, reason="node draws the page")
def test_the_page_explains_each_control_and_shows_what_is_always_on(entry, tmp_path):
    view = api.API.reads["permissions"](None, {})
    drawn = _render(tmp_path, {"answers": _answers(view)})
    text = _flat(drawn["hosts"]["sec-perms"]).replace(": \n", ": ")
    user_apps = catalogue.BY_ID["user-apps"]
    for words in ("While blocked: ", user_apps.when_blocked, "If you relax it: ", user_apps.cost, "Strict default: Block",
                  "When it applies: Applies at once", "after restart", "not controllable yet"):
        assert words in text
    always = "\n".join(drawn["hosts"]["sec-always"])
    assert all(each.name in always and each.why in always for each in catalogue.ALWAYS_ON)
    assert not any(line.lstrip().startswith("button") for line in drawn["hosts"]["sec-always"])   # read-only
    assert "Block mode" in "\n".join(drawn["hosts"]["sec-mode-help"]) and drawn["hidden"]["sec-limits"] is True


@pytest.mark.skipif(NODE is None, reason="node draws the page")
def test_a_change_for_one_agent_posts_its_rule_and_a_held_one_waits_for_approval(entry, tmp_path):
    view = api.API.reads["permissions"](None, {})
    scoped = api.API.reads["permissions"](None, {"agent": "claude-code"})
    held = {"ok": False, "approval": {"id": "a" * 24, "reasons": ["Let Claude Code use Homebrew installs (was: block)"]}}
    drawn = _render(tmp_path, {"answers": [*_answers(view), [API + "?agent=claude-code", scoped]],
                               "post": {"/api/shields/file-shield/api/permission-set": [428, held]},
                               "actions": [["change", "sec-perm-scope", "claude-code"], ["click", "sec-perms", "Allow"]]})
    assert API + "?agent=claude-code" in drawn["gets"]
    url, body = drawn["posts"][0]
    assert url.endswith("/permission-set") and body["agent"] == "claude-code" and body["mode"] == "allow" and "project" not in body
    note = "\n".join(drawn["hosts"]["sec-perm-note"])
    assert "Waiting for your approval" in note and "Homebrew" in note
    assert "Use the wider setting" in "\n".join(drawn["hosts"]["sec-perms"])   # docker is set for exactly this agent


@pytest.mark.skipif(NODE is None, reason="node draws the page")
def test_the_mode_a_check_and_the_limit_are_each_saved_as_one_field(entry, tmp_path):
    view = api.API.reads["permissions"](None, {})
    with_limit = {**SETTINGS, "hook_payload_limit_mb": 16}
    drawn = _render(tmp_path, {"answers": _answers(view, with_limit),
                               "actions": [["click", "sec-mode-audit", ""], ["click", "sec-checks", "Off"],
                                           ["change", "sec-hook-limit", "64"]]})
    assert drawn["hidden"]["sec-limits"] is False
    assert [body for url, body in drawn["posts"]] == [
        {"mode": "audit"},
        {"categories": {"injection": {"enabled": False, "min_severity": "info"}, "secret": {"enabled": True, "min_severity": "low"}}},
        {"hook_payload_limit_mb": 64}]
    assert all(url == "/api/settings" for url, _ in drawn["posts"])
