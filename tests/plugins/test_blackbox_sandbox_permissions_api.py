"""Sandbox permissions — the endpoints, the approval gate, the audit row and the page list
(plugins/blackbox/shields/files/sandbox/permissions/api.py, shields/files/page/files.html; design
"Sandbox permissions" 2026-11-23, build step 7, local-only).

Contracts (red on the base ed4152ceac: no ``permissions`` read, no permission writes):
* ``permissions`` lists every catalogue entry with its mode, allowed modes, when a change applies
  and whether it is controllable, the never-list, the rules and the agents inside the sandbox;
* through the REAL approval gate: a write that loosens (block → allow, a folder rule removed) is
  held (428) with a server-built reason, a tightening one is applied at once (200), and either way
  only the settings writer writes; a project is stored in its one canonical spelling;
* each applied change is an audit row (``permission_changed``) and the agent's profile follows;
* the page draws the list (allowed modes only, "not controllable yet", "now" / "after restart"),
  the exceptions with Remove and the never-list, and posts the person's choice.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from plugins.blackbox import approvals, audit, shields
from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.shields.files import api, mode as files_mode, sandbox
from plugins.blackbox.shields.files.sandbox import permissions

PAGE = Path(__file__).resolve().parents[2] / "plugins" / "blackbox" / "shields" / "files" / "page" / "files.html"
RENDER = Path(__file__).with_name("files_page_render.mjs")
NODE = shutil.which("node")


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    real = tmp_path.resolve()
    monkeypatch.setenv("HOME", str(real))
    monkeypatch.setenv("BLACKBOX_HOME", str(real / "bb"))
    (real / "work" / "shop").mkdir(parents=True)
    return real


@pytest.fixture
def entry(monkeypatch):
    state: dict = {"shields": {"file-shield": {"enabled": True, "protected": [], "sandboxed": ["claude-code"]}}}
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: state)

    def persist(updates):
        for key, value in updates.items():
            state[key] = value
        return True

    from plugins.blackbox.kernel import settings as kernel_settings
    monkeypatch.setattr(kernel_settings, "_persist", persist)
    return state


def _gate(name: str, body: dict) -> list[str]:
    return approvals.reasons(f"/api/shields/file-shield/api/{name}", body, approvals.Current())


def test_the_read_lists_the_catalogue_the_never_list_and_the_agents(entry):
    view = api.API.reads["permissions"](None, {})
    docker = next(row for row in view["permissions"] if row["id"] == "docker")
    assert docker["mode"] == "ask" and docker["modes"] == ["block", "ask", "allow"] and docker["applies"] == "after restart"
    assert next(row for row in view["permissions"] if row["id"] == "homebrew")["applies"] == "now"
    assert next(row for row in view["permissions"] if row["id"] == "camera-mic")["controllable"] is False
    assert any(row["id"] == "ssh-self" for row in view["never"])
    assert [agent["id"] for agent in view["agents"]] == ["claude-code"]


def test_a_loosening_write_is_held_and_a_tightening_one_is_not(entry):
    assert _gate("permission-set", {"permission": "docker", "mode": "allow", "agent": "claude-code"}) == \
        ["Let Claude Code use Docker (without asking; was: ask)"]
    assert _gate("permission-set", {"permission": "docker", "mode": "block"}) == []
    assert _gate("folder-set", {"path": "~/work/shop", "access": "none"}) == []
    api.API.writes["folder-set"](None, {"path": "~/work/shop", "access": "none"})
    assert _gate("folder-clear", {"path": "~/work/shop"}) == ["Stop keeping ~/work/shop from every AI agent"]
    assert _gate("permission-set", {"permission": "applescript", "mode": "allow"}) == []   # refused by the endpoint: nothing to confirm


def test_a_write_stores_one_spelling_records_it_and_the_profile_follows(entry, home):
    answer = api.API.writes["permission-set"](None, {"permission": "docker", "mode": "block", "project": str(home / "work" / "shop")})
    assert entry["agent_sandbox"]["permissions"] == [{"permission": "docker", "mode": "block", "project": "~/work/shop"}]
    assert answer["rules"] == entry["agent_sandbox"]["permissions"]
    [row] = [row for row in audit.read_audit(limit=20) if row.get("event") == "permission_changed"]
    assert row["detail"]["permission"] == "docker" and row["detail"]["loosened"] is False
    if sys.platform == "darwin":
        assert (sandbox.layout.profiles_dir() / "claude-code" / "projects.idx").is_file()
    with pytest.raises(shields.ShieldApiError):
        api.API.writes["permission-set"](None, {"permission": "applescript", "mode": "allow"})


def _render(tmp_path: Path, fixture: dict) -> dict:
    path = tmp_path / "fixture.json"
    path.write_text(json.dumps(fixture), encoding="utf-8")
    done = subprocess.run([NODE, str(RENDER), str(PAGE), str(path)], capture_output=True, text=True, timeout=60, check=False)
    assert done.returncode == 0, done.stderr[-2000:]
    return json.loads(done.stdout)


@pytest.mark.skipif(NODE is None, reason="node draws the page")
def test_the_page_names_an_agent_that_needs_a_restart_and_offers_stop(entry, tmp_path):
    view = {**api.API.reads["permissions"](None, {}),
            "restart_needed": [{"agent": "codex", "name": "Codex", "instance": "codex:ab", "pid": 4242, "note": "still runs with its old ones"}]}
    drawn = _render(tmp_path, {"answers": [["/permissions", view]], "post": {"stop-agent": [200, view]},
                               "clicks": [["permission-restart", "Stop it"]]})
    assert "restart needed" in "\n".join(drawn["hosts"]["permission-restart"]) and "Codex still runs" in "\n".join(drawn["hosts"]["permission-restart"])
    assert drawn["posts"] == [["stop-agent", {"instance": "codex:ab"}]]


@pytest.mark.skipif(NODE is None, reason="node draws the page")
def test_the_page_draws_the_list_and_posts_the_persons_choice(entry, tmp_path):
    api.API.writes["permission-set"](None, {"permission": "docker", "mode": "allow", "agent": "claude-code", "project": "~/work/shop"})
    view = api.API.reads["permissions"](None, {})
    drawn = _render(tmp_path, {"answers": [["/permissions", view]], "post": {"permission-set": [200, view], "permission-clear": [200, view]},
                               "clicks": [["permissions", "Block"], ["permission-rules", "Remove"]]})
    assert drawn["errors"] == []
    text = "\n".join(drawn["hosts"]["permissions"])
    assert "Docker" in text and "after restart" in text and "not controllable yet" in text
    applescript = text[text.index("AppleScript"):text.index("Stopping your programs")]
    assert "Allow" not in applescript and "Ask" in applescript   # only the modes it allows
    assert "Docker · Allow · claude-code in ~/work/shop" in "\n".join(drawn["hosts"]["permission-rules"])
    assert "ssh into this Mac" in "\n".join(drawn["hosts"]["permission-never"])
    assert drawn["posts"][0] == ["permission-set", {"permission": "homebrew", "mode": "block"}]
    assert drawn["posts"][1] == ["permission-clear", {"permission": "docker", "agent": "claude-code", "project": "~/work/shop"}]
