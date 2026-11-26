"""Sandbox permissions — folder rules enforced by the hook layer too (F9; LES-137; fix wave 7).

File Shield's page told the person that an agent on hooks only keeps its folder rules ("kept out" /
"read only"), but no hook checked them: only the sandbox profile did. The hook now reads the SAME
answer the profile renders (``permissions.folder_limits``, used by ``permissions.allowances``) for
the acting agent in the folder it works in.

Contracts (red on the base ffaf359e56: the hook refused nothing for a folder rule):
* drift test — for every folder rule (kept out / read only) in every scope (everywhere, one agent,
  one project, one agent in one project), for agents and folders inside and outside its scope: the
  hook refuses a READ exactly where the profile hides the folder, and a WRITE exactly where the
  profile hides it or makes it read-only;
* through the real verdict a coding agent's hook asks (``guard.tool_call_verdict``), in Audit mode:
  a kept-out folder is refused to the agent it names and allowed to another; a read-only folder is
  readable and refuses a change (write tool, redirect, ``rm``, ``mv``, ``touch``, a whole-tree
  ``rm -rf`` of the folder above it).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from plugins.blackbox import ruleset as ruleset_mod
from plugins.blackbox.guard import background as guard_background
from plugins.blackbox.guard import hooks
from plugins.blackbox.guard import reporting as guard_reporting
from plugins.blackbox.kernel import action_context, config as config_mod
from plugins.blackbox.ruleset import Ruleset
from plugins.blackbox.shields.files import folder_rules, mode as files_mode
from plugins.blackbox.shields.files.sandbox import permissions
from plugins.blackbox.shields.files.sandbox.permissions import Access, FolderRule, Scope, Settings

AGENTS = ("claude-code", "codex")


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    real = tmp_path.resolve()
    monkeypatch.setenv("HOME", str(real))
    monkeypatch.setenv("BLACKBOX_HOME", str(real / "bb"))
    for folder in ("clients", "shop", "elsewhere", "work/ledger"):
        (real / folder).mkdir(parents=True)
    (real / "clients" / "deal.txt").write_text("deal", encoding="utf-8")
    (real / "work" / "ledger" / "book.txt").write_text("book", encoding="utf-8")
    return real


@pytest.fixture
def entry(monkeypatch):
    """The config the hook reads: Audit mode, File Shield on, no protected items — only folder rules."""
    state = {"mode": "audit", "report": False, "shields": {"file-shield": {"enabled": True, "protected": [], "folders": []}}}
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: state)
    monkeypatch.setattr(ruleset_mod, "get", lambda cfg=None: Ruleset())
    monkeypatch.setattr(guard_background, "_spawn_osv_discovery", lambda *a, **k: None)
    monkeypatch.setattr(guard_background, "review_tool", lambda *a, **k: None)
    monkeypatch.setattr(guard_reporting, "_report_and_audit", lambda *a, **k: None)
    return SimpleNamespace(state=state)


def _scopes(home):
    shop = str(home / "shop")
    return [Scope(), Scope(agent="codex"), Scope(project="~/shop"), Scope(agent="codex", project="~/shop")], shop


def _hook_refuses(settings: Settings, agent: str, folder: str, tool: str, args: dict, monkeypatch) -> bool:
    monkeypatch.setattr(permissions, "current", lambda: settings)
    with action_context.working_in(folder, agent):
        return bool(folder_rules.detect(tool, args))


@pytest.mark.parametrize("access", [Access.NONE, Access.READ])
def test_the_hook_refuses_exactly_what_the_profile_refuses_for_every_folder_rule(home, monkeypatch, access):
    scopes, shop = _scopes(home)
    target = str(home / "clients" / "deal.txt")
    for scope in scopes:
        settings = Settings(folders=(FolderRule("~/clients", access, scope),))
        for agent in AGENTS:
            for folder in (shop, str(home / "elsewhere"), ""):
                profile = permissions.allowances(settings, agent, folder)
                clients = str(home / "clients")
                read = _hook_refuses(settings, agent, folder, "read_file", {"path": target}, monkeypatch)
                write = _hook_refuses(settings, agent, folder, "write_file", {"path": target, "content": "x"}, monkeypatch)
                where = f"{access.value} {scope} for {agent} in {folder or 'no folder'}"
                assert read == (clients in profile.hidden), where
                assert write == (clients in profile.hidden or clients in profile.read_only), where


def _verdict(tool, args, agent, cwd):
    return hooks.tool_call_verdict(tool_name=tool, args=args, cwd=cwd, agent=agent)


def test_a_folder_kept_from_one_agent_is_refused_to_it_through_the_real_verdict(home, entry):
    entry.state["agent_sandbox"] = {"folders": [{"path": "~/clients", "access": "none", "agent": "codex"}]}
    cwd = str(home / "shop")
    for tool, args in (("read_file", {"path": "~/clients/deal.txt"}), ("terminal", {"command": "ls ~/clients"}),
                       ("terminal", {"command": "cd ~/clients && cat deal.txt"})):
        refused = _verdict(tool, args, "codex", cwd)
        assert refused["decision"] == "block" and refused["blocked"] == ["files:folder-hit"], (tool, args)
        assert "kept out" in refused["findings"][0]["title"]
        assert _verdict(tool, args, "claude-code", cwd)["decision"] == "", (tool, args)


@pytest.mark.parametrize("command", ["echo x > ~/work/ledger/new.txt", "rm ~/work/ledger/book.txt",
                                     "mv ~/work/ledger/book.txt /tmp/", "touch ~/work/ledger/new.txt",
                                     "rm -rf ~/work", "chmod 777 ~/work/ledger/book.txt"])
def test_a_read_only_folder_refuses_every_change_through_the_real_verdict(home, entry, command):
    entry.state["agent_sandbox"] = {"folders": [{"path": "~/work/ledger", "access": "read"}]}
    refused = _verdict("terminal", {"command": command}, "claude-code", str(home / "shop"))
    assert refused["decision"] == "block" and refused["blocked"] == ["files:folder-hit"], command
    assert "read only" in refused["findings"][0]["title"]


@pytest.mark.parametrize("tool, args", [("read_file", {"path": "~/work/ledger/book.txt"}),
                                        ("terminal", {"command": "cat ~/work/ledger/book.txt"}),
                                        ("terminal", {"command": "ls ~/work/ledger && cp ~/work/ledger/book.txt ~/shop/"}),
                                        ("terminal", {"command": "grep -r total ~/work"})])
def test_a_read_only_folder_stays_readable(home, entry, tool, args):
    entry.state["agent_sandbox"] = {"folders": [{"path": "~/work/ledger", "access": "read"}]}
    assert _verdict(tool, args, "claude-code", str(home / "shop"))["decision"] == "", (tool, args)


def test_a_write_tool_is_refused_in_a_read_only_folder_and_a_project_rule_stays_in_its_project(home, entry):
    entry.state["agent_sandbox"] = {"folders": [{"path": "~/work/ledger", "access": "read", "project": "~/shop"}]}
    args = {"path": "~/work/ledger/book.txt", "content": "changed"}
    assert _verdict("write_file", args, "claude-code", str(home / "shop" / "api"))["decision"] == "block"
    assert _verdict("write_file", args, "claude-code", str(home / "elsewhere"))["decision"] == ""


def test_nothing_is_refused_while_file_shield_is_off(home, entry):
    entry.state["agent_sandbox"] = {"folders": [{"path": "~/clients", "access": "none"}]}
    entry.state["shields"]["file-shield"]["enabled"] = False
    assert files_mode.current().enabled is False
    assert _verdict("read_file", {"path": "~/clients/deal.txt"}, "codex", str(home / "shop"))["decision"] == ""
