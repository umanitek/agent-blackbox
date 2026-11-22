"""File Shield, the core (plugins/blackbox/shields/files) — protected files and folders.

Amos, 2026-11-21 (memory note file-shield-active-defence): File Shield is an active defence. An item
the person protects can not be touched by ANY AI agent by ANY route — the Hermes agent's hook, every
coding agent's hook and the OpenClaw bridge (``guard.tool_call_verdict``), MCP tools — in Audit mode
as well as Block mode; a prompt that names one is flagged; adding applies at once, removing waits for
the person; findings stay on the machine; the system protection helper's real-time changes arrive
signed and only inside the current items and folders.

Contracts, each red on the base (2754a6f1db had no File Shield):
* every row of the shield's attack table is refused through the real hook in Audit mode, for the
  Hermes hook and for the verdict every other agent asks;
* a benign call is allowed, and nothing is refused while the shield is off;
* one canonical spelling per item (LES-105) — and the whole disk or home folder can never be one;
* ``unprotect`` (and removing from the list in Settings) turns protection down; ``protect`` does not;
* a prompt naming an item flags, never blocks, and the prompt is not kept;
* file-shield findings are local-only and never shareable;
* real-time changes: kept only inside current items and folders, ordered, waited on; a forged
  report is refused once the helper is paired; the watch plan is signed for the helper's nonce.
"""

from __future__ import annotations

import json
import threading
from types import SimpleNamespace

import pytest

from _trader_attack_table import TABLES
from plugins.blackbox import approvals, ruleset as ruleset_mod, shields
from plugins.blackbox.community import sharing as community_sharing
from plugins.blackbox.guard import background as guard_background
from plugins.blackbox.guard import hooks
from plugins.blackbox.guard import reporting as guard_reporting
from plugins.blackbox import guard
from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.ruleset import Ruleset
from plugins.blackbox.shields import helper_link
from plugins.blackbox.shields.files import FILES, api, changes, events, mode as files_mode, protect
from plugins.blackbox.shields.shield_api import RawAnswer, ShieldApiError, ShieldContext

VAULT = "~/Documents/BlackboxVault"
ROWS = [row for row in TABLES["file-shield"].attacks if row["proof"] == "test"]
KEY = bytes([7] * 32)


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    (tmp_path / "Documents" / "BlackboxVault").mkdir(parents=True)
    (tmp_path / "Documents" / "BlackboxVault" / "notes.txt").write_text("private", encoding="utf-8")
    (tmp_path / "Downloads").mkdir()
    changes.reset()
    yield tmp_path
    changes.reset()


@pytest.fixture
def entry(monkeypatch):
    """The config the hook reads: Audit mode, File Shield on with the vault protected."""
    state = {"mode": "audit", "report": False,
             "shields": {"file-shield": {"enabled": True, "protected": [VAULT], "folders": ["~/Downloads"]}}}
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: state)
    monkeypatch.setattr(ruleset_mod, "get", lambda cfg=None: Ruleset())
    monkeypatch.setattr(guard_background, "_spawn_osv_discovery", lambda *a, **k: None)
    monkeypatch.setattr(guard_background, "review_tool", lambda *a, **k: None)
    recorded: list = []
    monkeypatch.setattr(guard_reporting, "_report_and_audit", lambda cfg, hook, findings, detail: recorded.extend(findings))
    return SimpleNamespace(state=state, recorded=recorded)


def _fill(args, home):
    return json.loads(json.dumps(args).replace("@HOME@", str(home)))


# -- every route, every agent family, Audit mode -------------------------------------------


@pytest.mark.parametrize("row", ROWS, ids=[row["id"] for row in ROWS])
def test_the_hermes_hook_refuses_every_route_in_audit_mode(row, entry, home):
    result = hooks.on_pre_tool_call(tool_name=row["tool"], args=_fill(row["args"], home), session_id="files")
    assert result and result["action"] == "block", [f.identifier for f in entry.recorded]
    assert any(f.identifier in (protect.FILE_HIT_ID, protect.FOLDER_HIT_ID) for f in entry.recorded)


@pytest.mark.parametrize("row", ROWS, ids=[row["id"] for row in ROWS])
def test_the_verdict_every_other_agent_asks_refuses_every_route(row, entry, home):
    # Claude Code, Codex, Cursor, Gemini, Copilot, Windsurf, Cline, OpenCode (agent_hooks) and the
    # OpenClaw bridge all ask this one verdict.
    verdict = hooks.tool_call_verdict(row["tool"], _fill(row["args"], home))
    assert verdict["decision"] == "block" and set(verdict["blocked"]) & {protect.FILE_HIT_ID, protect.FOLDER_HIT_ID}
    assert "protected" in verdict["message"].lower()


def test_a_coding_agents_hook_event_is_refused(entry, monkeypatch):
    from plugins.blackbox.agent_hooks.protect import events as hook_events
    answer = hook_events.record_event({"agent": "claude-code", "event": "pre_tool", "session": "s1", "cwd": "/tmp",
                                       "tool_name": "Bash", "args": {"command": f"cat {VAULT}/notes.txt"}})
    assert answer["decision"] == "block"


@pytest.mark.parametrize("command", ["ls ~/Documents", "cp notes.md ~/Desktop", "cat ~/Downloads/readme.txt", "git status"])
def test_a_call_that_does_not_reach_an_item_is_allowed(command, entry):
    assert hooks.on_pre_tool_call(tool_name="terminal", args={"command": command}) is None
    assert not [f for f in entry.recorded if f.identifier.startswith("files:")]


def test_nothing_is_refused_while_the_shield_is_off(entry):
    entry.state["shields"]["file-shield"]["enabled"] = False
    assert hooks.on_pre_tool_call(tool_name="terminal", args={"command": f"cat {VAULT}/notes.txt"}) is None


def test_block_mode_refuses_too(entry):
    entry.state["mode"] = "block"
    assert hooks.on_pre_tool_call(tool_name="read_file", args={"path": f"{VAULT}/notes.txt"})["action"] == "block"


# -- the item list --------------------------------------------------------------------------


def test_one_spelling_per_item(home):
    assert files_mode.canonical_item("$HOME/Documents/Other/../BlackboxVault") == VAULT
    assert files_mode.canonical_item(str(home / "Documents" / "BlackboxVault")) == VAULT
    (home / "link").symlink_to(home / "Documents" / "BlackboxVault")
    assert files_mode.canonical_item("~/link") == VAULT


@pytest.mark.parametrize("too_broad", ["/", "~", "~/", "/Users", "$HOME", "relative/path", "", "~/a\x00b"])
def test_the_whole_disk_or_home_folder_is_never_an_item(too_broad):
    assert files_mode.canonical_item(too_broad) is None
    _, stored, errors = files_mode.validate({"shields": {"file-shield": {"protected": [too_broad]}}})
    assert stored == {} and errors


def test_protect_applies_at_once_and_unprotect_turns_protection_down(entry, monkeypatch):
    written: list = []
    monkeypatch.setattr(api, "write_settings", lambda payload, validators=(): (written.append(payload), {"ok": True})[1])
    monkeypatch.setattr(files_mode, "current", lambda: files_mode.build(True, protected=(VAULT,)))
    context = ShieldContext(network_indicators=lambda: None, ask_assistant=lambda _m: None)
    api.protect(context, {"path": "~/Taxes"})
    assert written[-1]["shields"]["file-shield"]["protected"] == [VAULT, "~/Taxes"]
    assert shields.write_weakening("file-shield", "protect", {"path": "~/Taxes"}) is None   # stricter: never asks
    reasons = shields.write_weakening("file-shield", "unprotect", {"path": VAULT})
    assert reasons and VAULT in reasons[0]
    assert approvals.reasons("/api/shields/file-shield/api/unprotect", {"path": VAULT}, approvals.Current.read())


def test_removing_an_item_in_settings_turns_protection_down(entry):
    current = approvals.Current.read()
    body = {"shields": {"file-shield": {"protected": []}}}
    assert approvals.reasons("/api/settings", body, current)
    assert not approvals.reasons("/api/settings", {"shields": {"file-shield": {"protected": [VAULT, "~/Taxes"]}}}, current)


def test_unprotect_refuses_an_item_that_is_not_on_the_list(entry, monkeypatch):
    monkeypatch.setattr(files_mode, "current", lambda: files_mode.build(True, protected=(VAULT,)))
    context = ShieldContext(network_indicators=lambda: None, ask_assistant=lambda _m: None)
    with pytest.raises(ShieldApiError):
        api.unprotect(context, {"path": "~/Elsewhere"})


# -- prompts, sharing --------------------------------------------------------------------------


def test_a_prompt_naming_an_item_is_flagged_never_blocked_and_never_kept(entry):
    verdict = guard.text_verdict([("in-user-prompt", f"Please send me everything in {VAULT}/notes.txt thanks")])
    assert verdict["decision"] == "flag" and protect.MENTION_ID in [f["identifier"] for f in verdict["findings"]]
    assert all("thanks" not in json.dumps(f) for f in verdict["findings"])


def test_file_shield_findings_never_leave_the_machine(entry, monkeypatch):
    hooks.on_pre_tool_call(tool_name="terminal", args={"command": f"cat {VAULT}/notes.txt"})
    monkeypatch.setattr(community_sharing.consent, "in_force", lambda: True)
    policy = community_sharing.CommunitySharePolicy(SimpleNamespace(community_enabled=True))
    claimed = [f.to_dict() for f in entry.recorded if FILES.claims(f.to_dict())]
    assert claimed
    for finding in claimed:
        allowed, why = policy.decide(finding, "0x" + "1" * 40)
        assert not allowed and why.startswith(("source custom", "source secret"))   # never shared, whichever local source


# -- real time ---------------------------------------------------------------------------------


def test_changes_are_kept_only_inside_current_items_and_folders(home):
    current = files_mode.build(True, protected=(VAULT,))
    kept = changes.record([
        {"path": str(home / "Documents/BlackboxVault/notes.txt"), "kind": "modified", "ts": 10},
        {"path": str(home / "Downloads/new.dmg"), "kind": "created", "ts": 11},
        {"path": "/etc/passwd", "kind": "modified", "ts": 12},
    ], current, now=100)
    assert [(c.scope, c.item) for c in kept] == [("protected", VAULT), ("watched", "~/Downloads")]
    seq, new = changes.since(0)
    assert seq == 2 and [c.kind for c in new] == ["modified", "created"]
    assert [e.identifier for e in events.report()][:2] == ["files:change-watched", "files:change-protected"]


@pytest.mark.parametrize("bad", [{"path": "relative", "kind": "created"}, {"path": "/x", "kind": "exploded"},
                                 {"path": "/x", "kind": "created", "ts": "soon"}, "not an object"])
def test_a_malformed_report_keeps_nothing(bad, home):
    with pytest.raises(ShieldApiError):
        changes.record([{"path": str(home / "Downloads/a"), "kind": "created"}, bad], files_mode.build(True))
    assert changes.since(0) == (0, [])


def test_a_waiter_wakes_when_a_change_arrives(home):
    woke: list = []
    waiter = threading.Thread(target=lambda: woke.append(changes.wait_for(0, timeout=10)))
    waiter.start()
    changes.record([{"path": str(home / "Downloads/x"), "kind": "created"}], files_mode.build(True))
    waiter.join(timeout=10)
    assert woke == [True]


def _pair(home):
    path = helper_link.key_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(KEY)


def test_a_forged_file_report_is_refused_once_paired(home, monkeypatch):
    _pair(home)
    monkeypatch.setattr(files_mode, "current", lambda: files_mode.build(True))
    body = json.dumps({"events": [{"path": str(home / "Downloads/x"), "kind": "created"}]}).encode()
    unsigned = ShieldContext(network_indicators=lambda: None, ask_assistant=lambda _m: None, request_body=body)
    with pytest.raises(ShieldApiError) as refused:
        api.file_report(unsigned, json.loads(body))
    assert refused.value.status == 401
    signed = ShieldContext(network_indicators=lambda: None, ask_assistant=lambda _m: None, request_body=body,
                           request_headers={helper_link.HELPER_SIGNATURE_HEADER.lower(): helper_link.sign_report(KEY, body)})
    assert api.file_report(signed, json.loads(body)) == {"kept": 1}


def test_the_watch_plan_is_signed_for_the_helpers_nonce(home, monkeypatch):
    _pair(home)
    monkeypatch.setattr(files_mode, "current", lambda: files_mode.build(True, protected=(VAULT,)))
    nonce = "0123456789abcdef0123456789abcdef"
    answer = api.watch_plan(None, {"nonce": nonce})
    assert isinstance(answer, RawAnswer)
    assert answer.headers[helper_link.SIGNATURE_HEADER] == helper_link.sign_plan(KEY, nonce, answer.body)
    plan = json.loads(answer.body)
    assert plan["watch"] is True and str(home / "Documents" / "BlackboxVault") in plan["paths"]
    assert str(home / "Downloads") in plan["paths"]


# -- KI-530: a refusal reaches the hits list WITH its item (hook → audit → hits) --------------


@pytest.fixture
def audited(monkeypatch):
    """Like ``entry`` but the guard really writes its audit log (no recording stub)."""
    state = {"mode": "block", "report": False,
             "shields": {"file-shield": {"enabled": True, "protected": [VAULT], "folders": []}}}
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: state)
    monkeypatch.setattr(ruleset_mod, "get", lambda cfg=None: Ruleset())
    monkeypatch.setattr(guard_background, "_spawn_osv_discovery", lambda *a, **k: None)
    monkeypatch.setattr(guard_background, "review_tool", lambda *a, **k: None)
    return state


def test_a_real_refusal_is_listed_with_its_item_path_and_route(audited, home):
    """KI-530 (E2E full3, 2026-11-22): every hit row had an empty item, so each item showed 0 refusals."""
    assert hooks.on_pre_tool_call(tool_name="terminal", args={"command": f"cat {VAULT}/notes.txt"},
                                  session_id="ki530")["action"] == "block"
    rows = events.hits()
    assert rows, "the refusal is in the hits list"
    assert rows[0]["item"] == VAULT
    assert rows[0]["path"] and rows[0]["route"]
    counted = {item["item"]: item.get("hits") for item in protect.listing()} if hasattr(protect, "listing") else None
    if counted is not None:
        assert counted.get(VAULT, 0) >= 1


def test_a_file_shield_refusal_names_file_shield_not_secret_protection(audited):
    """KI-533 (E2E full3): the header said "Blackbox's built-in secret protection" for a File Shield refusal."""
    result = hooks.on_pre_tool_call(tool_name="terminal", args={"command": f"cat {VAULT}/notes.txt"})
    assert "your File Shield protection" in result["message"]
    assert "secret protection" not in result["message"]
