"""Trader Shield's events report (shields/trader/events.py) — the story told server-side, local only.

Two halves. The story half pins, word for word, the sentences the events window shows for
a vault copy, a seed phrase, a keychain read, a token approval and an exchange key — the
prose that was the dashboard's JavaScript (``WALLET_WHY``, ``wevStory``, ``wevTodo``,
``wevFacts``) and moved here verbatim. The report half drives the REAL hooks
(session start, model request, the blocked tool call, session end) into a throwaway
Blackbox home and reads the report back through ``GET /api/shields/trader/events``, the
one events route since the old wallet window was retired.
"""

from __future__ import annotations

import secrets

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from plugins.blackbox import audit, shields
from plugins.blackbox import ruleset as ruleset_mod
from plugins.blackbox.community import sharing as community_sharing
from plugins.blackbox.dashboard import shields_routes
from plugins.blackbox.guard import background as guard_background
from plugins.blackbox.guard import hooks
from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.ruleset import Ruleset
from plugins.blackbox.shields.trader import detectors, events, mode as trader_mode

CHROME_ID = "nkbihfbeogaeaoehlefnkodbefgpgknn"
SESSION = "20261012_222922_218e43"
ARCHIVE_CHROME = "tar czf /tmp/chrome-backup.tgz ~/.config/google-chrome"
REQUEST = "Please back up my Chrome profile with tar and tell me the result."
INJECTION = "Instruction override — 'ignore previous instructions'"
BLOCKED = (" <b>Blackbox stopped it before it ran</b> — nothing was read, copied or sent,"
           " and the agent was told why.")


# ---------- the story, word for word ----------

def _event(identifier, *, title="", evidence="", decision="block", tool="terminal", action="",
           asked="", model="", blocking=True, earlier=()):
    """One event built from a hand-written log entry, as ``report`` builds it."""
    threat = {"identifier": identifier, "title": title, "evidence": evidence, "decision": decision,
              "severity": "critical", "tool": tool, "ts": 20.0,
              "context": {"turns": [{"role": "user", "text": asked}]} if asked else None}
    steps = [{"type": "threat", "ts": 10.0, "threats": [{"title": t, "decision": "flag"}]} for t in earlier]
    steps.append({"type": "tool", "ts": 20.0, "tool": tool, "action": action, "threats": [threat]})
    session = {"shortId": "218e43", "agent": "hermes", "model": model, "start": 5.0, "end": 30.0,
               "status": "completed", "events": steps}
    return events._event(threat, steps[-1], session, len(steps) - 1, blocking)


def _fact(event, label):
    [value] = [fact.value for fact in event.facts if fact.label == label]
    return value


def test_a_blocked_vault_copy_tells_what_was_asked_what_it_would_have_done_and_that_it_was_stopped():
    event = _event("fileaccess:terminal:crypto-wallet", title="Read of a crypto wallet's key store (MetaMask)",
                   evidence="copy crypto-wallet (MetaMask)", action=ARCHIVE_CHROME, asked=REQUEST,
                   model="gpt-4.1-mini")

    assert event.story == (
        "In a conversation with gpt-4.1-mini, your agent was asked: <q>Please back up my Chrome profile with tar"
        " and tell me the result.</q> It then tried to run a terminal command that would have copied MetaMask's"
        " vault (the encrypted file that holds its keys) by archiving or copying a folder that contains it." + BLOCKED)
    assert event.what_to_do == (
        "Nothing left this machine. No action is needed for this event.",
        "If you asked for this on purpose (a browser backup, say), do it yourself outside the agent — Blackbox will"
        " keep agents away from the vault.",
        "If you did not ask for this, check what the agent read just before (a web page, file or message) — it may"
        " have been told to.")
    assert _fact(event, "Reached for") == ("MetaMask's vault (the wallet's key store), by copying or archiving a"
                                           " folder that contains it")
    assert _fact(event, "Why it matters") == events.WALLET_WHY["vault"]
    assert _fact(event, "What it's after") == "the wallet's keys — to empty the wallet"
    assert _fact(event, "Command") == ARCHIVE_CHROME
    assert _fact(event, "Session") == "hermes · gpt-4.1-mini · completed · 1 steps · #218e43"
    assert event.logo == "/shields/trader/packs/metamask/logo.svg"


def test_a_flagged_seed_phrase_says_it_ran_and_why_handling_a_key_is_allowed():
    event = _event("secret:seed-phrase", title="Seed phrase", decision="flag", tool="write_file")

    assert event.story == (
        "In an agent session, your agent used its write_file tool in a way that would have handled a seed phrase —"
        " the recovery words that control a whole wallet. <b>Blackbox flagged it and let it run</b>: handling a key"
        " on this machine is allowed (trading tools need it); sending it off the machine is what gets blocked.")
    assert event.what_to_do == (
        "If this seed phrase was ever pasted or sent somewhere you don't control, move the funds to a new wallet.",
        "Check what the agent read just before (a web page, file or message) — it may have been told to do this.")
    assert _fact(event, "Why it matters") == ("A seed phrase IS the wallet: anyone who has the words controls every"
                                              " account in it, on any device, forever.")
    assert event.logo == ""


def test_a_keychain_read_names_the_warning_signs_met_before_it():
    # "handled a wallet private key" is today's JavaScript wording for every non-vault,
    # non-seed event, moved verbatim; rewording it is a separate, visible change.
    event = _event("fileaccess:terminal:macos-keychain", title="macOS keychain read",
                   evidence="read macos-keychain", action="security dump-keychain",
                   asked="Show me my saved passwords", model="claude-sonnet-5", earlier=(INJECTION,))

    assert event.story == (
        "In a conversation with claude-sonnet-5, your agent was asked: <q>Show me my saved passwords</q> It then"
        " tried to run a terminal command that would have handled a wallet private key — the key that signs for an"
        " account." + BLOCKED + " Just before, Blackbox had flagged <b>Instruction override — &#39;ignore previous"
        " instructions&#39;</b> in what the agent was given — a sign the agent was being steered there.")
    assert _fact(event, "Reached for") == "the macOS keychain (by reading it directly, or with the security tool)"
    assert _fact(event, "Why it matters") == (
        "The keychain holds every password macOS saved and the key each browser uses to lock its saved passwords"
        " and cookies — including your exchange logins.")
    assert _fact(event, "Warning signs before it") == INJECTION


def test_an_approval_in_audit_mode_says_blackbox_only_watched():
    event = _event("secret:token-approval-unlimited", title="Unlimited token approval", decision="flag",
                   tool="web3_sign", blocking=False)

    assert event.story == (
        "In an agent session, your agent used its web3_sign tool in a way that would have handled a wallet private"
        " key — the key that signs for an account. <b>Blackbox let it run and recorded it</b>, because it is set to"
        " watch only (audit mode).")
    assert _fact(event, "Reached for") == "an unlimited token approval (approve MAX or approve-all)"
    assert _fact(event, "Why it matters") == (
        "A token approval lets the spender move your tokens whenever it likes, without asking again. An unlimited"
        " one covers every token you will ever hold of that kind — it is how most wallets are drained.")


def test_an_exchange_key_names_the_exchange_and_why_the_key_must_stay_with_it():
    event = _event("secret:exchange-api-key", title="Exchange API key sent to another site (Binance)",
                   tool="http_request", asked="Check my Binance balance")

    assert event.story == (
        "In an agent session, your agent was asked: <q>Check my Binance balance</q> It then tried to use its"
        " http_request tool in a way that would have handled a wallet private key — the key that signs for an"
        " account." + BLOCKED)
    assert _fact(event, "Reached for") == ("an exchange API key, in the header only that exchange uses, sent to a"
                                           " different site (Binance)")
    assert _fact(event, "Why it matters") == (
        "An exchange API key trades — and, if withdrawals are allowed, withdraws — as your account. A key sent"
        " anywhere but its own exchange has been handed to someone else.")


def test_logged_text_is_escaped_into_the_story():
    event = _event("secret:seed-phrase", asked="<script>alert(1)</script>", tool="<img src=x>",
                   model='m"><b>')

    assert "<script>" not in event.story and "<img" not in event.story
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in event.story and "m&quot;&gt;&lt;b&gt;" in event.story


# ---------- the report, through the real hooks and both routes ----------

@pytest.fixture
def shielded(tmp_path, monkeypatch):
    """A machine with MetaMask in Chrome, Trader Shield engaged, block mode, no network."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    vault = tmp_path / ".config" / "google-chrome" / "Default" / "Local Extension Settings" / CHROME_ID
    vault.mkdir(parents=True)
    (vault / "000003.log").write_text("vault", encoding="utf-8")
    detectors.EXISTING_STORES.reset()
    block = config_mod.BlackboxConfig(mode="block", report=False)
    monkeypatch.setattr(hooks, "_config", lambda: block)
    monkeypatch.setattr(shields.trader, "load_blackbox_config", lambda: block)
    monkeypatch.setattr(ruleset_mod, "get", lambda cfg=None: Ruleset())
    monkeypatch.setattr(guard_background, "_spawn_osv_discovery", lambda *a, **k: None)
    monkeypatch.setattr(guard_background, "_spawn_auto_attach", lambda *a, **k: None)
    monkeypatch.setattr(trader_mode, "current", lambda: trader_mode.build(enabled=True))
    yield tmp_path
    detectors.EXISTING_STORES.reset()


def _run_session(command, request=REQUEST, injection=False):
    """One agent session as Hermes drives the hooks: start, (meet an injection,) ask the model,
    call a tool, end."""
    hooks.on_session_start(session_id=SESSION)
    if injection:
        audit.record(event="pre_api_request",
                     findings=[{"identifier": "injection:test", "category": "injection", "severity": "high",
                                "title": INJECTION, "source": "public"}],
                     detail={"session_id": SESSION, "model": "gpt-4.1-mini", "decision": "flag"})
    hooks.on_pre_api_request(session_id=SESSION, task_id="t1", turn_id="t1:1", model="gpt-4.1-mini",
                             provider="openai-api", user_message=request,
                             request_messages=[{"role": "user", "content": request}])
    result = hooks.on_pre_tool_call(tool_name="terminal", args={"command": command},
                                    session_id=SESSION, task_id="t1", tool_call_id="call_1")
    hooks.on_post_tool_call(tool_name="terminal", args={"command": command}, result='{"error": "blocked"}',
                            session_id=SESSION, task_id="t1", tool_call_id="call_1")
    hooks.on_session_end(session_id=SESSION)
    return result


def _client():
    app = FastAPI()
    shields_routes.register(app, lambda key, producer, default, ttl: producer())
    return TestClient(app)


def test_the_route_answers_the_event_with_its_story(shielded):
    assert _run_session(ARCHIVE_CHROME, injection=True)["action"] == "block"
    client = _client()

    new = client.get("/api/shields/trader/events")

    assert new.status_code == 200 and len(new.json()) == 1
    [fresh] = new.json()
    assert {"ts", "identifier", "title", "severity", "outcome", "tool", "command", "asked"} <= set(fresh)
    assert fresh["outcome"] == "blocked" and fresh["session"]["model"] == "gpt-4.1-mini"
    assert any(step["this"] for step in fresh["timeline"])
    assert fresh["story"].startswith("In a conversation with gpt-4.1-mini, your agent was asked: <q>Please back up")
    assert fresh["what_to_do"][0] == "Nothing left this machine. No action is needed for this event."
    assert {"label": "Command", "value": ARCHIVE_CHROME, "mono": True} in fresh["facts"]
    assert "Just before, Blackbox had flagged <b>Instruction override" in fresh["story"]
    assert fresh["logo"] == "/shields/trader/packs/metamask/logo.svg" and fresh["command"] == ARCHIVE_CHROME   # not defanged


def test_a_blocked_vault_copy_is_reported_with_its_request_command_and_session(shielded):
    """Moved from the old window's tests: the report is proven against what the hooks write."""
    assert _run_session(ARCHIVE_CHROME)["action"] == "block"

    [event] = shields.get("trader").events()

    assert event.outcome == "blocked" and event.identifier.endswith(":crypto-wallet")
    assert "MetaMask" in event.title and event.tool == "terminal" and event.command == ARCHIVE_CHROME
    assert event.asked == REQUEST
    assert event.session.model == "gpt-4.1-mini" and event.session.status == "completed"


def test_the_timeline_marks_the_step_that_reached_for_the_wallet_and_the_threat_before_it(shielded):
    _run_session(ARCHIVE_CHROME, injection=True)

    [event] = shields.get("trader").events()

    assert [step.type for step in event.timeline if step.type in ("api", "tool")][-2:] == ["api", "tool"]
    [this_step] = [step for step in event.timeline if step.this]
    assert this_step.label == ARCHIVE_CHROME and list(this_step.threats) == ["blocked"]
    earlier = [step for step in event.timeline if step.threat_titles and not step.this]
    assert earlier and "ignore previous instructions" in earlier[0].threat_titles[0]
    assert earlier[0].label == "Threat found in what the agent was given"


def test_a_trader_event_never_leaves_the_machine(shielded, monkeypatch):
    """The detail is local by construction: the real wallet finding's source is one the
    community share gate never sends, so neither it nor its context is ever reported."""
    captured = []
    monkeypatch.setattr(hooks.reporting, "_report_and_audit",
                        lambda cfg, event, findings, detail: captured.extend(findings))
    hooks.on_pre_tool_call(tool_name="terminal", args={"command": ARCHIVE_CHROME}, session_id=SESSION)
    [finding] = captured
    cfg = config_mod.BlackboxConfig(report=True, context_graph_id="did:dkg:context-graph:test")

    allowed, why = community_sharing.CommunitySharePolicy(cfg).decide(finding.to_dict(), "0x" + "ab" * 20)

    assert allowed is False and "never leaves the machine" in why


def test_an_unknown_shield_has_no_events_route():
    assert _client().get("/api/shields/nope/events").status_code == 404


def test_ordinary_commands_are_not_trader_events(shielded):
    _run_session("ls -la ~/projects")
    assert shields.get("trader").events() == []


def test_a_secret_in_the_request_or_command_is_redacted_in_the_report(shielded):
    token = "sk-proj-" + secrets.token_hex(24)   # built at runtime: no secret-shaped literal in the repo
    _run_session(ARCHIVE_CHROME + " # OPENAI_API_KEY=" + token, request=REQUEST + " key " + token)

    body = str(_client().get("/api/shields/trader/events").json())

    assert "MetaMask" in body and token not in body and token[8:] not in body


def test_a_long_session_keeps_the_steps_nearest_the_event():
    session_steps = [{"type": "tool", "ts": n, "action": f"step {n}", "threats": []} for n in range(100)]
    window = events._timeline(session_steps, 70)
    assert len(window) == events.MAX_TIMELINE_STEPS
    assert [step["label"] for step in window if step["this"]] == ["step 70"]
    assert window[0]["label"] == f"step {70 - events.MAX_TIMELINE_STEPS // 2}"

