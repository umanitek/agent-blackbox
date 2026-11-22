"""The dashboard draws every shield from the API alone (static/shields.js).

index.html names no shield: each shield's banner, card, Settings group and the events window
are drawn by ``shields.js`` from ``GET /api/shields``, ``GET /api/shields/{id}/events`` and the
settings view, and render what the server says (story, what to do, facts, timeline) as given.
These tests carry the old wallet-protection panel's checks over to that file: every element
it creates starts ``hidden`` and can actually be hidden; the markup each inline script wires
precedes it, or is reached by delegation (LES-039); the first shield's banner keeps its
storage keys. A real-browser replay of the captured ``/api/shields`` payload
(fixtures/shields_api_payload.json, LES-018) at 1440 and 390 asserts zero console errors,
page errors and failed requests, no horizontal overflow, and every surface drawn.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from plugins.blackbox import shields
from plugins.blackbox.community.sighting import classify
from plugins.blackbox.dashboard import shields_routes
from plugins.blackbox.shields.trader import events as trader_events
from test_blackbox_dashboard_browser import PLAYWRIGHT, _chromium, fixture_app, served   # fixtures: the known-clean app
from test_blackbox_dashboard_server import _classes_that_override_hidden

STATIC = Path(shields_routes.SHIELDS_SCRIPT).parent
INDEX = (STATIC / "index.html").read_text(encoding="utf-8")
SCRIPT = (STATIC / "shields.js").read_text(encoding="utf-8")
FIXTURE = Path(__file__).with_name("fixtures") / "shields_api_payload.json"
#: Whether any Trader Shield pack is still planned (the Settings list then shows it as "coming soon").
HAS_UNSUPPORTED_PACK = any(pack.status != "supported" for pack in shields.loaded_packs("trader"))
REPLAY = Path(__file__).with_name("shields_replay.mjs")
REPO = Path(__file__).resolve().parents[2]
TRADER = shields.get("trader")


def _main_script() -> str:
    """index.html's main inline script (the one that mounts the shields)."""
    return next(body for body in re.findall(r"<script>(.*?)</script>", INDEX, re.DOTALL) if "BlackboxShields.mount(" in body)


def _shield_words() -> list[str]:
    """Every registered shield's id and name, and every pack's id and name."""
    words = []
    for shield in shields.all_shields():
        words += [shield.id, shield.name]
        for pack in shields.loaded_packs(shield.id):
            words += [pack.id, pack.name]
    return words


# ------------------------------------------------------------------ index.html names no shield


def test_index_html_names_no_shield_no_pack_and_no_old_setting():
    for word in _shield_words():
        assert not re.search(r"\b" + re.escape(word) + r"\b", INDEX, re.IGNORECASE), word
    assert not re.search(r"metamask|phantom|exodus|electrum|solana|trader|wallet_protection|WALLET_", INDEX)
    assert "/api/wallet-protection" not in INDEX and "/wallets/" not in INDEX


def test_shields_js_carries_no_shield_prose():
    """The story, what to do, the facts and every label come from the server; the only shield
    literal is the first shield's kept banner storage key."""
    without_kept_keys = SCRIPT.replace(SCRIPT[SCRIPT.index("var KEPT_BANNER_KEYS"):SCRIPT.index("var STATES")], "")
    for word in _shield_words():
        assert not re.search(r"\b" + re.escape(word) + r"\b", without_kept_keys, re.IGNORECASE), word
    for prose in (*trader_events.WALLET_WHY.values(), "seed phrase", "private key", "vault"):
        assert prose.lower() not in SCRIPT.lower(), prose
    assert "safeStory(e.story)" in SCRIPT and "list(e.what_to_do)" in SCRIPT and "list(e.facts)" in SCRIPT


# ------------------------------------------------------------------ hidden by default, and hideable


def test_every_shield_element_starts_hidden_and_can_be_hidden():
    styles = "".join(re.findall(r"<style[^>]*>.*?</style>", INDEX, re.DOTALL))
    templates = re.findall(r"<(?:div|section)\b[^>]*data-shield-(?:banner|card)=[^>]*>", SCRIPT)
    assert len(templates) == 2 and all(re.search(r"\shidden(?=[\s>])", tag) for tag in templates)
    assert _classes_that_override_hidden(styles + "".join(templates)) == []
    assert "overlay.hidden = true;" in SCRIPT and ".wev-overlay[hidden] { display: none; }" in INDEX
    assert "section.hidden = !card.enabled;" in SCRIPT                                   # the card: only while on
    assert ".hidden = card.enabled || !bannerDue(card.id);" in SCRIPT                    # the banner: only while off


def test_the_markup_each_inline_script_wires_precedes_it():
    """LES-039: the shield code mounts from the main inline script at parse time. What it finds
    by id at render time (the banner and card hosts) precedes that script, shields.js itself is
    loaded before it, and the Settings host — after the script — is reached only by delegation."""
    main = INDEX.index(_main_script())
    assert INDEX.index('<script src="./shields.js"></script>') < main
    for host in ('id="shield-banners"', 'id="shield-cards"'):
        assert INDEX.index(host) < main, host
    assert INDEX.index('id="set-shields"') > main
    looked_up = set(re.findall(r'byId\("([\w-]+)"\)', SCRIPT))
    assert looked_up == {"shield-banners", "shield-cards", "set-shields"}
    assert all(f'id="{host}"' in INDEX for host in looked_up)
    assert not re.search(r'byId\("[\w-]+"\)\.addEventListener', SCRIPT)                # nothing wired by id at mount
    assert 'document.addEventListener("change", onSettingsInput);' in SCRIPT


# ------------------------------------------------------------------ the banner, Settings and findings


def test_the_first_shields_banner_keeps_its_storage_keys_and_week():
    assert ('trader: { first: "blackbox.trader-shield.first-seen.v1", dismissed: "blackbox.trader-shield.dismissed.v1" }'
            in SCRIPT)
    assert "var BANNER_DAYS = 7;" in SCRIPT and '"blackbox.shield." + id + ".banner"' in SCRIPT


def test_engage_and_settings_post_the_shields_shape():
    assert "body.shields[id] = { enabled: true };" in SCRIPT
    assert "shields: shieldsUI.settings.payload()" in _main_script()
    assert "shieldsUI.settings.load(data && data.shields);" in _main_script()
    fields = {field.key: field for field in TRADER.settings_fields()}
    assert {field.kind for field in fields.values()} == {"toggle", "multi-pick", "lines"}
    assert re.fullmatch(fields["addresses"].pattern, "0x" + "ab" * 20)
    assert not re.fullmatch(fields["addresses"].pattern, "ab" * 32)                     # a raw key is never sent


def test_a_shields_findings_show_its_logo_everywhere_they_appear():
    """At a glance: the threats table, the alert, the finding detail and a type's list draw a
    claimed finding's logo (the event's pack logo, or the shield glyph)."""
    main = _main_script()
    assert "'<td>' + shieldsUI.findingMark(f) + typeTag(" in main                        # threats table
    assert 'icon.innerHTML = shieldsUI.findingMark(newest, "big") ||' in main            # threat alert
    assert '$("tm-ico").innerHTML = shieldsUI.findingMark(f, "big") ||' in main          # finding detail
    assert "'<span class=\"ldx-title\">' + shieldsUI.findingMark(f) +" in main          # a type's window
    assert "rows = rows.concat(shieldsUI.findingRows(f, rows));" in main


def test_a_new_finding_refreshes_the_shields_on_the_main_poll():
    """Real time: the 4 s findings poll, not the card's 30 s timer, brings a shield's events in."""
    notify = INDEX[INDEX.index("function processThreatNotifications(data)"):INDEX.index("function setThreatAlertsEnabled(")]
    assert notify.index("shieldsUI.onFindings(fresh);") < notify.index("if (!threatAlertsEnabled || !fresh.length) return;")
    assert "var POLL_MS = 4000;" in INDEX


def test_each_protection_state_has_its_own_mark():
    # Green check = secured (blocked), amber = watched only (audit mode), grey = not protected,
    # red = needs attention; the card carries a legend for them, and green is its own token.
    assert "--secure:" in INDEX and ".wp-ic.ok { color: var(--secure)" in INDEX
    assert ".wp-mode.block { background: var(--secure-soft); color: var(--secure)" in INDEX
    assert ".wp-mode.audit { background: var(--caution-soft); color: var(--caution)" in INDEX
    assert all(word in SCRIPT for word in ("secured — blocked", "watched — flagged only", "not protected", "needs attention"))
    assert "var STATES = { ok: 1, watch: 1, none: 1, warn: 1 };" in SCRIPT


def test_the_event_list_scrolls_inside_its_column():
    assert ".wp-evlist { max-height:" in INDEX and "overflow-y: auto" in INDEX.split(".wp-evlist {", 1)[1].split("}", 1)[0]
    assert '<div class="wp-evlist" tabindex="0"' in SCRIPT


def test_claimed_findings_are_the_shields_own():
    """The page tells a shield's findings apart by the patterns the card carries (its gate's own)."""
    for identifier in ("fileaccess:terminal:macos-keychain", "secret:token-approval-drainer", "secret:exchange-api-key"):
        assert TRADER.claims({"identifier": identifier}), identifier
    assert not TRADER.claims({"identifier": "fileaccess:terminal:user-protected"})
    cards = {card["shield_id"]: card for card in json.loads(FIXTURE.read_text(encoding="utf-8"))}
    for record in shields.all_shields():
        assert cards[record.id]["claims"] == [kind.identifier for kind in record.finding_kinds if kind.identifier]


@pytest.mark.parametrize("finding, goal", [
    ({"category": "fileaccess", "fields": {"file_category": "crypto-wallet"}}, "wallet-drain"),
    ({"category": "secret", "identifier": "secret:seed-phrase"}, "wallet-drain"),
    ({"category": "secret", "identifier": "secret:wallet-private-key"}, "wallet-drain"),
])
def test_a_wallet_event_names_its_goal_instead_of_unknown(finding, goal):
    classified = classify(finding)
    assert (classified.threat_goal, classified.resource_at_risk) == (goal, "wallet-keys")


def test_the_shield_page_is_served_with_its_get_started_button():
    """The card's "Learn more" opens /shields/trader (also /trader-shield); its Engage button
    posts the shields settings shape."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()
    shields_routes.register_pages(app)
    page = TestClient(app).get("/trader-shield")
    assert page.status_code == 200 and "Engage Trader Shield" in page.text
    assert "var body = { shields: { trader: { enabled: true } } };" in page.text and "wallet_protection" not in page.text
    assert "https://" not in page.text.split("<script>")[0].split("</style>")[0]   # no external fonts or styles: works offline


# ------------------------------------------------------------------ the replay, in a real browser


def _events_payload() -> list[dict]:
    """Two events built by the shield's own report code: a vault copy whose story is hostile
    (proving the window renders only <b>/<q> from a story), and a flagged seed phrase."""
    def event(identifier, title, decision, story=None):
        threat = {"identifier": identifier, "title": title, "evidence": "copy", "decision": decision,
                  "severity": "critical", "tool": "terminal", "ts": 1_760_000_020.0,
                  "context": {"turns": [{"role": "user", "text": "Back up my browser profile"}]}}
        step = {"type": "tool", "ts": 1_760_000_020.0, "tool": "terminal", "action": "tar czf /tmp/b.tgz ~/.config", "threats": [threat]}
        session = {"shortId": "218e43", "agent": "hermes", "model": "gpt-4.1-mini", "start": 1_760_000_000.0,
                   "end": 1_760_000_030.0, "status": "completed", "events": [step]}
        built = trader_events._event(threat, step, session, 0, True).as_json()
        if story is not None:
            built["story"] = story
        return shields_routes.sanitised(built, shields_routes._local_text)
    hostile = '<b>ok</b><img src=x onerror="window.__shieldsReplayInjected=true"><script>window.__shieldsReplayInjected=true</script>'
    return [event("fileaccess:terminal:crypto-wallet", "MetaMask key store (MetaMask)", "block", story=hostile),
            event("secret:seed-phrase", "Seed phrase", "flag")]


@pytest.mark.skipif(not PLAYWRIGHT.exists(), reason="node_modules/playwright is needed for the browser replay")
def test_the_captured_payload_replays_clean_at_desktop_and_phone_widths(served, tmp_path):  # health: allow F811 -- pytest injects the imported served fixture by parameter name
    chromium = _chromium()
    if chromium is None:
        pytest.skip("no Chromium build in Playwright's cache (npx playwright install chromium)")
    events_file = tmp_path / "events.json"
    events_file.write_text(json.dumps(_events_payload()), encoding="utf-8")
    result = subprocess.run(["node", str(REPLAY), served, str(FIXTURE), str(events_file), str(tmp_path)],
                            capture_output=True, text=True, timeout=300, cwd=str(REPO),
                            env={**os.environ, "PW_EXEC": chromium}, check=False)
    assert result.returncode == 0, result.stderr[-2000:]
    summary = json.loads((tmp_path / "shields-replay-summary.json").read_text(encoding="utf-8"))
    assert [view["viewport"]["width"] for view in summary] == [1440, 390]
    for view in summary:
        width, found = view["viewport"]["width"], view["found"]
        assert view["pageErrors"] == [] and view["consoleErrors"] == [], (width, view["pageErrors"], view["consoleErrors"])
        assert view["failedRequests"] == [], (width, view["failedRequests"])
        assert not [check for check in view["checks"] if check["horizontalOverflow"]], (width, view["checks"])
        card, text = found["card"], found["card"]["text"].lower()   # headings are upper-cased by CSS (LES-039)
        assert not card["hidden"] and "found on this machine" in text and "recent events" in text, (width, card)
        assert "blocking" in text and "chosen but unavailable" in text and found["cardLogos"] >= 1
        assert found["banner"]["present"] and found["banner"]["hidden"], (width, found["banner"])     # engaged: no banner
        story = found["windowStory"]["text"]   # <b> kept; any other tag shown as inert text, never run
        assert not found["window"]["hidden"] and story.startswith("ok<img src=x"), (width, story)
        assert found["injected"] is False and found["windowFacts"] >= 5 and found["windowSteps"] >= 3
        assert found["windowAfterEscape"]["hidden"]
        assert not found["settings"]["hidden"] and found["settingsInputs"] >= 3, (width, found["settings"])
        settings_text = found["settings"]["text"].lower()
        assert "engage trader shield" in settings_text
        # A pack that is not supported yet is offered disabled as "coming soon"; with every pack supported, none is.
        assert ("coming soon" in settings_text) == HAS_UNSUPPORTED_PACK, (width, settings_text)
        # A refused line is named as left out, and the save carries only the accepted one.
        assert "1 line is not accepted" in found["linesNote"]["text"], (width, found["linesNote"])
        assert found["linesSent"] == ["0x" + "a" * 40], (width, found["linesSent"])
        assert not found["offBanner"]["hidden"] and "engage trader shield" in found["offBanner"]["text"].lower()
        assert found["offCard"]["hidden"]
        assert found["sparse"] == [0, 1, 1, 0], (width, found["sparse"])


# ------------------------------------------------------------------ Settings picks, drawn in Node

RENDER = Path(__file__).with_name("shields_settings_render.mjs")
NODE = shutil.which("node")


def _render_settings(view: dict, tmp_path: Path) -> dict:
    view_file = tmp_path / "view.json"
    view_file.write_text(json.dumps(view), encoding="utf-8")
    result = subprocess.run([NODE, str(RENDER), str(STATIC / "shields.js"), str(view_file)],
                            capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 0, result.stderr[-2000:]
    return json.loads(result.stdout)


@pytest.mark.skipif(NODE is None, reason="node draws the Settings picks")
def test_only_a_really_unavailable_choice_is_drawn_greyed_out(tmp_path):
    """BB-SHIELDS-001: a choice with no status, or one not installed yet, stays pickable; only
    ``unavailable`` / ``needs-helper`` / ``planned`` are greyed, with the server's reason."""
    options = [{"id": "a", "name": "Agent A", "status": "supported"},
               {"id": "b", "name": "Agent B", "status": "not installed", "note": "not installed on this machine yet"},
               {"id": "c", "name": "Agent C", "status": ""},
               {"id": "d", "name": "Agent D", "status": "unavailable", "note": "This Mac has no sandbox-exec."},
               {"id": "e", "name": "Agent E", "status": "needs-helper"}]
    view = {"file-shield": {"mode": {"enabled": True, "sandboxed": ["b"]},
                            "fields": [{"key": "enabled", "kind": "toggle", "label": "Engage"},
                                       {"key": "sandboxed", "kind": "multi-pick", "label": "Sandbox", "options": options}]}}
    drawn = _render_settings(view, tmp_path)
    labels = {re.search(r"Agent [A-E]", label).group(0): label
              for label in re.findall(r'<label class="wallet-pick.*?</label>', drawn["settings"])}
    pickable = {name for name, label in labels.items() if 'data-option="' in label and "disabled" not in label}
    assert pickable == {"Agent A", "Agent B", "Agent C"}, labels
    assert "checked" in labels["Agent B"] and "not installed" in labels["Agent B"]
    assert "This Mac has no sandbox-exec." in labels["Agent D"] and "needs the system protection helper" in labels["Agent E"]
    assert drawn["pathRows"] == ""   # a sandboxed agent is not a key place: no "everywhere it keeps its keys" row


@pytest.mark.skipif(NODE is None, reason="node draws the Settings picks")
def test_the_real_file_shield_choices_are_pickable_where_the_sandbox_runs(tmp_path, monkeypatch):
    from plugins.blackbox.shields.files import sandbox
    monkeypatch.setattr(sandbox.platform, "unavailable", lambda: None)
    view = {"file-shield": shields.settings_view()["file-shield"]}
    view["file-shield"]["mode"]["enabled"] = True
    drawn = _render_settings(view, tmp_path)
    assert 'class="wallet-pick soon"' not in drawn["settings"] and 'data-option="hermes"' in drawn["settings"]


@pytest.mark.skipif(NODE is None, reason="node draws the Settings picks")
def test_a_shield_field_the_server_did_not_serve_is_never_posted_as_a_default(tmp_path):
    """KI-582 (FIX-0364): Save must post the values the page read (or the person's changes), never a default
    for a field it was not served — the page once posted a weakening the person never made."""
    fields = [{"key": "enabled", "kind": "toggle", "label": "Engage"},
              {"key": "sandboxed", "kind": "multi-pick", "label": "Sandbox", "options": [{"id": "a", "name": "A", "status": "supported"}]},
              {"key": "protected", "kind": "lines", "label": "Protected"}]
    view = {"file-shield": {"mode": {"enabled": True, "sandboxed": ["a"]}, "fields": fields}}
    assert _render_settings(view, tmp_path)["payload"] == {"file-shield": {"enabled": True, "sandboxed": ["a"]}}
    view = {"file-shield": {"mode": {"enabled": True, "sandboxed": ["a"], "protected": ["~/Vault"]}, "fields": fields}}
    assert _render_settings(view, tmp_path)["payload"] == {"file-shield": {"enabled": True, "sandboxed": ["a"], "protected": ["~/Vault"]}}
