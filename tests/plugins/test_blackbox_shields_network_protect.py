"""Network Shield's protection core (plugins/blackbox/shields/network/protect, api, status).

Moved from Blackbox Desktop's add-on into the core (Amos, 2026-11-21): a public list's manifest is
checked, a list is parsed safely and the hot path never downloads; the helper's plan follows the
mode, carries the verified lists only while the shield is on, never firewalls a non-public
address (FIX-0222) and is versioned; a helper report is validated and stored bounded; the card
never says a protection is active on the setting alone; switched off, each protection is undone
(the plan turns exactly that part off; with the shield off everything is off); the live endpoints refuse while the
shield is off, and the plan always answers.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from plugins.blackbox.shields.network import api, helper, mode as network_mode, status
from plugins.blackbox.shields.network import helper_link
from plugins.blackbox.shields.network.protect import blocklists, enforcement
from plugins.blackbox.shields.network.respond import events
from plugins.blackbox.shields.shield_api import AssistantAnswer, ShieldApiError, ShieldContext


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    monkeypatch.setattr(blocklists, "_memory", {})
    return tmp_path


def _on(**options):
    return network_mode.build(enabled=True, **options)


def _context(indicators=None):
    return ShieldContext(network_indicators=lambda: indicators,
                         ask_assistant=lambda message: AssistantAnswer(ok=True, answer="fine"))


# ------------------------------------------------------------------ public lists


def test_list_manifests_are_checked():
    good = {"list": {"url": "https://raw.githubusercontent.com/x/y/z.txt", "format": "domains", "licence": "GPL-3.0"}}
    assert blocklists.validate_pack(good) is None
    assert "https" in blocklists.validate_pack({"list": {**good["list"], "url": "http://raw.githubusercontent.com/x"}})
    assert "https" in blocklists.validate_pack({"list": {**good["list"], "url": "https://evil.example.com/x"}})
    assert "format" in blocklists.validate_pack({"list": {**good["list"], "format": "regex"}})


def test_lists_parse_names_and_drop_addresses_comments_and_junk():
    parsed = blocklists.parse("# c\nads.example.com\n0.0.0.0 track.example.net # x\n127.0.0.1 localhost.localdomain\n1.2.3.4\n*.wild.example.org\nbad name\n")
    assert parsed == frozenset({"ads.example.com", "track.example.net", "wild.example.org"})


def test_the_hot_path_reads_a_list_only_from_its_copy(monkeypatch):
    pack = next(pack for pack in network_mode.list_packs() if pack.id == "hagezi-multi")
    monkeypatch.setattr(blocklists, "_download", lambda *_: pytest.fail("the hot path downloaded"))
    assert blocklists.cached_domains(pack) == frozenset()
    path = blocklists._cache_path(pack)
    path.parent.mkdir(parents=True)
    path.write_text("tracker.example.com\n", encoding="utf-8")
    assert blocklists.cached_domains(pack) == frozenset({"tracker.example.com"})


# ------------------------------------------------------------------ enforcement


def test_the_plan_is_built_once_per_change(monkeypatch):
    built = []
    real = enforcement._build_plan
    monkeypatch.setattr(enforcement, "_build_plan", lambda *args: built.append(1) or real(*args))
    monkeypatch.setattr(enforcement, "_plan_cache", {"key": None, "plan": None})
    found = SimpleNamespace(domains=frozenset({"evil.example.com"}), ips=frozenset(), built_at=1.0)
    first = enforcement.plan(_on(), found)
    assert enforcement.plan(_on(), found, have=first["version"]) == {"version": first["version"], "unchanged": True}
    assert len(built) == 1
    enforcement.plan(_on(block=("x.example.org",)), found)
    assert len(built) == 2, "a changed setting builds a new plan"


def test_the_plan_carries_the_verified_lists_only_while_the_protections_are_on():
    found = SimpleNamespace(domains=frozenset({"evil.example.com"}), ips=frozenset({"45.130.148.102"}))
    off = enforcement.plan(network_mode.build(), found)
    assert off["dns"] == {"enabled": False, "verified": [], "lists": [], "spared": [], "block": []} and off["firewall"]["ips"] == []
    on = enforcement.plan(_on(protections=(network_mode.DNS, network_mode.FIREWALL), block=("bad.example.org", "198.51.100.7")), found)
    assert on["dns"]["verified"] == ["evil.example.com"] and on["dns"]["block"] == ["bad.example.org"]
    assert on["firewall"]["ips"] == ["198.51.100.7", "45.130.148.102"] and on["graph_ready"] is True
    assert enforcement.plan(_on(), found, have=on["version"])["unchanged"] is False   # a different plan
    again = enforcement.plan(_on(protections=(network_mode.DNS, network_mode.FIREWALL), block=("bad.example.org", "198.51.100.7")), found, have=on["version"])
    assert again == {"version": on["version"], "unchanged": True}


def test_the_firewall_never_drops_a_non_public_address_from_the_graph():
    """Seen on bb-desktop-1120: the verified graph lists 192.168.54.1, CGNAT 100.x (tailnets),
    169.254.169.254 and 0.0.0.0. Dropping them would cut a user off their own router, tailnet or
    cloud metadata service; the user's own block list may still name one."""
    listed = {"45.130.148.102", "192.168.54.1", "100.106.194.93", "169.254.169.254", "0.0.0.0", "10.0.0.1", "::1", "fe80::1"}
    found = SimpleNamespace(domains=frozenset(), ips=frozenset(listed))
    on = enforcement.plan(_on(protections=(network_mode.FIREWALL,), block=("192.168.1.50",)), found)
    assert on["firewall"]["ips"] == ["192.168.1.50", "45.130.148.102"]


@pytest.mark.parametrize("body", [
    {"running": "yes", "dns_active": True, "firewall_active": False},
    {"running": True, "dns_active": True, "firewall_active": False, "blocks": [{"domain": "x x", "list": "verified"}]},
    {"running": True, "dns_active": True, "firewall_active": False, "blocks": [{"domain": "a.example.com", "list": "other"}]},
    {"running": True, "dns_active": True, "firewall_active": False, "queries": -1},
    {"running": True, "dns_active": True, "firewall_active": False, "blocks": [{}] * 501},
])
def test_a_bad_report_is_refused(body):
    with pytest.raises(ShieldApiError) as refused:
        enforcement.record_report(body)
    assert refused.value.status == 400


def test_reports_are_stored_bounded_and_go_stale():
    body = {"running": True, "dns_active": True, "firewall_active": False, "queries": 10, "version": "v",
            "blocks": [{"domain": "evil.example.com", "list": "verified", "count": 2, "ts": 100}]}
    summary = enforcement.record_report(body, now=200)
    assert summary["running"] and summary["blocked_total"] == 2
    enforcement.record_report({**body, "blocks": [{"domain": f"n{i}.example.com", "list": "lists"} for i in range(500)]}, now=201)
    assert len(enforcement.recent_blocks(1000)) == enforcement.MAX_RECENT
    assert enforcement.summary(now=201 + enforcement.STALE_AFTER_SECONDS + 1)["running"] is False


# ------------------------------------------------------------------ card, events, API


def test_the_card_never_says_active_without_the_helpers_report(tmp_path, monkeypatch):
    installed = tmp_path / "ai.umanitek.blackbox.netd.plist"
    installed.write_text("<plist/>", encoding="utf-8")
    monkeypatch.setattr(helper, "LAUNCH_DAEMON", installed)
    monkeypatch.setattr(helper_link, "pairing", lambda: helper_link.PAIRED)   # paired, but not reporting yet
    quiet = {"running": False, "dns_active": False, "firewall_active": False, "cut_active": False,
             "ssh_lockdown_active": False, "cut_total": 0, "blocked_total": 0, "firewall_dropped": 0}
    monkeypatch.setattr(enforcement, "summary", lambda: quiet)
    mode = _on(protections=(network_mode.DNS, network_mode.LOCKDOWN, network_mode.CUT))
    card = status.build(mode)
    assert [row.state for row in card.sections[0].rows] == ["waiting", "off", "active", "waiting", "off"]
    assert card.sections[1].rows[0].state == "waiting"
    monkeypatch.setattr(enforcement, "summary", lambda: {**quiet, "running": True, "dns_active": True})
    assert [row.state for row in status.build(mode).sections[0].rows][:1] == ["active"]


def test_stories_escape_outside_values(monkeypatch):
    monkeypatch.setattr(enforcement, "recent_blocks", lambda limit: [{"domain": "<script>x</script>.com", "list": "verified", "ts": 1}])
    story = events.report()[0].story
    assert "<script>" not in story and "&lt;script&gt;" in story


def test_live_endpoints_refuse_while_off_and_the_plan_always_answers(monkeypatch):
    monkeypatch.setattr(network_mode, "current", lambda: network_mode.build())
    for handler in (lambda: api.connections(_context(), {}), lambda: api.remote(_context(), {}), lambda: api.ssh(_context(), {})):
        with pytest.raises(ShieldApiError) as refused:
            handler()
        assert refused.value.status == 409
    assert api.enforcement_plan(_context(), {})["dns"]["enabled"] is False
    view = api.overview(_context(), {})
    assert view["graph"] == {"ready": False, "reachable": None, "keeping_last_lists": False,
                             "complete": False, "domains": 0, "ips": 0}
    assert view["helper"] is False and view["enforcer"]["running"] is False


def test_every_endpoint_desktop_uses_is_served_by_the_core():
    """Blackbox Desktop's screens call these paths; their JSON is the contract (no add-on needed)."""
    assert {"overview", "connections", "system", "enforcement", "blocks", "ssh", "remote-access",
            "system-plan", "exposure", "posture"} <= set(api.API.reads)
    assert {"enforcer-report", "end-session", "block-address", "unblock-address", "remote-settings",
            "system-report", "posture-fix", "posture-refresh", "tamper-guard"} <= set(api.API.writes)


# ------------------------------------------------------------------ the helper's per-protection results (helper/PLAN.md)

_REPORT = {"running": True, "dns_active": False, "firewall_active": True}


def test_a_protection_the_helper_could_not_apply_says_why_on_the_card(tmp_path, monkeypatch):
    installed = tmp_path / "ai.umanitek.blackbox.netd.plist"
    installed.write_text("<plist/>", encoding="utf-8")
    monkeypatch.setattr(helper, "LAUNCH_DAEMON", installed)
    enforcement.record_report({**_REPORT, "protections": {"dns": {"applied": False, "error": "port 53\nin use"},
                                                          "firewall": {"applied": True, "error": None}}})
    assert enforcement.summary()["errors"] == {"dns": "port 53 in use"}
    rows = status.build(_on(protections=(network_mode.DNS, network_mode.FIREWALL))).sections[0].rows
    assert (rows[0].state, rows[0].sub) == ("warn", "The helper says: port 53 in use")
    assert rows[1].state == "active"


def test_an_older_report_without_results_is_accepted_and_a_bad_one_refused():
    assert enforcement.record_report(_REPORT)["errors"] == {}
    for bad in ({"teleport": {"applied": True}}, {"dns": {"applied": "yes"}}, {"dns": {"applied": False, "error": 3}}, ["dns"]):
        with pytest.raises(ShieldApiError) as refused:
            enforcement.record_report({**_REPORT, "protections": bad})
        assert refused.value.status == 400


# ------------------------------------------------------------------ switched off = undone

FOUND = SimpleNamespace(domains=frozenset({"evil.example.com"}), ips=frozenset({"45.130.148.102"}), built_at=1.0, complete=True)
#: protection id → (plan section, the key that says it is on)
PLAN_PARTS = {network_mode.DNS: ("dns", "enabled"), network_mode.FIREWALL: ("firewall", "enabled"),
              network_mode.CUT: ("cut", "enabled"), network_mode.SSH_LOCKDOWN: ("ssh", "lockdown")}


def test_with_the_shield_off_the_plan_turns_everything_off(monkeypatch):
    monkeypatch.setattr(enforcement, "_plan_cache", {"key": None, "plan": None})
    plan = enforcement.plan(network_mode.build(enabled=False, protections=tuple(PLAN_PARTS)), FOUND, cut_ips=("45.130.148.102",))
    assert all(plan[section][key] is False for section, key in PLAN_PARTS.values())
    assert plan["watch"] is False


@pytest.mark.parametrize("protection", list(PLAN_PARTS))
def test_switching_one_protection_off_turns_exactly_that_part_off(protection, monkeypatch):
    monkeypatch.setattr(enforcement, "_plan_cache", {"key": None, "plan": None})
    others = tuple(p for p in PLAN_PARTS if p != protection)
    plan = enforcement.plan(network_mode.build(enabled=True, protections=others), FOUND, cut_ips=("45.130.148.102",))
    section, key = PLAN_PARTS[protection]
    assert plan[section][key] is False
    assert all(plan[s][k] is True for p, (s, k) in PLAN_PARTS.items() if p != protection)




@pytest.mark.parametrize("indicators", [
    None,                                                                                  # store down / never read
    SimpleNamespace(domains=frozenset(), ips=frozenset(), complete=False, built_at=2.0),   # read nothing after a restart
    SimpleNamespace(domains=frozenset({"evil.example.com"}), ips=frozenset(), complete=False, built_at=3.0),   # partly read
])
def test_a_plan_without_the_whole_graph_tells_the_helper_to_keep_its_lists(indicators):
    """E2E recheck 2026-11-21: with the graph node down the plan's lists were empty and the helper
    emptied the firewall's table. An incomplete read must never be the whole truth (keep_verified)."""
    plan = enforcement.plan(_on(protections=(network_mode.DNS, network_mode.FIREWALL)), indicators)
    assert plan["keep_verified"] is True and plan["graph_complete"] is False


def test_a_complete_graph_replaces_the_helpers_lists():
    found = SimpleNamespace(domains=frozenset({"evil.example.com"}), ips=frozenset(), complete=True, built_at=4.0)
    plan = enforcement.plan(_on(protections=(network_mode.DNS, network_mode.FIREWALL)), found)
    assert plan["keep_verified"] is False and plan["graph_complete"] is True
