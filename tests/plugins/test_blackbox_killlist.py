"""Refine R14 — the kill list: a 2-of-3 signed, versioned DISABLE / WARN list for
installed skills and MCP servers, enforced at the hook, gated by blast radius,
and never able to disable (or enable) everything at once.

* parse: quorum, own subject, closed entries; one curator key is not enough.
* gates: a wide kill needs the root; a popular target needs the root AND a
  24 h hold; >20 new disables refuse the whole version → last-good stays;
  an older version never replaces a newer one.
* store: last-good on disk; a refused decision never writes.
* hook: DISABLE blocks in block mode and only flags in audit mode; WARN only
  flags; a matching call is refused but nothing is uninstalled; a bad cached
  list kills nothing; the finding is never shared.
* curate: propose → approve (--root) → published to the verified graph.
* refresh: the ruleset carries the admitted list; a refused one is remembered for the alarm.
"""

from __future__ import annotations

import json
import time

import pytest

from plugins.blackbox import killlist, ruleset
from plugins.blackbox.curate import verbs
from plugins.blackbox.curate.proposal import ProposalStore
from plugins.blackbox.guard import hooks
from plugins.blackbox.kernel import signing
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.ruleset import compiler, curator_tier, disk_cache
from test_blackbox_curate import NETWORK, VM_GRAPH, FakeNode, _ctx, _machine, curators

DAY = "2026-10-02"
NOW = 1_800_000_000.0


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))


def _entry(identifier="evil-skill", action="disable", **kw):
    return killlist.KillEntry(registry="skill", identifier=identifier, action=killlist.KillAction(action), **kw)


def _signed(entries, keys, manifest, version=1, day=DAY, root=None):
    kill_list = killlist.KillList(version=version, day=day, entries=tuple(entries))
    envelope = killlist.sign_kill_list(kill_list, keys[0], manifest, VM_GRAPH)
    for key in keys[1:]:
        envelope = signing.cosign(envelope, key)
    if root is not None:
        envelope = signing.cosign(envelope, root)
    return envelope, kill_list


def _row(envelope):
    quads = killlist.kill_list_quads(envelope)
    return {"r": quads[0]["subject"], "signedStatement": json.loads(quads[1]["object"])}


# ------------------------------------------------------------------ the statement


def test_a_kill_list_needs_two_curator_keys_and_a_closed_entry_shape(curators):
    manifest = curators["manifest"]
    two = [curators["a"], curators["b"]]
    envelope, kill_list = _signed([_entry(version="1.2.3")], two, manifest)
    parsed = killlist.parse_kill_list(_row(envelope), manifest, graph=VM_GRAPH)
    assert parsed is not None and parsed[1] == kill_list
    one, _ = _signed([_entry(version="1.2.3")], [curators["a"]], manifest)
    assert killlist.parse_kill_list(_row(one), manifest, graph=VM_GRAPH) is None
    assert killlist.parse_kill_list({"r": "urn:guardian:curator:kill-list:9", "signedStatement": _row(envelope)["signedStatement"]},
                                    manifest, graph=VM_GRAPH) is None                           # not its own subject
    assert killlist.KillEntry.from_json({"registry": "npm", "identifier": "x", "action": "disable"}) is None
    assert killlist.KillEntry.from_json({"registry": "skill", "identifier": "*", "action": "disable"}) is None   # * needs a publisher
    assert killlist.KillEntry.from_json({"registry": "skill", "identifier": "x", "action": "disable", "reason": "free text"}) is None
    with pytest.raises(ValueError):
        killlist.sign_kill_list(killlist.KillList(version=1, day="not-a-day", entries=(_entry(),)), two[0], manifest, VM_GRAPH)


# ------------------------------------------------------------------ the gates


def test_wide_kills_need_the_root_and_popular_targets_need_the_root_plus_a_day():
    wide = _entry(identifier="any-version-skill")                       # no version, no hash → wide
    pinned = _entry(version="1.0.0")
    popular = _entry(identifier="lodash-skill", version="2.0.0")
    is_popular = lambda e: e.identifier == "lodash-skill"
    kill_list = killlist.KillList(version=1, day=DAY, entries=(wide, pinned, popular))
    without_root = killlist.admit(kill_list, signers={"a", "b"}, root_signers=set(), previous=None, now=NOW, is_popular=is_popular)
    assert without_root.applied == (pinned,) and {e.identifier for e, _why in without_root.dropped} == {"any-version-skill", "lodash-skill"}
    signed_midnight = time.mktime(time.strptime(DAY, "%Y-%m-%d")) - time.timezone
    with_root_held = killlist.admit(kill_list, signers={"a", "b"}, root_signers={"root"}, previous=None,
                                    now=signed_midnight + 3600, is_popular=is_popular)
    assert with_root_held.applied == (wide, pinned) and with_root_held.deferred == (popular,)
    released = killlist.admit(kill_list, signers={"a", "b"}, root_signers={"root"}, previous=None,
                              now=signed_midnight + killlist.POPULAR_HOLD_SECONDS + 1, is_popular=is_popular)
    assert released.applied == (wide, pinned, popular) and released.deferred == ()


def test_too_many_new_disables_refuse_the_version_and_an_older_version_never_wins():
    previous = killlist.KillList(version=3, day=DAY, entries=(_entry("old", version="1"),))
    flood = killlist.KillList(version=4, day=DAY, entries=tuple(_entry(f"s{i}", version="1") for i in range(killlist.MAX_NEW_DISABLES + 1)))
    refused = killlist.admit(flood, signers={"a", "b"}, root_signers=set(), previous=previous, now=NOW)
    assert refused.refused.startswith("21 new disables") and refused.applied == previous.entries and refused.version == 3
    fits = killlist.KillList(version=4, day=DAY, entries=previous.entries + tuple(_entry(f"s{i}", version="1") for i in range(killlist.MAX_NEW_DISABLES)))
    assert not killlist.admit(fits, signers={"a", "b"}, root_signers=set(), previous=previous, now=NOW).refused
    replay = killlist.KillList(version=2, day=DAY, entries=())
    assert "not newer" in killlist.admit(replay, signers={"a", "b"}, root_signers=set(), previous=previous, now=NOW).refused


def test_the_last_good_store_never_writes_a_refused_decision(tmp_path):
    store = killlist.LastGoodStore(tmp_path / "kill_list.json")
    assert store.current() is None
    store.remember(killlist.Decision(applied=(_entry(version="1"),), version=1), DAY)
    assert store.current().version == 1 and store.current().entries[0].identifier == "evil-skill"
    store.remember(killlist.Decision(applied=(), version=2, refused="bad"), DAY)
    assert store.current().version == 1                                   # the refusal left last-good in force
    (tmp_path / "kill_list.json").write_text("{nope", encoding="utf-8")
    assert store.current() is None


# ------------------------------------------------------------------ the hook


def _ruleset_with(entries, version=1):
    rs = compiler.Ruleset(synced_at=NOW)
    rs.kill_list = killlist.KillList(version=version, day=DAY, entries=tuple(entries)).as_cache()
    return rs


def _install(name="evil-skill", version="1.0.0"):
    return {"name": name, "version": version, "code": "print('hi')", "permissions": ""}


def test_a_disabled_skill_is_refused_in_block_mode_and_only_flagged_in_audit_mode(monkeypatch):
    rs = _ruleset_with([_entry(version="1.0.0"), killlist.KillEntry("mcp", "shady-server", killlist.KillAction.WARN, tool_prefix="shady_")])
    monkeypatch.setattr(ruleset, "get", lambda cfg: rs)
    recorded = []
    monkeypatch.setattr(hooks.reporting, "_report_and_audit", lambda cfg, event, findings, detail: recorded.append((findings, detail)))
    monkeypatch.setattr(hooks, "_config", lambda: BlackboxConfig(mode="block", block_severity="critical", discover=False))
    result = hooks.on_pre_tool_call("skill_install", _install())
    assert result is not None and result["action"] == "block" and "kill list" in result["message"]
    assert recorded[-1][0][0].identifier == "kill:skill:evil-skill@1.0.0" and recorded[-1][1]["decision"] == "block"
    assert hooks.on_pre_tool_call("skill_install", _install(version="2.0.0")) is None            # the pin does not match
    assert hooks.on_pre_tool_call("shady_fetch", {"url": "x"}) is None                           # WARN never blocks
    assert recorded[-1][0][0].severity == "medium" and recorded[-1][1]["decision"] == "flag"
    monkeypatch.setattr(hooks, "_config", lambda: BlackboxConfig(mode="audit", discover=False))
    assert hooks.on_pre_tool_call("skill_install", _install()) is None                           # audit mode: flag only
    assert recorded[-1][1]["decision"] == "flag"


def test_the_kill_finding_is_local_policy_never_a_sighting_and_a_bad_cache_kills_nothing():
    found = killlist.finding_for(killlist.KillList(version=1, day=DAY, entries=(_entry(version="1.0.0"),)), "skill_install", _install())
    assert found.source == "custom" and found.confirmed and found.kind == "malware" and found.fields["kill_action"] == "disable"
    assert killlist.KillList.from_cache({"version": 1, "entries": [{"registry": "bogus"}]}) is None
    rs = compiler.Ruleset(synced_at=NOW)
    rs.kill_list = {"version": 1, "entries": [{"registry": "bogus"}]}
    assert hooks._kill_list_findings(rs, "skill_install", _install()) == []
    publisher_wide = killlist.KillEntry("skill", "*", killlist.KillAction.DISABLE, publisher="EvilCorp")
    assert killlist.match([publisher_wide], "skill_install", {**_install("anything"), "publisher": "evilcorp"}) is publisher_wide
    assert killlist.match([publisher_wide], "skill_install", _install("anything")) is None


def test_the_ruleset_cache_round_trips_the_kill_list():
    rs = _ruleset_with([_entry(version="1.0.0")], version=7)
    rs.kill_list_refused = "21 new disables"
    back = disk_cache._deserialize(disk_cache._serialize(rs))
    assert killlist.KillList.from_cache(back.kill_list).version == 7 and back.kill_list_refused == "21 new disables"


# ------------------------------------------------------------------ the refresh applies and the curator publishes


class _VmNode(FakeNode):
    """Serves kill-list rows from the verified graph on top of the curate fake."""

    def __init__(self, rows):
        super().__init__()
        self.rows = list(rows)

    def query(self, sparql, cg_id, view=None, on_error=None, **kw):
        if "g:KillList" in sparql:
            served, self.rows = self.rows, []
            return served
        if "VALUES ?r" in sparql:                                   # the read-back after a publish
            return super().query(sparql, cg_id, view=view, on_error=on_error, **kw)
        return on_error if "g:KeyManifest" not in sparql else []


def test_the_refresh_admits_the_newest_list_and_keeps_last_good_on_a_refusal(monkeypatch, curators):
    manifest = curators["manifest"]
    two = [curators["a"], curators["b"]]
    import plugins.blackbox.community.statements.curator_view as cv
    monkeypatch.setattr(curator_tier.community, "read_curator_view", lambda client, cfg: cv.CuratorView(manifest=manifest))
    cfg = BlackboxConfig(context_graph_id=VM_GRAPH)
    good, _ = _signed([_entry(version="1.0.0")], two, manifest, version=1)
    rs = compiler.Ruleset(synced_at=NOW)
    curator_tier.apply_curator_tier(rs, _VmNode([_row(good)]), cfg)
    assert killlist.KillList.from_cache(rs.kill_list).version == 1 and rs.kill_list_refused == ""
    flood, _ = _signed([_entry(f"s{i}", version="1") for i in range(killlist.MAX_NEW_DISABLES + 1)], two, manifest, version=2)
    rs2 = compiler.Ruleset(synced_at=NOW)
    curator_tier.apply_curator_tier(rs2, _VmNode([_row(good), _row(flood)]), cfg)
    assert killlist.KillList.from_cache(rs2.kill_list).version == 1 and rs2.kill_list_refused.startswith("21 new disables")
    rs3 = compiler.Ruleset(synced_at=NOW)
    curator_tier.apply_curator_tier(rs3, _VmNode([]), cfg)                                   # nothing readable: last-good
    assert killlist.KillList.from_cache(rs3.kill_list).version == 1


def test_curators_propose_and_publish_a_kill_list_to_the_verified_graph(monkeypatch, tmp_path, curators):
    node = FakeNode()
    _machine(monkeypatch, tmp_path, "A", curators["a"])
    with pytest.raises(verbs.VerbError):
        verbs.propose_kill_list(_ctx(node, curators["manifest"]), ProposalStore(), entries=[{"registry": "skill"}])
    proposal = verbs.propose_kill_list(_ctx(node, curators["manifest"]), ProposalStore(),
                                       entries=[{"registry": "skill", "identifier": "evil-skill", "action": "disable",
                                                 "reason": "malware", "version": "1.0.0"}])
    assert proposal.kind == killlist.KILL_LIST_STATEMENT and node.vm_published == []
    _machine(monkeypatch, tmp_path, "B", curators["b"])
    store_b = ProposalStore()
    store_b.save(proposal)
    _published, outcome = verbs.approve(_ctx(node, curators["manifest"]), store_b, proposal.id, evidence="", typed_code=None, yes=True)
    assert outcome.startswith("published to " + VM_GRAPH)
    (graph, _path, quads), = node.vm_published
    assert graph == VM_GRAPH and quads[0]["subject"] == "urn:guardian:curator:kill-list:1"
    envelope = signing.from_text(json.loads(quads[1]["object"]))
    assert curators["manifest"].has_quorum(envelope, statement_type=killlist.KILL_LIST_STATEMENT)
