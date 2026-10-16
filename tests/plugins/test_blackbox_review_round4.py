"""Review round 4 (2026-10-02, adversarial review of Phase 2) — the guards for every fixed finding.

* An MCP kill is WIDE: the root must co-sign; a tool prefix shorter than 3 chars
  or missing is not a valid entry (two curator keys can no longer disable every tool).
* Root-alone reductions need READABLE heartbeats that are genuinely old — an
  unreadable or unconfigured community graph is not silence — and ≤ 20 per read.
* An undated manifest never beats a dated one (no time-lock bypass); a conflicting
  order is skipped so readers stay frozen at the previous version.
* Withdrawing consent stops keep-alive copies, retries and digests.
* A local override never demotes a kill-list, custom-rule or secret finding; the
  Blackbox home is a protected path.
* The reputation salts live in their own file and die with their entries.
* A counted-author listing longer than 12 months is not a valid statement.
* A 2-of-3 signed pause is enforced by the community tier.
* A cosign that outgrows the envelope is a readable refusal.
"""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from _community_rows import GRAPH, NETWORK
from plugins.blackbox import killlist, overrides
from plugins.blackbox.community import keep_alive, reputation, share_retry
from plugins.blackbox.community.statements import curator_statements as cs
from plugins.blackbox.community.statements import curator_view as cv
from plugins.blackbox.community.trust import manifests as trust_manifests
from plugins.blackbox.detection import Finding
from plugins.blackbox.kernel import signing
from plugins.blackbox.kernel.config import DEFAULT_PROTECTED_PATHS, BlackboxConfig
from plugins.blackbox.kernel.signing import key_manifest as km
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind
from plugins.blackbox.ruleset import community_tier, compiler
from test_blackbox_curator_view import _curator_row
from test_blackbox_community_ruleset import FakeClient

TODAY = "2026-10-02"
THREAT = "dep:npm:evil@1.0.0"


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))


@pytest.fixture
def keys():
    curators = [Ed25519PrivateKey.generate() for _ in range(3)]
    return {"curators": curators, "root": Ed25519PrivateKey.generate(), "hex": [signing.public_key_hex(k) for k in curators]}


def _manifest(keys, **over):
    base = dict(environment=NETWORK, graph="0xabc/agent-blackbox-vm", chain="", root_epoch=1, version=1,
                curator_keys=tuple(sorted(keys["hex"])),
                curator_operators=("operator-a", "operator-b", "operator-c"), threshold=2, promotion_author="0x" + "1" * 40,
                legacy_assets_hash=km.legacy_assets_hash([]))
    base.update(over)
    return km.KeyManifest(**base)


# ------------------------------------------------------------------ finding 1: MCP kills


def test_an_mcp_kill_is_wide_and_needs_a_real_prefix():
    entry = killlist.KillEntry("mcp", "shady", killlist.KillAction.DISABLE, version="0", artifact_hash="a" * 64, tool_prefix="shady_")
    assert entry.wide and entry.valid()
    assert killlist.KillEntry.from_json({"registry": "mcp", "identifier": "x", "action": "disable", "tool_prefix": "t"}) is None
    assert killlist.KillEntry.from_json({"registry": "mcp", "identifier": "x", "action": "disable"}) is None
    kill_list = killlist.KillList(version=1, day=TODAY, entries=(entry,))
    decision = killlist.admit(kill_list, signers={"a", "b"}, root_signers=set(), previous=None, now=1_800_000_000.0)
    assert decision.applied == () and "root" in decision.dropped[0][1]


# ------------------------------------------------------------------ finding 2: root-alone reductions


def test_root_alone_needs_readable_old_heartbeats_and_is_capped(keys):
    manifest = _manifest(keys)
    root_hex = signing.public_key_hex(keys["root"])
    rows = [_rows_of(cs.sign_statement(Kind.REVOCATION, f"dep:npm:c{i}@1", sequence=i + 1, fields={"reason": "false-positive"},
                                       key=keys["root"], manifest=manifest, graph=manifest.graph)) for i in range(25)]
    unreadable = cv.build_view(manifest, rows, [], verified_graph=manifest.graph, community_graph=GRAPH, today=TODAY,
                               root_keys={root_hex}, community_readable=False)
    assert unreadable.revoked == frozenset()                                              # not silence
    no_heartbeat_ever = cv.build_view(manifest, rows, [], verified_graph=manifest.graph, community_graph=GRAPH, today=TODAY,
                                      root_keys={root_hex}, community_readable=True)
    assert no_heartbeat_ever.revoked == frozenset()
    old_beat = _curator_row(Kind.HEARTBEAT, "curator", {"key": keys["hex"][0]}, keys["curators"][:1], manifest, graph=GRAPH, sequence=1)
    silent = cv.build_view(manifest, rows, [old_beat], verified_graph=manifest.graph, community_graph=GRAPH, today="2026-12-01",
                           root_keys={root_hex}, community_readable=True)
    assert len(silent.revoked) == cv.ROOT_ALONE_PER_READ                                   # capped, never all 25


def _rows_of(envelope):
    quads = cs.statement_quads(envelope)
    row = {"r": quads[0]["subject"]}
    for quad in quads:
        if quad["object"].startswith('"'):
            row[quad["predicate"].rsplit("/", 1)[-1]] = json.loads(quad["object"])
    return row


# ------------------------------------------------------------------ finding 3 + 8: the effective manifest


@pytest.mark.usefixtures("time_lock_one_day")
def test_an_undated_manifest_never_beats_a_dated_one_and_a_conflict_freezes(keys):
    dated = _manifest(keys, version=1, issued_day="2026-09-01")
    undated_newer = _manifest(keys, version=2)
    assert trust_manifests.effective_manifest([dated, undated_newer], TODAY) == dated
    assert trust_manifests.effective_manifest([undated_newer], TODAY) == undated_newer                   # nothing dated: it serves
    pending = _manifest(keys, version=3, issued_day=TODAY)
    assert trust_manifests.effective_manifest([dated, pending], TODAY) == dated
    twin = km.KeyManifest(**{**pending.__dict__, "promotion_author": "0x" + "2" * 40})
    assert trust_manifests.effective_manifest([dated, pending, twin], "2026-10-10") == dated            # conflicting order skipped
    assert trust_manifests.manifests_conflict([pending, twin])


# ------------------------------------------------------------------ finding 4: no opt-in (never given, or withdrawn) stops every beat


@pytest.mark.parametrize("state", ["never-opted-in", "withdrawn"])
def test_no_consent_in_force_stops_keep_alive_retries_and_digests(real_consent, tmp_path, monkeypatch, state):
    """Sharing is opt-in (2026-10-16): with no acceptance on record — the default — or after a
    withdrawal, nothing leaves on any beat, even with `report: true`; the opt-in starts them."""
    cfg = BlackboxConfig(report=True, context_graph_id=GRAPH)
    store = keep_alive.LiveReportStore(tmp_path / "live.json", clock=lambda: 1_800_000_000.0)
    store.remember(graph=GRAPH, name="report-a", identifier=THREAT, subject="s", severity="high", quads=[{"a": "b"}], epoch=keep_alive.Epoch(1))
    queue = share_retry.ShareRetryQueue(tmp_path / "q.json", clock=lambda: 1_800_000_000.0 + 100)
    queue.add(share_retry.PendingShare(name="r", graph=GRAPH, identifier=THREAT, category="dependency", severity="high", subject="s",
                                       quads=(), attempts=1, first_failed=1_800_000_000.0, next_due=0))
    sent = []

    class Node:
        def status(self):
            return {"networkId": NETWORK}

        def share_knowledge_asset(self, *a, **k):
            sent.append(a[1])
            return {"state": "succeeded"}

    if state == "withdrawn":
        real_consent.record()
        real_consent.withdraw()                                                 # the operator opted out
    assert not real_consent.in_force()
    assert keep_alive.publish_due_copies(Node(), cfg, store, now=1_800_000_000.0 + 11 * 86_400) == 0
    assert share_retry.retry_due_shares(Node(), cfg, queue) == 0 and sent == []
    from plugins.blackbox.community import digest
    assert digest.publish_due_digests(Node(), cfg) == 0
    real_consent.record()
    assert keep_alive.publish_due_copies(Node(), cfg, store, now=1_800_000_000.0 + 11 * 86_400) == 1


# ------------------------------------------------------------------ finding 5: overrides and the protected home


def test_overrides_never_demote_custom_tier_findings_and_the_home_is_protected():
    kill = Finding(identifier="kill:skill:evil@*", category="skill", severity="critical", title="k", confirmed=True, source="custom", kind="malware")
    verified = Finding(identifier=THREAT, category="dependency", severity="critical", title="v", confirmed=True, source="public", kind="malware")
    blocking, demoted = overrides.demote_blocking([kill, verified], frozenset({"kill:skill:evil@*", THREAT}))
    assert blocking == [kill] and demoted == [verified]
    assert "~/.hermes/blackbox/*" in DEFAULT_PROTECTED_PATHS and "~/.hermes/plugins/blackbox/*" in DEFAULT_PROTECTED_PATHS


# ------------------------------------------------------------------ finding 7: salts live apart and die with their entries


def test_salts_are_in_their_own_file_and_pruned_with_expired_entries(tmp_path):
    ledger = reputation.ReputationLedger(tmp_path / "reputation.json")
    ledger.record("a" * 64, reputation.Outcome("2026-09-01", True), first_seen_day="2026-08-01")
    ledger.record("b" * 64, reputation.Outcome("2020-01-01", True), first_seen_day="2019-12-01")   # long expired
    entries = json.loads((tmp_path / "reputation.json").read_text(encoding="utf-8"))
    assert "salts" not in entries and "a" * 64 not in json.dumps(entries)
    assert ledger.keys() == ["a" * 64]                                                       # b's entry is expired
    ledger.record("a" * 64, reputation.Outcome("2026-09-02", True))                        # the next write persists the pruning
    from plugins.blackbox.community.reputation import sealed_index
    salts = sealed_index.open_sealed((tmp_path / "reputation_salts.json").read_text(encoding="utf-8"),
                                     sealed_index.load_or_create_key(tmp_path / "reputation_index.key"))
    assert set(salts) == {"a" * 64}                                                          # b's salt died with its entry


# ------------------------------------------------------------------ finding H + pause + cosign


def test_a_listing_longer_than_twelve_months_is_refused_and_a_signed_pause_is_enforced(keys, monkeypatch):
    manifest = _manifest(keys)
    two = keys["curators"][:2]
    with pytest.raises(ValueError):
        cs.sign_statement(Kind.COUNTED_AUTHORS, "author:" + "a" * 64, sequence=1,
                          fields={"listed": "yes", "class": "established", "org": "", "expires": "2028-10-02", "address": "0x" + "b" * 40},
                          key=two[0], manifest=manifest, graph=manifest.graph, day=__import__("datetime").date(2026, 10, 2))
    pause = _curator_row(Kind.PAUSE, "curator", {"until": "2026-10-05"}, two, manifest, graph=manifest.graph, sequence=1)
    view = cv.build_view(manifest, [pause], [], verified_graph=manifest.graph, community_graph=GRAPH, today=TODAY)
    assert view.pause_active(TODAY) and not view.pause_active("2026-10-06")
    monkeypatch.setattr(community_tier.community, "ensure_community_subscription", lambda client, cfg: None)
    monkeypatch.setattr(community_tier.community, "community_pause_active", lambda client, cfg: False)
    monkeypatch.setattr(community_tier.community, "curator_today", lambda: TODAY)
    from plugins.blackbox.community import CommunityRead, ReadState
    monkeypatch.setattr(community_tier.community, "read_verified_reports",
                        lambda client, cfg, **kw: CommunityRead(ReadState.ROWS, reports=(), curator=view))
    rs = compiler.Ruleset()
    community_tier.apply_community_tier(rs, FakeClient(), BlackboxConfig(context_graph_id=GRAPH), None)
    assert rs.community_paused is True and rs.community == {}


def test_a_cosign_that_outgrows_the_envelope_is_a_refusal(keys, monkeypatch, tmp_path):
    from plugins.blackbox.curate import verbs
    from plugins.blackbox.curate.proposal import Proposal, ProposalState, ProposalStore
    from test_blackbox_curate import FakeNode, _ctx, _machine
    manifest = _manifest(keys, graph="0xabc/agent-blackbox-vm")
    big = killlist.KillList(version=1, day=TODAY, entries=(killlist.KillEntry("skill", "evil", killlist.KillAction.WARN, version="1"),))
    envelope = killlist.sign_kill_list(big, keys["curators"][0], manifest, manifest.graph)
    monkeypatch.setattr(verbs.signing, "cosign", lambda env, key: (_ for _ in ()).throw(ValueError("signed envelope exceeds 4096 characters")))
    _machine(monkeypatch, tmp_path, "B", keys["curators"][1])
    store = ProposalStore()
    proposal = Proposal.new(killlist.KILL_LIST_STATEMENT, "kill-list", envelope, manifest.graph, checks={}).transition(ProposalState.PROPOSED)
    store.save(proposal)
    with pytest.raises(verbs.VerbError, match="split the list"):
        verbs.approve(_ctx(FakeNode(), manifest), store, proposal.id, evidence="", typed_code=None, yes=True, root=True)


def test_a_pause_cannot_be_chained_back_to_back_by_the_same_signers(keys):
    """KI-229 / §09: the SAME pair renewing its own pause on or before its `until` is ignored;
    a different signer set, or a pause after a gap, counts."""
    manifest = _manifest(keys)
    two, other = keys["curators"][:2], keys["curators"][1:3]
    first = _curator_row(Kind.PAUSE, "curator", {"until": "2026-10-05"}, two, manifest, graph=manifest.graph, sequence=1)
    renewal = _curator_row(Kind.PAUSE, "curator", {"until": "2026-10-09"}, two, manifest, graph=manifest.graph, sequence=2)
    view = cv.build_view(manifest, [first, renewal], [], verified_graph=manifest.graph, community_graph=GRAPH, today=TODAY)
    assert view.pause_until == "2026-10-05"                                # the chained renewal is ignored
    by_others = _curator_row(Kind.PAUSE, "curator", {"until": "2026-10-09"}, other, manifest, graph=manifest.graph, sequence=3)
    view = cv.build_view(manifest, [first, by_others], [], verified_graph=manifest.graph, community_graph=GRAPH, today=TODAY)
    assert view.pause_until == "2026-10-09"                                # a different pair may pause
