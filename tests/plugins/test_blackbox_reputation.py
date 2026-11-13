"""Refine R4 — automated graduation: bands, Beta reputation with forgetting,
hardened novelty, partners, collusion collapse, the curator-private ledger.

The plan's adversarial tests: 20 fresh wallets Σweight = 0; a staggered ring
collapses; self-dealt and front-run confirmations earn 0; one partner
organisation with two nodes counts once. Plus: a lockout re-graduates from
zero; erasure crypto-shreds the ledger entry; readers apply a published
collapse through the counted-author ``org``; the curate verbs build the
counted-author proposal and never publish the ledger.
"""

from __future__ import annotations

import json

import pytest

from plugins.blackbox.community import reputation as rep
from plugins.blackbox.community.reputation import sealed_index
from plugins.blackbox.community import stages
from plugins.blackbox.community.statements import curator_view as cv
from plugins.blackbox.curate import verbs
from plugins.blackbox.curate.proposals.proposal import ProposalStore
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind
from test_blackbox_curate import FakeNode, _ctx, _machine, curators

TODAY = "2026-10-02"
KEY = "a" * 64


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))


def _keys(prefix, n):
    return [f"{prefix}{i:02d}".ljust(64, "0") for i in range(n)]


# ------------------------------------------------------------------ bands and weight


def test_twenty_fresh_wallets_weigh_exactly_zero():
    standings = [rep.ReporterStanding(key=k, first_seen_day=TODAY) for k in _keys("w", 20)]
    assert sum(rep.weight_for(s, reputation=1.0) for s in standings) == 0.0
    assert not any(rep.graduates(s, TODAY) for s in standings)


def test_weight_follows_the_band_and_a_sponsored_node_is_capped():
    established = rep.ReporterStanding(key=KEY, band=rep.ReputationBand.ESTABLISHED)
    assert rep.weight_for(established, reputation=0.8) == 0.8 and rep.weight_for(established, reputation=7.0) == 1.0
    sponsored = rep.ReporterStanding(key=KEY, sponsor="acme")
    assert rep.weight_for(sponsored, reputation=1.0, sponsor_reputation=1.0) == rep.SPONSOR_WEIGHT_CAP
    assert rep.weight_for(sponsored, reputation=1.0, sponsor_reputation=0.5) == 0.25
    locked = rep.ReporterStanding(key=KEY, band=rep.ReputationBand.ESTABLISHED, lockout_until="2027-01-01")
    assert rep.weight_for(locked, reputation=1.0) == 0.0


# ------------------------------------------------------------------ reputation, graduation, demotion


def test_beta_reputation_forgets_with_age():
    fresh_bad = [rep.Outcome("2026-10-01", False)] * 3
    old_bad = [rep.Outcome("2025-01-01", False)] * 3
    good = [rep.Outcome("2026-09-30", True)] * 5
    assert rep.beta_reputation([], TODAY) == 0.5
    assert rep.beta_reputation(good + old_bad, TODAY) > rep.beta_reputation(good + fresh_bad, TODAY)
    assert rep.beta_reputation(good, TODAY) > rep.REPUTATION_FLOOR


def test_graduation_needs_age_novelty_and_a_clean_record():
    ready = rep.ReporterStanding(key=KEY, first_seen_day="2026-09-01", novel_credits=5)
    assert rep.graduates(ready, TODAY)
    assert not rep.graduates(rep.ReporterStanding(key=KEY, first_seen_day="2026-09-25", novel_credits=5), TODAY)   # too young
    assert not rep.graduates(rep.ReporterStanding(key=KEY, first_seen_day="2026-09-01", novel_credits=4), TODAY)   # not novel enough
    assert not rep.graduates(rep.ReporterStanding(key=KEY, first_seen_day="2026-09-01", novel_credits=9, strikes=1), TODAY)
    assert not rep.graduates(rep.ReporterStanding(key=KEY, first_seen_day="2026-09-01", novel_credits=9, lockout_until="2027-01-01"), TODAY)


def test_two_strikes_or_a_low_reputation_lock_out_and_re_graduation_starts_from_zero():
    established = rep.ReporterStanding(key=KEY, band=rep.ReputationBand.ESTABLISHED, first_seen_day="2026-01-01",
                                       confirmed=20, rejected=2, strikes=2, novel_credits=9)
    demoted = rep.demotion(established, reputation=0.9, today=TODAY)
    assert demoted is not None and demoted.band is rep.ReputationBand.PROBATION and demoted.lockout_until == "2026-12-31"
    assert (demoted.confirmed, demoted.rejected, demoted.strikes, demoted.novel_credits) == (0, 0, 0, 0)
    assert rep.demotion(rep.ReporterStanding(key=KEY, band=rep.ReputationBand.ESTABLISHED), reputation=0.4, today=TODAY) is not None
    assert rep.demotion(rep.ReporterStanding(key=KEY, band=rep.ReputationBand.ESTABLISHED, strikes=1), reputation=0.9, today=TODAY) is None
    assert rep.demotion(rep.ReporterStanding(key=KEY), reputation=0.0, today=TODAY) is None     # probation has nothing to lose


# ------------------------------------------------------------------ novelty


def test_self_dealt_and_front_run_confirmations_earn_nothing_toward_graduation():
    base = dict(first_cluster=True, absent_everywhere=True, corroborated_in_the_wild=True, publisher="npm:someone")
    assert rep.novelty_credit(rep.NoveltyFacts(**base, artifact_age_hours=100.0)).credit is rep.NoveltyCredit.CREDIT
    self_dealt = rep.novelty_credit(rep.NoveltyFacts(**base, artifact_age_hours=10.0))
    assert self_dealt.credit is rep.NoveltyCredit.SIGHTING_ONLY and "72 h" in self_dealt.reason
    front_run = rep.novelty_credit(rep.NoveltyFacts(**{**base, "absent_everywhere": False}))
    assert front_run.credit is rep.NoveltyCredit.NONE and "front-running" in front_run.reason
    assert rep.novelty_credit(rep.NoveltyFacts(**{**base, "corroborated_in_the_wild": False})).credit is rep.NoveltyCredit.NONE
    assert rep.novelty_credit(rep.NoveltyFacts(**{**base, "first_cluster": False})).credit is rep.NoveltyCredit.SIGHTING_ONLY
    assert rep.novelty_credit(rep.NoveltyFacts(**base, publisher_credits_used=1)).credit is rep.NoveltyCredit.SIGHTING_ONLY


# ------------------------------------------------------------------ partners


def test_one_partner_organisation_with_two_nodes_counts_once_and_rejections_suspend_it():
    grants = [rep.PartnerGrant("acme", _keys("p", 2)[0], "2026-09-01", "2027-03-01"),
              rep.PartnerGrant("acme", _keys("p", 2)[1], "2026-09-01", "2027-03-01"),
              rep.PartnerGrant("other", "o" * 64, "2026-09-01", "2027-03-01", sponsored=True),
              rep.PartnerGrant("stale", "s" * 64, "2025-01-01", "2027-03-01")]      # over the 12-month cap
    assert set(rep.org_clusters(grants, TODAY)) == {"acme", "other"} and len(rep.org_clusters(grants, TODAY)["acme"]) == 2
    assert rep.partner_weight(grants[0], reputation=0.9, rejections_last_30d=1, today=TODAY) == 0.9
    assert rep.partner_weight(grants[0], reputation=0.9, rejections_last_30d=2, today=TODAY) == 0.0
    assert rep.partner_weight(grants[2], reputation=1.0, rejections_last_30d=0, today=TODAY) == rep.SPONSOR_WEIGHT_CAP
    assert rep.partner_weight(grants[3], reputation=1.0, rejections_last_30d=0, today=TODAY) == 0.0


# ------------------------------------------------------------------ collusion


def test_a_staggered_ring_collapses_to_one_cluster_and_is_named_for_the_curator():
    threats = {f"ioc:domain:t{i}.example" for i in range(6)}
    ring = {k: threats for k in _keys("r", 4)}                                   # four wallets, the same six threats
    honest = {"h" * 64: {"ioc:domain:t0.example", "ioc:domain:other.example", "dep:npm:x@1"}}
    clusters = rep.collapse({**ring, **honest})
    assert len({clusters[k] for k in ring}) == 1 and clusters["h" * 64] == "h" * 64
    assert rep.rings({**ring, **honest}) == [frozenset(ring)]
    # a shared transport peer id collapses even disjoint report sets
    by_peer = rep.collapse({"a" * 64: {"x"}, "b" * 64: {"y"}, "c" * 64: {"z"}}, {"a" * 64: "12D3peer", "b" * 64: "12D3peer"})
    assert by_peer["a" * 64] == by_peer["b" * 64] != by_peer["c" * 64]
    assert rep.jaccard({"a"}, set()) == 0.0


def test_readers_count_a_published_collapse_once():
    keys = _keys("e", 5)
    counted = {k: cv.CountedAuthor(k, "0x" + k[:40], "established", "ring-1", "2027-01-01") for k in keys}
    view = cv.CuratorView(counted=counted)
    assert stages.clusters_for(keys, view) == stages.Clusters(partner=0, established=1)
    counted[keys[0]] = cv.CountedAuthor(keys[0], "0x" + keys[0][:40], "established", "", "2027-01-01")
    assert stages.clusters_for(keys, cv.CuratorView(counted=counted)).established == 2


# ------------------------------------------------------------------ the private ledger


def test_the_ledger_is_salted_and_erasure_crypto_shreds_the_entry(tmp_path):
    ledger = rep.ReputationLedger(tmp_path / "reputation.json")
    ledger.record(KEY, rep.Outcome("2026-09-10", True), novel=True, first_seen_day="2026-09-01")
    ledger.record(KEY, rep.Outcome("2026-09-20", False))
    standing = ledger.standing(KEY)
    assert (standing.confirmed, standing.rejected, standing.novel_credits, standing.first_seen_day) == (1, 1, 1, "2026-09-01")
    assert 0.4 < ledger.reputation(KEY, TODAY) < 0.6
    raw = json.loads((tmp_path / "reputation.json").read_text(encoding="utf-8"))
    index = (tmp_path / "reputation_salts.json").read_text(encoding="utf-8")
    salts = sealed_index.open_sealed(index, sealed_index.load_or_create_key(tmp_path / "reputation_index.key"))
    assert list(salts) == [KEY] and KEY not in json.dumps(raw["entries"])               # entries carry only the pseudonym; salts apart
    assert KEY not in index                                                              # and the index is sealed (KI-257)
    assert ledger.erase(KEY) and not ledger.erase(KEY)
    assert ledger.standing(KEY) == rep.ReporterStanding(key=KEY) and ledger.keys() == []
    assert json.loads((tmp_path / "reputation.json").read_text(encoding="utf-8"))["entries"] == {}


def test_a_garbage_ledger_file_is_an_empty_ledger(tmp_path):
    (tmp_path / "reputation.json").write_text("{nope", encoding="utf-8")
    assert rep.ReputationLedger(tmp_path / "reputation.json").keys() == []


# ------------------------------------------------------------------ graduation → counted-author statements


def test_nomination_fields_follow_the_standing():
    ready = rep.ReporterStanding(key=KEY, first_seen_day="2026-09-01", novel_credits=5)
    fields = rep.nomination_fields(ready, address="0xAbC", today=TODAY)
    assert fields == {"listed": "yes", "class": "established", "org": "", "expires": "2027-10-02", "address": "0xabc"}
    assert rep.nomination_fields(rep.ReporterStanding(key=KEY), address="0xabc", today=TODAY) is None
    bad = rep.ReporterStanding(key=KEY, band=rep.ReputationBand.ESTABLISHED, strikes=2)
    assert rep.nomination_fields(bad, address="0xabc", today=TODAY, reputation=0.9)["listed"] == "no"
    partner = rep.ReporterStanding(key=KEY, band=rep.ReputationBand.PARTNER, org="acme")
    assert rep.nomination_fields(partner, address="0xabc", today=TODAY, reputation=0.9)["class"] == "partner"
    collapsed = rep.ReporterStanding(key=KEY, band=rep.ReputationBand.ESTABLISHED)
    assert rep.nomination_fields(collapsed, address="0xabc", today=TODAY, reputation=0.9, cluster="ring-1")["org"] == "ring-1"


def test_the_curate_verbs_record_outcomes_and_propose_the_listing_without_publishing_the_ledger(monkeypatch, tmp_path, curators):
    node = FakeNode()
    _machine(monkeypatch, tmp_path, "A", curators["a"])
    for day in ("2026-09-02", "2026-09-05", "2026-09-09", "2026-09-12", "2026-09-15"):
        verbs.record_outcome(KEY, confirmed=True, day=day, novel=True, first_seen_day="2026-09-01")
    rows = verbs.graduation_candidates(TODAY)
    assert [(s.key, action) for s, _score, action in rows] == [(KEY, "graduate")]
    with pytest.raises(verbs.VerbError):
        verbs.record_outcome("0x" + "1" * 40, confirmed=True, day=TODAY)                  # an address is not an identity
    proposal = verbs.propose_graduation(_ctx(node, curators["manifest"]), ProposalStore(), key=KEY, address="0x" + "1" * 40, today=TODAY)
    assert proposal.kind == Kind.COUNTED_AUTHORS.value and proposal.identifier == f"author:{KEY}"
    assert proposal.parsed().payload["listed"] == "yes" and proposal.parsed().payload["class"] == "established"
    assert node.shared == [] and node.vm_published == []                                   # one key: nothing published yet
    assert rep.ReputationLedger().standing(KEY).band is rep.ReputationBand.PROBATION        # KI-255: a proposal moves nothing
    with pytest.raises(verbs.VerbError, match="already waiting"):
        verbs.propose_graduation(_ctx(node, curators["manifest"]), ProposalStore(), key=KEY, address="0x" + "1" * 40, today=TODAY)


def test_retention_is_counted_from_the_utc_day_like_every_day_it_is_compared_with(tmp_path, monkeypatch):
    """The cutoff used the machine's LOCAL date while every `last_day` is a UTC day, so for part
    of each day an entry was dropped a day early or kept a day late."""
    from plugins.blackbox.community import reputation
    from plugins.blackbox.community.reputation import ledger as ledger_module
    monkeypatch.setattr(ledger_module, "today_utc", lambda: "2022-01-01")
    book = reputation.ReputationLedger(tmp_path / "rep.json")
    on_the_cutoff, one_day_older = "a" * 64, "b" * 64

    book.record(on_the_cutoff, reputation.Outcome("2020-01-02", confirmed=True))    # exactly RETENTION_DAYS (730) ago
    book.record(one_day_older, reputation.Outcome("2020-01-01", confirmed=True))

    kept = book._load()
    assert len(kept["entries"]) == 1 and set(kept["salts"]) == {on_the_cutoff}
