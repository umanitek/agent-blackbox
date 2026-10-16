"""Community Curation C6 — the reporter ladder runs itself.

A curator's published verdict credits the reporters it concerns in the
curator's PRIVATE ledger, once, with no command typed; the novelty rule runs on
facts gathered from the public record; any curator node rebuilds the same
ledger from that record; and a band moves when a listing is published, never
when it is proposed.

Reporters, three curator machines and the shared network come from the
multi-machine harness; every report is built by the product's own writer.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from _clock import utc_today
from _community_rows import Reporter
from _machines import share_report
from test_blackbox_curate_community import ADDRESS, Curators, _listing

from plugins.blackbox.community import reputation
from plugins.blackbox.curate import verbs
from plugins.blackbox.curate.ladder import novelty_facts, outcomes
from plugins.blackbox.curate.proposal import ProposalStore
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind

TODAY = utc_today()
LONG_AGO = (TODAY - timedelta(days=30)).isoformat()      # a reporter's first report: more than 14 days back
RECENT = (TODAY - timedelta(days=3)).isoformat()
THREATS = [f"ioc:ip:198.51.100.{i}" for i in range(1, 7)]


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    monkeypatch.delenv("BLACKBOX_CURATOR_ROOT_KEYS", raising=False)
    monkeypatch.delenv("BLACKBOX_COMMUNITY_ROOT_KEYS", raising=False)
    monkeypatch.setattr(outcomes.osv, "lookup", lambda ecosystem, name, version: None)   # no network: nothing is known to a feed


class Ladder(Curators):
    """The curators plus a partner organisation whose reports corroborate others'."""

    def __init__(self, tmp_path, monkeypatch):
        super().__init__(tmp_path, monkeypatch)
        self.partner = Reporter("0xpartner")
        self.two_key(Kind.COUNTED_AUTHORS, f"author:{self.partner.author}",
                     _listing(self.partner, **{"class": "partner", "org": "acme"}))

    def report(self, identifier, reporter, day):
        share_report(self.reader.node, identifier, reporter, day=day)

    def novel_report(self, identifier, reporter, day=LONG_AGO):
        """*reporter* reports first; the partner sees it in the wild later."""
        self.report(identifier, reporter, day)
        self.report(identifier, self.partner, RECENT)

    def ledger(self, machine):
        with machine:
            return reputation.ReputationLedger()

    def standing(self, machine, reporter):
        with machine:
            return reputation.ReputationLedger().standing(reporter.author)

    def sync(self, machine):
        with machine:
            return outcomes.credit_verdicts(self.ctx(machine))


# ------------------------------------------------------------------ a verdict credits its reporters, once


def test_a_published_confirmation_credits_each_reporter_once_with_no_command_typed(tmp_path, monkeypatch):
    team = Ladder(tmp_path, monkeypatch)
    alice, bob = Reporter("0xa"), Reporter("0xb")
    team.report(THREATS[0], alice, LONG_AGO)
    team.report(THREATS[0], bob, RECENT)
    team.two_key(Kind.CONFIRMATION, THREATS[0], {})                    # B publishes; nothing else is run
    assert team.standing(team.b, alice).confirmed == 1 and team.standing(team.b, bob).confirmed == 1
    assert team.standing(team.b, alice).first_seen_day == LONG_AGO     # since when it has been reporting: its own signed day
    again = team.sync(team.b)
    assert again.available and again.credited == 0                      # the same verdict credits nobody twice
    assert team.standing(team.b, alice).confirmed == 1


def test_a_published_rejection_is_an_honest_error_not_a_strike(tmp_path, monkeypatch):
    team = Ladder(tmp_path, monkeypatch)
    alice = Reporter("0xa")
    team.report(THREATS[0], alice, LONG_AGO)
    team.two_key(Kind.REJECTION, THREATS[0], {"reason": "benign"})
    standing = team.standing(team.b, alice)
    assert (standing.rejected, standing.strikes, standing.confirmed) == (1, 0, 0)


def test_a_confirmation_that_is_later_rejected_takes_its_novelty_credit_back(tmp_path, monkeypatch):
    team = Ladder(tmp_path, monkeypatch)
    alice = Reporter("0xa")
    team.novel_report(THREATS[0], alice)
    team.two_key(Kind.CONFIRMATION, THREATS[0], {})
    assert team.standing(team.b, alice).novel_credits == 1
    team.two_key(Kind.REJECTION, THREATS[0], {"reason": "benign"})
    standing = team.standing(team.b, alice)
    assert standing.novel_credits == 0 and standing.rejected == 1


# ------------------------------------------------------------------ novelty, from the public record


def test_five_novel_confirmed_reports_and_fourteen_days_make_a_graduation_candidate(tmp_path, monkeypatch):
    team = Ladder(tmp_path, monkeypatch)
    alice = Reporter("0xa")
    for threat in THREATS[:4]:
        team.novel_report(threat, alice)
        team.two_key(Kind.CONFIRMATION, threat, {})
    four = team.standing(team.b, alice)
    assert four.novel_credits == 4 and not reputation.graduates(four, TODAY.isoformat())    # four is not five
    team.novel_report(THREATS[4], alice)
    team.two_key(Kind.CONFIRMATION, THREATS[4], {})
    standing = team.standing(team.b, alice)
    assert standing.novel_credits == 5 and reputation.graduates(standing, TODAY.isoformat())
    with team.b:
        actions = {s.key: action for s, _score, action in verbs.graduation_candidates(TODAY.isoformat())}
        assert actions[alice.author] == "graduate"


def test_five_novel_reports_in_under_fourteen_days_do_not_graduate(tmp_path, monkeypatch):
    team = Ladder(tmp_path, monkeypatch)
    newcomer = Reporter("0xnew")
    for threat in THREATS[:5]:
        team.novel_report(threat, newcomer, day=(TODAY - timedelta(days=5)).isoformat())
        team.two_key(Kind.CONFIRMATION, threat, {})
    standing = team.standing(team.b, newcomer)
    assert standing.novel_credits == 5 and not reputation.graduates(standing, TODAY.isoformat())


def test_a_report_that_was_not_first_or_that_nobody_counted_also_saw_earns_no_novelty(tmp_path, monkeypatch):
    team = Ladder(tmp_path, monkeypatch)
    alice, late, alone = Reporter("0xa"), Reporter("0xlate"), Reporter("0xalone")
    team.novel_report(THREATS[0], alice)                                # alice first, the partner corroborates
    team.report(THREATS[0], late, RECENT)                               # late was not first
    team.report(THREATS[1], alone, LONG_AGO)                            # nobody counted saw this one
    team.two_key(Kind.CONFIRMATION, THREATS[0], {})
    team.two_key(Kind.CONFIRMATION, THREATS[1], {})
    assert team.standing(team.b, alice).novel_credits == 1
    assert (team.standing(team.b, late).confirmed, team.standing(team.b, late).novel_credits) == (1, 0)
    assert (team.standing(team.b, alone).confirmed, team.standing(team.b, alone).novel_credits) == (1, 0)


def test_reporting_what_a_public_advisory_already_lists_earns_no_novelty(tmp_path, monkeypatch):
    """Front-running a feed earns nothing."""
    team = Ladder(tmp_path, monkeypatch)
    monkeypatch.setattr(outcomes.osv, "lookup", lambda ecosystem, name, version: {"advisory_id": "MAL-2026-1", "kind": "malware"})
    alice = Reporter("0xa")
    team.novel_report("dep:npm:evil-pkg@1.0.0", alice)
    team.two_key(Kind.CONFIRMATION, "dep:npm:evil-pkg@1.0.0", {})
    standing = team.standing(team.b, alice)
    assert (standing.confirmed, standing.novel_credits) == (1, 0)


def test_one_upstream_publisher_yields_at_most_one_novelty_credit(tmp_path, monkeypatch):
    team = Ladder(tmp_path, monkeypatch)
    alice, bob = Reporter("0xa"), Reporter("0xb")
    team.novel_report("dep:npm:evil-pkg@1.0.0", alice)
    team.two_key(Kind.CONFIRMATION, "dep:npm:evil-pkg@1.0.0", {})
    team.novel_report("dep:npm:evil-pkg@1.0.1", bob)                    # the same package, another version, another reporter
    team.two_key(Kind.CONFIRMATION, "dep:npm:evil-pkg@1.0.1", {})
    assert team.standing(team.b, alice).novel_credits == 1 and team.standing(team.b, bob).novel_credits == 0
    with team.b:
        assert reputation.ReputationLedger().publisher_credits("npm:evil-pkg") == 1


def test_a_failed_advisory_lookup_grants_no_credit():
    report = type("R", (), {"author": "a" * 64, "identifier": "dep:npm:evil-pkg@1.0.0", "day": LONG_AGO})()

    def broken(*_):
        raise RuntimeError("advisory database unreachable")

    facts = novelty_facts.gather(report, [report], counted={}, verified=set(), osv_lookup=broken, publisher_credits=lambda p: 0)
    assert not facts.absent_everywhere and facts.publisher == "npm:evil-pkg"


# ------------------------------------------------------------------ every curator node reaches the same ledger


def test_two_curator_machines_rebuild_their_ledgers_separately_and_agree(tmp_path, monkeypatch):
    team = Ladder(tmp_path, monkeypatch)
    alice, bob = Reporter("0xa"), Reporter("0xb")
    for threat in THREATS[:3]:
        team.novel_report(threat, alice)
        team.two_key(Kind.CONFIRMATION, threat, {})                     # published (and credited) on B
    team.report(THREATS[3], bob, RECENT)
    team.two_key(Kind.REJECTION, THREATS[3], {"reason": "benign"})
    assert team.standing(team.a, alice).confirmed == 0                  # A has not looked yet
    first = team.sync(team.a)
    assert first.available and first.credited > 0
    for reporter in (alice, bob, team.partner):
        assert team.standing(team.a, reporter) == team.standing(team.b, reporter)
    with team.a:
        a_score = reputation.ReputationLedger().reputation(alice.author, TODAY.isoformat())
    with team.b:
        assert reputation.ReputationLedger().reputation(alice.author, TODAY.isoformat()) == a_score


def test_an_unreadable_graph_changes_nothing(tmp_path, monkeypatch):
    team = Ladder(tmp_path, monkeypatch)
    alice = Reporter("0xa")
    team.report(THREATS[0], alice, LONG_AGO)
    team.two_key(Kind.CONFIRMATION, THREATS[0], {})
    with team.a:
        ctx = team.ctx(team.a)                                          # built while A's node could still read
        team.a.node.offline = True                                      # then every query fails
        report = outcomes.credit_verdicts(ctx)
    assert not report.available and team.standing(team.a, alice).confirmed == 0


# ------------------------------------------------------------------ bands move on publish, never on proposal


def test_a_band_moves_when_the_listing_is_published_and_not_before(tmp_path, monkeypatch):
    team = Ladder(tmp_path, monkeypatch)
    alice = Reporter("0xa")
    for threat in THREATS[:5]:
        team.novel_report(threat, alice)
        team.two_key(Kind.CONFIRMATION, threat, {})
    team.sync(team.a)
    with team.a:
        proposal = verbs.propose_graduation(team.ctx(team.a, interest=[f"author:{alice.author}"]), ProposalStore(),
                                            key=alice.author, address=ADDRESS, today=TODAY.isoformat())
        assert proposal.parsed().payload["expires"] == (TODAY + timedelta(days=reputation.LISTING_DAYS)).isoformat()   # a verified listing
        assert reputation.ReputationLedger().standing(alice.author).band is reputation.ReputationBand.PROBATION
        verbs.send(team.ctx(team.a), proposal, team.b.name)
    assert team.standing(team.b, alice).band is reputation.ReputationBand.PROBATION      # proposed, not published
    with team.b:
        from plugins.blackbox.curate import transport
        for received in transport.receive_proposals(team.b.node, transport.InboxCursor()):
            ProposalStore().save(received)
        _, outcome = verbs.approve(team.ctx(team.b, interest=[f"author:{alice.author}"]), ProposalStore(), proposal.id,
                                   evidence="", typed_code=None, yes=True)
    assert outcome.startswith("published")
    assert team.standing(team.b, alice).band is reputation.ReputationBand.ESTABLISHED    # the publisher's ledger, at once
    team.sync(team.a)
    assert team.standing(team.a, alice).band is reputation.ReputationBand.ESTABLISHED    # the proposer's, on its next sync


def test_a_published_delisting_demotes_and_locks_out(tmp_path, monkeypatch):
    team = Ladder(tmp_path, monkeypatch)
    assert team.standing(team.b, team.partner).band is reputation.ReputationBand.PARTNER   # set when its listing was published
    team.two_key(Kind.COUNTED_AUTHORS, f"author:{team.partner.author}", _listing(team.partner, listed="no"))
    assert team.standing(team.b, team.partner).band is reputation.ReputationBand.PROBATION


# ------------------------------------------------------------------ one operator, several keys


def test_keys_that_report_the_same_threats_in_turn_are_shown_to_the_curator_as_one_group(tmp_path, monkeypatch):
    team = Ladder(tmp_path, monkeypatch)
    ring_a, ring_b, honest = Reporter("0xring1"), Reporter("0xring2"), Reporter("0xhonest")
    for threat in THREATS[:4]:
        team.report(threat, ring_a, LONG_AGO)
        team.report(threat, ring_b, RECENT)
    team.report(THREATS[5], honest, RECENT)
    with team.a:
        groups = outcomes.overlap_rings(team.ctx(team.a))
    assert groups == [frozenset({ring_a.author, ring_b.author})]
