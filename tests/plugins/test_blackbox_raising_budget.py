"""Community Curation C3 — the reader's daily cap on what the community curators can raise.

The community authority's keys sign routine statements on their own, so they are
online keys (KI-258). Every reader admits at most 100 new confirmations or
attestations and 20 new listings per day of its own clock from that authority;
the rest are HELD and admitted on the following days, oldest first. Reductions
(rejections, delistings, pauses) are never held. A node's first read is a
baseline and admits everything.

One graph (2026-10-16): the community authority is dormant, so on a reader the
cap holds nothing. Its rules are pinned on the pure function, kept for when
community curators are added; the reader test pins that the verified
authority's word is never held.
"""

from __future__ import annotations

import pytest
from _community_rows import GRAPH, Reporter
from test_blackbox_authority import CFG, CITED, Side, TODAY, VM_GRAPH
from test_blackbox_curator_view import _entry
from test_blackbox_trust_store import Store

from plugins.blackbox.community import read_curator_view
from plugins.blackbox.community.statements import curator_view as cv
from plugins.blackbox.community.trust import raising_budget
from plugins.blackbox.community.trust.trust_store import statement_key
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind

TOMORROW = "2026-10-03"


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    monkeypatch.delenv("BLACKBOX_CURATOR_ROOT_KEYS", raising=False)
    monkeypatch.setattr(cv, "_today", lambda: TODAY)


def _threats(n):
    return [f"ioc:ip:10.1.{i // 250}.{i % 250}" for i in range(n)]


def _listing(side, reporter, **kw):
    fields = _entry(reporter.author, **{k: v for k, v in kw.items() if k in ("listed", "expires")})
    return side.row(Kind.COUNTED_AUTHORS, f"author:{reporter.author}", fields, sequence=kw.get("sequence", 1))


# ------------------------------------------------------------------ through the reader


def test_the_verified_authoritys_word_is_never_held_however_much_it_says(monkeypatch):
    """The cap binds the community authority's online keys only, and that authority is
    dormant (one graph, 2026-10-16): a burst from the verified authority is read at once."""
    curators = Side(VM_GRAPH)
    monkeypatch.setenv("BLACKBOX_CURATOR_ROOT_KEYS", curators.root_hex)
    assert read_curator_view(Store(verified=[curators.manifest_row()]), CFG).manifest is not None   # the baseline
    threats = _threats(raising_budget.CONFIRMATIONS_PER_DAY + 1)
    rows = [curators.row(Kind.CONFIRMATION, threat, CITED, sequence=i + 1) for i, threat in enumerate(threats)]
    view = read_curator_view(Store(shared=rows, verified=[curators.manifest_row()]), CFG, interest=threats)
    assert all(view.verdict(threat) is Kind.CONFIRMATION for threat in threats) and view.held_raising == 0


# ------------------------------------------------------------------ the pure function


def test_every_reader_drains_held_statements_in_the_same_order():
    side = Side(GRAPH)
    rows = [side.row(Kind.CONFIRMATION, threat, CITED, sequence=i + 1) for i, threat in enumerate(_threats(105))]
    forward = raising_budget.admit(rows, {}, first_read=False, today=TODAY)
    backward = raising_budget.admit(list(reversed(rows)), {}, first_read=False, today=TODAY)
    assert forward.held == backward.held == {statement_key(row) for row in rows[100:]}
    drained = raising_budget.admit(rows, forward.admitted, first_read=False, today=TOMORROW)
    assert not drained.held and len(drained.admitted) == 105


def test_only_raising_statements_are_ever_bucketed():
    side = Side(GRAPH)
    alice = Reporter("0xa")
    assert raising_budget.bucket(side.row(Kind.CONFIRMATION, "ioc:ip:10.0.0.1", CITED))[0] == "confirm"
    assert raising_budget.bucket(side.row(Kind.ATTESTATION, "ioc:ip:10.0.0.1", {"stage": "corroborated"}))[0] == "confirm"
    assert raising_budget.bucket(_listing(side, alice))[0] == "list"
    for row in (_listing(side, alice, listed="no"), side.row(Kind.REJECTION, "ioc:ip:10.0.0.1", {"reason": "benign"}),
                side.row(Kind.PAUSE, "curator", {"until": "2026-10-05"}), side.row(Kind.DEFERRAL, "ioc:ip:10.0.0.1", {}, signers=1),
                {"signedStatement": "not an envelope"}):
        assert raising_budget.bucket(row) is None
