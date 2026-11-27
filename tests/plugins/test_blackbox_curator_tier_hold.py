"""A curator read that could not tell never brings a revoked rule back (review 2026-11-26, finding 2).

The curator tier replaced the generation's revocations with whatever the new
view said. A view that could not tell — the node's status raised (the view was
then a bare, "available" empty one), or a manifest / statement page failed —
says nothing about revocations, so every revoked verified rule blocked again
(and the live scope's revoked set went empty with it). Now: a status failure
is an UNAVAILABLE view, and while the view could not tell the prior
generation's revocations stay in force. A complete read still decides (an
un-revoke waits for one, the safe direction).
"""

from __future__ import annotations

from plugins.blackbox import community
from plugins.blackbox.community.statements.curator_view import CuratorView
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.kernel.dkg_client import DkgError
from plugins.blackbox.ruleset import compiler, curator_tier

CFG = BlackboxConfig(context_graph_id="0x" + "a" * 40 + "/blackbox-threats")
REVOKED = "ioc:domain:revoked.example"


class _NoStatus:
    def status(self, timeout=None):
        raise DkgError("status timed out")


def _rules() -> compiler.Ruleset:
    rs = compiler.Ruleset()
    rs.ioc = {REVOKED: {"identifier": REVOKED, "source": "public"}}
    return rs


def _prior() -> compiler.Ruleset:
    prior = compiler.Ruleset()
    prior.curator_revoked = frozenset({REVOKED})
    return prior


def test_a_status_failure_is_an_unavailable_view():
    assert community.read_curator_view(_NoStatus(), CFG).unavailable is True


def test_an_unavailable_view_keeps_the_prior_revocations(monkeypatch):
    monkeypatch.setattr(curator_tier.community, "read_curator_view", lambda client, config: CuratorView(unavailable=True))
    rs = _rules()
    assert any(rule["identifier"] == REVOKED for _category, rule in rs.iter_rules())
    curator_tier.apply_curator_tier(rs, object(), CFG, _prior())
    assert REVOKED in rs.curator_revoked
    assert not any(rule["identifier"] == REVOKED for _category, rule in rs.iter_rules())
    assert rs.curator_read_unavailable is True


def test_a_complete_read_still_decides(monkeypatch):
    monkeypatch.setattr(curator_tier.community, "read_curator_view", lambda client, config: CuratorView())
    rs = _rules()
    curator_tier.apply_curator_tier(rs, object(), CFG, _prior())
    assert rs.curator_revoked == frozenset()
