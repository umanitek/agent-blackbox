"""A live lookup cut off at its row limit could not tell (review 2026-11-26, finding 5).

Each store query carries ``LIMIT ROW_LIMIT``. An answer that comes back with
that many rows may be missing the rows of the rule that matters, so it is
COULD_NOT_TELL — never CLEAN (LES-011). Hits it did hold are still hits.
"""

from __future__ import annotations

import pytest

from plugins.blackbox.kernel.store import StoreAnswer, StoreClient
from plugins.blackbox.ruleset import live
from plugins.blackbox.ruleset.live import lookup as live_lookup

TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
DP = "urn:defender:p:"
ASSET = "did:dkg:context-graph:0x" + "a" * 40 + "/vm/_verifiable_memory/1"
SCOPE = live.VerifiedScope(store_url="http://127.0.0.1:7878/query", assertion_graphs=frozenset({ASSET}))


@pytest.fixture(autouse=True)
def _fresh_lookup_health(monkeypatch, tmp_path):
    monkeypatch.setattr(live_lookup, "HEALTH", live.LookupHealth(tmp_path / "lookup-state.json"))


def _dependency(subject: str, package: str) -> list[dict[str, str]]:
    triples = [(TYPE, "urn:defender:DependencySignal"), (f"{DP}package", f'"{package}"'),
               (f"{DP}ecosystem", '"npm"'), (f"{DP}version", '"1.0.0"'), (f"{DP}severity", '"critical"')]
    return [{"g": ASSET, "t": subject, "p": p, "o": o} for p, o in triples]


class _Store(StoreClient):
    def __init__(self, rows) -> None:
        super().__init__("http://127.0.0.1:7878/query")
        self.rows = rows

    def select(self, sparql, *, timeout=None):
        return StoreAnswer(list(self.rows))


def test_an_answer_cut_at_the_row_limit_is_not_clean(monkeypatch):
    noise = _dependency("urn:defender:signal:other", "other-pkg")
    monkeypatch.setattr(live_lookup, "ROW_LIMIT", len(noise))
    answer = live.VerifiedLookup(SCOPE, _Store(noise)).dependencies([("npm", "evil-pkg", "1.0.0")])
    assert answer.outcome == live.COULD_NOT_TELL and not answer.known


def test_a_hit_inside_a_cut_answer_is_still_a_hit_and_a_short_answer_is_clean(monkeypatch):
    rows = _dependency("urn:defender:signal:evil", "evil-pkg")
    monkeypatch.setattr(live_lookup, "ROW_LIMIT", len(rows))
    cut = live.VerifiedLookup(SCOPE, _Store(rows)).dependencies([("npm", "evil-pkg", "1.0.0")])
    assert "npm:evil-pkg@1.0.0" in cut.rules
    monkeypatch.setattr(live_lookup, "ROW_LIMIT", len(rows) + 1)
    assert live.VerifiedLookup(SCOPE, _Store([])).dependencies([("npm", "evil-pkg", "1.0.0")]).outcome == live.CLEAN
