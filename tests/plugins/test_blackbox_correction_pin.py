"""The production refresh compiles with the correction pin (review 2026-11-26, finding 1; trust-and-threat-lab R3).

The signed-correction check (``live.corrections``) was only ever passed by
tests: the refresh compiled with no pin, so every UNSIGNED ``CorrectionSignal``
withdrew its threat — anyone holding the publishing wallet could un-block a
real threat. The refresh now builds the pin (``live.correction_pin``, module ``live/correction_pinning.py``) from the
trusted manifest's legacy pin and the assets' UAL and day:

* no trusted manifest (today's default — no curator root is pinned for any
  network): no pin is in force, every correction is honoured as before;
* a trusted manifest pinning the shipped legacy list: a correction in a legacy
  asset is honoured unsigned, one in any other asset only with a quorum envelope.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from plugins.blackbox.community.statements.curator_view import CuratorView
from plugins.blackbox.kernel import constants
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.kernel.signing import key_manifest as km
from plugins.blackbox.ruleset import anchors, fetching, refresh_cycle
from plugins.blackbox.ruleset.live import correction_pinning as pin_mod
from plugins.blackbox.ruleset.live import scope as scope_mod

CG = "0x" + "a" * 40 + "/blackbox-threats"
VM = f"did:dkg:context-graph:{CG}/_verifiable_memory/"
LEGACY_ASSET, NEW_ASSET = f"{VM}1", f"{VM}2"
UALS = {LEGACY_ASSET: "did:dkg:base:8453/0x" + "a" * 40 + "/1", NEW_ASSET: "did:dkg:base:8453/0x" + "a" * 40 + "/2"}
EVIL = "urn:defender:threat:evil"


def _manifest(legacy_uals) -> km.KeyManifest:
    return km.KeyManifest(environment="test-net", graph=CG, chain="", root_epoch=1, version=1, threshold=2,
                          promotion_author="0x" + "1" * 40, legacy_assets_hash=km.legacy_assets_hash(legacy_uals),
                          curator_keys=("aa" * 32, "bb" * 32), curator_operators=("A", "B"))


class _Client:
    def status(self, timeout=None):
        return {"storeUrl": "http://127.0.0.1:7878/query", "networkId": "test-net"}

    def query(self, sparql, cg_id, view=None, on_error=None, **kwargs):
        return on_error   # every other read fails open


@pytest.fixture
def refresh(monkeypatch, tmp_path):
    monkeypatch.setattr(constants, "blackbox_home", lambda: tmp_path)
    monkeypatch.setattr(refresh_cycle, "_memory", refresh_cycle._new_memory())
    legacy_list = tmp_path / "legacy_assets.txt"
    legacy_list.write_text(UALS[LEGACY_ASSET] + "\n", encoding="utf-8")
    monkeypatch.setattr(anchors, "LEGACY_ASSETS_FILE", legacy_list)
    monkeypatch.setattr(scope_mod, "read_new_asset_facts", lambda store, wanted, known: dict(known))
    listing = fetching.PartitionListing(frozenset(UALS), tuple(sorted(UALS)))
    monkeypatch.setattr(fetching, "confirmed_partitions", lambda client, cg: listing)
    # The asset's UAL and day, as the node's _meta gives them (no store on this machine).
    monkeypatch.setattr(pin_mod, "tier_assets", lambda store, facts, legacy: {
        graph: replace(fact, ual=UALS[graph], day="2026-11-01") for graph, fact in facts.items()})

    def run(view: CuratorView, correction_asset: str):
        rows = [{"threat": "urn:defender:correction:1", "rdfType": constants.DEFENDER_CORRECTION_TYPE_IRI,
                 "correctionAction": constants.DEFENDER_CORRECTION_SUPPRESS, "targetSubject": EVIL,
                 "g": correction_asset}]
        monkeypatch.setattr(refresh_cycle.fetching, "fetch_tier", lambda client, cg, view, **kw: rows)
        monkeypatch.setattr(refresh_cycle.curator_tier.community, "read_curator_view", lambda client, config: view)
        return refresh_cycle.refresh(BlackboxConfig(context_graph_id=CG), _Client(), force_query=True)

    return run


def test_an_unsigned_correction_outside_the_legacy_list_suppresses_nothing(refresh):
    rs = refresh(CuratorView(manifest=_manifest([UALS[LEGACY_ASSET]])), NEW_ASSET)
    assert EVIL not in rs.suppressed_subjects


def test_an_unsigned_correction_in_a_legacy_asset_is_honoured(refresh):
    rs = refresh(CuratorView(manifest=_manifest([UALS[LEGACY_ASSET]])), LEGACY_ASSET)
    assert rs.suppressed_subjects == {EVIL}


def test_without_a_trusted_manifest_no_pin_is_in_force_as_today(refresh):
    """What the live graph compiles to today: no curator root is pinned for any network,
    so no manifest is trusted and its correction keeps being honoured."""
    assert refresh(CuratorView(), NEW_ASSET).suppressed_subjects == {EVIL}


def test_a_list_that_does_not_match_the_pin_honours_no_unsigned_correction(refresh):
    rs = refresh(CuratorView(manifest=_manifest([UALS[LEGACY_ASSET], "did:dkg:base:8453/0xother/9"])), LEGACY_ASSET)
    assert rs.suppressed_subjects == frozenset()
