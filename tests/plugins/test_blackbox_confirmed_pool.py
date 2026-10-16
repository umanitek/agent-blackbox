"""Community Curation C8 — the confirmed pool and the valve.

The pool is the community authority's hand-off to the verified graph's owner:
threats with a standing, evidenced community confirmation, exported as a bundle
that a machine holding nothing but the community root key verifies offline.

One graph (2026-10-16): there are no community curators for now, so the
community authority is dormant and nothing reaches a pool on a real network.
The pool's code is kept for when curators are added; these tests pin its pure
functions and the bundle checks on rows and bundles built by hand.
"""

from __future__ import annotations

import dataclasses
import json

from _community_rows import GRAPH, NETWORK
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_blackbox_authority import CITED, Side

from plugins.blackbox.community import pool
from plugins.blackbox.community.statements import curator_statements as cs
from plugins.blackbox.curate import node_ui_views
from plugins.blackbox.kernel import signing
from plugins.blackbox.kernel.signing import key_manifest
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind

IP = "ioc:ip:203.0.113.7"


def signing_manifest(manifest, root) -> str:
    """*manifest* signed by *root*, as the text a bundle carries."""
    return key_manifest.sign_manifest(manifest, root).to_text()


def test_the_pool_hands_on_the_statement_as_its_curators_wrote_it_whatever_copies_it_is_given():
    """The pure function, fed raw rows: a rewritten copy alone, and a copy an outsider added a
    signature to, read before or after the genuine one."""
    side = Side(GRAPH)                                                   # its rows are signed on 2026-10-02
    genuine = side.row(Kind.CONFIRMATION, IP, CITED)
    rewritten = {**genuine, "signedStatement": json.dumps(json.loads(genuine["signedStatement"]), indent=1)}
    for _ in range(4):                                                   # several outsider keys: some sort before the curators'
        outsider = Ed25519PrivateKey.generate()                          # gitleaks:allow — a throwaway test key
        padded = {**genuine, "signedStatement": signing.cosign(signing.from_text(genuine["signedStatement"]), outsider).to_text()}
        for rows in ([rewritten], [padded, genuine], [genuine, padded], [padded, rewritten]):
            entries = pool.confirmed_pool(side.manifest, rows, [], graph=GRAPH, today="2026-10-03")
            assert [entry.confirmation for entry in entries] == [genuine["signedStatement"]]
            assert len(entries[0].curators) == 2 and entries[0].reporters == 0 and entries[0].severity == ""


def _by_hand(side, entries):
    """A bundle document for *side* written by hand (what a hostile sender could assemble)."""
    return {"format": "blackbox.confirmed-pool", "version": 1, "environment": NETWORK, "graph": GRAPH,
            "manifests": [side.manifest_row()["signedStatement"]], "entries": entries}


def test_a_genuinely_signed_confirmation_without_evidence_is_not_a_pool_entry():
    side = Side(GRAPH)
    bare = side.row(Kind.CONFIRMATION, IP, {})["signedStatement"]                    # two real curator signatures, no evidence
    entry = {"identifier": IP, "threat": {"category": "ioc", "severity": "", "fields": {}}, "evidence": "",
             "confirmation": bare, "reports": [], "listings": []}
    report = pool.verify_bundle(json.dumps(_by_hand(side, [entry])), {side.root_hex}, environment=NETWORK, graph=GRAPH,
                                today="2026-10-03")
    assert report.error == "" and not report.entries[0].ok and "no evidence reference" in report.entries[0].reason


def test_two_root_signed_manifests_that_disagree_fail_the_whole_bundle():
    side = Side(GRAPH)
    other = dataclasses.replace(side.manifest, curator_keys=tuple(sorted(
        signing.public_key_hex(Ed25519PrivateKey.generate()) for _ in range(3))))    # gitleaks:allow — throwaway test keys
    document = _by_hand(side, [])
    document["manifests"].append(signing_manifest(other, side.root))
    report = pool.verify_bundle(json.dumps(document), {side.root_hex}, environment=NETWORK, graph=GRAPH, today="2026-10-03")
    assert "disagree" in report.error and not report.ok


def test_the_saved_view_lists_exactly_the_confirmation_statements():
    view = node_ui_views.find_view("confirmed-pool")
    assert view in node_ui_views.COMMUNITY_VIEWS
    assert cs.statement_subject(Kind.CONFIRMATION, IP, 1).startswith("urn:guardian:curator:confirmation:")
    assert 'STRSTARTS(STR(?r), "urn:guardian:curator:confirmation:")' in view.sparql and "?signedStatement" in view.sparql
