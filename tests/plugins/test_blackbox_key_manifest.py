"""Refine R7a — the curator signing envelope and the key-manifest format.

The plan's tests: a sandbox key is rejected on mainnet; replayed
lower-sequence statements lose to terminal ones; the legacy corpus keeps
serving. Plus the format's own guarantees: two signatures over the same
domain-separated bytes, 2-of-3 quorum, manifest order by (root epoch,
version), and a manifest signed by anything but the root is not trusted.

K2 (trust-and-threat lab): a quorum counts one key per listed operator,
the threshold sits inside the operator table, a narrowing list removes
exactly one key and loosens nothing, and the break-glass key counts on
corrections.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from plugins.blackbox.kernel import signing
from plugins.blackbox.kernel.signing import key_manifest as km
from plugins.blackbox.kernel.signing import statement_order as order
from plugins.blackbox.kernel.signing.trust_anchors import RootPins

MAINNET, SANDBOX = "otp:2043", "sim-sandbox"
VM_GRAPH = "0x37b1Fdfd/agent-blackbox-vm"
CHAIN = "base:8453"
PROMOTION = order.CuratorStatement.PROMOTION.value
LEGACY = ["did:dkg:base:8453/0xabc/1", "did:dkg:base:8453/0xabc/2"]


def _keys(n):
    return [Ed25519PrivateKey.generate() for _ in range(n)]


def _hex(keys):
    return tuple(sorted(signing.public_key_hex(k) for k in keys))


def _manifest(curators, *, environment=MAINNET, root_epoch=1, version=1, threshold=2, operators=None, **over):
    """A manifest over *curators*; each key gets its own operator unless
    *operators* (parallel to *curators*, in the same order) says otherwise."""
    operators = operators or [f"operator-{i}" for i in range(len(curators))]
    fields = dict(environment=environment, graph=VM_GRAPH, chain=CHAIN, root_epoch=root_epoch, version=version,
                  threshold=threshold, promotion_author="0x1111111111111111111111111111111111111111",
                  legacy_assets_hash=km.legacy_assets_hash(LEGACY),
                  **km.roster({signing.public_key_hex(k): o for k, o in zip(curators, operators)}))
    return km.KeyManifest(**{**fields, **over})


def _statement(signers, *, environment=MAINNET, root_epoch=1, sequence=1, statement_type=PROMOTION):
    first, *rest = signers
    envelope = signing.sign(first, statement_type=statement_type, environment=environment, graph=VM_GRAPH,
                            payload={"identifier": "dep:npm:evil@1.0.0"}, chain=CHAIN,
                            root_epoch=root_epoch, sequence=sequence)
    for key in rest:
        envelope = signing.cosign(envelope, key)
    return envelope


# ------------------------------------------------------------------ envelope


def test_two_signatures_cover_the_same_domain_separated_bytes():
    a, b = _keys(2)
    statement = signing.from_text(_statement([a, b]).to_text())
    assert signing.verified_signers(statement, statement_type=PROMOTION, environment=MAINNET, graph=VM_GRAPH,
                                    chain=CHAIN, root_epoch=1) == frozenset(_hex([a, b]))
    for field, value in (("chain", "base:84532"), ("root_epoch", 2), ("sequence", 99)):
        moved = signing.SignedEnvelope(**{**statement.__dict__, field: value})
        assert signing.verified_signers(moved, statement_type=PROMOTION, environment=MAINNET,
                                        graph=VM_GRAPH) == frozenset()


def test_a_key_cannot_sign_twice_and_reporter_verify_refuses_cosigned_statements():
    a, b = _keys(2)
    with pytest.raises(ValueError):
        signing.cosign(_statement([a]), a)
    assert signing.verify(_statement([a, b]), statement_type=PROMOTION, environment=MAINNET, graph=VM_GRAPH) is None


# ------------------------------------------------------------------ quorum + environments


def test_two_of_three_curator_keys_make_a_quorum_one_does_not():
    a, b, c = _keys(3)
    manifest = _manifest([a, b, c])
    assert manifest.has_quorum(_statement([a, c]), statement_type=PROMOTION)
    assert not manifest.has_quorum(_statement([b]), statement_type=PROMOTION)


def test_a_sandbox_key_is_rejected_on_mainnet():
    """The plan's test (KI-143): per-environment keys + the environment inside the signature."""
    main_a, main_b, main_c, sand_a, sand_b = _keys(5)
    mainnet = _manifest([main_a, main_b, main_c])
    # Sandbox keys signing a statement FOR mainnet: not mainnet's keys.
    assert not mainnet.has_quorum(_statement([sand_a, sand_b]), statement_type=PROMOTION)
    # Mainnet keys' signatures made in the sandbox cannot be replayed on mainnet.
    assert not mainnet.has_quorum(_statement([main_a, main_b], environment=SANDBOX), statement_type=PROMOTION)
    assert mainnet.has_quorum(_statement([main_a, main_b]), statement_type=PROMOTION)


def test_a_statement_from_another_root_epoch_does_not_count():
    a, b, c = _keys(3)
    assert not _manifest([a, b, c], root_epoch=2).has_quorum(_statement([a, b], root_epoch=1),
                                                            statement_type=PROMOTION)


# ------------------------------------------------------------------ manifest format


def test_a_root_signed_manifest_round_trips_and_nothing_else_is_trusted():
    root, impostor, *curators = _keys(5)
    manifest = _manifest(curators)
    envelope = signing.from_text(km.sign_manifest(manifest, root).to_text())
    roots = RootPins.unbound([signing.public_key_hex(root)])
    assert km.verify_manifest(envelope, environment=MAINNET, graph=VM_GRAPH, roots=roots) == km.ManifestVerdict(manifest)
    assert km.verify_manifest(km.sign_manifest(manifest, impostor), environment=MAINNET, graph=VM_GRAPH,
                              roots=roots) is None
    assert km.verify_manifest(envelope, environment=SANDBOX, graph=VM_GRAPH, roots=roots) is None
    forged = signing.SignedEnvelope(**{**envelope.__dict__, "payload": {**envelope.payload, "threshold": "1"}})
    assert km.verify_manifest(forged, environment=MAINNET, graph=VM_GRAPH, roots=roots) is None


def test_manifests_order_by_root_epoch_then_version():
    curators = _keys(3)
    old_root_max = _manifest(curators, root_epoch=1, version=2**31)
    rotated = _manifest(curators, root_epoch=2, version=1)
    assert km.newest([rotated, old_root_max]) == rotated
    assert km.newest([_manifest(curators, version=3), _manifest(curators, version=4)]).version == 4


@pytest.mark.parametrize("change", [
    {"threshold": 1},                                  # one key is never enough (KI-134)
    {"threshold": 4},                                  # more than the keys listed
    {"curator_keys": ("ab" * 32, "ab" * 32, "cd" * 32)},   # duplicate keys
    {"curator_keys": ("not-a-key",), "curator_operators": ("acme",)},
    {"curator_operators": ("acme", "globex")},         # one operator per key
    {"curator_operators": ("acme", "", "globex")},
    {"curator_operators": ("acme", "a,b", "globex")},  # the payload joins operators with commas
    {"curator_operators": ("acme", " globex", "initech")},
    {"curator_operators": ("acme", "x" * (km.MAX_OPERATOR_LENGTH + 1), "globex")},
    {"version": 0},
    {"legacy_assets_hash": "not-a-hash"},
    {"promotion_author": ""},
])
def test_an_invalid_manifest_cannot_be_built(change):
    valid = _manifest(_keys(3)).__dict__
    with pytest.raises(km.KeyManifestError):
        km.KeyManifest(**{**valid, **change})


# ------------------------------------------------------------------ ordering: replays lose


def test_replayed_lower_sequence_statements_lose_to_terminal_ones():
    """The plan's test: an old promotion re-shared after a revocation must not resurrect the rule."""
    threat = "dep:npm:evil@1.0.0"
    promotion = order.OrderedStatement(threat, order.CuratorStatement.PROMOTION, 3)
    revocation = order.OrderedStatement(threat, order.CuratorStatement.REVOCATION, 5)
    for arrival in ([promotion, revocation], [revocation, promotion]):
        assert order.current_by_threat(arrival)[threat] == revocation
    repromotion = order.OrderedStatement(threat, order.CuratorStatement.PROMOTION, 7)
    assert order.current_by_threat([revocation, promotion, repromotion])[threat] == repromotion
    tie = order.OrderedStatement(threat, order.CuratorStatement.PROMOTION, 5)
    assert order.current_by_threat([tie, revocation])[threat] == revocation   # safety is asymmetric


def test_statement_types_know_whether_they_raise_or_end_enforcement():
    kinds = order.CuratorStatement
    assert {k for k in kinds if k.raises_enforcement} == {kinds.PROMOTION, kinds.PAUSE, kinds.CONFIRMATION,
                                                         kinds.COUNTED_AUTHORS, kinds.BACKLOG,
                                                         kinds.ATTESTATION}   # R3-attest: an attested stage can raise to flag
    assert {k for k in kinds if k.terminal} == {kinds.REVOCATION, kinds.REJECTION}
    assert {k for k in kinds if not k.needs_quorum} == {kinds.IN_REVIEW, kinds.DEFERRAL, kinds.DEFERRAL_LAPSED, kinds.AWAY,
                                                         kinds.HEARTBEAT}   # R10b: a key beats for itself


# ------------------------------------------------------------------ legacy corpus


def test_the_legacy_corpus_is_grandfathered_by_its_content_hash():
    """KI-118: requiring signatures must never un-serve the existing corpus.
    The first manifest pins EXACTLY the legacy asset set: order and repeats
    don't matter, but an asset added afterwards is not legacy."""
    manifest = _manifest(_keys(3))
    assert manifest.grandfathers(list(reversed(LEGACY)) + LEGACY[:1])
    assert not manifest.grandfathers(LEGACY + ["did:dkg:base:8453/0xabc/3"])


def test_the_canonical_signed_bytes_are_pinned_to_the_envelope_version():
    """Every reader on every machine must build the SAME bytes. If this test
    fails, the encoding changed: bump ENVELOPE_VERSION (old signatures must
    then fail, not silently verify differently) and re-pin both values."""
    import hashlib
    from plugins.blackbox.kernel.signing import envelope
    fixed = envelope.SignedEnvelope(statement_type="blackbox.promotion", environment="otp:2043", graph="g",
                                    schema_version=1, payload={"identifier": "dep:npm:evil@1.0.0"}, signatures=(),
                                    chain="base:8453", root_epoch=1, sequence=7)
    assert envelope.ENVELOPE_VERSION == 2
    assert hashlib.sha256(envelope._signed_message(fixed)).hexdigest() == (
        "acea28b35f71bf06324e291744cd48470618d62744079518467144bca619fd62")


# ------------------------------------------------------------------ K2: operators, threshold table


def test_five_keys_run_by_two_operators_cannot_carry_a_threshold_of_three():
    """a threshold above the distinct operators could never be met — curation would halt."""
    curators = _keys(5)
    two_operators = ["umanitek", "umanitek", "umanitek", "umoja-ark", "umoja-ark"]
    with pytest.raises(km.KeyManifestError, match="outside the table"):
        _manifest(curators, threshold=3, operators=two_operators)
    assert _manifest(curators, threshold=2, operators=two_operators).threshold == 2


@pytest.mark.parametrize("operators,lowest,highest", [(2, 2, 2), (3, 2, 3), (4, 2, 4), (5, 3, 5), (6, 3, 6),
                                                      (7, 4, 7), (8, 4, 8)])
def test_the_threshold_table_by_distinct_operators(operators, lowest, highest):
    curators = _keys(operators)
    for threshold in range(1, operators + 2):
        if lowest <= threshold <= highest:
            assert _manifest(curators, threshold=threshold).threshold == threshold
        else:
            with pytest.raises(km.KeyManifestError):
                _manifest(curators, threshold=threshold)


def test_one_operator_alone_can_never_carry_a_list():
    with pytest.raises(km.KeyManifestError, match="1 distinct operator"):
        _manifest(_keys(3), operators=["acme", "acme", "acme"])


def test_the_break_glass_operator_never_counts_toward_the_threshold_bound():
    a, b, glass = _keys(3)
    glass_hex = signing.public_key_hex(glass)
    with pytest.raises(km.KeyManifestError, match="1 distinct operator"):   # only one operator can sign a raise
        _manifest([a, b, glass], operators=["acme", "acme", "vault"], break_glass_key=glass_hex)
    assert _manifest([a, b, glass], break_glass_key=glass_hex).break_glass_key == glass_hex


def test_two_keys_of_one_operator_never_make_a_quorum_of_two():
    a, a2, b = _keys(3)
    manifest = _manifest([a, a2, b], operators=["acme", "acme", "globex"])
    assert not manifest.has_quorum(_statement([a, a2]), statement_type=PROMOTION)
    assert manifest.curator_signers(_statement([a, a2]), statement_type=PROMOTION) == {min(_hex([a, a2]))}   # deterministic
    assert manifest.has_quorum(_statement([a2, b]), statement_type=PROMOTION)
    assert len(manifest.curator_signers(_statement([a, a2, b]), statement_type=PROMOTION)) == 2


@pytest.mark.parametrize("reducing", ["blackbox.revocation", "blackbox.rejection", "blackbox.correction"])
def test_the_break_glass_key_counts_on_reductions_including_corrections(reducing):
    honest, dropped, glass = _keys(3)
    manifest = _manifest([honest, dropped, glass], break_glass_key=signing.public_key_hex(glass))
    assert manifest.has_quorum(_statement([honest, glass], statement_type=reducing), statement_type=reducing)
    assert not manifest.has_quorum(_statement([honest, glass]), statement_type=PROMOTION)


# ------------------------------------------------------------------ K2: narrowing lists


def test_a_list_that_removes_one_key_narrows_its_predecessor():
    curators = _keys(4)
    previous = _manifest(curators)
    assert _manifest(curators[:3], version=2).narrows(previous)
    assert _manifest(curators[:3], version=2, threshold=3).narrows(previous)   # raising the threshold also narrows


def test_a_list_that_loosens_anything_does_not_narrow():
    curators = _keys(4)
    previous = _manifest(curators)
    kept = curators[:3]
    loosened = {
        "two keys removed": _manifest(curators[:2], version=2),
        "nothing removed": _manifest(curators, version=2),
        "a key swapped in": _manifest(kept[:2] + _keys(1), version=2),
        "a changed chain": _manifest(kept, version=2, chain="base:84532"),
        "a changed legacy hash": _manifest(kept, version=2, legacy_assets_hash=km.legacy_assets_hash(LEGACY + ["did:x"])),
        "a changed min_reader_version": _manifest(kept, version=2, min_reader_version="1.2.0"),
        "a new break-glass key": _manifest(kept, version=2, break_glass_key=signing.public_key_hex(kept[0])),
    }
    for reason, manifest in loosened.items():
        assert not manifest.narrows(previous), reason
    assert not _manifest(kept, version=2).narrows(_manifest(curators, threshold=3)), "a lowered threshold"


def test_a_relabelled_operator_is_not_a_narrowing():
    """Relabelling could split one organisation's keys into two quorum votes."""
    curators = _keys(4)
    previous = _manifest(curators, operators=["acme", "acme", "globex", "initech"])
    relabelled = _manifest(curators[:3], version=2, operators=["acme", "umbrella", "globex"])
    assert not relabelled.narrows(previous)
    assert _manifest(curators[1:], version=2, operators=["acme", "globex", "initech"]).narrows(previous)


# ------------------------------------------------------------------ K2: parsing


def test_an_old_manifest_without_operators_is_rejected_by_parse():
    root, *curators = _keys(4)
    payload = _manifest(curators).to_payload()
    assert sorted(km.parse_manifest(payload).curator_operators) == ["operator-0", "operator-1", "operator-2"]
    old = {k: v for k, v in payload.items() if k != "curatorOperators"}
    with pytest.raises(km.KeyManifestError, match="no curatorOperators"):
        km.parse_manifest(old)
    envelope = signing.sign(root, statement_type=km.KEY_MANIFEST_STATEMENT, environment=MAINNET, graph=VM_GRAPH,
                            payload=old, chain=CHAIN, root_epoch=1, sequence=1)
    roots = RootPins.unbound([signing.public_key_hex(root)])
    assert km.verify_manifest(envelope, environment=MAINNET, graph=VM_GRAPH, roots=roots) is None   # never raises


def test_operators_round_trip_through_the_signed_payload():
    root, *curators = _keys(4)
    manifest = _manifest(curators, operators=["Umanitek", "Umoja Ark", "Umanitek"])
    assert km.parse_manifest(manifest.to_payload()) == manifest
    roots = RootPins.unbound([signing.public_key_hex(root)])
    verdict = km.verify_manifest(signing.from_text(km.sign_manifest(manifest, root).to_text()),
                                 environment=MAINNET, graph=VM_GRAPH, roots=roots)
    assert verdict is not None and verdict.manifest.curator_operators == manifest.curator_operators


@pytest.mark.parametrize("change,message", [
    ({"threshold": "two"}, "must be integers"),
    ({"rootEpoch": ""}, "must be integers"),
    ({"graph": None}, "missing graph"),
    ({"promotionAuthor": None, "legacyAssetsHash": None}, "missing promotionAuthor, legacyAssetsHash"),
])
def test_a_malformed_payload_is_a_clear_parse_error_and_never_a_trusted_manifest(change, message):
    root, *curators = _keys(4)
    payload = {**_manifest(curators).to_payload(), **change}
    payload = {k: v for k, v in payload.items() if v is not None}
    with pytest.raises(km.KeyManifestError, match=message):
        km.parse_manifest(payload)
    envelope = signing.sign(root, statement_type=km.KEY_MANIFEST_STATEMENT, environment=MAINNET, graph=VM_GRAPH,
                            payload=payload, chain=CHAIN, root_epoch=1, sequence=1)
    roots = RootPins.unbound([signing.public_key_hex(root)])
    assert km.verify_manifest(envelope, environment=MAINNET, graph=VM_GRAPH, roots=roots) is None


# --- the freeze / ceiling / sticky rules, shared by key manifests and graph migrations ----------

def _items(*rows):
    from plugins.blackbox.community.trust.ordered_policy import Ordered

    return [Ordered(order, content, freeze_only) for order, content, freeze_only in rows]


def test_a_conflict_is_two_contents_at_one_order_or_a_freeze_only_statement():
    from plugins.blackbox.community.trust import ordered_policy as policy

    items = _items(((1, 1), "a", False), ((1, 2), "b", False), ((1, 2), "c", False), ((1, 4), "d", True))
    assert policy.conflict_orders(items) == {(1, 2), (1, 4)}


def test_a_conflict_above_the_sticky_order_freezes_it_and_everything_above():
    from plugins.blackbox.community.trust import ordered_policy as policy

    items = _items(((1, 1), "a", False), ((1, 2), "b", False), ((1, 2), "c", False), ((1, 3), "d", False))
    conflicts = policy.conflict_orders(items)
    allowed = [item.order for item in items if policy.usable(item, conflicts=conflicts, sticky_order=(1, 1), sticky_hash="a")]
    assert allowed == [(1, 1)] and policy.freeze_order(items, (1, 1)) == (1, 2)
    assert policy.ignored_conflict(items, (1, 1)) is False


def test_a_conflict_at_or_below_the_sticky_order_never_moves_the_reader_but_is_reported():
    from plugins.blackbox.community.trust import ordered_policy as policy

    items = _items(((1, 2), "kept", False), ((1, 2), "forged", False), ((1, 3), "next", False))
    conflicts = policy.conflict_orders(items)
    allowed = [item.content for item in items
               if policy.usable(item, conflicts=conflicts, sticky_order=(1, 2), sticky_hash="kept")]
    assert allowed == ["kept", "next"] and policy.freeze_order(items, (1, 2)) is None
    assert policy.ignored_conflict(items, (1, 2)) is True
    # without the sticky content's hash an ambiguous sticky order is skipped, never guessed
    assert [i.content for i in items if policy.usable(i, conflicts=conflicts, sticky_order=(1, 2), sticky_hash="")] == ["next"]
