"""Which verified-graph corrections a reader honours (trust-and-threat-lab R3).

WHY: a ``CorrectionSignal`` suppress row withdraws the threat it targets from
every tier. Before the legacy pin it was honoured unsigned, so anyone holding
the publishing wallet could un-block real threats. After the pin a correction
carries the same kind of curator envelope as a promoted rule, or it is ignored:

* a correction row in a LEGACY asset (one in the shipped, pin-verified legacy
  list) is honoured as before;
* any other correction counts only with a ``SIGNED_STATEMENT_PRED`` envelope of
  type ``blackbox.correction`` that the manifest in force for its asset accepts
  (``has_quorum``). A correction reduces enforcement, so the break-glass key
  counts toward it (K2, ``statement_order.reduces_enforcement``);
* the subjects come from the SIGNED payload (``targetSubjects``); the row's
  unsigned ``targetSubject`` only locates one of them. A row re-aimed at a
  subject its envelope does not name suppresses nothing (a transplanted
  envelope).

Signed payload of a correction (flat str->str, like every envelope)::

    {"action": "suppress", "targetSubjects": "urn:guardian:threat:a urn:guardian:threat:b"}

``targetSubjects`` is whitespace-separated: subject IRIs never contain
whitespace (``kernel.sparql_text.is_safe_iri``) but may contain commas.

Pattern: Specification — :func:`honoured_target` is the one test "does this
row suppress, and what". Pure: no I/O. Usage::

    suppressed = signed_suppressions(tagged_rows, manifests={graph: manifest_on_its_day},
                                     legacy=frozenset(legacy_graphs))   # legacy=None: no pin in force
    rs = compiler.build_from_rows(tagged_rows, pin=CorrectionPin(manifests, legacy))
"""

from __future__ import annotations

from typing import Any, FrozenSet, Iterable, Mapping, NamedTuple, Optional, Tuple

from ...kernel import constants, signing
from ...kernel.dkg_client import extract_binding
from ...kernel.signing import key_manifest

#: The statement type a post-pin correction's envelope must carry (reduction-only, K2).
CORRECTION_STATEMENT = signing.statement_order.CORRECTION_STATEMENT
#: Signed payload field naming the subjects a correction may suppress.
TARGETS_FIELD = "targetSubjects"
#: Signed payload field naming what the correction does (only suppress is honoured).
ACTION_FIELD = "action"
#: The source tag of verified-graph rows; community rows never correct anything.
PUBLIC_SOURCE = "public"

#: One compiled row with its tier tag, as the refresh cycle hands it to the compiler.
TaggedRow = tuple[Mapping[str, Any], str]


class CorrectionPin(NamedTuple):
    """What decides which corrections count, carried into the compile as one value:
    ``manifests`` (assertion graph -> the key manifest in force for that asset) and
    ``legacy`` (the assertion graphs inside the verified legacy list; None = no
    legacy pin in force, every correction honoured). Unpacks into
    :func:`signed_suppressions`: ``signed_suppressions(rows, *pin)``."""

    manifests: Mapping[str, key_manifest.KeyManifest]
    legacy: Optional[frozenset[str]]


#: Before the legacy pin: every correction is honoured as it always was.
NO_PIN = CorrectionPin(manifests={}, legacy=None)


def signed_suppressions(rows: Iterable[TaggedRow], manifests: Mapping[str, key_manifest.KeyManifest],
                        legacy: Optional[frozenset[str]]) -> frozenset[str]:
    """The threat subjects the PUBLIC suppress corrections in *rows* withdraw.

    *rows* — ``(row, source)`` binding rows; a correction row carries ``rdfType``,
    ``correctionAction``, ``targetSubject``, ``g`` (its assertion graph) and
    ``signedStatement`` (the envelope literal) when the correction lane read them.
    *manifests* — assertion graph -> the key manifest in force for that asset
    (an asset without one cannot pass a signature check). *legacy* — the
    assertion graphs inside the verified legacy list; None = no legacy pin is in
    force yet, so every correction is honoured as before the pin."""
    suppressed = set()
    for row, source in rows:
        if source != PUBLIC_SOURCE:
            continue
        target = honoured_target(row, manifests, legacy)
        if target:
            suppressed.add(target)
    return frozenset(suppressed)


def honoured_target(row: Mapping[str, Any], manifests: Mapping[str, key_manifest.KeyManifest],
                    legacy: Optional[frozenset[str]]) -> str:
    """The subject *row* suppresses, or "" when it is not a suppress correction
    this reader honours (see :func:`signed_suppressions` for the arguments)."""
    if extract_binding(row.get("rdfType")) != constants.DEFENDER_CORRECTION_TYPE_IRI:
        return ""
    action = extract_binding(row.get("correctionAction")).strip().lower()
    target = extract_binding(row.get("targetSubject")).strip()
    if action != constants.DEFENDER_CORRECTION_SUPPRESS or not target:
        return ""
    graph = extract_binding(row.get("g")).strip()
    if legacy is None or graph in legacy:
        return target
    manifest = manifests.get(graph)
    if manifest is None:
        return ""
    return target if target in _signed_targets(extract_binding(row.get("signedStatement")), manifest) else ""


def _signed_targets(text: str, manifest: key_manifest.KeyManifest) -> frozenset[str]:
    """The subjects a quorum-signed suppress correction names; empty for an
    envelope that is missing, malformed, of another type or short of quorum."""
    envelope = signing.from_text(text) if text else None
    if envelope is None or not manifest.has_quorum(envelope, statement_type=CORRECTION_STATEMENT):
        return frozenset()
    if str(envelope.payload.get(ACTION_FIELD, "")).strip().lower() != constants.DEFENDER_CORRECTION_SUPPRESS:
        return frozenset()
    return frozenset(str(envelope.payload.get(TARGETS_FIELD, "")).split())
