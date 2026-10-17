"""What a promotion names — ONE community report — and the member-asset promotion statement.

Blackbox runs on one context graph. Edge nodes share signed reports into the
verified graph's shared memory (its sub-graph ``reports``); the curators
review one and promote it. Whatever way the promotion is published
(``curate.publishing.strategies``), its two-key payload names the report it
was made from — that report is its provenance, never a random id:

* ``identifier`` — the threat: the report's own signed identifier;
* ``report`` — the report's subject (``urn:guardian:report:<reporter>:<hash>``,
  the same in every keep-alive copy of the report);
* ``reportDigest`` — :func:`.envelope.content_id` of the report's signed
  envelope: exactly what the report says, whichever copy holds it;
* ``reporterKey`` — the reporter key that signed it. A digest names what was
  said, not who said it: any key can sign the same words (naming the
  reporter's address, which is display only), so the payload names the key
  too — the reporter's pseudonymous identity the promotion makes permanent.

:func:`reference` reads those four from either payload (:class:`ReportRef`);
:func:`is_the_report` says whether a signed report is exactly the one named.

The MEMBER-ASSET statement (:class:`Promotion`, :func:`promotion_payload`,
:func:`parse`) is a pointer: those four plus ``severity`` (the curators'
severity for the verified rule) and ``day`` (the UTC day it was signed; the
key manifest in force on that day judges it, as the manifest on its day
judges a promoted row). It is published beside the reporter's own asset,
promoted from shared memory to Verified Memory, and a reader serves the
report as a verified rule only when a statement signed by a quorum of the
verified authority's curator keys names it and the report reads back from
Verified Memory with that digest, signed by that key
(``ruleset/live/promoted.py``).

On the graph such a statement is a ``g:CuratorStatement`` subject
(:func:`statement_subject`, a new asset per statement) with
``g:promotesReport`` (the report, as an IRI) and ``g:signedStatement``. It
carries NO ``g:identifier`` triple on purpose: the verified reader's
identifier lane would compile the statement row itself into a rule, and the
curator view would read it as a verdict.

Where a node holds a report — shared or verified, in which asset — is read
from the node's own store by subject (:func:`report_copies_sparql`,
:func:`report_copy`): every curator key re-reads the report it signs for, the
curator publishes the asset that holds it, and a reader serves only a copy in
Verified Memory. The curator publishes a shared copy by its asset name, which
the node's record of the author's seal carries (:func:`sealed_names_sparql`,
:func:`sealed_name`).

Pattern: Value Objects (:class:`ReportRef`, :class:`Promotion`,
:class:`ReportCopy`) with paired build / parse functions.

Usage::

    from ..kernel.signing import promotion_statement as statement
    ref = statement.reference(envelope.payload)     # the report a promotion names (None: names none)
    payload = statement.promotion_payload("dep:npm:x@1.0.0", report=subject, report_digest=digest,
                                          reporter_key=key, severity="critical", day="2026-10-16")
    quads = statement.statement_quads(envelope)     # the curators' co-signed member-asset envelope
    found = statement.parse(envelope)               # None unless a well-formed member-asset promotion
    rows = store.select(statement.report_copies_sparql(graph, [ref.report], 64)).rows
    copies = [copy for row in rows if (copy := statement.report_copy(graph, row))]
    rows = store.select(statement.sealed_names_sparql(graph, copies, 64)).rows
    names = {copy.asset_id: name for copy in copies for row in rows if (name := statement.sealed_name(graph, copy, row))}
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Mapping, Optional

from .. import constants, rdf_terms, sparql_text, threat_ids
from .envelope import SignedEnvelope, content_id, from_text, verify
from .statement_order import CuratorStatement

PROMOTION_STATEMENT = CuratorStatement.PROMOTION.value
#: The statement type a report is signed as (``community.report_signer.REPORT_STATEMENT``).
REPORT_STATEMENT = "blackbox.report"
#: The statement → the report it promotes (an IRI, so a graph browser follows it).
PROMOTES_REPORT_PRED = f"{constants.BLACKBOX_ONTOLOGY}promotesReport"
#: The threat types a report can be promoted as: the ones whose report carries the
#: whole rule. Never an injection (a report carries the hash of the pattern, not the
#: pattern) or an escalation shape (no verified escalation rule is promoted).
PROMOTABLE_PREFIXES = ("dep:", "ioc:", "skill:", "fileaccess:")
#: The member-asset payload's closed key set.
PAYLOAD_KEYS = frozenset({"identifier", "report", "reportDigest", "reporterKey", "severity", "day"})

_DIGEST = _KEY = re.compile(r"[0-9a-f]{64}")
_DAY = re.compile(r"\d{4}-\d{2}-\d{2}")
_REPORT_SUBJECT = re.compile(r"urn:guardian:report:(0x[0-9a-f]{40}):[0-9a-f]{16}")
_MAX_IDENTIFIER_CHARS = 512


@dataclass(frozen=True)
class ReportRef:
    """The ONE report a promotion names (UNVERIFIED until the caller checked
    the envelope's signatures and re-read the report)."""

    identifier: str
    report: str
    report_digest: str
    reporter_key: str

    @property
    def reporter(self) -> str:
        """The reporter's agent address, as the report subject names it."""
        match = _REPORT_SUBJECT.fullmatch(self.report)
        return match.group(1) if match else ""

    def fields(self) -> dict[str, str]:
        """The payload keys that name this report (:func:`reference` reads them back)."""
        return {"identifier": self.identifier, "report": self.report, "reportDigest": self.report_digest,
                "reporterKey": self.reporter_key}


@dataclass(frozen=True)
class Promotion(ReportRef):
    """One member-asset promotion as its signed payload states it.
    ``sequence`` — the envelope's per-identifier sequence number."""

    severity: str
    day: str
    sequence: int


def promotion_payload(identifier: str, *, report: str, report_digest: str, reporter_key: str, severity: str,
                      day: str) -> dict[str, str]:
    """The flat payload the curators sign for a member-asset promotion. Raises
    ``ValueError`` when it is not a well-formed one (see :func:`parse`)."""
    payload = {"identifier": identifier, "report": report, "reportDigest": report_digest,
               "reporterKey": reporter_key, "severity": severity, "day": day}
    why = _refusal(payload)
    if why:
        raise ValueError(f"not a valid promotion: {why}")
    return payload


def parse(envelope: Optional[SignedEnvelope]) -> Optional[Promotion]:
    """The member-asset promotion *envelope* states, or None for anything that
    is not one: another statement type, a payload outside the closed key set,
    no promotable report named (:func:`reference`), a malformed severity or
    day. Signatures are NOT checked here."""
    if envelope is None or envelope.statement_type != PROMOTION_STATEMENT or _refusal(envelope.payload):
        return None
    payload = envelope.payload
    return Promotion(identifier=payload["identifier"], report=payload["report"], report_digest=payload["reportDigest"],
                     reporter_key=payload["reporterKey"], severity=payload["severity"], day=payload["day"],
                     sequence=envelope.sequence)


def reference(payload: Mapping[str, str]) -> Optional[ReportRef]:
    """The report a promotion *payload* — of either shape — names; None when
    it names none: an identifier of a type no report is promoted as, a report
    subject that is not a reporter's own subject for that identifier, a
    malformed digest or reporter key."""
    if reference_refusal(payload):
        return None
    return ReportRef(identifier=payload["identifier"], report=payload["report"],
                     report_digest=payload["reportDigest"], reporter_key=payload["reporterKey"])


def reference_refusal(payload: Mapping[str, str]) -> str:
    """Why *payload* names no promotable report ("" when it names one)."""
    identifier, report = str(payload.get("identifier") or ""), str(payload.get("report") or "")
    if not identifier.startswith(PROMOTABLE_PREFIXES) or len(identifier) > _MAX_IDENTIFIER_CHARS:
        return f"a report is promoted as {PROMOTABLE_PREFIXES} only"
    match = _REPORT_SUBJECT.fullmatch(report)
    if match is None or threat_ids.report_uri(identifier, match.group(1)) != report:
        return "the report is not a reporter's own report of this identifier"
    if not _DIGEST.fullmatch(str(payload.get("reportDigest") or "")):
        return "the report digest is 64 lower-case hex characters"
    if not _KEY.fullmatch(str(payload.get("reporterKey") or "")):
        return "the reporter key is 64 lower-case hex characters"
    return ""


def _refusal(payload: Mapping[str, str]) -> str:
    """Why *payload* is not a well-formed member-asset promotion ("" when it is)."""
    if set(payload) != PAYLOAD_KEYS:
        return f"the payload holds exactly {sorted(PAYLOAD_KEYS)}"
    why = reference_refusal(payload)
    if why:
        return why
    if payload["severity"] not in constants.SEVERITY_ORDER:
        return f"severity is one of {constants.SEVERITY_ORDER}"
    if not _DAY.fullmatch(payload["day"]):
        return "the day is YYYY-MM-DD"
    return ""


def statement_subject(identifier: str, sequence: int) -> str:
    """``urn:guardian:curator:promotion:<identifier hash>:<sequence>`` — the
    curator-statement subject scheme: a new asset per statement."""
    return f"{_statement_prefix(identifier)}{sequence}"


def _statement_prefix(identifier: str) -> str:
    return f"urn:guardian:curator:promotion:{threat_ids.stable_hash(identifier, 24)}:"


def statement_quads(envelope: SignedEnvelope) -> list[rdf_terms.Quad]:
    """The graph quads of a signed promotion statement. Raises ``ValueError``
    for an envelope that is not a signed, well-formed promotion."""
    promotion = parse(envelope)
    if promotion is None or not envelope.signatures:
        raise ValueError(f"a promotion statement needs a signed, well-formed {PROMOTION_STATEMENT} envelope")
    subject = statement_subject(promotion.identifier, promotion.sequence)
    quads = [
        rdf_terms.make_quad(subject, constants.RDF_TYPE, rdf_terms.iri(constants.CURATOR_STATEMENT_TYPE_IRI)),
        rdf_terms.make_quad(subject, PROMOTES_REPORT_PRED, rdf_terms.iri(promotion.report)),
        rdf_terms.make_quad(subject, constants.SIGNED_STATEMENT_PRED, rdf_terms.literal(envelope.to_text())),
    ]
    rdf_terms.assert_quads_literal_size(quads, label="promotion statement")
    return quads


def statements_sparql(after: str, identifier: str = "") -> str:
    """One page of promotion statements after the subject cursor *after*
    (``sparql_text.page_rows`` pages it) — only those about *identifier* when
    given: ``?r`` the statement, ``?report``, ``?signedStatement``."""
    cursor = f"FILTER(STR(?r) > {sparql_text.sparql_string_literal(after)})" if after else ""
    about = f"FILTER(STRSTARTS(STR(?r), {sparql_text.sparql_string_literal(_statement_prefix(identifier))}))" if identifier else ""
    return (f"SELECT ?r ?report ?signedStatement WHERE {{ "
            f"?r a <{constants.CURATOR_STATEMENT_TYPE_IRI}> ; <{PROMOTES_REPORT_PRED}> ?report ; "
            f"<{constants.SIGNED_STATEMENT_PRED}> ?signedStatement . {about} {cursor} }} "
            f"ORDER BY STR(?r) LIMIT {sparql_text.STATEMENT_PAGE_SIZE}")


# ---------------------------------------------------------------- where a node holds a report


@dataclass(frozen=True)
class ReportCopy:
    """One copy of a report in a node's store: ``text`` — its signed envelope;
    the asset graph it sits in — ``layer`` (``_shared_memory`` or
    ``_verifiable_memory``), ``sub_graph`` ("" = the root), and the asset's
    ``author`` (agent address) and per-author ``number``."""

    subject: str
    text: str
    layer: str
    sub_graph: str
    author: str
    number: str

    @property
    def verified(self) -> bool:
        return self.layer == VERIFIED_LAYER

    @property
    def asset_id(self) -> str:
        """The node's compact identifier of the asset holding the copy (``0x<author>:<number>``)."""
        return f"{self.author}:{self.number}"


SHARED_LAYER, VERIFIED_LAYER = "_shared_memory", "_verifiable_memory"
#: A per-asset graph under a context graph's data IRI (OT-RFC-46):
#: ``[<sub-graph>/]<layer>/<author>/<number>``.
_ASSET_GRAPH = re.compile(r"(?:([A-Za-z0-9._-]+)/)?(_shared_memory|_verifiable_memory)/(0x[0-9a-fA-F]{40})/(\d+)")


def report_copies_sparql(graph: str, subjects: Iterable[str], limit: int, *, verified_only: bool = False) -> str:
    """Every copy of the reports *subjects* in *graph*'s per-asset graphs, read
    from a node's own store — only in assets their own reporter authored (no
    other node can fill a report's subject with copies) and, with
    *verified_only*, only in Verified Memory: ``?g`` (the asset graph), ``?r``,
    ``?signedStatement``. VALUES-bound subjects, so an index lookup; LIMITed.
    "" when nothing is safe to embed."""
    pairs = " ".join(f"(<{subject}> {sparql_text.sparql_string_literal('/' + match.group(1) + '/')})"
                     for subject in sorted(set(subjects)) if (match := _REPORT_SUBJECT.fullmatch(subject)))
    prefix = _data_prefix(graph)
    if not pairs or not prefix:
        return ""
    verified = sparql_text.sparql_string_literal(f"/{VERIFIED_LAYER}/")
    layer = f" FILTER(CONTAINS(STR(?g), {verified}))" if verified_only else ""
    return (f"SELECT ?g ?r ?signedStatement WHERE {{ VALUES (?r ?author) {{ {pairs} }} "
            f"GRAPH ?g {{ ?r <{constants.SIGNED_STATEMENT_PRED}> ?signedStatement }} "
            f"FILTER(STRSTARTS(STR(?g), {sparql_text.sparql_string_literal(prefix)})) "
            f"FILTER(CONTAINS(LCASE(STR(?g)), ?author)){layer} }} LIMIT {int(limit)}")


def report_copy(graph: str, row: Mapping[str, object]) -> Optional[ReportCopy]:
    """The :class:`ReportCopy` one :func:`report_copies_sparql` row describes;
    None for a row outside *graph*'s per-asset graphs or in an asset another
    node than the report's own reporter authored."""
    asset = sparql_text.extract_binding(row.get("g"))
    prefix = _data_prefix(graph)
    match = _ASSET_GRAPH.fullmatch(asset[len(prefix):]) if prefix and asset.startswith(prefix) else None
    subject = _REPORT_SUBJECT.fullmatch(sparql_text.extract_binding(row.get("r")))
    if match is None or subject is None or match.group(3).lower() != subject.group(1):
        return None
    sub_graph, layer, author, number = match.groups()
    return ReportCopy(subject=subject.group(0), text=sparql_text.extract_binding(row.get("signedStatement")),
                      layer=layer, sub_graph=sub_graph or "", author=author.lower(), number=number)


def is_the_report(ref: ReportRef, text: str) -> bool:
    """True when the signed report *text* is exactly the one *ref* names: the
    same content (digest) and a valid signature by the named reporter key,
    for the network and graph the text itself states. The caller still checks
    the network and graph are its own."""
    envelope = from_text(text)
    if envelope is None or content_id(envelope) != ref.report_digest:
        return False
    signer = verify(envelope, statement_type=REPORT_STATEMENT, environment=envelope.environment, graph=envelope.graph)
    return signer == ref.reporter_key


#: The DKG's lifecycle record of an asset, in its context graph's ``_meta``:
#: ``urn:dkg:assertion:<graph>:[<sub-graph>:]<author>:<name>`` with ``dkg:kaId`` (the author's asset
#: number) and ``dkg:assertionName``. DKG 10.0.25 writes one on the graph's curator node for another
#: author's asset, with ``dkg:swmShareComplete``, when it keeps that author's seal from the share
#: (OriginTrail/dkg#3307); the node's asset descriptor does not answer for such an asset before it is
#: published, and ``vm/publish`` selects it by that name.
_LIFECYCLE = "urn:dkg:assertion:"
_DKG_ONTOLOGY = "http://dkg.io/ontology/"


def sealed_names_sparql(graph: str, copies: Iterable[ReportCopy], limit: int) -> str:
    """The lifecycle records this node keeps with their author's seal (``dkg:swmShareComplete``)
    for the assets holding *copies*: ``?lifecycle``, ``?ka`` (the asset number), ``?name``. "" when
    nothing is safe to embed."""
    prefix = _data_prefix(graph)
    starts = sorted({_lifecycle_start(graph, copy) for copy in copies})
    if not prefix or not starts:
        return ""
    values = " ".join(sparql_text.sparql_string_literal(start) for start in starts)
    return (f"SELECT ?lifecycle ?ka ?name WHERE {{ VALUES ?start {{ {values} }} "
            f"GRAPH <{prefix}_meta> {{ ?lifecycle <{_DKG_ONTOLOGY}kaId> ?ka ; <{_DKG_ONTOLOGY}assertionName> ?name ; "
            f"<{_DKG_ONTOLOGY}swmShareComplete> ?complete }} FILTER(STRSTARTS(LCASE(STR(?lifecycle)), ?start)) "
            f"FILTER(STR(?complete) = \"true\") }} LIMIT {int(limit)}")


def sealed_name(graph: str, copy: ReportCopy, row: Mapping[str, object]) -> str:
    """The asset name one :func:`sealed_names_sparql` row records for *copy*: the record names
    *copy*'s sub-graph, author and asset number and ends with the name it carries; "" otherwise."""
    lifecycle = sparql_text.extract_binding(row.get("lifecycle"))
    name = sparql_text.extract_binding(row.get("name"))
    start = _lifecycle_start(graph, copy)
    if (not name or lifecycle[:len(start)].lower() != start or lifecycle[len(start):] != name
            or sparql_text.extract_binding(row.get("ka")) != copy.number):
        return ""
    return name


def _lifecycle_start(graph: str, copy: ReportCopy) -> str:
    """How the lifecycle record of *copy*'s asset begins, lower-cased (the record spells the
    author address checksummed)."""
    sub_graph = f"{copy.sub_graph}:" if copy.sub_graph else ""
    return f"{_LIFECYCLE}{graph}:{sub_graph}{copy.author}:".lower()


def _data_prefix(graph: str) -> str:
    """``did:dkg:context-graph:<graph>/`` — "" for an id that is not safe to embed."""
    if not graph or any(char in graph for char in '<>"{}|^`\\ \r\n\t'):
        return ""
    return f"did:dkg:context-graph:{graph}/"
