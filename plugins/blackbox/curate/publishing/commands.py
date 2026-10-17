"""``blackbox curate correct`` and ``blackbox curate never-flag`` — signed corrections (trust-and-threat-lab P5, §03.4).

Both verbs register here (``curate/parser.py`` calls :func:`add_publishing_parser`;
each sub-parser's own ``func`` dispatches straight to its command), never in
``curate/commands.py``.

A correction is a PERSON's act (the automation policy has no correction
action, so the curator service never signs one). The flow:

1. On curator A, ``blackbox curate correct ioc:ip:8.8.8.8 --reason "public DNS
   resolver" --source "misp-warninglists:public-dns-v4"``: refused unless this
   machine acts for the verified authority under an EFFECTIVE key manifest;
   reads the subjects the verified graph holds for the identifier (F-031: a
   legacy row does not live at ``threat_uri(identifier)``), shows exactly what
   would be signed and a confirmation code. Nothing is signed yet.
2. Amos re-runs it with ``--code <code>`` (and ``--to <curator B>``): the first
   signature; the proposal is stored and sent.
3. Curator B — or the machine holding the break-glass key — runs ``inbox`` then
   ``approve <id>``: the second signature (a correction reduces enforcement, so
   the break-glass key counts, K2), consent, and the correction is published AT
   ONCE (never batched), followed by its advisory twin (``publish.post_advisory_twin``).

``never-flag <file>`` does the same for one MISP warninglist file: the batch is
reviewed first (:mod:`.never_flag` — exact addresses only, no ranges, no
shared-hosting apex), only values the verified graph actually holds become
corrections, and ONE code covers the reviewed batch (one proposal per value).

Pattern: Command — one function per verb over :class:`.context.CurateContext`.
"""

from __future__ import annotations

import argparse
import functools
import json
import logging
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from ...kernel import constants, display_safety, signing, sparql_text, threat_ids
from ...kernel.signing import promotion_statement as statement
from ...kernel.signing.authority import Authority
from .. import consent, keys, transport
from ..context import CORRECTION_STATEMENT, CorrectionDraft, CurateContext, build_context
from ..proposal import Proposal, ProposalState, ProposalStore
from . import never_flag, row_builders
from .errors import VerbError
from .publish import require_effective_manifest
from .sequences import next_sequence

logger = logging.getLogger(__name__)
_term = display_safety.term_safe

#: Values per subject query (the live lookup's own chunk size).
LOOKUP_CHUNK = 200
#: Refused values printed in a never-flag review (the rest are counted).
_REVIEW_PRINT_LIMIT = 50

#: identifier -> the verified-graph subjects that hold it.
SubjectLookup = Callable[[CurateContext, Sequence[str]], dict[str, tuple[str, ...]]]


def add_publishing_parser(verbs_: Any) -> None:
    """Register ``correct`` and ``never-flag`` on the ``blackbox curate`` verbs."""
    c = verbs_.add_parser("correct", help="Sign a correction: stop the verified graph flagging one address (a person's act)")
    c.add_argument("identifier", help="the address as an identifier, e.g. ioc:ip:8.8.8.8")
    c.add_argument("--reason", required=True, help="why it is not a threat (one line)")
    c.add_argument("--source", required=True, help="where that is established, e.g. misp-warninglists:public-dns-v4")
    _add_signing_options(c)
    c.set_defaults(func=_guarded(cmd_correct))
    n = verbs_.add_parser("never-flag", help="Review a MISP warninglist file and sign its addresses as corrections")
    n.add_argument("file", help="a MISP warninglist list.json (public DNS resolvers, Cisco Umbrella top 1K)")
    n.add_argument("--reason", default="known-good address (never-flag list)", help="the reason every correction carries")
    _add_signing_options(n)
    n.set_defaults(func=_guarded(cmd_never_flag))


def _add_signing_options(parser: Any) -> None:
    parser.add_argument("--code", default=None, help="the 8-hex code shown for exactly this content (signs it)")
    parser.add_argument("--yes", action="store_true", help="SANDBOX only: consent without typing the code")
    parser.add_argument("--to", default="", metavar="PEER", help="send the proposal(s) to this curator (name or peer id)")


def _guarded(verb: Callable[[argparse.Namespace], int]) -> Callable[[argparse.Namespace], int]:
    """The CLI boundary every curate verb has: a refusal or failure is one readable line."""
    @functools.wraps(verb)
    def run(args: argparse.Namespace) -> int:
        try:
            return verb(args)
        except VerbError as exc:
            print(f"Refused: {exc}")
            return 2
        except Exception as exc:
            print(f"curate {args.verb} failed: {_term(str(exc), 200)}")
            return 1
    return run


def cmd_correct(args: argparse.Namespace, *, context: Optional[CurateContext] = None,
                lookup: Optional[SubjectLookup] = None, store: Optional[ProposalStore] = None) -> int:
    """``curate correct``: one correction, shown and then signed under Amos's code."""
    identifier = canonical_address(args.identifier)
    ctx = context or build_context(getattr(args, "compiled_ruleset", None), authority="verified")
    _require_correction_rights(ctx)
    subjects = (lookup or verified_subjects)(ctx, [identifier]).get(identifier, ())
    if not subjects:
        raise VerbError(f"the verified graph holds nothing for {identifier}: there is nothing to correct")
    payload = _payload(identifier, subjects, reason=args.reason, source=args.source)
    return _sign_after_consent(ctx, store or ProposalStore(), [payload], args, review=[])


def cmd_never_flag(args: argparse.Namespace, *, context: Optional[CurateContext] = None,
                   lookup: Optional[SubjectLookup] = None, store: Optional[ProposalStore] = None) -> int:
    """``curate never-flag``: review the file, then sign one correction per held address under one code."""
    try:
        with open(args.file, encoding="utf-8-sig") as handle:
            batch = never_flag.review(json.load(handle))
    except (OSError, ValueError) as exc:   # NeverFlagError is a ValueError
        raise VerbError(f"cannot use {args.file}: {exc}") from exc
    ctx = context or build_context(getattr(args, "compiled_ruleset", None), authority="verified")
    _require_correction_rights(ctx)
    held = (lookup or verified_subjects)(ctx, batch.accepted)
    payloads = [_payload(identifier, held[identifier], reason=args.reason, source=batch.source)
                for identifier in batch.accepted if held.get(identifier)]
    review = [f"never-flag review of {batch.source}: {len(batch.accepted)} exact address(es) accepted, "
              f"{len(batch.refused)} refused, {len(payloads)} held by the verified graph (only those are corrected)"]
    review += [f"  refused {_term(refusal.value, 80)} — {refusal.reason}" for refusal in batch.refused[:_REVIEW_PRINT_LIMIT]]
    if len(batch.refused) > _REVIEW_PRINT_LIMIT:
        review.append(f"  … and {len(batch.refused) - _REVIEW_PRINT_LIMIT} more refused")
    if not payloads:
        print("\n".join(review))
        raise VerbError("no accepted address is held by the verified graph: there is nothing to correct")
    return _sign_after_consent(ctx, store or ProposalStore(), payloads, args, review=review)


def canonical_address(identifier: str) -> str:
    """*identifier* when it is a canonical ``ioc:`` identifier; refused otherwise.
    A package, a skill or a pattern is withdrawn by revocation, not corrected."""
    parts = identifier.split(":", 2)
    if len(parts) != 3 or parts[0] != "ioc" or parts[1] not in threat_ids.IOC_TYPES:
        raise VerbError("a correction suppresses an ADDRESS (ioc:<type>:<value>); withdraw a package, skill or "
                        "pattern with `blackbox curate propose --verdict revocation <identifier>`")
    if threat_ids.ioc_identifier(parts[1], parts[2]) != identifier or not threat_ids.ioc_value_is_well_formed(parts[1], parts[2]):
        raise VerbError(f"not a canonical identifier; did you mean {threat_ids.ioc_identifier(parts[1], parts[2])}?")
    return identifier


def verified_subjects(ctx: CurateContext, identifiers: Sequence[str]) -> dict[str, tuple[str, ...]]:
    """The subjects the verified graph holds for each ``ioc:`` identifier, matched
    as the live lookup matches (the exact ``dp:value`` / ``normalizedValue``),
    plus every promoted report a promotion statement points at for it (the
    one-graph flow: the report's own subject is the rule's).
    Every subject is returned — the live lookup keeps one rule per identifier,
    and suppressing only that one would expose the next. Raises
    :class:`VerbError` when the graph cannot be read (could not tell, LES-011)."""
    by_value: dict[str, str] = {identifier.split(":", 2)[2]: identifier for identifier in identifiers}
    found: dict[str, list[str]] = _promoted_reports(ctx, identifiers)
    values = list(by_value)
    for start in range(0, len(values), LOOKUP_CHUNK):
        chunk = values[start:start + LOOKUP_CHUNK]
        rows = sparql_text.query_rows(ctx.client, _subjects_sparql(chunk), ctx.verified_graph,
                                      constants.VIEW_VERIFIABLE_MEMORY)
        if rows is None:
            raise VerbError("the verified graph could not be read; nothing was signed (try again)")
        for row in rows:
            identifier = by_value.get(sparql_text.extract_binding(row.get("val")))
            subject = sparql_text.extract_binding(row.get("t"))
            if identifier and subject:
                found.setdefault(identifier, []).append(subject)
    return {identifier: tuple(sorted(set(subjects))) for identifier, subjects in found.items()}


def _promoted_reports(ctx: CurateContext, identifiers: Sequence[str]) -> dict[str, list[str]]:
    """identifier → the reports the verified graph's promotion statements point at (one paged read)."""
    rows = sparql_text.page_rows(ctx.client, ctx.verified_graph, constants.VIEW_VERIFIABLE_MEMORY, statement.statements_sparql)
    if rows is None:
        raise VerbError("the verified graph could not be read; nothing was signed (try again)")
    wanted, found = set(identifiers), {}
    for row in rows:
        stated = statement.parse(signing.from_text(sparql_text.extract_binding(row.get("signedStatement"))))
        if stated is not None and stated.identifier in wanted:
            found.setdefault(stated.identifier, []).append(stated.report)
    return found


def _subjects_sparql(values: Sequence[str]) -> str:
    literals = " ".join(sparql_text.sparql_string_literal(value) for value in values)
    return (f"SELECT DISTINCT ?t ?val WHERE {{ VALUES ?val {{ {literals} }} "
            f"{{ ?t <urn:defender:p:value> ?val }} UNION {{ ?t <{constants.SOURCE_OBSERVATION_NORMALIZED_VALUE_PRED}> ?val }} "
            f"}} LIMIT {len(values) * (row_builders.MAX_CORRECTION_TARGETS + 1)}")


def _require_correction_rights(ctx: CurateContext) -> None:
    if ctx.authority is not Authority.VERIFIED:
        raise VerbError("only the verified graph's curators correct verified rows")
    require_effective_manifest(ctx)


def _payload(identifier: str, subjects: Iterable[str], *, reason: str, source: str) -> dict[str, str]:
    try:
        return row_builders.correction_payload(identifier, tuple(subjects), reason=reason, source=source)
    except row_builders.RowBuildError as exc:
        raise VerbError(f"{identifier}: {exc}") from exc


def _sign_after_consent(ctx: CurateContext, store: ProposalStore, payloads: list[Mapping[str, str]],
                        args: argparse.Namespace, *, review: list[str]) -> int:
    """Show *payloads* and their code; with the matching code, sign each one
    (first signature), store it as a proposal and send it when ``--to`` names a peer."""
    content = json.dumps(payloads, sort_keys=True, separators=(",", ":"))
    ledger = consent.ConsentLedger()
    code = ledger.show(content, f"{CORRECTION_STATEMENT} × {len(payloads)} · graph {ctx.verified_graph}")
    for line in review:
        print(line)
    for payload in payloads:
        print(f"  correct {_term(payload['identifier'], 80)} — suppresses {_term(payload['targetSubjects'], 300)}"
              f" — {_term(payload['reason'], 100)} ({_term(payload['source'], 100)})")
    if args.code is None and not args.yes:
        print(f"Nothing signed. To sign exactly this, run the same command with --code {code}")
        return 2
    allowed, why = ledger.consent(content, typed=args.code, sandbox=ctx.sandbox, yes=args.yes)
    if not allowed:
        print(f"Not signed — {why}. Confirmation code: {code}")
        return 2
    key = keys.curator_key_store().load_or_create()
    for payload in payloads:
        identifier = payload["identifier"]
        envelope = ctx.sign(CorrectionDraft(payload, sequence=next_sequence(ctx, store, identifier)), key)
        proposal = Proposal.new(CORRECTION_STATEMENT, identifier, envelope, ctx.verified_graph,
                                checks={envelope.signers[0]: f"{payload['reason']} ({payload['source']})"})
        proposal = proposal.transition(ProposalState.PROPOSED)
        store.save(proposal)
        sent = f" · sent to {_term(args.to, 60)}: delivered={transport.send_proposal(ctx.client, args.to, proposal).get('delivered')}" \
            if args.to else ""
        print(f"proposed {proposal.id} ({CORRECTION_STATEMENT} · {_term(identifier, 80)}){sent}")
    if not args.to:
        print("not sent: pass --to <peer> so curator B (or the break-glass key) gives the second signature")
    return 0
