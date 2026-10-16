"""``blackbox curate`` — the curator's CLI (Refine R6, curator tooling lite).

Verbs (plan §09): ``keys`` (this machine's curator key; a root key in the
sandbox) · ``manifest`` (sandbox: stage a root-signed key manifest) · ``queue``
(the delta view: NEW vs ALREADY VERIFIED, by lane) · ``show`` (the dossier +
checklist preview) · ``propose`` (promotion / verdict / nomination / pause,
first key) · ``inbox`` (receive proposals) · ``approve`` (second key: co-sign,
consent, publish) · ``publish`` · ``reject`` · ``list`` · ``watch`` (intake ->
webhook) · ``views`` / ``view`` (saved node-UI queries) · ``pool`` / ``export`` /
``verify-bundle`` (the confirmed pool and its hand-off bundle, :mod:`.handoff`). Each verb is one
Command function; read verbs need no keys. The argument parser is
:mod:`.parser`; the compiled ruleset is injected by cli.py, the composition root.
"""

from __future__ import annotations

import argparse
import json
import time
from typing import Callable, Dict

from .. import community
from ..detection import osv
from ..kernel import display_safety, node_routes, signing
from ..kernel.signing.authority import Authority
from ..kernel.signing.statement_order import CuratorStatement
from . import console, dossier, handoff, intake, keys, node_ui_views, promotion, publishing, queue, transport, verbs, watch
from .ladder import outcomes
from .upkeep import heartbeat, published
from .context import CurateContext, build_context, verified_identifiers
from .proposal import ProposalState, ProposalStore

_term = display_safety.term_safe


# -- dispatch --------------------------------------------------------------------


def cmd_curate(args: argparse.Namespace) -> int:
    verb: Callable[[argparse.Namespace], int] = _VERBS.get(args.verb or "", _usage)
    try:
        return verb(args)
    except verbs.VerbError as exc:
        print(f"Refused: {exc}")
        return 2
    except Exception as exc:  # the outermost CLI boundary: a readable line, never a traceback
        print(f"curate {args.verb} failed: {_term(str(exc), 200)}")
        return 1


def _usage(args: argparse.Namespace) -> int:
    print("usage: blackbox curate [--authority verified|community] {keys,manifest,queue,show,propose,inbox,approve,"
          "publish,reject,list,heartbeat,upkeep,pool,export,verify-bundle,policy,run,watch,views,view,outcome,graduate}")
    return 2


def _ctx(args: argparse.Namespace) -> CurateContext:
    """The context for this verb: the acting authority (``--authority`` or
    worked out from this machine's key) and the identifiers the verb is about."""
    return build_context(getattr(args, "compiled_ruleset", None), authority=getattr(args, "authority", None),
                         interest=_interest(args))


def _interest(args: argparse.Namespace) -> list:
    """The identifiers this verb needs the curators' statements about."""
    wanted = [getattr(args, "identifier", None), getattr(args, "promote", None)]
    wanted += [pair[1] for pair in (getattr(args, "verdict", None), getattr(args, "attest", None)) if pair]
    for key in (getattr(args, "nominate", None), getattr(args, "key", None)):
        if key:
            wanted.append(f"author:{str(key).lower()}")
    return [identifier for identifier in wanted if identifier]


# -- read verbs ------------------------------------------------------------------


def _keys(args: argparse.Namespace) -> int:
    print(f"curator key: {keys.curator_key_store().public_key_hex()}")
    if args.root:
        ctx = _ctx(args)
        if not ctx.sandbox:   # KI-256: a locally held root exists only in a development setup
            raise verbs.VerbError("this network has a pinned root; the root key is offline and never created on this machine")
        variable = "BLACKBOX_COMMUNITY_ROOT_KEYS" if ctx.authority is Authority.COMMUNITY else "BLACKBOX_CURATOR_ROOT_KEYS"
        print(f"{ctx.authority.value} root key (SANDBOX ONLY): {keys.root_key_store(ctx.authority).public_key_hex()}")
        print(f"Set {variable} to this root key on every sandbox node before publishing a manifest.")
    return 0


def _queue(args: argparse.Namespace) -> int:
    ctx = _ctx(args)
    if ctx.compiled is None:
        print("No compiled ruleset available.")
        return 1
    view = queue.delta_view(ctx.compiled.community, verified_identifiers(ctx.compiled, ctx.compiled.community))
    print(f"NEW: {len(view.new)} · ALREADY VERIFIED (closed as duplicates): {len(view.already_verified)}"
          f" · UNLISTED-ONLY (stored, no lane): {len(view.unlisted_only)}"
          + ("" if ctx.manifest else " · no trusted key manifest: every author is unlisted"))
    for item in view.new:
        print(f"  lane {item.lane.value}  [{item.stage} · {item.enforcement}]  {_term(item.identifier, 80)}  "
              f"{item.reporters} signer(s){' · disputed' if item.disputed else ''}  — {_term(item.reason, 100)}")
    return 0


def _show(args: argparse.Namespace) -> int:
    ctx = _ctx(args)
    rule = ctx.compiled.community.get(args.identifier) if ctx.compiled is not None else None
    read = community.read_verified_reports(ctx.client, ctx.cfg)
    weight = community.counted_dispute_weight(read.disputes, ctx.view).get(args.identifier, 0) if read.available else 0
    verdict = ctx.view.verdict(args.identifier)
    built = (dossier.DossierBuilder(args.identifier).community(rule).advisories(osv.lookup)
             .allowlist(community.allowlist.check(args.identifier, rule))
             .curator(verdict.value if verdict else None, weight)
             .community_confirmation(handoff.confirmation_for(ctx, args.identifier, getattr(args, "bundle", "")))
             .heat(read.heat.get(args.identifier))
             .history(ProposalStore().for_identifier(args.identifier)).build())
    for line in dossier.render(built):
        print(_term(line, 220))
    kind = str((rule or {}).get("kind") or "malware")
    for item in dossier.checklist(args.identifier, kind=kind, evidence="", reason=""):
        print(f"  checklist {item.item}. {item.title}: {'ok' if item.ok else 'NOT YET'} — {item.note}")
    return 0


def _pool(args: argparse.Namespace) -> int:
    return handoff.print_pool(_ctx(args))


def _export(args: argparse.Namespace) -> int:
    return handoff.export(_ctx(args), args.out)


def _verify_bundle(args: argparse.Namespace) -> int:
    return handoff.verify_file(args.file, root=args.root, network=args.network, graph=args.graph)   # offline: no context


def _list(args: argparse.Namespace) -> int:
    rows = ProposalStore().all()
    if not rows:
        print("No proposals on this machine.")
        return 0
    for p in rows:
        when = time.strftime("%Y-%m-%d %H:%M", time.gmtime(p.updated))
        print(f"  {p.id}  {p.state.value:<9} {when}  {_term(p.kind, 24)}  {_term(p.identifier, 70)}  {_term(p.note, 60)}")
    return 0


def _view(args: argparse.Namespace) -> int:
    ctx = _ctx(args)
    saved = node_ui_views.find_view(args.slug)
    community_view = saved in node_ui_views.COMMUNITY_VIEWS   # the community lives in the graph's shared memory
    rows = ctx.client.query(saved.sparql, ctx.verified_graph,
                            view=("shared-working-memory" if community_view else "verifiable-memory"), on_error=None) or []
    print(f"{saved.name} — {len(rows)} row(s)")
    for row in rows[:200]:
        print("  " + "  ".join(f"{k}={_term(v, 60)}" for k, v in row.items()))
    return 0


def _views(args: argparse.Namespace) -> int:
    ctx = _ctx(args)
    graph, views = ctx.verified_graph, (*node_ui_views.COMMUNITY_VIEWS, *node_ui_views.VERIFIED_VIEWS)
    if graph:   # one graph: the community's views and the verified tier's in one catalog
        node_routes.write_query_catalog(ctx.client, graph, node_ui_views.catalog_quads(views, graph))
        print(f"installed {len(views)} saved view(s) for {graph}")
    return 0


# -- write verbs -----------------------------------------------------------------


def _propose(args: argparse.Namespace) -> int:
    ctx = _ctx(args)
    store = ProposalStore()
    if args.promote:
        proposal = _propose_promotion(ctx, store, args)
    elif args.verdict:
        kind = CuratorStatement(f"blackbox.{args.verdict[0]}")
        fields = {"reason": args.reason} if args.reason else {}
        proposal = verbs.propose_statement(ctx, store, kind=kind, identifier=args.verdict[1], fields=fields, evidence=args.evidence)
    elif args.kill_list:
        with open(args.kill_list, encoding="utf-8-sig") as handle:
            proposal = verbs.propose_kill_list(ctx, store, entries=json.load(handle))
    elif args.attest:
        proposal = verbs.propose_statement(ctx, store, kind=CuratorStatement.ATTESTATION, identifier=args.attest[1],
                                           fields={"stage": args.attest[0]}, evidence=args.evidence)
    elif args.nominate:
        fields = {"listed": "no" if args.delist else "yes", "class": args.author_class, "org": args.org,
                  "expires": args.expires or verbs.default_expiry(ctx), "address": args.address.lower()}
        proposal = verbs.propose_statement(ctx, store, kind=CuratorStatement.COUNTED_AUTHORS,
                                           identifier=f"author:{args.nominate.lower()}", fields=fields)
    else:
        proposal = verbs.propose_statement(ctx, store, kind=CuratorStatement.PAUSE, identifier="curator",
                                           fields={"until": args.until})
    print(f"proposed {proposal.id} ({proposal.kind} · {_term(proposal.identifier, 80)})")
    if args.to:
        result = verbs.send(ctx, proposal, args.to)
        print(f"sent to {_term(args.to, 60)}: delivered={result.get('delivered')}")
    else:
        print("not sent: pass --to <peer> to hand it to the second curator")
    return 0


def _propose_promotion(ctx: CurateContext, store: ProposalStore, args: argparse.Namespace):
    """The report to promote comes from the community read (``--report`` picks one; default: the earliest)."""
    read = community.read_verified_reports(ctx.client, ctx.cfg)
    if not read.available:
        raise verbs.VerbError("the community reports could not be read; nothing was signed (try again)")
    try:
        report = promotion.choose_report(read.reports, args.promote, subject=args.report)
    except promotion.PromotionError as exc:
        raise verbs.VerbError(str(exc)) from exc
    return verbs.propose_promotion(ctx, store, report=report, severity=args.severity, evidence=args.evidence,
                                   reason=args.reason, name=args.name)


def _inbox(args: argparse.Namespace) -> int:
    ctx = _ctx(args)
    store = ProposalStore()
    received = transport.receive_proposals(ctx.client, transport.InboxCursor())
    for proposal in received:
        store.save(proposal)
        print(f"received {proposal.id} ({proposal.kind} · {_term(proposal.identifier, 80)})")
    if not received:
        print("no new proposals")
    return 0


def _approve(args: argparse.Namespace) -> int:
    proposal, outcome = verbs.approve(_ctx(args), ProposalStore(), args.proposal_id, evidence=args.evidence,
                                      typed_code=args.code, yes=args.yes, root=args.root)
    print(f"{proposal.id}: {outcome}")
    return 0 if proposal.state is ProposalState.PUBLISHED or "published" in outcome else 2


def _publish(args: argparse.Namespace) -> int:
    proposal, outcome = publishing.publish(_ctx(args), ProposalStore(), args.proposal_id, typed_code=args.code, yes=args.yes)
    print(f"{proposal.id}: {outcome}")
    return 0 if outcome.startswith("published") else 2


def _heartbeat(args: argparse.Namespace) -> int:
    proposal, outcome = heartbeat.publish_heartbeat(_ctx(args), ProposalStore(), typed_code=args.code, yes=args.yes)
    print(f"heartbeat {proposal.id}: {outcome}")
    return 0 if outcome.startswith("published") else 2


def _upkeep(args: argparse.Namespace) -> int:
    ctx = _ctx(args)
    sent = published.publish_due(ctx.client, ctx.cfg)
    print(f"kept alive: {sent} statement(s) re-published this epoch; {len(published.store().all())} current statement(s) remembered")
    return 0


def _reject(args: argparse.Namespace) -> int:
    store = ProposalStore()
    proposal = store.get(args.proposal_id)
    if proposal is None:
        raise verbs.VerbError("no proposal with that id")
    store.save(proposal.transition(ProposalState.REJECTED, note="rejected locally"))
    print(f"{proposal.id}: rejected locally (nothing was sent)")
    return 0


def _manifest(args: argparse.Namespace) -> int:
    ctx = _ctx(args)
    if ctx.authority is Authority.VERIFIED and not args.promotion_author:
        raise verbs.VerbError("a verified-authority manifest needs --promotion-author (the pinned publisher of verified rows)")
    proposal = verbs.manifest_proposal(ctx, ProposalStore(), curator_keys=args.curator_keys,
                                       curator_operators=args.curator_operators, threshold=args.threshold,
                                       promotion_author=args.promotion_author, root_epoch=args.root_epoch,
                                       version=args.manifest_version, legacy_uals=[], issued_day=args.issued_day)
    root = signing.public_key_hex(keys.root_key_store(ctx.authority).load_or_create())
    print(f"{ctx.authority.value} manifest for {proposal.graph} staged as {proposal.id} (root {root[:16]}…); "
          f"run `blackbox curate publish {proposal.id} --yes`")
    return 0


def _watch(args: argparse.Namespace) -> int:
    watcher = intake.IntakeWatcher()
    alarms = intake.AlarmWatcher()
    try:   # W3: this node's OWN credential (<curate home>/alarm_sink.json) unless a URL is given
        sink = watch.WebhookSink(args.webhook) if args.webhook else watch.node_sink()
    except watch.SinkCredentialError as exc:
        raise verbs.VerbError(str(exc)) from exc
    while True:
        ctx = _ctx(args)   # KI-261: a fresh view every round (the curators' statements change between rounds)
        compiled, now = ctx.compiled, time.time()
        if compiled is not None:
            announced = watcher.poll(queue.delta_view(compiled.community, verified_identifiers(compiled, compiled.community)), sink)
            if announced:
                print(f"announced {len(announced)} new threat(s): " + ", ".join(_term(a, 60) for a in announced[:10]))
        items = verbs.curator_alarms(ctx, compiled, today=_today(), now=now) + watch.manifest_items(ctx.manifest, now)
        delivered = alarms.poll(items, sink, now=now)   # R10b + W1 items + the daily dead-man beat
        alarms.post_metrics(lambda: console.collect_metrics(console.MetricsSources(), lambda: ctx, now),
                            sink, now)   # F-035: C4's one record, built only when the hourly post is due
        if delivered:
            print(f"delivered {len(delivered)} curator alarm(s)")
        if args.once:
            return 0
        time.sleep(max(5.0, args.interval))


def _today() -> str:
    return time.strftime("%Y-%m-%d", time.gmtime())


def _outcome(args: argparse.Namespace) -> int:
    standing = verbs.record_outcome(args.key, confirmed=args.confirmed, day=args.day or _today(), novel=args.novel,
                                    strike=args.strike, first_seen_day=args.first_seen)
    print(f"recorded for {_term(args.key[:16], 16)}…: band {standing.band.value} · confirmed {standing.confirmed} · "
          f"rejected {standing.rejected} · strikes {standing.strikes} · novel {standing.novel_credits}")
    return 0


def _graduate(args: argparse.Namespace) -> int:
    today = _today()
    if args.erase:
        print("erased" if community.reputation.ReputationLedger().erase(args.erase) else "no ledger entry for that key")
        ended = published.forget_identifier(f"author:{args.erase.lower()}")   # and its listing is no longer kept alive
        if ended:
            print(f"stopped keeping {ended} published statement(s) about that reporter alive")
        return 0
    if args.propose:
        if not args.address:
            print("--address is required with --propose (the agent address shown on the list)")
            return 2
        proposal = verbs.propose_graduation(_ctx(args), ProposalStore(), key=args.propose, address=args.address, today=today,
                                            cluster=args.cluster)
        print(f"proposed {proposal.id} ({proposal.kind} · {_term(proposal.identifier, 80)})")
        if args.to:
            result = verbs.send(_ctx(args), proposal, args.to)
            print(f"sent to {_term(args.to, 60)}: delivered={result.get('delivered')}")
        return 0
    ctx = _ctx(args)
    synced = outcomes.credit_verdicts(ctx)   # every curator node rebuilds its ledger from the public record
    print(f"synced with the published verdicts: {synced.credited} new outcome(s), {synced.novel} novel"
          if synced.available else "could not read the community graph: the ledger below may be behind")
    rows = verbs.graduation_candidates(today)
    if not rows:
        print("the reputation ledger is empty")
        return 0
    for standing, score, action in rows:
        print(f"{standing.key[:16]}…  {standing.band.value:<11} rep {score:.2f}  confirmed {standing.confirmed} rejected "
              f"{standing.rejected} strikes {standing.strikes} novel {standing.novel_credits}  {action or '-'}")
    for ring in outcomes.overlap_rings(ctx):
        print("possible single operator (same threats, in turn): " + ", ".join(f"{key[:16]}…" for key in sorted(ring))
              + "  -> list them under one --cluster so they count once")
    return 0


def _metrics(args: argparse.Namespace) -> int:
    snapshot = community.shadow.latest()
    if snapshot is None:
        print("no shadow snapshots yet (set `community_shadow: true`; one is written per refresh)")
    else:
        print(f"{snapshot.at}  community {snapshot.community_total} · already verified {snapshot.already_verified} "
              f"(delta share {snapshot.delta_share:.0%}) · reporters median {snapshot.reporters_median:.1f} · "
              f"days to corroborated median {snapshot.days_to_corroborated_median:.1f}")
        print(f"  stages: {snapshot.stages} · would enforce: {snapshot.would_enforce} · counted {snapshot.counted} / unlisted {snapshot.unlisted}")
    unlisted, counted, ratio = community.shadow.calibration_gap(community.reputation.ReputationLedger(), _today())
    print(f"  newcomer calibration: unlisted rejection {unlisted:.0%} vs counted {counted:.0%} → ratio {ratio:.2f}"
          + (" — REVIEW the graduation rule (gap > 2×)" if ratio > 2 else ""))
    return 0


_VERBS: dict[str, Callable[[argparse.Namespace], int]] = {
    "keys": _keys, "manifest": _manifest, "queue": _queue, "show": _show, "propose": _propose, "inbox": _inbox,
    "approve": _approve, "publish": _publish, "reject": _reject, "list": _list, "watch": _watch, "views": _views,
    "heartbeat": _heartbeat, "upkeep": _upkeep, "pool": _pool, "export": _export, "verify-bundle": _verify_bundle,
    "view": _view, "outcome": _outcome, "graduate": _graduate, "metrics": _metrics,
}
