"""One beat of the curator service (Community Curation C9, plan §07).

A curator node runs ONE service. Every few minutes it performs the same steps
in the same order:

1. heartbeat — "this key is alive";
2. read — the proposals the other curators sent;
3. co-sign — for each proposal the policy allows, check it AGAIN on this
   node, co-sign and publish; everything else waits for a person;
4. first signatures — for each new threat in the queue: confirm a dependency
   the outside sources gave a malicious-package advisory for (sign, send to the
   other curators), defer or lapse by the clock, acknowledge the rest. Before
   it: the source look-ups and the lab's collect; after it: the lab's submit;
5. credit — record the outcome of every published verdict in the private ledger;
6. ladder — propose the listings, renewals and delistings the ledger calls for;
7. keep alive — re-publish this node's current statements before shared memory forgets them;
8. publish a batch (``--publisher`` node only); then the weekly withdrawal
   re-check and the alarms. Those steps' bodies live in their own modules
   (:mod:`.steps` adapts each to the beat).

Nothing is signed unless this machine's key is a curator key of the trusted
manifest AND its operator accepted the automation policy as it reads today
(:mod:`.policy_consent`) AND its self-test passes (:mod:`.self_test` — a failing
curator is suspended until a run passes). Without that the beat still reads, credits and
lists what waits for a person. Two nodes reach the same answer separately:
the first signs after its own check, the second signs only after ITS own
check; a proposal the second node cannot reproduce is not co-signed.

A step that fails is recorded and the others still run. Nothing is left
half-done: a statement that was signed but could not be published stays
APPROVED and the next beat publishes it; a proposal that could not be sent is
sent again.

Pattern: Template Method — :meth:`Beat.run` is the fixed order; each step is
one small method that records what it did in the beat's :class:`.report.Run`.

Usage::

    beat = Beat(lambda interest: build_context(compiled_ruleset, interest=interest), peers=["curator-b", "curator-c"])
    report = beat.run()
    print(report.summary())
"""

from __future__ import annotations

import logging
import time
from dataclasses import replace
from datetime import timezone
from typing import TYPE_CHECKING, Callable, List, Mapping, Optional, Sequence

from ... import community
from ...community import reputation
from ...kernel.health import utc_day
from ...kernel import signing
from ...kernel.signing import CuratorStatement
from .. import keys, publishing, queue, verbs
from ..proposals import transport
from ..context import CurateContext
from ..ladder import outcomes
from ..proposals import Proposal, ProposalState, ProposalStore
from ..upkeep import heartbeat, published
from . import evidence, inbox, policy, self_test
from .budget import ServiceBudget
from .policy import Action, Facts, PolicyDecision
from .policy_consent import PolicyConsent
from .report import SETTLED, BeatReport, HumanItem, Run, standing

if TYPE_CHECKING:   # .steps is imported when a beat is built: it loads curate.sources, which reads this package
    from .steps import ServiceSteps

logger = logging.getLogger(__name__)

#: Builds the context for one beat, given the identifiers the beat needs statements about.
ContextFactory = Callable[[Sequence[str]], CurateContext]
OwnLookup = Callable[[str], evidence.OwnCheck]

#: Which daily limit an action counts against (reductions and notices: none).
_LIMITED = {Action.CONFIRM: "confirm", Action.LIST: "list"}
#: The note on a proposal the other curators have been sent.
SENT = "sent to the other curators"
#: In-review acknowledgements one beat publishes at most (a full queue is acknowledged over a few beats).
ACKNOWLEDGEMENTS_PER_BEAT = 25
_NO_CHECK = evidence.OwnCheck(evidence.Lookup.NOT_APPLICABLE)


class Beat:
    """The curator service's beat. *context* builds a fresh context for the
    identifiers a beat needs; *peers* — the other curators' nodes (proposals
    are sent to each); *lookup* — this node's own advisory check (injected so
    a test can stand in for the public source) — the co-sign re-check; *steps* — the
    trust-and-threat-lab steps (:class:`.steps.ServiceSteps`; none when not given)."""

    def __init__(self, context: ContextFactory, *, peers: Sequence[str] = (), lookup: OwnLookup = evidence.own_check,
                 store: Optional[ProposalStore] = None, consent: Optional[PolicyConsent] = None,
                 budget: Optional[ServiceBudget] = None, ledger: Optional[reputation.ReputationLedger] = None,
                 clock: Callable[[], float] = time.time, tester: Optional[self_test.SelfTest] = None,
                 steps: Optional[ServiceSteps] = None) -> None:
        self._context, self._peers, self._lookup, self._clock = context, tuple(peers), lookup, clock
        self._tester = tester or self_test.SelfTest()   # *tester*: the self-test, run at start, daily, and while failing
        self._store, self._consent, self._budget, self._ledger = store, consent, budget, ledger
        self._steps = steps or _no_steps()

    # -- the fixed order ----------------------------------------------------

    def run(self) -> BeatReport:
        run, more = self._begin(), self._steps
        for step in (self._heartbeat, self._read, self._cosign,
                     more.look_up,         # SRC1: the outside sources, budgeted
                     more.lab_collect,     # L2: finished lab runs, before the verdicts
                     self._first_signatures,
                     more.lab_submit,      # L4: lab jobs for what no source lists
                     self._credit, self._ladder, self._keep_alive,
                     more.publish_batch,   # step 8, P4: the --publisher node only
                     more.withdrawal,      # SRC4: weekly
                     more.watch):          # W1-W3: alarms, the dead-man beat, metrics
            name = step.__name__.strip("_").replace("_", " ")
            try:
                step(run)
            except publishing.VerbError as exc:
                run.errors.append(f"{name}: {exc}")
            except Exception as exc:   # the service's outermost boundary: one failed step never stops the beat
                logger.warning("blackbox curate service: step '%s' failed: %s", name, exc)
                run.errors.append(f"{name}: {exc}")
        return run.report()

    def _begin(self) -> Run:
        store = self._store or ProposalStore()
        ledger = self._ledger or reputation.ReputationLedger()
        first = self._context(())
        wanted = [*(p.identifier for p in store.open(now=self._clock())),
                  *(first.compiled.community if first.compiled is not None else ()),
                  *(f"author:{key}" for key in ledger.keys())]
        ctx = self._context(wanted)
        my_key = keys.curator_key_store().public_key_hex()
        today = utc_day(self._clock())
        suspended = self_test.why_suspended(self._tester.check(today))   # a failed self-test signs nothing
        why_not = ""
        if ctx.manifest is None or my_key not in ctx.manifest.curator_keys:
            why_not = "this machine's key is not a curator key of a trusted manifest"
        elif not (self._consent or PolicyConsent()).accepted(policy.policy_text(), my_key):
            why_not = "the automation policy is not accepted on this machine (`blackbox curate policy`)"
        why_not = why_not or suspended
        return Run(ctx=ctx, store=store, ledger=ledger, budget=self._budget or ServiceBudget(), today=today,
                    my_key=my_key, why_not=why_not)

    # -- 1 heartbeat ---------------------------------------------------------

    def _heartbeat(self, run: Run) -> None:
        if not run.may_sign:
            run.heartbeat = "not signed"
            return
        if run.ctx.own_view.heartbeats.get(run.my_key, "") >= run.today:
            return
        decision = policy.decide(Action.HEARTBEAT, heartbeat.CURATOR, Facts())
        waiting = [p for p in run.store.open(now=self._clock())
                   if p.kind == CuratorStatement.HEARTBEAT.value and p.state is ProposalState.APPROVED]
        if waiting:   # signed on an earlier beat but not published: finish that one, never sign a second
            for older in waiting[:-1]:
                run.store.save(older.transition(ProposalState.REJECTED, note="superseded by a newer heartbeat"))
            _, outcome = publishing.publish(run.ctx, run.store, waiting[-1].id, typed_code=None, yes=False, standing=standing(decision))
        else:
            _, outcome = heartbeat.publish_heartbeat(run.ctx, run.store, standing=standing(decision))
        run.heartbeat = "published" if outcome.startswith("published") else outcome

    # -- 2 read --------------------------------------------------------------

    def _read(self, run: Run) -> None:
        saved, dropped = inbox.admit(run.ctx.manifest, run.store,
                                     transport.receive_proposals(run.ctx.client, transport.InboxCursor()))
        run.received += len(saved)
        run.dropped += dropped

    # -- 3 co-sign -----------------------------------------------------------

    def _cosign(self, run: Run) -> None:
        for proposal in run.store.open(now=self._clock()):
            envelope = proposal.parsed()
            if envelope is None or proposal.state is ProposalState.DRAFT:
                continue
            mine = proposal.state is ProposalState.PROPOSED and run.my_key in envelope.signers
            self._each(run, f"proposal {proposal.id}", self._own_proposal if mine else self._second_key, proposal, envelope)

    @staticmethod
    def _each(run: Run, what: str, work: Callable[..., None], *args: object) -> None:
        """Do one item's work; a refusal or a failed write is recorded for THAT
        item and the step goes on with the next (which items a beat reaches
        must never depend on the order they are read in)."""
        try:
            work(run, *args)
        except publishing.VerbError as exc:
            run.errors.append(f"{what}: {exc}")

    def _own_proposal(self, run: Run, proposal: Proposal, envelope: signing.SignedEnvelope) -> None:
        """A proposal this node signed first: finished once another curator
        published it; otherwise sent (again) until one of them has it."""
        if inbox.published_elsewhere(run.ctx, proposal, envelope):
            done = proposal.transition(ProposalState.APPROVED).transition(ProposalState.PUBLISHED, note="published by another curator")
            run.store.save(done)
            transport.DeliveryLedger().delivered(proposal.id)
        elif proposal.note != SENT:
            self._send(run, proposal)

    def _second_key(self, run: Run, proposal: Proposal, envelope: signing.SignedEnvelope) -> None:
        """Check a proposal AGAIN on this node; co-sign and publish it only when
        the policy allows it on this node's own facts. (An APPROVED proposal is
        one whose publish did not complete: it is published, not signed again.)"""
        identifier = str(envelope.payload.get("identifier", ""))
        fields = {key: value for key, value in envelope.payload.items() if key not in ("identifier", "day")}
        action = policy.action_for(proposal.kind, fields)
        check = self._lookup(identifier) if action in (Action.CONFIRM, Action.DEFER) else _NO_CHECK
        decision = policy.decide(action, identifier, self._facts(run, action, identifier, fields, check))
        what = f"{proposal.kind.split('.', 1)[-1]} of {identifier} (proposal {proposal.id})"
        if not decision.automatic:
            run.human.append(HumanItem(proposal.id, f"{what}: {decision.reason}"))
            return
        if not self._allowed(run, decision, what):
            return
        if proposal.state is ProposalState.APPROVED:
            _, outcome = publishing.publish(run.ctx, run.store, proposal.id, typed_code=None, yes=False, standing=standing(decision))
        else:
            _, outcome = verbs.approve(run.ctx, run.store, proposal.id, evidence=check.evidence, typed_code=None, yes=False,
                                       standing=standing(decision))
        alone = len(envelope.signatures) == 1 and proposal.state is ProposalState.APPROVED   # this node's own single-key statement
        self._record(run, decision, run.published if alone else run.cosigned, what if alone else proposal.id, outcome, identifier)

    def _facts(self, run: Run, action: Action, identifier: str, fields: Mapping[str, str],
               check: evidence.OwnCheck) -> Facts:
        """What THIS node established about one item, for the policy."""
        if action is Action.CONFIRM:
            return Facts(malicious_advisory=check.advisory, evidence_cited=fields.get("evidence", ""))
        if action is Action.DEFER:
            return Facts(corroborated=evidence.community_stage(run.ctx.compiled, identifier) == "corroborated",
                         lookup_clean=check.status is evidence.Lookup.CLEAN)
        if action is Action.LAPSE_DEFERRAL:
            return Facts(deferral_age_days=evidence.deferral_age_days(run.ctx.own_view, identifier, run.today))
        if action in (Action.LIST, Action.DELIST) and identifier.startswith("author:"):
            return Facts(ledger_calls_for=evidence.ledger_calls_for(identifier[len("author:"):], run.ctx.own_view,
                                                                    run.ledger, run.today))
        return Facts()

    def _allowed(self, run: Run, decision: PolicyDecision, what: str) -> bool:
        """May the service sign this automatic decision NOW: it may sign at
        all, and its own daily limit for a raising statement is not used up."""
        if not run.may_sign:
            run.human.append(HumanItem(what, f"the policy allows the service to do this ({decision.reason}), but {run.why_not}"))
            return False
        limit = _LIMITED.get(decision.action)
        if limit and not run.budget.left(limit, run.today):
            run.limited += 1
            return False
        return True

    @staticmethod
    def _record(run: Run, decision: PolicyDecision, done: list[str], what: str, outcome: str, identifier: str) -> None:
        """A publish that was read back counts (and spends the daily limit); anything else is an error to retry."""
        run.settled.add(identifier)
        if not outcome.startswith("published"):
            run.errors.append(f"{what}: {outcome}")
            return
        done.append(what)
        if decision.action in _LIMITED:
            run.budget.spend(_LIMITED[decision.action], run.today)

    def _send(self, run: Run, proposal: Proposal) -> None:
        """Send a first-signed proposal to every other curator; it is marked
        sent once one of them has it, and sent again next beat otherwise."""
        delivered = 0
        for peer in self._peers:
            try:
                delivered += 1 if verbs.send(run.ctx, proposal, peer).get("delivered") else 0
            except Exception as exc:   # one unreachable curator must not stop the others being asked
                logger.info("blackbox curate service: proposal %s not delivered to %s (%s)", proposal.id, peer, exc)
        ledger = transport.DeliveryLedger()
        if delivered:
            run.store.save(replace(proposal, note=SENT))
            ledger.delivered(proposal.id)
        else:   # retried every beat; an alarm from the third (transport.ALARM_AFTER_BEATS)
            run.errors.append(ledger.failed(proposal.id, now=self._clock()).text())

    # -- 4 first signatures --------------------------------------------------

    def _first_signatures(self, run: Run) -> None:
        if run.ctx.compiled is None:
            return
        view = run.queue_view()
        in_flight = {proposal.identifier for proposal in run.store.open(now=self._clock())}
        for item in view.new:
            verdict = run.ctx.own_view.verdicts.get(item.identifier)
            kind = verdict.kind if verdict is not None else None
            if kind not in SETTLED and item.identifier not in in_flight and item.identifier not in run.settled:
                self._each(run, item.identifier, self._routine, item, kind)

    def _routine(self, run: Run, item: queue.QueueItem, kind: Optional[CuratorStatement]) -> None:
        """The routine work for one new threat, most valuable first: confirm on
        the advisory the sources found; else the deferral clock; else a person."""
        identifier = item.identifier
        check = run.checks.get(identifier, evidence.NOT_LOOKED_UP)   # this beat's look-ups: never one call per item
        confirm = policy.decide(Action.CONFIRM, identifier, Facts(malicious_advisory=check.advisory, evidence_cited=check.evidence))
        if confirm.automatic:
            self._first_key(run, CuratorStatement.CONFIRMATION, identifier, {}, check.evidence, confirm)
            return
        if kind is CuratorStatement.DEFERRAL:
            lapse = policy.decide(Action.LAPSE_DEFERRAL, identifier, Facts(deferral_age_days=evidence.deferral_age_days(run.ctx.own_view, identifier, run.today)))
            if lapse.automatic:
                self._single_key(run, CuratorStatement.DEFERRAL_LAPSED, identifier, lapse)
            return
        defer = policy.decide(Action.DEFER, identifier, Facts(corroborated=item.stage == "corroborated",
                                                              lookup_clean=check.status is evidence.Lookup.CLEAN))
        if defer.automatic and kind is not CuratorStatement.DEFERRAL_LAPSED:   # a lapsed deferral is not deferred again
            self._single_key(run, CuratorStatement.DEFERRAL, identifier, defer)
            return
        run.human.append(HumanItem(identifier, f"lane {item.lane.value}: {confirm.reason}"))
        if kind is None and run.may_sign and run.acknowledged < ACKNOWLEDGEMENTS_PER_BEAT:
            run.acknowledged += 1
            self._single_key(run, CuratorStatement.IN_REVIEW, identifier, policy.decide(Action.ACKNOWLEDGE, identifier, Facts()))

    def _first_key(self, run: Run, kind: CuratorStatement, identifier: str, fields: Mapping[str, str], cited: str,
                   decision: PolicyDecision) -> None:
        """Sign first and send to the other curators (a statement that needs two keys)."""
        if not self._allowed(run, decision, f"{decision.action.value} {identifier}"):
            return
        proposal = verbs.propose_statement(run.ctx, run.store, kind=kind, identifier=identifier, fields=fields, evidence=cited)
        run.proposed.append(proposal.id)
        run.settled.add(identifier)
        if decision.action in _LIMITED:
            run.budget.spend(_LIMITED[decision.action], run.today)
        self._send(run, proposal)

    def _single_key(self, run: Run, kind: CuratorStatement, identifier: str, decision: PolicyDecision) -> None:
        """Sign and publish a statement one key may make alone (a deferral, a lapse, an acknowledgement)."""
        what = f"{kind.value.split('.', 1)[1]} {identifier}"
        if not self._allowed(run, decision, what):
            return
        proposal = verbs.propose_statement(run.ctx, run.store, kind=kind, identifier=identifier, fields={})
        run.store.save(proposal.transition(ProposalState.APPROVED))
        _, outcome = publishing.publish(run.ctx, run.store, proposal.id, typed_code=None, yes=False, standing=standing(decision))
        self._record(run, decision, run.published, what, outcome, identifier)

    # -- 5 credit ------------------------------------------------------------

    def _credit(self, run: Run) -> None:
        run.credited = outcomes.credit_verdicts(run.ctx, ledger=run.ledger).credited

    # -- 6 ladder ------------------------------------------------------------

    def _ladder(self, run: Run) -> None:
        in_flight = {proposal.identifier for proposal in run.store.open(now=self._clock())}
        counted = run.ctx.own_view.counted
        for key in sorted(set(run.ledger.keys()) | set(counted)):
            calls = evidence.ledger_calls_for(key, run.ctx.own_view, run.ledger, run.today)
            if not calls or f"author:{key}" in in_flight | run.settled or (calls == "delist" and key not in counted):
                continue
            self._each(run, f"author:{key}", self._ladder_proposal, key, calls)

    def _ladder_proposal(self, run: Run, key: str, calls: str) -> None:
        identifier, standing = f"author:{key}", run.ledger.standing(key)
        decision = policy.decide(Action.LIST if calls == "list" else Action.DELIST, identifier, Facts(ledger_calls_for=calls))
        address = self._address(run, key)
        if not address:
            run.human.append(HumanItem(identifier, f"the ledger calls for '{calls}', but this reporter's agent address is not known here"))
            return
        days = verbs.listing_days(run.ctx)
        fields = reputation.nomination_fields(standing, address=address, today=run.today,
                                              reputation=run.ledger.reputation(key, run.today), listing_days=days) \
            or reputation.renewal_fields(standing, address=address, today=run.today, listing_days=days)
        self._first_key(run, CuratorStatement.COUNTED_AUTHORS, identifier, fields, "", decision)

    def _address(self, run: Run, key: str) -> str:
        """The agent address shown beside reporter *key* (display only): from its listing, else from its reports."""
        listed = run.ctx.own_view.counted.get(key)
        if listed is not None:
            return listed.address
        if run.addresses is None:
            read = community.read_verified_reports(run.ctx.client, run.ctx.cfg)
            run.addresses = {report.author: report.reporter for report in read.reports}
        return run.addresses.get(key, "")

    # -- 7 keep alive --------------------------------------------------------

    def _keep_alive(self, run: Run) -> None:
        if run.may_sign:
            run.kept_alive = published.publish_due(run.ctx.client, run.ctx.cfg, now=self._clock())


def _no_steps() -> ServiceSteps:
    from .steps import ServiceSteps   # see the TYPE_CHECKING import above
    return ServiceSteps()
