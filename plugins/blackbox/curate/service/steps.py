"""The beat's trust-and-threat-lab steps (§03.4, SVC4): each is ONE line in :meth:`.beat.Beat.run`.

Every step's body lives in its own module; this module only adapts it to the
beat's :class:`.report.Run` (what it reads, what it records):

* :meth:`ServiceSteps.look_up` — the outside sources (``curate/sources``,
  SRC1): ``SourceRegistry.lookup(items, LookupBudget)`` over the admitted
  queue, at most a budget's worth a beat, oldest first. The first-signature
  step reads its answers (``Run.checks``); an item this beat did not look
  up is "could not tell", never clean.
* :meth:`ServiceSteps.lab_collect` / :meth:`ServiceSteps.lab_submit` — the lab
  (``curate/lab``, L2/L4): collect finished jobs BEFORE the verdicts; submit
  the items no source lists AFTER admission (``trigger.submit_candidate``,
  wait-and-flag). Only on a node given a :class:`LabWiring`.
* :meth:`ServiceSteps.publish_batch` — step 8, ``BatchPublisher.run(ctx)``
  (``curate/publishing``, P4): only on the node started with ``--publisher``
  (the wallet holder), and only while this node may sign.
* :meth:`ServiceSteps.withdrawal` — the weekly source-withdrawal re-check
  (``sources.WithdrawalWatcher``, SRC4); the watcher keeps its own week.
* :meth:`ServiceSteps.watch` — the alarms (``curate.watch`` / ``intake.AlarmWatcher``,
  W1–W3) on every curator node: curator alarms, manifest items, a suspended
  self-test, the injected ledger checks, the once-a-day dead-man beat and the
  hourly metrics record, through this node's OWN sink.

The daily self-test (SVC2) is not a step: it runs when a beat begins
(:meth:`.beat.Beat._begin`), because its result decides whether the whole beat may sign.

Imported lazily by :mod:`.beat` and :mod:`.commands` (never at package import):
``curate.sources`` reads ``service.evidence``, so importing the sources while the
``service`` package initialises would close a cycle.

Pattern: Facade — one object holding each step's collaborator; a collaborator
left ``None`` turns its step off (:meth:`ServiceSteps.for_node` builds a node's set).

Usage::

    steps = ServiceSteps.for_node(publisher=True, beat_seconds=300)
    Beat(context, peers=["curator-b"], steps=steps).run()
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Optional, Sequence

from ... import community
from ...kernel.health import HealthItem, utc_day_or
from ...kernel.signing import CuratorStatement
from .. import console, intake, verbs, watch
from ..context import CurateContext
from ..lab import LabController
from ..lab.jobs import strip_query, threat_digest
from ..lab.trigger import LabCandidate, LabRequests, LabSetup, SubmissionStatus, VISIT_LEVEL, sources_say, submit_candidate
from ..publishing import BatchPublisher
from ..sources import (SOURCES, CitedConfirmation, LookupBudget, LookupItem, SourceRegistry, WithdrawalWatcher,
                       rechecks_for)
from . import self_test
from .evidence import Lookup, OwnCheck
from .report import SETTLED, HumanItem, Run

#: The source a confirmation's ``advisory:<id>`` evidence cites (the only citable evidence a confirmation carries).
ADVISORY_SOURCE = "osv"
_ADVISORY = "advisory:"
#: A ledger check (W2): this node's context and the time → the health items it raises.
LedgerCheck = Callable[[CurateContext, float], list[HealthItem]]
#: The batch outcomes that are an error of the step (the publisher keeps the batch and retries it).
_BATCH_ERRORS = frozenset({"failed", "could-not-tell"})


@dataclass(frozen=True)
class LabWiring:
    """How this node reaches its lab: ``controller`` builds the controller for a
    beat's context; ``setup`` — the levels this node's labs run. Level 3 (the
    urlscan visit) is refused until the controller routes it to the source registry's
    own urlscan scan: sent to a lab host it would be refused and read "could not tell"."""

    controller: Callable[[CurateContext], LabController]
    setup: LabSetup
    requests: LabRequests = field(default_factory=LabRequests)

    def __post_init__(self) -> None:
        if VISIT_LEVEL in self.setup.images:
            raise ValueError("level 3 runs on urlscan through the source registry, not on a lab host")


class ServiceSteps:
    """The beat's new steps and their collaborators (see the module doc). Every
    argument is optional; ``None`` leaves that step off. *sink* — this node's alarm
    sink (``watch.node_sink``: raises when the node has none, which is the step's error);
    *metrics* — where the metrics record reads (no publish ledger on a node that does not publish)."""

    def __init__(self, *, sources: Optional[SourceRegistry] = None, lookup_budget: LookupBudget = LookupBudget(),
                 lab: Optional[LabWiring] = None, publisher: Optional[BatchPublisher] = None,
                 withdrawal: Optional[WithdrawalWatcher] = None, alarms: Optional[intake.AlarmWatcher] = None,
                 sink: Optional[Callable[[], watch.IntakeSink]] = None,
                 metrics: Optional[console.MetricsSources] = None, ledger_checks: Sequence[LedgerCheck] = (),
                 clock: Callable[[], float] = time.time) -> None:
        self._sources, self._lookup_budget, self._lab, self._publisher = sources, lookup_budget, lab, publisher
        self._withdrawal, self._alarms, self._sink, self._metrics = withdrawal, alarms, sink, metrics
        self._ledger_checks, self._clock = tuple(ledger_checks), clock

    @classmethod
    def for_node(cls, *, publisher: bool, beat_seconds: float) -> ServiceSteps:
        """A curator node's steps: every source, the weekly withdrawal re-check and the
        alarms; the batch publisher only with *publisher*. No lab yet: a node has no lab
        configuration (URL, controller key, image hashes) to build a :class:`LabWiring` from."""
        return cls(sources=SourceRegistry(SOURCES), withdrawal=WithdrawalWatcher(rechecks_for(SOURCES)),
                   publisher=BatchPublisher(beat_seconds=beat_seconds) if publisher else None,
                   alarms=intake.AlarmWatcher(), sink=watch.node_sink,
                   metrics=console.MetricsSources() if publisher else console.MetricsSources(publish_ledger=None))

    # -- before the verdicts ------------------------------------------------------

    def look_up(self, run: Run) -> None:
        """SRC1: ask every source about this beat's share of the admitted queue."""
        compiled = run.ctx.compiled
        if self._sources is None or compiled is None:
            return
        view = run.queue_view()
        rules = compiled.community
        items = [LookupItem(item.identifier, item.lane, first_seen=utc_day_or(rules[item.identifier].get("firstSeen"), run.today))
                 for item in view.new if not _settled(run, item.identifier)]
        run.looked_up = self._sources.lookup(items, self._lookup_budget, today=run.today)
        run.checks.update({result.item.identifier: own_check_from(result.verdicts) for result in run.looked_up})

    def lab_collect(self, run: Run) -> None:
        """L2: send queued lab jobs, ask after running ones, collect and sign finished runs."""
        if self._lab is None:
            return
        run.lab = self._lab.controller(run.ctx)
        run.lab.poll()

    # -- after admission ----------------------------------------------------------

    def lab_submit(self, run: Run) -> None:
        """L4: a lab job for each looked-up item no source lists, when the trigger rule fires."""
        if self._lab is None or run.lab is None:
            return
        clean = [result.item.identifier for result in run.looked_up
                 if sources_say(result.verdicts) is Lookup.CLEAN and result.item.identifier not in run.settled]
        if not clean:
            return
        queued = {item.identifier: item for item in run.queue_view().new}
        requested = self._lab.requests.requested_digests()
        authors = _authors_by_identifier(run.ctx)
        for identifier in clean:
            clusters = community.clusters_for(authors.get(identifier, ()), run.ctx.view)
            candidate = LabCandidate(queued[identifier], clusters.partner, clusters.established, Lookup.CLEAN,
                                     curator_requested=threat_digest(strip_query(identifier)) in requested)
            submission = submit_candidate(candidate, run.lab.store, self._lab.setup, submit=run.lab.submit,
                                          scan_ready=lambda _identifier: False)
            run.lab_jobs += len(submission.records)
            if submission.status is SubmissionStatus.AWAITING_LAB:
                run.human.append(HumanItem(identifier, submission.why))

    # -- after the routine work ---------------------------------------------------

    def publish_batch(self, run: Run) -> None:
        """Step 8 (P4): one batch of quorum-signed promotions, on the ``--publisher`` node only."""
        if self._publisher is None:
            return
        if not run.may_sign:   # fail closed: a node that may not sign does not spend the wallet either
            run.batch = "held"
            return
        report = self._publisher.run(run.ctx)
        run.batch = report.action
        if report.action in _BATCH_ERRORS:
            run.errors.append(f"publish batch: {report.action}{f' ({report.note})' if report.note else ''}")

    def withdrawal(self, run: Run) -> None:
        """SRC4: once a week, revoke what a cited source withdrew; expired addresses wait for a person."""
        if self._withdrawal is None or not run.may_sign:   # a revocation is signed: no signing, no re-check (nor its week)
            return
        report = self._withdrawal.run(run.ctx, run.store, cited_confirmations(run.ctx.own_view))
        run.proposed.extend(proposal.id for proposal in report.revocations)
        run.human.extend(HumanItem(request.identifier, f"untested since {request.tested_day}: a correction "
                                   f"({request.reason}) waits for a person (`blackbox curate correct`)")
                         for request in report.corrections)
        run.errors.extend(f"withdrawal: could not propose revoking {identifier}" for identifier in report.failures)

    def watch(self, run: Run) -> None:
        """W1–W3: deliver this node's new alarms and its daily dead-man beat; post the hourly metrics."""
        if self._alarms is None or self._sink is None:
            return
        sink, now = self._sink(), self._clock()
        items = alarm_items(run.ctx, today=run.today, now=now, ledger_checks=self._ledger_checks)
        run.alarms = len(self._alarms.poll(items, sink, now=now))
        metrics = self._metrics or console.MetricsSources(publish_ledger=None)
        self._alarms.post_metrics(lambda: console.collect_metrics(metrics, lambda: run.ctx, now), sink, now)


def alarm_items(ctx: CurateContext, *, today: str, now: float,
                ledger_checks: Sequence[LedgerCheck] = ()) -> list[HealthItem]:
    """Every alarm this curator node raises right now: its own facts (queue, ledger, velocity,
    retries, expiries — ``verbs.curator_alarms``), the key manifest's clock, the self-test (a
    suspended curator) and any publish-ledger checks. The ONE assembly for the service's watch
    step and `curate watch` — the CLI's own copy left out the self-test."""
    items = verbs.curator_alarms(ctx, ctx.compiled, today=today, now=now)
    items += watch.manifest_items(ctx.manifest, now) + self_test.health_items(self_test.SelfTestStore().read())
    for check in ledger_checks:
        items += check(ctx, now)
    return items


def own_check_from(verdicts: Sequence[OwnCheck]) -> OwnCheck:
    """One item's sources folded for the policy: a FOUND verdict that names an
    advisory (the only machine-checkable evidence of malware), else what the
    sources say together (``trigger.sources_say``)."""
    advised = next((verdict for verdict in verdicts if verdict.status is Lookup.FOUND and verdict.advisory), None)
    return advised if advised is not None else OwnCheck(sources_say(verdicts))


def cited_confirmations(view: community.CuratorView) -> tuple[CitedConfirmation, ...]:
    """The confirmations in *view* that cite an advisory, as the withdrawal watcher re-checks them."""
    return tuple(CitedConfirmation(record.identifier, ADVISORY_SOURCE, record.field("evidence")[len(_ADVISORY):],
                                   tested_day=record.day)
                 for record in view.verdicts.values()
                 if record.kind is CuratorStatement.CONFIRMATION and record.field("evidence").startswith(_ADVISORY))


def _settled(run: Run, identifier: str) -> bool:
    verdict = run.ctx.own_view.verdicts.get(identifier)
    return identifier in run.settled or (verdict is not None and verdict.kind in SETTLED)


def _authors_by_identifier(ctx: CurateContext) -> dict[str, tuple[str, ...]]:
    """The verified reporter keys behind each community threat (read once a beat, only when the lab may run)."""
    authors: dict[str, list[str]] = {}
    for report in community.read_verified_reports(ctx.client, ctx.cfg).reports:
        authors.setdefault(report.identifier, []).append(report.author)
    return {identifier: tuple(keys) for identifier, keys in authors.items()}




__all__ = ["ADVISORY_SOURCE", "LabWiring", "LedgerCheck", "ServiceSteps", "alarm_items",
           "cited_confirmations", "own_check_from"]
