"""The key console's routes: join requests, approve/decline, removal, renewal (trust-and-threat-lab C3, §03.2),
and the read-only metrics view ``GET /api/metrics`` over ``metrics.py`` (C4, §03.4).

Pattern: Facade. Each route is HTTP over code that already exists — the
roster decisions (``roster.py``, built through the K2 validator), the root
signature (``root_signer.RootSigner`` → ``CurateContext.sign`` → the
SigningLog) and the existing publish path (``publishing.publish``: consent
code, the write, the read-back). They are added to ``create_console_app``'s
app, so all three gates of ``app.py`` run first; every change is a POST
(the boundary's CSRF check covers it), never a GET.

Signing is two steps, both POSTs:

1. ``.../approve``, ``/api/curators/{key}/remove`` or ``/api/manifest/renew``
   with ``{"passphrase", "secondFactor"}`` — builds the next list, signs it
   with root A (logged), checks the signature against the pinned roots for
   its epoch, and stages it as an APPROVED proposal. The answer carries the
   diff, the proposal id and the content-bound confirmation code.
2. ``/api/manifests/{proposal_id}/publish`` with ``{"confirmationCode"}`` —
   the existing publish path, unchanged. Every root signature is therefore
   both logged and published.

Usage::

    app = create_console_app(settings)
    add_console_routes(app, ConsoleServices(context=lambda: build_context(None, authority="verified")))
"""

# No ``from __future__ import annotations``: FastAPI resolves the route annotations below.
import threading
import time
from dataclasses import dataclass, field
from datetime import timezone
from typing import Any, Callable, Dict, Optional

from ...kernel.health import utc_day
from ...kernel import threat_ids
from ...kernel.signing import key_manifest, trust_anchors
from ...kernel.signing import Authority
from .. import publishing
from ..proposals import consent
from ..context import CurateContext
from ..proposals import Proposal, ProposalState, ProposalStore
from .metrics import MetricsSources, collect_metrics
from .root_signer import RootSigner, RootSignerError, TotpSecondFactor
from .root_store import EncryptedRootStore
from .roster import (ConsoleState, JoinRequest, JoinState, RosterError, SelfTestReport, SignedList, diff,
                     renewal_status, renewed, with_curator, without_curator)

MAX_PASSPHRASE_LENGTH = 1024
_SECOND_FACTOR_PATTERN = r"^[0-9]{6}$"
_KEY_PATTERN = rf"^{threat_ids.HEX64_PATTERN}$"


def _default_signer(ctx: CurateContext) -> RootSigner:
    return RootSigner(ctx, EncryptedRootStore(), TotpSecondFactor())


@dataclass(frozen=True)
class ConsoleServices:
    """What the routes work with — every piece injectable for tests.

    ``context`` — a fresh ``CurateContext`` per request (the effective list is
    ``ctx.manifest``); ``signer`` — the root-A Command for that context;
    ``state`` — join requests and the lists signed here; ``proposals`` — where
    a signed list waits for publishing; ``roots`` — the pinned roots of an
    environment; ``clock`` — Unix seconds; ``metrics`` — the stores the
    read-only metrics view reads (``metrics.py``, C4).
    """

    context: Callable[[], CurateContext]
    signer: Callable[[CurateContext], RootSigner] = _default_signer
    state: ConsoleState = field(default_factory=ConsoleState)
    proposals: Callable[[], ProposalStore] = ProposalStore
    roots: Callable[[str], trust_anchors.RootPins] = trust_anchors.RootPins.for_environment
    clock: Callable[[], float] = time.time
    metrics: MetricsSources = field(default_factory=MetricsSources)

    def today(self) -> str:
        return utc_day(self.clock())


class _Refused(Exception):
    """A request the console answers with *status* and a safe message."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


class ConsoleActions:
    """What each route does, framework-free: every method returns the JSON body
    or raises :class:`_Refused` / :class:`RosterError` / ``RootSignerError`` /
    ``VerbError`` (``_answer`` turns those into ``{"error"}`` with a status)."""

    def __init__(self, services: ConsoleServices) -> None:
        self._services = services
        self._state = services.state
        # One signature at a time: the version / 24 h / waiting checks and the
        # signature's record are one step, or two racing requests sign two lists
        # at one order (every reader freezes) or two narrowing lists in 24 h.
        self._signing = threading.Lock()

    # -- join requests ------------------------------------------------------------

    def joins(self) -> dict[str, object]:
        return {"joinRequests": [j.as_dict() for j in self._state.joins()]}

    def submit(self, curator_key: str, operator: str, self_test: dict[str, Any]) -> dict[str, object]:
        request = JoinRequest.new(curator_key, operator, SelfTestReport.from_mapping(self_test), self._services.clock())
        self._state.submit(request)
        return request.as_dict()

    def decline(self, curator_key: str) -> dict[str, object]:
        self._pending_join(curator_key)
        return self._state.decide(curator_key, JoinState.DECLINED).as_dict()

    def preview_join(self, curator_key: str, threshold: Optional[int]) -> dict[str, object]:
        ctx = self._context()
        return {"diff": diff(self._effective(ctx), self._proposed_join(ctx, curator_key, threshold))}

    def approve(self, curator_key: str, passphrase: str, second_factor: str, threshold: Optional[int]) -> dict[str, object]:
        ctx = self._context()
        with self._signing:
            staged = self._sign_and_stage(ctx, self._proposed_join(ctx, curator_key, threshold), passphrase,
                                          second_factor)
            self._state.decide(curator_key, JoinState.APPROVED)
        return staged

    # -- removal, renewal, publishing --------------------------------------------------

    def preview_removal(self, curator_key: str) -> dict[str, object]:
        ctx = self._context()
        return {"diff": diff(self._effective(ctx), self._proposed_removal(ctx, curator_key))}

    def remove(self, curator_key: str, passphrase: str, second_factor: str) -> dict[str, object]:
        ctx = self._context()
        with self._signing:
            return self._sign_and_stage(ctx, self._proposed_removal(ctx, curator_key), passphrase, second_factor)

    def renew(self, passphrase: str, second_factor: str) -> dict[str, object]:
        ctx = self._context()
        with self._signing:
            current = self._unwaited(self._effective(ctx))
            proposed = renewed(current, version=self._state.next_version(current), today=self._services.today())
            return self._sign_and_stage(ctx, proposed, passphrase, second_factor)

    def renewal(self) -> dict[str, object]:
        return renewal_status(self._effective(self._context()), self._services.today()).as_dict()

    def publish(self, proposal_id: str, confirmation_code: str) -> dict[str, object]:
        """The existing publish path, for a key list staged here."""
        store = self._services.proposals()
        staged = store.get(proposal_id)
        if staged is None or staged.kind != publishing.MANIFEST_KIND:
            raise _Refused(404, "no staged key list with that id")
        _proposal, outcome = publishing.publish(self._context(), store, proposal_id, typed_code=confirmation_code,
                                                yes=False)
        # publish() promises: the text starts with "published" only after the read-back.
        return {"published": outcome.startswith("published"), "outcome": outcome}

    # -- the steps ---------------------------------------------------------------------

    def _context(self) -> CurateContext:
        try:
            ctx = self._services.context()
        except Exception:   # the node is down or misconfigured: say so, never a traceback
            raise _Refused(503, "the node could not be reached") from None
        if ctx.authority is not Authority.VERIFIED:
            raise _Refused(409, "the key console signs only the verified authority's list (root A)")
        return ctx

    @staticmethod
    def _effective(ctx: CurateContext) -> key_manifest.KeyManifest:
        if ctx.manifest is None:
            raise _Refused(409, "no effective key list yet; the first list comes from the bootstrap ceremony")
        return ctx.manifest

    def _pending_join(self, curator_key: str) -> JoinRequest:
        request = self._state.join(curator_key)
        if request is None or request.state is not JoinState.PENDING:
            raise _Refused(404, "no waiting join request for this key")
        return request

    def _unwaited(self, current: key_manifest.KeyManifest) -> key_manifest.KeyManifest:
        waiting = self._state.waiting_refusal(current, self._services.clock())
        if waiting:
            raise _Refused(409, waiting)
        return current

    def _proposed_join(self, ctx: CurateContext, curator_key: str, threshold: Optional[int]) -> key_manifest.KeyManifest:
        request = self._pending_join(curator_key)
        if not request.self_test.passed:
            raise RosterError("this curator's self-test did not pass the fixture set; it cannot be approved")
        current = self._unwaited(self._effective(ctx))
        return with_curator(current, request.curator_key, request.operator, version=self._state.next_version(current),
                            today=self._services.today(), threshold=threshold)

    def _proposed_removal(self, ctx: CurateContext, curator_key: str) -> key_manifest.KeyManifest:
        current = self._effective(ctx)
        too_soon = self._state.narrowing_refusal(current.root_epoch, self._services.clock())
        if too_soon:
            raise _Refused(409, too_soon)
        return without_curator(current, curator_key, version=self._state.next_version(current))

    def _sign_and_stage(self, ctx: CurateContext, proposed: key_manifest.KeyManifest, passphrase: str,
                        second_factor: str) -> dict[str, object]:
        """Root A signs *proposed* (logged), the console records it, and — only when a
        root pinned for its epoch signed it — stages it APPROVED for :meth:`publish`."""
        before = self._effective(ctx)
        envelope = self._services.signer(ctx).sign(proposed, passphrase, second_factor)
        self._state.record_list(SignedList(proposed.root_epoch, proposed.version, proposed.narrows(before),
                                           self._services.clock()))
        verdict = key_manifest.verify_manifest(envelope, environment=proposed.environment, graph=proposed.graph,
                                               roots=self._services.roots(ctx.environment))
        if verdict is None or verdict.freeze_only:
            raise _Refused(409, f"signed and logged, but this root is not pinned for epoch {proposed.root_epoch}; "
                                "not staged for publishing")
        root = envelope.signatures[0].signer
        proposal = Proposal.new(publishing.MANIFEST_KIND, "curator", envelope, proposed.graph, checks={root: "root"})
        proposal = proposal.transition(ProposalState.PROPOSED).transition(ProposalState.APPROVED)
        self._services.proposals().save(proposal)
        code = consent.ConsentLedger().show(proposal.envelope, publishing.summary(proposal))
        return {"proposalId": proposal.id, "confirmationCode": code, "diff": diff(before, proposed)}


def _answer(work: Callable[[], dict[str, object]], status: int = 200) -> Any:
    """Run *work*; every refusal is ``{"error"}`` with its status, never a traceback."""
    from fastapi.responses import JSONResponse

    try:
        return JSONResponse(work(), status_code=status)
    except _Refused as exc:
        return JSONResponse({"error": str(exc)}, status_code=exc.status)
    except (RosterError, publishing.VerbError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except RootSignerError:
        return JSONResponse({"error": "the root signature was refused"}, status_code=403)


def add_console_routes(app: Any, services: ConsoleServices) -> None:
    """Register the C3 routes and the C4 metrics view on the console app (``app.state.console_services`` too)."""
    app.state.console_services = services
    actions = ConsoleActions(services)
    _add_join_routes(app, actions)
    _add_roster_routes(app, actions)
    _add_metrics_route(app, services)


def _add_join_routes(app: Any, actions: ConsoleActions) -> None:
    from fastapi import Body, Path as PathParam

    @app.get("/api/join-requests")
    def list_joins():
        return _answer(actions.joins)

    @app.post("/api/join-requests")
    def submit_join(curator_key: str = Body(..., alias="curatorKey", max_length=64),
                    operator: str = Body(..., max_length=key_manifest.MAX_OPERATOR_LENGTH),
                    self_test: dict[str, Any] = Body(..., alias="selfTest")):
        return _answer(lambda: actions.submit(curator_key, operator, self_test), status=201)

    @app.post("/api/join-requests/{curator_key}/decline")
    def decline_join(curator_key: str = PathParam(..., pattern=_KEY_PATTERN)):
        return _answer(lambda: actions.decline(curator_key))

    @app.get("/api/join-requests/{curator_key}/preview")
    def preview_join(curator_key: str = PathParam(..., pattern=_KEY_PATTERN), threshold: Optional[int] = None):
        return _answer(lambda: actions.preview_join(curator_key, threshold))

    @app.post("/api/join-requests/{curator_key}/approve")
    def approve_join(curator_key: str = PathParam(..., pattern=_KEY_PATTERN),
                     passphrase: str = Body(..., min_length=1, max_length=MAX_PASSPHRASE_LENGTH),
                     second_factor: str = Body(..., alias="secondFactor", pattern=_SECOND_FACTOR_PATTERN),
                     threshold: Optional[int] = Body(None)):
        return _answer(lambda: actions.approve(curator_key, passphrase, second_factor, threshold))


def _add_roster_routes(app: Any, actions: ConsoleActions) -> None:
    from fastapi import Body, Path as PathParam

    @app.get("/api/curators/{curator_key}/removal-preview")
    def preview_removal(curator_key: str = PathParam(..., pattern=_KEY_PATTERN)):
        return _answer(lambda: actions.preview_removal(curator_key))

    @app.post("/api/curators/{curator_key}/remove")
    def remove_curator(curator_key: str = PathParam(..., pattern=_KEY_PATTERN),
                       passphrase: str = Body(..., min_length=1, max_length=MAX_PASSPHRASE_LENGTH),
                       second_factor: str = Body(..., alias="secondFactor", pattern=_SECOND_FACTOR_PATTERN)):
        return _answer(lambda: actions.remove(curator_key, passphrase, second_factor))

    @app.post("/api/manifest/renew")
    def renew(passphrase: str = Body(..., min_length=1, max_length=MAX_PASSPHRASE_LENGTH),
              second_factor: str = Body(..., alias="secondFactor", pattern=_SECOND_FACTOR_PATTERN)):
        return _answer(lambda: actions.renew(passphrase, second_factor))

    @app.get("/api/renewal")
    def renewal():
        return _answer(actions.renewal)

    @app.post("/api/manifests/{proposal_id}/publish")
    def publish_manifest(proposal_id: str = PathParam(..., pattern=r"^[0-9a-f]{16}$"),
                         confirmation_code: str = Body(..., alias="confirmationCode", embed=True, max_length=16)):
        return _answer(lambda: actions.publish(proposal_id, confirmation_code))


def _add_metrics_route(app: Any, services: ConsoleServices) -> None:
    """``GET /api/metrics`` — the F-035 numbers (C4), read-only; a store that
    cannot be read answers "unavailable" for its metrics, never an error."""

    @app.get("/api/metrics")
    def metrics():
        return _answer(lambda: collect_metrics(services.metrics, services.context, services.clock()).as_dict())


__all__ = ["ConsoleActions", "ConsoleServices", "add_console_routes"]
