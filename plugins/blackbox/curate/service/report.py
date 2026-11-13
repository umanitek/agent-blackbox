"""What one beat of the curator service did, and its working state (Community Curation C9).

* :class:`HumanItem` — one thing that waits for a person.
* :class:`BeatReport` — the frozen result of a beat (what ``blackbox curate run`` prints).
* :class:`Run` — the state the beat's steps share while they run.
* :func:`standing` — the line the consent ledger records for an automatic decision.
* :data:`DISPUTE_ROUTE` — where a listed party disputes a verdict; every verdict row names it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

from ...community import reputation
from .. import queue
from ..context import CurateContext, verified_identifiers
from ..proposals import ProposalStore
from . import policy
from ...kernel.signing import CuratorStatement
from .budget import ServiceBudget
from .evidence import OwnCheck
from .policy import PolicyDecision

if TYPE_CHECKING:   # named in annotations only: curate.sources reads service.evidence (an import cycle)
    from ..lab import LabController
    from ..sources import LookupResult

#: The public dispute page (trust-and-threat-lab §03.3): every verdict row names it,
#: so a listed party always knows where to dispute (``intake.DisputeIntake`` serves it).
DISPUTE_ROUTE = "https://blackboxcommand.com/dispute"
#: Verdicts after which the service has nothing more to do for a threat.
SETTLED = frozenset({CuratorStatement.CONFIRMATION, CuratorStatement.REJECTION, CuratorStatement.REVOCATION})


@dataclass(frozen=True)
class HumanItem:
    """One thing that waits for a person: ``subject`` (a threat, ``author:<key>``
    or a proposal id) and ``why`` the service did not do it."""

    subject: str
    why: str


@dataclass(frozen=True)
class BeatReport:
    """What one beat did. ``may_sign`` — the service was allowed to sign
    (``why_not`` says why not). ``heartbeat`` — "published", "not due", or
    what stopped it. ``received`` / ``dropped`` — proposals taken from the
    inbox / messages that were not a curator's proposal. ``cosigned`` /
    ``proposed`` — proposal ids this beat co-signed and published / signed
    first. ``published`` — single-key statements it published. ``limited`` —
    raising statements left for tomorrow by the service's own daily limit.
    ``human`` — what waits for a person. ``errors`` — steps that failed.
    ``looked_up`` — queue items the outside sources were asked about;
    ``lab_jobs`` — lab jobs requested; ``batch`` — what the batch publisher did
    ("" on a node that does not publish); ``alarms`` — alarms delivered."""

    may_sign: bool
    why_not: str = ""
    heartbeat: str = "not due"
    received: int = 0
    dropped: int = 0
    cosigned: tuple[str, ...] = ()
    proposed: tuple[str, ...] = ()
    published: tuple[str, ...] = ()
    credited: int = 0
    kept_alive: int = 0
    limited: int = 0
    human: tuple[HumanItem, ...] = ()
    errors: tuple[str, ...] = ()
    looked_up: int = 0
    lab_jobs: int = 0
    batch: str = ""
    alarms: int = 0

    def summary(self) -> str:
        signing_state = "signing" if self.may_sign else f"NOT signing ({self.why_not})"
        return (f"beat: {signing_state} · heartbeat {self.heartbeat} · received {self.received} · co-signed {len(self.cosigned)} · "
                f"proposed {len(self.proposed)} · published {len(self.published)} · credited {self.credited} · "
                f"kept alive {self.kept_alive} · held by the daily limit {self.limited} · looked up {self.looked_up} · "
                f"lab jobs {self.lab_jobs} · " + (f"batch {self.batch} · " if self.batch else "")
                + f"alarms {self.alarms} · {len(self.human)} for a person · {len(self.errors)} error(s)")


@dataclass
class Run:
    """The state of one beat (mutable while the steps run; frozen into a :class:`BeatReport`)."""

    ctx: CurateContext
    store: ProposalStore
    ledger: reputation.ReputationLedger
    budget: ServiceBudget
    today: str
    my_key: str
    why_not: str
    heartbeat: str = "not due"
    received: int = 0
    dropped: int = 0
    credited: int = 0
    kept_alive: int = 0
    limited: int = 0
    acknowledged: int = 0
    cosigned: list[str] = field(default_factory=list)
    proposed: list[str] = field(default_factory=list)
    published: list[str] = field(default_factory=list)
    human: list[HumanItem] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    addresses: Optional[dict[str, str]] = None
    #: Identifiers a step already acted on in THIS beat: the view was read when the beat
    #: began, so a later step must not act on what an earlier one just changed.
    settled: set[str] = field(default_factory=set)
    #: The admitted queue as this beat read it (:meth:`queue_view`), and what the sources said (look-up step).
    view: Optional[queue.DeltaView] = None
    looked_up: tuple[LookupResult, ...] = ()
    checks: dict[str, OwnCheck] = field(default_factory=dict)
    lab: Optional[LabController] = None
    lab_jobs: int = 0
    batch: str = ""
    alarms: int = 0

    def queue_view(self) -> queue.DeltaView:
        """The delta view of the compiled community tier, read once a beat (raises without a compiled tier)."""
        if self.view is None:
            compiled = self.ctx.compiled
            if compiled is None:
                raise LookupError("no compiled ruleset: the queue is not known")
            self.view = queue.delta_view(compiled.community, verified_identifiers(compiled, compiled.community))
        return self.view

    @property
    def may_sign(self) -> bool:
        return not self.why_not

    def report(self) -> BeatReport:
        return BeatReport(may_sign=self.may_sign, why_not=self.why_not, heartbeat=self.heartbeat, received=self.received,
                          dropped=self.dropped, cosigned=tuple(self.cosigned), proposed=tuple(self.proposed),
                          published=tuple(self.published), credited=self.credited, kept_alive=self.kept_alive,
                          limited=self.limited, human=tuple(self.human), errors=tuple(self.errors),
                          looked_up=len(self.looked_up), lab_jobs=self.lab_jobs, batch=self.batch, alarms=self.alarms)


def standing(decision: PolicyDecision) -> str:
    """The standing-consent line the consent ledger records for an automatic decision."""
    return f"{decision.action.value}: {decision.reason} (policy {policy.policy_hash()[:8]})"
