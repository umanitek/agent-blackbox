"""``curate`` — the curator node's tooling (Community Graph Refine, R6; Community Curation).

A curator machine acts for ONE authority (:mod:`.context`): the verified one
publishes its manifest and enforcement statements in the verified graph; the
community one publishes everything in the community graph and can only ever
cause FLAG. ``blackbox curate --authority community …`` selects it explicitly.

The read side (queue, dossier, saved node-UI views) and the two-key write
side (propose -> private message -> approve + consent -> publish) of the
curator role. Public entry: :func:`add_curate_parser` (wired by cli.py) and
:func:`status_health_items` (this machine's curator alarms on ``blackbox status``).

* :mod:`.parser` — the `blackbox curate` argument parser; :mod:`.commands` — one Command per verb.
* :mod:`.publishing` — numbering, quorum check, consent and the write of an approved proposal.
* :mod:`.queue` — the delta view (NEW vs ALREADY VERIFIED) and lanes.
* :mod:`.dossier` — evidence dossier (Builder) + the ≤3-item checklist.
* :mod:`.proposal` — proposals and their lifecycle (State) + store.
* :mod:`.consent` — content-bound typed consent + the local ledger.
* :mod:`.promotion` — one community report promoted: which report, what the promotion names, the re-checks.
* :mod:`.transport` — proposals by private point-to-point message.
* :mod:`.intake` — watch the delta view, notify a webhook.
* :mod:`.node_ui_views` — saved queries for the DKG node's own UI.
* :mod:`.catalog_import` — threat-catalog import helpers (unused; kept for adoption or deletion).
"""

from typing import List

from ..kernel.health import HealthItem
from . import transport
from .commands import cmd_curate
from .parser import add_curate_parser
from .service import self_test

__all__ = ["add_curate_parser", "cmd_curate", "status_health_items"]


def status_health_items(now: float) -> list[HealthItem]:
    """This machine's curator alarms for ``blackbox status``: a suspended self-test
    and proposals that reached no other curator for 3 beats. Read from local
    files only; empty on a node that is not a curator."""
    return [*self_test.health_items(self_test.SelfTestStore().read()), *transport.delivery_health_items(now)]
