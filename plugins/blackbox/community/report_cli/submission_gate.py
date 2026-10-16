"""The gates a manual `blackbox report` passes before anything is sent (R13, LES-016).

ONE place for the refusal messages the command prints, so the report path and the
statement path cannot drift. Usage::

    reduction = submission_gate.is_reduction(args)
    refusal = submission_gate.refusal_for(cfg, reduction)
    if refusal is not None:
        return refusal          # the exit code; the reason was printed

Why reductions are special (KI-222): a RETRACTION or DISPUTE reduces what the network
believes about a threat, so it must get through even after the operator switched sharing
off or withdrew consent — otherwise withdrawing consent would trap their own statements.
Reports need a configured graph, sharing on, and a consent record for the current terms.
"""

from __future__ import annotations

from typing import Any, Optional

from .. import consent


def is_reduction(args: Any) -> bool:
    """Whether *args* name a statement that only REDUCES (a retraction or a dispute)."""
    return bool(getattr(args, "false_positive", None) or getattr(args, "retract", None))


def refusal_for(cfg: Any, reduction: bool) -> Optional[int]:
    """The exit code to return when the command must stop here (its reason printed), else None."""
    if not cfg.context_graph_id:
        print("Community sharing is dormant: no graph is configured.")
        print("Nothing was submitted.")
        return 2
    if reduction:
        return None
    if not cfg.community_enabled:
        print("Community sharing is OFF (config key `report: false`).")
        print("Nothing was submitted.")
        return 2
    if not consent.in_force():   # R13: the same gate as automatic sharing
        print(f"Not submitted: {consent.why_not()}.")
        return 2
    return None
