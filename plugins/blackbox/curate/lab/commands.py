"""``blackbox curate lab`` — ask the threat lab about one threat, and see the lab
queue (trust-and-threat-lab L4, proposal §03.5).

The verb registers here, never in ``curate/commands.py``: ``curate/parser.py``
calls :func:`add_lab_parser`, and the sub-parser's own ``func`` default
dispatches straight to :func:`cmd_lab`.

* ``blackbox curate lab <identifier>`` — a curator's explicit request (the
  trigger's path (b), ``curate/lab/trigger.py``). Without ``--code`` it shows
  what will be asked and the 8-hex code; with ``--code`` the typed code is
  checked by the consent ledger (single-use, 10 minutes) and the request is
  logged as a human act (:class:`~.trigger.LabRequests`: the threat digest
  and the code, never the identifier's text). The beat's submit step sends
  the job once the item has a partner-cluster report and no source lists
  it. There is no ``--yes``: the request is a person's act.
* ``blackbox curate lab status`` — this node's lab jobs by state, the oldest
  waiting job's age, the typed requests on file and the newest jobs.

Usage::

    blackbox curate lab ioc:domain:wallet-claim.example          # shows the code
    blackbox curate lab ioc:domain:wallet-claim.example --code 1a2b3c4d
    blackbox curate lab status
"""

from __future__ import annotations

import argparse
import shlex
import time
from collections import Counter
from typing import Any, Callable, Optional

from ...kernel import display_safety, threat_ids
from ..proposals import ConsentLedger, confirmation_code
from .jobs import WAITING_STATES, LabJobState, LabJobStore, strip_query, threat_digest
from .trigger import LabRequests

STATUS = "status"
#: The content a request's code is bound to (the consent ledger hashes it).
REQUEST_CONTENT = "blackbox.lab-request\n{identifier}"
#: Longer than any identifier the threat-id builders make; bounds the stored digest's input.
MAX_IDENTIFIER_CHARS = 2_048
#: Jobs listed by ``status`` (newest first).
STATUS_LISTED_JOBS = 20
_term = display_safety.term_safe


def add_lab_parser(verbs_: Any) -> None:
    """Register ``lab`` on the ``blackbox curate`` verbs."""
    lab = verbs_.add_parser("lab", help="The threat lab: request a lab test of one threat (typed code), "
                                        "or `lab status` for the lab queue")
    lab.add_argument("target", metavar="IDENTIFIER|status",
                     help="the threat to test (e.g. ioc:domain:…, dep:npm/…@1.0.0), or `status`")
    lab.add_argument("--code", default=None, help="the 8-hex code shown for this request")
    lab.set_defaults(func=cmd_lab)


def cmd_lab(args: argparse.Namespace) -> int:
    """``status`` or a typed request; 2 when refused, 1 when it failed."""
    try:
        if args.target == STATUS:
            return status_command()
        return request_command(args.target, code=args.code)
    except Exception as exc:  # the outermost CLI boundary: a readable line, never a traceback
        print(f"curate lab failed: {_term(str(exc), 200)}")
        return 1


def request_command(identifier: str, *, code: Optional[str], ledger: Optional[ConsentLedger] = None,
                    requests: Optional[LabRequests] = None) -> int:
    """Show the request's code, or check the typed *code* and log the human act."""
    stored = strip_query(identifier.strip())
    if threat_ids.category_for(stored) == "other" or len(stored) > MAX_IDENTIFIER_CHARS:
        print("Refused: not a threat identifier (dep:…, skill:…, ioc:…, injection:…, escalation:…, fileaccess:…)")
        return 2
    ledger = ledger or ConsentLedger()
    content = REQUEST_CONTENT.format(identifier=stored)
    if code is None:
        # The ledger keeps the summary: the digest, never the identifier's text.
        shown = ledger.show(content, f"lab request {threat_digest(stored)[:16]}")
        print(f"Lab request for {_term(stored, 120)}: the next beat sends it to the lab once a partner")
        print("cluster reports it and no source lists it. It is logged as your act.")
        print(f"To request: blackbox curate lab {shlex.quote(_term(stored, MAX_IDENTIFIER_CHARS))} --code {shown}")
        return 0
    allowed, why = ledger.consent(content, typed=code, sandbox=False, yes=False)
    if not allowed:
        print(f"Refused: {why}")
        return 2
    (requests or LabRequests()).record(stored, code=confirmation_code(content))
    print(f"Requested: {_term(stored, 120)}. `blackbox curate lab status` shows the job once the beat sends it.")
    return 0


def status_command(*, store: Optional[LabJobStore] = None, requests: Optional[LabRequests] = None,
                   clock: Callable[[], float] = time.time) -> int:
    """Print the lab queue on this node."""
    records = (store or LabJobStore()).records()
    counts = Counter(record.state for record in records)
    print("lab jobs: " + ", ".join(f"{state.value} {counts.get(state, 0)}"
                                   for state in LabJobState if state is not LabJobState.REFUSED))
    waiting = [r.job.requested_at for r in records if r.state in WAITING_STATES]
    if waiting:
        print(f"oldest waiting job: {int((clock() - min(waiting)) // 60)} min")
    print(f"typed requests on file: {len((requests or LabRequests()).requested_digests())}")
    for record in sorted(records, key=lambda r: r.job.requested_at, reverse=True)[:STATUS_LISTED_JOBS]:
        job = record.job
        print(f"  level {job.level}  {record.state.value:<14}  {job.lane.name.lower():<28}  {_term(job.identifier, 80)}")
    return 0


__all__ = ["REQUEST_CONTENT", "STATUS", "add_lab_parser", "cmd_lab", "request_command", "status_command"]
