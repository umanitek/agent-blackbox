"""``blackbox curate policy`` and ``blackbox curate run`` (Community Curation C9).

``policy`` — read, accept or withdraw the automation policy. Accepting is a
typed act, like every curator consent: the operator types the first 8 hex
characters of the policy's hash, shown under the text. No node is contacted;
the acceptance is a local file.

``run`` — the curator service: one beat every few minutes (``--once`` for a
single beat). It is its own process, started only on curator nodes; with
``--publisher`` (the wallet holder's node, curator A) its beat also publishes
the batches (step 8).

Both verbs register here (:func:`add_service_parser`, called by
``curate/parser.py``); each sub-parser's ``func`` default dispatches straight
to :func:`cmd_service`.
"""

from __future__ import annotations

import argparse
import time
from typing import TYPE_CHECKING, Any, Optional, Sequence

from .. import keys
from ..proposals import CODE_CHARS
from ..context import build_context
from ..publishing import VerbError
from ..publishing.errors import guarded
from ...kernel import display_safety
from . import policy
from .beat import Beat, ContextFactory
from .policy_consent import PolicyConsent

if TYPE_CHECKING:   # .steps is imported when the service starts (see beat.py)
    from .steps import ServiceSteps

#: The shortest pause between two beats (a beat reads the whole community graph).
MIN_INTERVAL_SECONDS = 60.0
_term = display_safety.term_safe


def policy_command(*, accept: bool, withdraw: bool, code: Optional[str]) -> int:
    """Show the policy and where this machine stands; ``--accept --code`` or ``--withdraw`` change it."""
    consent = PolicyConsent()
    text, key_hex = policy.policy_text(), keys.curator_key_store().public_key_hex()
    shown_code = policy.policy_hash()[:CODE_CHARS]
    if withdraw:
        print("standing consent withdrawn: the service signs nothing on its own from its next beat"
              if consent.withdraw() else "there was no standing consent on this machine")
        return 0
    if accept:
        if (code or "").strip().lower() != shown_code:
            raise VerbError(f"type the code shown under the policy to accept it (--code {shown_code} for the text as it is now)")
        consent.accept(text, key_hex=key_hex, day=time.strftime("%Y-%m-%d", time.gmtime()))
        print(f"accepted for curator key {key_hex[:16]}…: the service may now sign what this policy allows")
        return 0
    print(text)
    held = consent.acceptance()
    if consent.accepted(text, key_hex):
        print(f"ACCEPTED on {held.day} for this machine's curator key. `blackbox curate policy --withdraw` stops the service signing.")
    elif held is not None:
        print("NOT ACCEPTED: the policy text or this machine's key changed since the last acceptance. The service signs nothing.")
    else:
        print("NOT ACCEPTED: the service prepares proposals and waits for a person.")
    print(f"To accept this exact text: blackbox curate policy --accept --code {shown_code}")
    return 0


def add_service_parser(verbs_: Any) -> None:
    """Register ``run`` and ``policy`` on the ``blackbox curate`` verbs."""
    r = verbs_.add_parser("run", help="The curator service: heartbeat, routine confirmations, the ladder, keep-alive, "
                                      "source look-ups, alarms; the rest waits for a person")
    r.add_argument("--peer", action="append", metavar="PEER", help="another curator's node (name or peer id); repeat for each")
    r.add_argument("--interval", type=float, default=300.0, help="seconds between beats (default 300, at least 60)")
    r.add_argument("--once", action="store_true", help="one beat, then exit")
    r.add_argument("--publisher", action="store_true",
                   help="this node holds the publishing wallet: each beat also publishes a batch of confirmed threats (step 8)")
    r.set_defaults(func=cmd_service)
    o = verbs_.add_parser("policy", help="The automation policy: what the curator service may sign on its own; accept or withdraw it")
    change = o.add_mutually_exclusive_group()
    change.add_argument("--accept", action="store_true", help="accept the policy exactly as shown (needs --code)")
    change.add_argument("--withdraw", action="store_true", help="withdraw the standing consent")
    o.add_argument("--code", default=None, help="the 8-hex code shown under the policy text")
    o.set_defaults(func=cmd_service)


@guarded
def cmd_service(args: argparse.Namespace) -> int:
    """``run`` or ``policy``; 2 when refused, 1 when it failed (:func:`..publishing.errors.guarded`)."""
    if args.verb == "policy":
        return policy_command(accept=args.accept, withdraw=args.withdraw, code=args.code)   # local: no context

    def context(interest: Sequence[str]):
        return build_context(getattr(args, "compiled_ruleset", None), authority=getattr(args, "authority", None),
                             interest=interest)
    return run_command(context, peers=args.peer or [], interval=args.interval, once=args.once,
                       publisher=args.publisher)


def run_command(context: ContextFactory, *, peers: Sequence[str], interval: float, once: bool, publisher: bool = False,
                steps: Optional[ServiceSteps] = None) -> int:
    """Run the curator service: beat, say what happened, sleep, repeat. With
    *once*, one beat; the exit code is 1 when a step of it failed. *publisher* —
    this node publishes the batches; *steps* — the trust-and-threat-lab steps
    (default: this node's, :meth:`.steps.ServiceSteps.for_node`)."""
    if steps is None:
        from .steps import ServiceSteps   # see the TYPE_CHECKING import above
        steps = ServiceSteps.for_node(publisher=publisher, beat_seconds=max(MIN_INTERVAL_SECONDS, interval))
    beat = Beat(context, peers=peers, steps=steps)
    while True:
        report = beat.run()
        print(report.summary())
        for item in report.human[:20]:
            print(f"  for a person: {_term(item.subject, 90)} — {_term(item.why, 160)}")
        for error in report.errors:
            print(f"  error: {_term(error, 200)}")
        if once:
            return 1 if report.errors else 0
        time.sleep(max(MIN_INTERVAL_SECONDS, interval))
