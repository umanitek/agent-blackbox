"""What this curator node published in the community graph and must keep alive.

Every reader keeps its own verified copy of the trust statements it has seen
(``community.trust.trust_store``), but a node that joins later only sees what
is on the network NOW — and shared memory forgets after about 30 days. So the
machine that published a statement re-publishes it once per keep-alive epoch
(10 days by default: a third of the memory) under a new asset name with the
same signed content; readers fold the copies to one.

Only CURRENT statements are kept alive: publishing a newer statement in the
same slot — a delisting after a listing, a rejection after a confirmation, a
new manifest — ends keep-alive for the older one, and a listing past its
expiry or a pause past its end is retired. Heartbeats are never kept alive
(a fresh one is published every day).

The store reuses the report keep-alive store (one implementation of the
"what must I re-publish" file); only its path differs:
``$BLACKBOX_HOME/curate/published_statements.json``.

Usage::

    published.remember(cfg, graph=graph, name=asset_name, quads=quads)        # after a publish that was read back
    sent = published.publish_due(client, cfg)                                 # from the curator's beat
    published.forget_identifier("author:<reporter key>")                      # a reporter asked to be erased
"""

from __future__ import annotations

import json
import logging
import time
from datetime import date, timedelta
from typing import Any, Iterable, Optional

from ... import community
from ...kernel.health import utc_day
from ...kernel import constants, dkg_client, signing
from ...kernel.signing import KEY_MANIFEST_STATEMENT
from ...kernel.signing import CuratorStatement
from .. import keys

logger = logging.getLogger(__name__)

_STORE_FILE = "published_statements.json"
#: Most copies one beat sends (a curator with many current statements spreads them).
MAX_COPIES_PER_BEAT = 50
#: How many statements a slot keeps alive: the two newest pauses (readers need
#: the previous one to refuse a back-to-back renewal), one of everything else.
_KEPT_PER_SLOT = {"pause": 2}
_VERDICTS = frozenset({CuratorStatement.CONFIRMATION.value, CuratorStatement.REJECTION.value,
                       CuratorStatement.IN_REVIEW.value, CuratorStatement.DEFERRAL.value,
                       CuratorStatement.DEFERRAL_LAPSED.value})


def store() -> community.keep_alive.LiveReportStore:
    """The published-statements store (the report keep-alive store at the curator's path)."""
    return community.keep_alive.LiveReportStore(keys.curate_home() / _STORE_FILE)


def _signed(quads: Iterable[dict[str, str]]) -> Optional[signing.SignedEnvelope]:
    """The signed envelope a statement's quads carry (None: nothing to keep alive)."""
    for quad in quads:
        if quad.get("predicate") == constants.SIGNED_STATEMENT_PRED:
            text = quad["object"]
            return signing.from_text(_unquote(text))
    return None


def _unquote(literal: str) -> str:
    """The text inside an N-Triples string literal."""
    try:
        return str(json.loads(literal))
    except ValueError:
        return literal.strip('"')


def slot(envelope: signing.SignedEnvelope) -> Optional[tuple[str, str]]:
    """Which slot a statement occupies — a newer statement in the same slot
    supersedes it. None: never kept alive (a heartbeat)."""
    kind = envelope.statement_type
    identifier = str(envelope.payload.get("identifier", ""))
    if kind == CuratorStatement.HEARTBEAT.value:
        return None
    if kind == KEY_MANIFEST_STATEMENT:
        return "manifest", envelope.graph
    if kind in _VERDICTS:
        return "verdict", identifier
    if kind == CuratorStatement.AWAY.value:
        return "away", str(envelope.payload.get("key", ""))
    return kind.split(".", 1)[-1].replace("counted-authors", "listing"), identifier


def _order(envelope: signing.SignedEnvelope) -> tuple[int, int]:
    return envelope.root_epoch, envelope.sequence


def remember(cfg: Any, *, graph: str, name: str, quads: list[dict[str, str]], now: Optional[float] = None) -> None:
    """Remember a statement this node just published in the community graph (and
    read back), so it is kept alive; older statements in the same slot stop
    being kept alive. Fail-open: a publish never fails over its memory."""
    try:
        envelope = _signed(quads)
        where = slot(envelope) if envelope is not None else None
        days = float(getattr(cfg, "community_keepalive_epoch_days", 0) or 0)
        if envelope is None or where is None or days <= 0:
            return
        when = time.time() if now is None else now
        live = store()
        live.remember(graph=graph, name=name, identifier=str(envelope.payload.get("identifier", "")) or where[1],
                      subject=quads[0]["subject"], severity="info", quads=quads,
                      epoch=community.keep_alive.current_epoch(when, days))
        _retire_superseded(live, where)
    except Exception as exc:   # never fail a publish over its memory
        logger.warning("blackbox: could not remember a published curator statement for keep-alive (%s)", exc)


def _retire_superseded(live: Any, where: tuple[str, str]) -> None:
    """Keep only the newest statement(s) of *where*; the rest are allowed to lapse."""
    entries = []
    for entry in live.all():
        envelope = _signed(entry.quads)
        if envelope is not None and slot(envelope) == where:
            entries.append((_order(envelope), entry.name))
    entries.sort(reverse=True)
    stale = [name for _, name in entries[_KEPT_PER_SLOT.get(where[0], 1):]]
    if stale:
        live.forget_names(stale)


def _still_current(envelope: signing.SignedEnvelope, today: str) -> bool:
    """False for a listing past the day readers stop counting it, and a pause past its end."""
    kind, payload = envelope.statement_type, envelope.payload
    if kind == CuratorStatement.PAUSE.value:
        return str(payload.get("until", "")) >= today
    if kind == CuratorStatement.COUNTED_AUTHORS.value and payload.get("listed") == "yes":
        try:
            capped = (date.fromisoformat(str(payload.get("day"))) + timedelta(days=community.COMMUNITY_LISTING_MAX_DAYS)).isoformat()
        except ValueError:
            capped = str(payload.get("expires", ""))
        return min(str(payload.get("expires", "")), capped) >= today
    return True


def publish_due(client: Any, cfg: Any, now: Optional[float] = None) -> int:
    """Re-publish this epoch's copy of every current statement that lacks one;
    returns how many copies were sent. The first refused share ends the beat
    (the node is refusing writes; the next beat tries again)."""
    days = float(getattr(cfg, "community_keepalive_epoch_days", 0) or 0)
    if days <= 0:
        return 0
    when = time.time() if now is None else now
    today = utc_day(when)
    epoch = community.keep_alive.current_epoch(when, days)
    live = store()
    sent, retired = 0, []
    for entry in live.due(epoch, when)[:MAX_COPIES_PER_BEAT]:
        envelope = _signed(entry.quads)
        if envelope is None or not _still_current(envelope, today):
            retired.append(entry.name)
            continue
        try:
            community.ensure_report_lane(client, entry.graph)
            client.share_knowledge_asset(entry.graph, community.keep_alive.copy_name(entry.name, epoch), list(entry.quads))
        except Exception as exc:
            if not dkg_client.is_already_sealed(exc):
                logger.info("blackbox: curator keep-alive copy refused this beat (%s); retrying on the next", str(exc)[:120])
                break
        live.mark_published(entry.name, epoch)
        sent += 1
    if retired:
        live.forget_names(retired)
    if sent:
        logger.info("blackbox: %d curator statement(s) kept alive for epoch %d", sent, int(epoch))
    return sent


def forget_identifier(identifier: str) -> int:
    """Stop keeping every statement about *identifier* alive (a reporter's erasure request)."""
    return store().forget_identifier(identifier)
