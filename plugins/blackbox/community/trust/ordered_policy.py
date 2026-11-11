"""The freeze, ceiling and sticky rules a reader applies to ordered root-signed statements.

Key manifests (:mod:`.manifests`) and graph migrations (:mod:`.migrations`) are both
signed by a trusted root, ordered by ``(root epoch, sequence)``, and followed by the
SAME rules (D30/D31 — "a freeze holds"). These rules decide whether someone holding a
root key can move readers, so they are written once, here:

* a CONFLICT at an order is two different contents there (pending ones included — a
  counter-statement is the defender's tool and freezes at once) or any freeze-only
  statement there (a pinned root signing another epoch may freeze, never lead);
* a conflict ABOVE the reader's sticky order freezes it: that order and every order above
  it are skipped (the CEILING), so one counter-statement stops a flood of versions;
* a conflict AT OR BELOW the sticky order never moves the reader — it is reported as an
  ignored conflict (someone with a root key is signing old orders);
* at the sticky order only the content the reader already followed (*sticky_hash*) is
  usable; without a hash an ambiguous sticky order is skipped, never guessed.

Each caller hands in :class:`Ordered` items — its own records reduced to order, content
hash and freeze-only — and keeps only what is its own (a manifest's narrowing step, a
migration's time-lock). Pure functions; no I/O.

Usage::

    items = [Ordered(m.order, m.content_hash(), v.freeze_only) for v in verdicts]
    if usable(item, conflicts=conflict_orders(items), ceiling=ceiling(items, sticky), sticky_order=sticky,
              sticky_hash=h): ...
"""

from __future__ import annotations

from typing import Iterable, NamedTuple, Optional

#: ``(root epoch, sequence)`` — later is higher.
Order = tuple[int, int]


class Ordered(NamedTuple):
    """One root-signed statement as these rules see it."""

    order: Order
    content: str            #: what makes two statements at one order the same one or a conflict
    freeze_only: bool = False


def conflict_orders(items: Iterable[Ordered]) -> set[Order]:
    """The orders at which the statements conflict (see the module doc)."""
    contents: dict[Order, set[str]] = {}
    conflicts: set[Order] = set()
    for item in items:
        contents.setdefault(item.order, set()).add(item.content)
        if item.freeze_only:
            conflicts.add(item.order)
    return conflicts | {order for order, hashes in contents.items() if len(hashes) > 1}


def freezing(conflicts: set[Order], sticky_order: Optional[Order]) -> set[Order]:
    """The conflicts that move the reader: those ABOVE its sticky order (all of them without one)."""
    return {order for order in conflicts if sticky_order is None or order > sticky_order}


def freeze_order(items: Iterable[Ordered], sticky_order: Optional[Order] = None) -> Optional[Order]:
    """The lowest conflict above *sticky_order*: the order the reader is frozen at (None: not frozen)."""
    return min(freezing(conflict_orders(items), sticky_order), default=None)


def ignored_conflict(items: Iterable[Ordered], sticky_order: Optional[Order]) -> bool:
    """SECURITY: a conflict at or below the sticky order — it cannot move this reader, but
    someone with a root key is signing old orders."""
    return sticky_order is not None and any(order <= sticky_order for order in conflict_orders(items))


def usable(item: Ordered, *, conflicts: set[Order], sticky_order: Optional[Order], sticky_hash: str) -> bool:
    """Whether the reader may follow *item*: below the ceiling (the lowest freezing conflict);
    at the sticky order only with the sticky content; elsewhere only at an unconflicted order.
    A freeze-only item is never followed (the caller drops it; it only conflicts)."""
    ceiling = min(freezing(conflicts, sticky_order), default=None)
    if ceiling is not None and item.order >= ceiling:
        return False
    if item.order == sticky_order and sticky_hash:
        return item.content == sticky_hash
    return item.order not in conflicts
