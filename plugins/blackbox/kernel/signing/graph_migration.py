"""The graph migration statement — the authority may name a successor graph.

A verified graph's id is tied to the publisher that owns it, so moving the
verified tier to a new graph needs a statement readers can check offline,
not a release. A graph migration is that statement: signed by a ROOT exactly
like a key manifest (:mod:`.key_manifest`), it says that for ONE environment
(DKG network id) the verified graph ``from_graph`` is succeeded by
``to_graph`` from the UTC day ``from_day``.

It is a cut-off, not a copy: what ``from_graph`` held before ``from_day``
keeps its standing there, and new rows come from ``to_graph``. How readers
apply it (the time-lock counted from ``issued_day``, freezes on a
conflicting statement at the same order, which graph is active) is reader
policy in ``community/trust`` — this module is only the FORMAT.

Migrations are ordered by ``(root_epoch, sequence)`` compared as a pair, like
manifests. The envelope is bound to ``from_graph`` — the graph a reader is
configured with — so it verifies the same wherever the row was found, and
can never be replayed as a statement about another graph. Verification uses
the same epoch-bound rules as a manifest: a root pinned for ANOTHER epoch
yields :attr:`MigrationVerdict.freeze_only` — it may conflict, never be
followed.

Pattern: Value Objects (:class:`GraphMigration`, :class:`MigrationVerdict`) + pure functions.

Usage::

    from ..kernel.signing import graph_migration, trust_anchors
    migration = graph_migration.GraphMigration(environment=net, from_graph=old_graph, to_graph=new_graph,
        from_day="2026-10-10", issued_day="2026-10-11", root_epoch=1, sequence=1)
    envelope = graph_migration.sign_migration(migration, root_private_key)
    verdict = graph_migration.verify_migration(envelope, environment=net, graph=old_graph,
                                               roots=trust_anchors.RootPins.for_environment(net))
    if verdict is not None and not verdict.freeze_only:
        verdict.migration.to_graph     # the successor, once reader policy says it is in effect
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Mapping, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import envelope as signing
from .trust_anchors import RootPins

#: The statement type of a graph migration (signed by a root).
GRAPH_MIGRATION_STATEMENT = "blackbox.graph-migration"
#: Payload fields, all required.
_PAYLOAD_FIELDS = ("environment", "fromGraph", "toGraph", "fromDay", "issuedDay", "rootEpoch", "sequence")


class GraphMigrationError(ValueError):
    """A migration that must not be built or trusted; the message says why."""


@dataclass(frozen=True)
class GraphMigration:
    """One environment's verified graph handed to its successor, signed by a root.

    ``environment`` — the DKG network id it applies to. ``from_graph`` — the
    verified graph being succeeded (the envelope is bound to it).
    ``to_graph`` — the successor graph. ``from_day`` — the UTC day
    (YYYY-MM-DD) from which ``from_graph``'s new rows stop counting.
    ``issued_day`` — the UTC day the root signed it (the time-lock counts from
    it). ``root_epoch`` / ``sequence`` — its order (see :attr:`order`).
    """

    environment: str
    from_graph: str
    to_graph: str
    from_day: str
    issued_day: str
    root_epoch: int
    sequence: int

    def __post_init__(self) -> None:
        _validate(self)

    @property
    def order(self) -> tuple[int, int]:
        """``(root_epoch, sequence)`` — compare migrations by this pair."""
        return self.root_epoch, self.sequence

    def to_payload(self) -> dict[str, str]:
        """The migration as the flat str→str payload its envelope signs."""
        return {
            "environment": self.environment,
            "fromGraph": self.from_graph,
            "toGraph": self.to_graph,
            "fromDay": self.from_day,
            "issuedDay": self.issued_day,
            "rootEpoch": str(self.root_epoch),
            "sequence": str(self.sequence),
        }


def _validate(migration: GraphMigration) -> None:
    for name in ("environment", "from_graph", "to_graph"):
        value = getattr(migration, name)
        if not (isinstance(value, str) and value and value == value.strip()):
            raise GraphMigrationError(f"{name} must be a non-empty string without edge spaces")
    if migration.from_graph == migration.to_graph:
        raise GraphMigrationError("to_graph must differ from from_graph")
    for name in ("from_day", "issued_day"):
        if not _is_utc_day(getattr(migration, name)):
            raise GraphMigrationError(f"{name} must be a UTC day (YYYY-MM-DD)")
    if migration.root_epoch < 0 or migration.sequence < 1:
        raise GraphMigrationError("root_epoch must be >= 0 and sequence >= 1")


def _is_utc_day(value: object) -> bool:
    if not isinstance(value, str) or len(value) != len("YYYY-MM-DD"):
        return False
    try:
        return date.fromisoformat(value).isoformat() == value
    except ValueError:
        return False


def sign_migration(migration: GraphMigration, root_key: Ed25519PrivateKey) -> signing.SignedEnvelope:
    """The migration as a root-signed statement, bound to its ``from_graph``."""
    return signing.sign(root_key, statement_type=GRAPH_MIGRATION_STATEMENT, environment=migration.environment,
                        graph=migration.from_graph, payload=migration.to_payload(),
                        root_epoch=migration.root_epoch, sequence=migration.sequence)


@dataclass(frozen=True)
class MigrationVerdict:
    """A root-signed migration and how far it may be trusted. ``freeze_only`` —
    True when the signing root is pinned, but for a different epoch: such a
    migration may only CONFLICT with others at its order (freezing readers),
    never become the one they follow."""

    migration: GraphMigration
    freeze_only: bool = False


def verify_migration(envelope: Optional[signing.SignedEnvelope], *, environment: str, graph: str,
                     roots: RootPins) -> Optional[MigrationVerdict]:
    """The verdict when *envelope* is signed by one of *roots* as a migration
    away from *graph* in *environment* and its payload agrees with its signed
    domain fields and is written in its one canonical form; otherwise None.
    ``freeze_only`` when no signing root may sign the migration's root epoch.
    Never raises."""
    if envelope is None:
        return None
    signers = signing.verified_signers(envelope, statement_type=GRAPH_MIGRATION_STATEMENT,
                                       environment=environment, graph=graph, chain="") & roots.keys
    if not signers:
        return None
    migration = _from_payload(envelope.payload)
    if migration is None or (migration.environment, migration.from_graph, migration.root_epoch,
                             migration.sequence) != (environment, graph, envelope.root_epoch, envelope.sequence):
        return None
    # One migration, one signed form: a payload with extra keys or numbers written
    # another way ("01") would be a second statement identity for the same migration.
    if dict(envelope.payload) != migration.to_payload():
        return None
    return MigrationVerdict(migration,
                            freeze_only=not any(roots.may_sign(key, migration.root_epoch) for key in signers))


def parse_migration(payload: Mapping[str, str]) -> GraphMigration:
    """The migration a signed payload carries; raises :class:`GraphMigrationError`
    saying what is missing or invalid."""
    missing = [field for field in _PAYLOAD_FIELDS if field not in payload]
    if missing:
        raise GraphMigrationError(f"migration payload is missing {', '.join(missing)}")
    try:
        root_epoch, sequence = int(payload["rootEpoch"]), int(payload["sequence"])
    except (TypeError, ValueError) as exc:
        raise GraphMigrationError("rootEpoch and sequence must be integers") from exc
    return GraphMigration(environment=payload["environment"], from_graph=payload["fromGraph"],
                          to_graph=payload["toGraph"], from_day=payload["fromDay"],
                          issued_day=payload["issuedDay"], root_epoch=root_epoch, sequence=sequence)


def _from_payload(payload: Mapping[str, str]) -> Optional[GraphMigration]:
    try:
        return parse_migration(payload)
    except GraphMigrationError:
        return None
