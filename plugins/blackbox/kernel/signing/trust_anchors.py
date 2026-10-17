"""Trust anchors — which root keys this node trusts, per authority.

A root key signs one thing: the key manifest that names the curator keys
(:mod:`.key_manifest`). This module answers "which roots may do that here".
There are two authorities (:mod:`.authority`) and their roots are NEVER
interchangeable:

* VERIFIED roots are pinned per NETWORK and bound to a ROOT EPOCH
  (``constants.CURATOR_ROOT_KEYS``, read as :class:`RootPins`): a pinned root
  may sign manifests of its own epoch only. A pinned root that signs another
  epoch is still recognised, but its manifest can only freeze readers, never
  become the list they act on (``key_manifest.ManifestVerdict.freeze_only``) —
  so a root can never sign ahead into another epoch's rotation.
* COMMUNITY roots are pinned per COMMUNITY GRAPH (:data:`COMMUNITY_ROOT_KEYS`):
  a community root is trusted for the one graph it is pinned to and nothing
  else. A graph's entry lists its root and its pre-agreed backup root, so a
  lost or exposed root is replaced by a manifest, not by an emergency release.

Only an UNPINNED network or graph (a development setup) may take roots from the
environment (``BLACKBOX_CURATOR_ROOT_KEYS`` / ``BLACKBOX_COMMUNITY_ROOT_KEYS``);
a pinned one ignores the variable. A root is deliberately NOT a config-file
setting, so a config edit can never move trust: pointing the config at another
graph selects that graph's pin, or no root at all.

Usage::

    from ..kernel.signing import trust_anchors
    pins = trust_anchors.RootPins.for_environment(environment)   # verified authority, by network id
    pins.may_sign(root_hex, root_epoch)                  # False: a wrong-epoch root (freeze only)
    trust_anchors.trusted_roots(environment)             # the same roots as a plain key set
    trust_anchors.community_roots(community_graph_id)    # community authority, by graph id
    trust_anchors.community_root_pinned(graph_id)        # True: the env variable is ignored
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import FrozenSet, Iterable, Mapping, Tuple

from .. import constants

_KEY_HEX = re.compile(r"[0-9a-f]{64}")
_ROOT_ENV = "BLACKBOX_CURATOR_ROOT_KEYS"
_COMMUNITY_ROOT_ENV = "BLACKBOX_COMMUNITY_ROOT_KEYS"

#: Community roots pinned per community graph id: ``{graph id: (root, backup root)}``.
#: Empty: a community authority speaks only in a community graph of its own, and
#: since 2026-10-16 there is one graph, the verified one (readers trust no
#: community root at all — ``community.trust``).
COMMUNITY_ROOT_KEYS: Mapping[str, tuple[str, ...]] = {}


def _keys(values: Iterable[str]) -> frozenset[str]:
    """Well-formed keys only (64 lower-case hex); malformed ones are ignored."""
    return frozenset(k.strip().lower() for k in values if _KEY_HEX.fullmatch(k.strip().lower()))


@dataclass(frozen=True)
class RootPins:
    """The root keys trusted to sign key manifests, and at which root epochs.

    ``by_epoch`` — the PINNED roots: ``((root_epoch, root keys), ...)``, sorted by
    epoch; a pinned root may sign its own epoch(s) only. ``any_epoch`` — roots
    with no epoch binding: the environment override on an UNPINNED (sandbox)
    network, and community roots. A network with pins never has ``any_epoch``
    roots, so the environment cannot add a root to it.

    Pattern: Value Object. Build with :meth:`for_environment` (verified
    authority) or :meth:`unbound` (a plain key set); ask :meth:`may_sign`.
    """

    by_epoch: tuple[tuple[int, frozenset[str]], ...] = ()
    any_epoch: frozenset[str] = frozenset()

    @classmethod
    def for_environment(cls, environment: str, env: Mapping[str, str] = os.environ) -> RootPins:
        """The verified-authority roots of *environment* (a DKG network id): its
        pins from ``constants.CURATOR_ROOT_KEYS``, else (unpinned networks only)
        the ``BLACKBOX_CURATOR_ROOT_KEYS`` variable, valid at any epoch."""
        pinned = constants.CURATOR_ROOT_KEYS.get(environment)
        if pinned:   # a LISTED network never takes the variable — not even when its pins are malformed (fail closed)
            return cls(by_epoch=tuple(sorted((int(epoch), _keys(keys)) for epoch, keys in pinned.items() if _keys(keys))))
        return cls.unbound(env.get(_ROOT_ENV, "").split(","))

    @classmethod
    def unbound(cls, keys: Iterable[str]) -> RootPins:
        """Roots that may sign at any epoch (malformed keys are ignored)."""
        return cls(any_epoch=_keys(keys))

    @property
    def keys(self) -> frozenset[str]:
        """Every trusted root, whatever its epoch."""
        return self.any_epoch.union(*(keys for _, keys in self.by_epoch))

    @property
    def pinned(self) -> bool:
        """True when the roots are epoch-bound pins (the environment is ignored)."""
        return bool(self.by_epoch)

    def may_sign(self, key: str, root_epoch: int) -> bool:
        """True when *key* is trusted to sign a manifest at *root_epoch*."""
        key = key.lower()
        return key in self.any_epoch or any(key in keys for epoch, keys in self.by_epoch if epoch == root_epoch)

    def __bool__(self) -> bool:
        return bool(self.keys)


def trusted_roots(environment: str, env: Mapping[str, str] = os.environ) -> frozenset[str]:
    """The curator root keys *environment* trusts, as a plain set (every epoch):
    for membership checks only. Verifying a manifest needs the epochs —
    use :meth:`RootPins.for_environment`."""
    return RootPins.for_environment(environment, env).keys


def community_root_pinned(graph_id: str) -> bool:
    """True when *graph_id* has pinned community roots (the environment is then ignored)."""
    return bool(COMMUNITY_ROOT_KEYS.get(graph_id))


def community_roots(graph_id: str, env: Mapping[str, str] = os.environ) -> frozenset[str]:
    """The community root keys trusted for the community graph *graph_id*: the
    pinned ones, else (unpinned graphs only) those in
    ``BLACKBOX_COMMUNITY_ROOT_KEYS``. No graph id, no root."""
    if not graph_id:
        return frozenset()
    pinned = COMMUNITY_ROOT_KEYS.get(graph_id)
    if pinned:
        return _keys(pinned)
    return _keys(env.get(_COMMUNITY_ROOT_ENV, "").split(","))
