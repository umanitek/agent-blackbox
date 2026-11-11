"""This node's reporting identity — the agent address it speaks for.

THE one resolver of "who is this node" for anything identity-keyed (report
subjects, per-reporter counting, the in-report signature R0 adds). Kernel,
because both the community write path and the hooks need it and neither owns
it. Fails closed: ``None`` means "no identity", never a shared placeholder.

Usage::

    from ..kernel import identity
    reporter = identity.reporter_address(client)   # str | None
"""

from __future__ import annotations

from typing import Optional

from .dkg_client import DkgClient

_reporter_cache: dict[str, str] = {}


def reporter_address(client: DkgClient) -> Optional[str]:
    """Resolve this node's agent address (cached), or ``None`` when unknown.

    Pattern: Sentinel Object — ``None`` IS the "no identity" signal (KI-003).
    The old ``"node"`` string fallback would have merged every identity-less
    node worldwide onto one report subject (first-writer-wins), silently
    dropping reports and corrupting distinct-reporter counting. Identity-keyed
    writes fail closed instead; only real addresses are cached.

    ``agent_identity`` is definitive; ``status`` is a fallback for older daemons.
    """
    if "addr" in _reporter_cache:
        return _reporter_cache["addr"]
    for resolver_name in ("agent_identity", "status"):
        resolver = getattr(client, resolver_name, None)
        if resolver is None:
            continue
        try:
            info = resolver()
        except Exception:
            continue
        if not isinstance(info, dict):
            continue
        for key in ("agentAddress", "defaultAgentAddress", "address"):
            val = info.get(key)
            if isinstance(val, str) and val.strip():
                _reporter_cache["addr"] = val.strip()
                return _reporter_cache["addr"]
    return None
