"""The per-agent network rules a Linux policy asks of the root helper (design "Linux deep layers"
§1.3, build step 17): Linux's sandbox can not refuse a TCP connect by port from inside an
unprivileged launcher, so the helper's nftables table refuses it for each agent's cgroup scope —
ssh back into this computer always (the never-list), Docker's TCP ports while ``docker`` is
refused, every local port but the listed ones, DNS and the dashboard's while ``local-ports`` is
blocked. The helper learns them from File Shield's watch plan (``agents``), keyed by each policy's
digest (the scope's name carries it).

Usage::

    network_rules(policy_text)   # NetworkRules(digest="0123…", local_ports=True, allow=(5432,), docker_tcp=True)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

#: How many digest characters a scope's name carries (the launcher's ``scope::DIGEST_CHARS``).
SCOPE_DIGEST_CHARS = 12


@dataclass(frozen=True)
class NetworkRules:
    """What one policy refuses on the network: ``local_ports`` (every local TCP port but ``allow``),
    ``docker_tcp`` (Docker's TCP ports). ssh back into this computer is refused for every agent."""

    digest: str
    local_ports: bool = False
    allow: tuple[int, ...] = ()
    docker_tcp: bool = False

    def plan(self) -> dict[str, object]:
        """The watch plan's entry (JSON) for the helper."""
        return {"digest": self.digest[:SCOPE_DIGEST_CHARS], "local_ports": self.local_ports, "allow": list(self.allow),
                "docker_tcp": self.docker_tcp}


def _digest(line: str) -> str:
    marker = line.rsplit("sha256:", 1)
    hexes = marker[1].strip() if len(marker) == 2 else ""
    return hexes if hexes and all(char in "0123456789abcdef" for char in hexes) else ""


def network_rules(text: str) -> Optional[NetworkRules]:
    """The rules in a rendered policy *text*, None when it carries no digest (an unsigned render)."""
    lines = text.splitlines()
    digest = _digest(lines[1]) if len(lines) > 1 else ""
    if not digest:
        return None
    ports: set[int] = set()
    blocked = docker = False
    for line in lines[2:]:
        name, _, value = line.partition(" ")
        if name == "local-ports":
            blocked = value == "block"
        elif name in ("allow-port", "dashboard-port") and value.isdigit():
            ports.add(int(value))
        elif name == "docker":
            docker = value == "refuse"
    return NetworkRules(digest, blocked, tuple(sorted(ports)) if blocked else (), docker)


__all__ = ["SCOPE_DIGEST_CHARS", "NetworkRules", "network_rules"]
