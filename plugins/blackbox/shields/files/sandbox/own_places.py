"""Blackbox's own files the agent sandbox keeps closed to writes, worked out from the agent catalogue
(no OS calls here).

* :func:`hook_configs` — every coding agent's hook config and Blackbox's own hook files in the
  person's home: closed to writes inside the sandbox, so a program an agent starts can not take
  Blackbox's hook out of its own agent's config.

Usage::

    hook_configs()     # ["/Users/me/.claude/settings.json", …]
"""

from __future__ import annotations

from pathlib import Path

from ....kernel import agent_hosts


def hook_configs() -> list[str]:
    """Every coding agent's hook config and Blackbox's own hook files in the default home: closed
    to writes inside the sandbox, so a program an agent starts can not take Blackbox's hook out of
    its own agent's config (hook-layer refusals stop the agent's own tools; this stops a script)."""
    user = Path.home()
    out = []
    for host in agent_hosts.HOSTS:
        target = host.config_path(user)
        out += [str(target / event) for event in host.events] if host.style == "scripts" else [str(target)]
        out += [str(path) for path in host.companion_paths(user)]
    return out


__all__ = ["hook_configs"]
