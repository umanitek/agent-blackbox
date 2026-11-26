"""Agent Blackbox — graph-driven agent security for Hermes.

Blackbox syncs a threat ruleset from the local OriginTrail DKG node (verified
threats from the public graph + the node's local graph) and matches every tool
call and model request against it. In audit mode (default) it records findings
and shares anonymized sightings; in block mode it refuses tool calls that match
a threat at or above the configured severity.

This module is intentionally thin: it wires the five hooks and the ``blackbox``
CLI, delegating all behaviour to the feature packages (:mod:`guard` for the hooks,
:mod:`cli` for the command). The package map is ARCHITECTURE.md.

WHY nothing heavy is imported here (Linux round L7, BB-LINUX-PENDING-cc89c4): Hermes drops a
plugin whose import + ``register()`` overruns ``plugins.load_timeout_seconds`` (10 s), and the
whole guard took 10-15 s to import on a busy 4-CPU machine. ``register()`` now only hands
Hermes the gates of ``guard.startup`` (standard library only) and returns in microseconds; the
guard loads on its own thread at the first hook call (see ``guard/startup.py`` for what a hook
does meanwhile), and the CLI's modules load when Hermes builds the ``blackbox`` command.
"""

from __future__ import annotations

from .guard import startup as _startup
from .kernel.constants import __version__

__all__ = ["__version__", "register"]


def _setup_cli(parser) -> None:
    """Build the ``blackbox`` subcommands (imports the CLI, never beside the guard's own start)."""
    with _startup.loading():
        from . import cli
    cli.setup_cli(parser)


def register(ctx) -> None:
    """Wire Blackbox's hooks and CLI into the hermes plugin context."""
    for name, gate in _startup.HERMES_HOOKS.items():
        ctx.register_hook(name, gate)
    ctx.register_cli_command(
        "blackbox",
        "Agent Blackbox — threat-graph-driven agent security",
        _setup_cli,
    )
