"""What one attach or detach of one agent reports — the shape every caller reads.

:func:`attach_hermes` / :func:`detach_hermes` / :func:`attach_openclaw` /
:func:`detach_openclaw` each return one :class:`AttachReport`; the CLI printers, the
dashboard's agent window, the auto-attach audit (``guard.background``) and uninstall read
it. Keys an operation does not set are absent (``report.get(key)``), hence ``total=False``.
It stays a dict on purpose: the dashboard serves these rows as JSON unchanged.
"""

from __future__ import annotations

from typing import TypedDict


class AttachReport(TypedDict, total=False):
    """One target's attach / detach outcome.

    Every report: ``target`` (the folder), ``kind`` ("hermes" | "openclaw"), ``ok`` (the
    operation finished; False with ``error`` when it failed open), ``already`` (nothing to do),
    ``dry_run``. Attach: ``protected`` (Blackbox loads there now), ``changed`` (anything was
    written — what auto-attach audits; every kind sets it). Hermes attach: ``copied`` (the plugin
    files), ``enabled`` (``plugins.enabled``). Hermes detach: ``disabled``, ``removed`` (files
    deleted). OpenClaw: ``config_path`` (the config file), ``backed_up`` (a copy of it was kept), ``version`` /
    ``unsupported`` (the OpenClaw found), ``note`` (said to the operator, e.g. comments not kept).
    """

    target: str
    kind: str
    ok: bool
    already: bool
    dry_run: bool
    error: str
    protected: bool
    changed: bool
    copied: bool
    enabled: bool
    disabled: bool
    removed: bool
    config_path: str
    backed_up: bool
    version: str
    unsupported: bool
    note: str
