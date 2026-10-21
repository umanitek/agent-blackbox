"""Detection — the CHECK hot path: is this tool call / model request a threat?

Pure matchers over the ruleset — public dependency / IOC rules are asked of the
ruleset object (a live lookup against the node's local store, DKG-lookup B4),
the small tiers are scanned from its compiled lists — plus two advisory look-asides.
Callers use this package's surface only:

* ``Finding`` and the ``detect_*`` / ``discover_*`` functions (from
  :mod:`.detectors`) — pure, microsecond-scale, no I/O.
* Action parsing used by the hook's activity log — ``parse_dependency_installs``,
  ``parse_downloads``, ``parse_shell_reads``, ``file_access_arg``,
  ``command_from_args`` / ``SHELL_TOOLS``, and ``shell_file_args`` (what a shell
  command reads or copies whole — Trader Shield's wallet matcher builds on it).
* :mod:`.osv` — OSV.dev dependency lookups (3 s timeout, background only).
* :mod:`.reviewer` — the opt-in LLM second opinion (advisory, never blocks);
  :func:`cmd_setup_llm` configures it (``blackbox setup-llm``).

Usage::

    from ..detection import Finding, detect_all
    from ..detection import osv, reviewer
"""

from __future__ import annotations

from . import osv, reviewer
from .action_parsing import (FETCH_TOOL_PREFIXES, HOST_FILE_AND_SKILL_TOOLS, SENSITIVE_PATH_CATEGORIES, file_access_arg, parse_dependency_installs,
                             parse_downloads, parse_shell_reads, skill_install_arg)
from .content_scanners import SKILL_DANGER_SHAPES
from .osv import DEPENDENCY_ECOSYSTEMS, advisory_kind
from .reviewer_setup import cmd_setup_llm
from .finding import KIND_FLAG_ONLY
from .detectors import (
    ANSWERED_BY_FALLBACK,
    Finding,
    detect_all,
    detect_custom_fileaccess,
    detect_own_wallet_keys,
    detect_dependency,
    detect_escalation,
    detect_fileaccess,
    detect_injection,
    detect_ioc,
    detect_model_request_secrets,
    detect_secret_exposure,
    detect_skill,
    discover_dependency_candidates,
    discover_injection,
    injection_scan_text,
)
from .paths.shell_files import shell_file_args
from .shell_shapes import ESCALATION_SHAPES, SHELL_TOOLS, command_from_args

from .content_scanners import iter_ioc_candidates
from .action_parsing import command_text

__all__ = [
    'ANSWERED_BY_FALLBACK',
    'DEPENDENCY_ECOSYSTEMS',
    'ESCALATION_SHAPES',
    'FETCH_TOOL_PREFIXES',
    'HOST_FILE_AND_SKILL_TOOLS',
    'KIND_FLAG_ONLY',
    'SENSITIVE_PATH_CATEGORIES',
    'SHELL_TOOLS',
    'SKILL_DANGER_SHAPES',
    'Finding',
    'advisory_kind',
    'cmd_setup_llm',
    'command_from_args',
    'command_text',
    'detect_all',
    'detect_custom_fileaccess',
    'detect_dependency',
    'detect_escalation',
    'detect_fileaccess',
    'detect_injection',
    'detect_ioc',
    'detect_model_request_secrets',
    'detect_own_wallet_keys',
    'detect_secret_exposure',
    'detect_skill',
    'discover_dependency_candidates',
    'discover_injection',
    'file_access_arg',
    'injection_scan_text',
    'iter_ioc_candidates',
    'osv',
    'parse_dependency_installs',
    'parse_downloads',
    'parse_shell_reads',
    'reviewer',
    'shell_file_args',
    'skill_install_arg',
]
