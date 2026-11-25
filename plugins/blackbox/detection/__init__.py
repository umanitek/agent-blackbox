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
* Dependency files (:mod:`.manifests`, KI-595) — ``check_install_files`` (the manifests and
  lockfiles an install that names no package installs from), ``check_landed`` (what an install
  added to its lockfile, after it ran), ``check_dependency_write`` (packages a write adds to such
  a file); each answers ``DependencyCheck`` (findings + the notes on what was not checked).
* :mod:`.osv` — OSV.dev dependency lookups (3 s timeout, background only).
* :mod:`.reviewer` — the opt-in LLM second opinion (advisory, never blocks);
  :func:`cmd_setup_llm` configures it (``blackbox setup-llm``).

Usage::

    from ..detection import Finding, detect_all
    from ..detection import osv, reviewer
"""

from __future__ import annotations

from . import osv, reviewer, script_files
from .action_parsing import (FETCH_TOOL_PREFIXES, HOST_FILE_AND_SKILL_TOOLS, SENSITIVE_PATH_CATEGORIES, file_access_arg, parse_dependency_installs,
                             parse_downloads, parse_shell_reads, skill_install_arg)
from .content_scanners import SKILL_DANGER_SHAPES
from .osv import DEPENDENCY_ECOSYSTEMS, advisory_kind
from .reviewer_setup import cmd_setup_llm
from .finding import FIELD_WALLET_SECRET_SENT, KIND_FLAG_ONLY, MANAGER_ORDER, PERSON_PROTECTED
from .elevation import ELEVATION_ID, detect_elevation
from .hook_switches import detect_hook_switch_off
from .paths.guard_settings import MATCHED as GUARD_TAMPER
from .persistence_writes import MATCHED as STARTUP_ITEM, detect_persistence_write
from .privileged_writes import MATCHED as ROOT_WRITE, detect_privileged_write
from .paths.protected import PathTouch, mentions as protected_path_mentions, touches as protected_path_touches

#: ``Finding.matched`` values refused in EVERY mode, Audit included: an agent switching Blackbox
#: off (its self-protection), an agent touching what the person protected (File Shield), an
#: agent writing a place something starts from by itself (as the agent sandbox refuses it) and an
#: order from whoever manages this machine (an add-on's ``MANAGER_ORDER`` finding).
ALWAYS_BLOCKED_MATCHES = frozenset({GUARD_TAMPER, PERSON_PROTECTED, STARTUP_ITEM, MANAGER_ORDER})
from .paths.guard_settings import detect_guard_tamper
from .paths.guard_secrets import builtin_patterns as blackbox_key_patterns
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
    run_isolated,
)
from .paths.shell_files import shell_file_args
from .shell_shapes import ESCALATION_SHAPES, SHELL_TOOLS, command_from_args
from .hidden_commands import undecidable as builds_hidden_command

from .content_scanners import iter_ioc_candidates
from .manifests import DependencyCheck, check_dependency_write, check_install_files, check_landed

__all__ = [
                             'ALWAYS_BLOCKED_MATCHES',
                             'ANSWERED_BY_FALLBACK',
                             'DEPENDENCY_ECOSYSTEMS',
                             'ELEVATION_ID',
                             'ESCALATION_SHAPES',
                             'FETCH_TOOL_PREFIXES',
                             'FIELD_WALLET_SECRET_SENT',
                             'GUARD_TAMPER',
                             'HOST_FILE_AND_SKILL_TOOLS',
                             'KIND_FLAG_ONLY',
                             'MANAGER_ORDER',
                             'PERSON_PROTECTED',
                             'ROOT_WRITE',
                             'SENSITIVE_PATH_CATEGORIES',
                             'SHELL_TOOLS',
                             'SKILL_DANGER_SHAPES',
                             'STARTUP_ITEM',
                             'DependencyCheck',
                             'Finding',
                             'PathTouch',
                             'advisory_kind',
                             'blackbox_key_patterns',
                             'builds_hidden_command',
                             'check_dependency_write',
                             'check_install_files',
                             'check_landed',
                             'cmd_setup_llm',
                             'command_from_args',
                             'detect_all',
                             'detect_custom_fileaccess',
                             'detect_dependency',
                             'detect_elevation',
                             'detect_escalation',
                             'detect_fileaccess',
                             'detect_guard_tamper',
                             'detect_hook_switch_off',
                             'detect_injection',
                             'detect_ioc',
                             'detect_model_request_secrets',
                             'detect_own_wallet_keys',
                             'detect_persistence_write',
                             'detect_privileged_write',
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
                             'protected_path_mentions',
                             'protected_path_touches',
                             'reviewer',
                             'run_isolated',
                             'script_files',
                             'shell_file_args',
                             'skill_install_arg',
]
