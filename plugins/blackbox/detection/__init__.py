"""Detection — the CHECK hot path: is this tool call / model request a threat?

Pure matchers over the compiled ruleset plus the two advisory look-asides.
Callers use this package's surface only:

* ``Finding`` and the ``detect_*`` / ``discover_*`` functions (from
  :mod:`.detectors`) — pure, microsecond-scale, no I/O.
* Action parsing used by the hook's activity log — ``parse_dependency_installs``,
  ``parse_downloads``, ``parse_shell_reads``, ``file_access_arg``,
  ``command_from_args`` / ``SHELL_TOOLS``.
* :mod:`.osv` — OSV.dev dependency lookups (3 s timeout, background only).
* :mod:`.reviewer` — the opt-in LLM second opinion (advisory, never blocks);
  :func:`cmd_setup_llm` configures it (``blackbox setup-llm``).

Usage::

    from ..detection import Finding, detect_all
    from ..detection import osv, reviewer
"""

from __future__ import annotations

from . import osv, reviewer
from .action_parsing import (FETCH_TOOL_PREFIXES, SENSITIVE_PATH_CATEGORIES, file_access_arg, parse_dependency_installs,
                             parse_downloads, parse_shell_reads, skill_install_arg)
from .content_scanners import SKILL_DANGER_SHAPES
from .osv import DEPENDENCY_ECOSYSTEMS, advisory_kind
from .reviewer_setup import cmd_setup_llm
from .detectors import (
    Finding,
    detect_all,
    detect_custom_fileaccess,
    detect_dependency,
    detect_escalation,
    detect_fileaccess,
    detect_injection,
    detect_ioc,
    detect_secret_exposure,
    detect_skill,
    discover_dependency_candidates,
    discover_injection,
    injection_scan_text,
)
from .shell_shapes import ESCALATION_SHAPES, SHELL_TOOLS, command_from_args

from .content_scanners import iter_ioc_candidates
from .injection_detection import injection_scan_text
from .action_parsing import command_text

__all__ = [
    "iter_ioc_candidates", "injection_scan_text", "command_text",
    "DEPENDENCY_ECOSYSTEMS",
    "advisory_kind",
    "ESCALATION_SHAPES",
    "FETCH_TOOL_PREFIXES",
    "SENSITIVE_PATH_CATEGORIES",
    "SHELL_TOOLS",
    "SKILL_DANGER_SHAPES",
    "Finding",
    "skill_install_arg",
    "cmd_setup_llm",
    "command_from_args",
    "detect_all",
    "detect_custom_fileaccess",
    "detect_dependency",
    "detect_escalation",
    "detect_fileaccess",
    "detect_injection",
    "detect_ioc",
    "detect_secret_exposure",
    "detect_skill",
    "discover_dependency_candidates",
    "discover_injection",
    "file_access_arg",
    "injection_scan_text",
    "osv",
    "parse_dependency_installs",
    "parse_downloads",
    "parse_shell_reads",
    "reviewer",
]
