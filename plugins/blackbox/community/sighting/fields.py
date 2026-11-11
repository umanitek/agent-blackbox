"""The sighting a report carries beside its evidence (threat-profiles §03.2).

For each finding the guard is about to share, :func:`sighting_fields` says, in
closed vocabulary only: which host tool met it, what the agent was doing, whether
it was blocked or flagged, how it was matched and by which Blackbox build, the
verified rule it matched (a link the reader follows into its OWN verified copy),
and what the threat goes after (:mod:`.classification`). Everything here is
derived from the finding the detector already built — nothing is read from the
user's prompt, command, path or page.

Pattern: Builder of one flat mapping, merged into the report's evidence by the
share gate (:func:`..sharing.shareable_fields`).

Usage::

    finding["sighting"] = sighting_fields(finding, outcome="flagged")
"""

from __future__ import annotations

from typing import Any, Dict, Mapping

from ... import detection
from ...kernel import constants
from . import vocab
from .classification import classify

#: Detection's tool sets, read once: a host tool name travels verbatim.
_HOST_TOOLS = frozenset({*detection.SHELL_TOOLS, *detection.HOST_FILE_AND_SKILL_TOOLS})
#: How each category's tool call reads as an action (fileaccess and ioc decide per finding).
_ACTION_BY_CATEGORY = {"dependency": "install-package", "skill": "install-skill", "escalation": "run-command"}
#: Where an indicator was met -> what the agent was doing.
_ACTION_BY_IOC_CONTEXT = {"fetched-by-tool": "fetch", "in-dependency": "install-package", "in-skill": "install-skill"}
#: Where an injection was found -> what the agent was doing.
_ACTION_BY_INJECTION_CONTEXT = {"in-fetched-page": "model-input", "in-tool-output": "model-input",
                                "in-user-prompt": "model-input", "in-skill": "install-skill",
                                "in-tool-input": "use-tool"}


def is_reportable_tool(tool: str) -> bool:
    """Whether *tool* (lower-case) may travel in a report as written: a host tool, a name of
    the reportable tool shape, or one of ``mcp-tool`` / ``other``. The report schema asks this;
    :func:`canonical_tool` maps any other tool onto it."""
    return tool in vocab.OTHER_TOOLS or tool in _HOST_TOOLS or bool(vocab.TOOL_SHAPE.fullmatch(tool))


def canonical_tool(tool_name: str) -> str:
    """The tool name a report may carry: a host tool verbatim, any other tool
    ``mcp-tool`` (MCP naming) or ``other`` — never a private tool's own name.
    ``""`` when no tool was involved (an injection in model input)."""
    tool = (tool_name or "").strip().lower()
    if not tool:
        return ""
    if tool in _HOST_TOOLS or vocab.TOOL_SHAPE.fullmatch(tool):
        return tool
    return "mcp-tool" if tool.startswith("mcp") or "__" in tool else "other"


def _action(finding: Mapping[str, Any], tool: str) -> str:
    category = str(finding.get("category") or "")
    fields = finding.get("fields") if isinstance(finding.get("fields"), Mapping) else {}
    if category in _ACTION_BY_CATEGORY:
        return _ACTION_BY_CATEGORY[category]
    if category == "fileaccess":
        return "write-file" if str(finding.get("evidence") or "").startswith("write") else "read-file"
    if category == "injection":
        return _ACTION_BY_INJECTION_CONTEXT.get(str(fields.get("context") or ""), "model-input")
    if category == "ioc":
        return _ACTION_BY_IOC_CONTEXT.get(str(fields.get("ioc_context") or ""), "use-tool" if tool else "model-input")
    return "use-tool"


def _matched_by(finding: Mapping[str, Any]) -> str:
    """``verified`` for a verified-graph match; a built-in finding that cites a
    public advisory (OSV) is ``advisory``; any other built-in one ``built-in``."""
    if finding.get("source") == "public":
        return "verified"
    fields = finding.get("fields") if isinstance(finding.get("fields"), Mapping) else {}
    return "advisory" if fields.get("advisory_id") else "built-in"


def sighting_fields(finding: Mapping[str, Any], *, outcome: str) -> dict[str, str]:
    """The sighting fields for one finding dict (``Finding.to_dict()``), every
    value from :mod:`.vocab`. *outcome* is ``blocked`` or ``flagged`` — what the
    hook did with THIS finding."""
    tool = canonical_tool(str(finding.get("tool_name") or ""))
    matched_by = _matched_by(finding)
    out = {"matched_by": matched_by, "blackbox_version": constants.__version__,
           "agent_action": _action(finding, tool), "outcome": outcome if outcome in vocab.OUTCOMES else "flagged",
           **classify(finding).as_fields()}
    if tool:
        out["agent_tool"] = tool
    subject = str(finding.get("rule_subject") or "")
    if matched_by == "verified" and vocab.VERIFIED_SUBJECT_SHAPE.fullmatch(subject):
        out["verified_subject"] = subject
    return out
