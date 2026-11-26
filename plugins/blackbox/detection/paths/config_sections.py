"""The part of another program's config file that is Blackbox's: the ``blackbox:`` entry of a
Hermes ``config.yaml`` and the ``"blackbox": {…}`` entry of a JSON config (OpenClaw's). The
self-protection guard (:mod:`.guard_settings`) refuses an edit that reaches this part and leaves the
rest of the file to the person and their agent.

Usage::

    blackbox_section("model: x\nblackbox:\n  mode: block\n")   # "blackbox:\n  mode: block"
    json_entry('{"blackbox": {"mode": "block"}, "x": 1}')        # '"blackbox": {"mode": "block"}'
"""

from __future__ import annotations

import re


def blackbox_section(config_text: str) -> str:
    """The lines of the ``blackbox:`` entry in a Hermes config (the key and everything indented under it)."""
    lines, section, indent = config_text.splitlines(), [], None
    for line in lines:
        stripped = line.lstrip()
        if indent is None:
            if re.match(r"blackbox\s*:", stripped):
                indent = len(line) - len(stripped)
                section.append(line)
            continue
        if stripped and len(line) - len(stripped) <= indent:
            break
        section.append(line)
    return "\n".join(section)


def json_entry(config_text: str) -> str:
    """The text of the ``"blackbox": {…}`` entry in a JSON config (OpenClaw's), braces matched."""
    start = re.search(r'"blackbox"\s*:\s*\{', config_text)
    if not start:
        return ""
    depth = 0
    for position in range(start.end() - 1, len(config_text)):
        depth += {"{": 1, "}": -1}.get(config_text[position], 0)
        if depth == 0:
            return config_text[start.start():position + 1]
    return config_text[start.start():]


__all__ = ["blackbox_section", "json_entry"]
