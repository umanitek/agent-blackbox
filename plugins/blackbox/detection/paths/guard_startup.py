"""The agent sandbox's PATH block in a shell startup file, as the self-protection guard judges an
agent's change to that file (``guard_settings.detect_guard_tamper`` asks here): the file is the
person's own, only the block (``kernel.shell_path``) is Blackbox's.

Usage::

    edit_reaches_path_block("~/.zshrc", [old_text, new_text])   # True → refuse the edit
    keeps_path_block("~/.zshrc", {"content": whole_new_text})    # True → the write keeps the block
"""

from __future__ import annotations

import os
from typing import Any

from ...kernel import shell_path
from ...kernel.bounded_files import read_small_text

#: The most of a startup file read to judge a change to it.
MAX_CONFIG_BYTES = 1_000_000


def edit_reaches_path_block(config_path: str, edits: list[str]) -> bool:
    """True when an edit of a shell startup file touches the agent sandbox's PATH block: names its
    markers, or changes text that sits inside the block as the file is now."""
    if any(shell_path.BEGIN in edit or shell_path.END in edit for edit in edits):
        return True
    block = shell_path.section(read_small_text(os.path.expanduser(config_path), MAX_CONFIG_BYTES) or "")
    return bool(block) and any(edit.strip() and edit.strip() in block for edit in edits)


def keeps_path_block(path: str, args: dict[str, Any]) -> bool:
    """True when a whole-file write of shell startup file *path* keeps the agent sandbox's PATH
    block exactly as it is now, as its last lines (KI-535: the person's own lines stay theirs)."""
    if os.path.basename(os.path.expanduser(str(path))) not in shell_path.STARTUP_FILES:
        return False
    content = args.get("content")
    current = read_small_text(os.path.expanduser(str(path)), MAX_CONFIG_BYTES)
    block = shell_path.section(current or "")
    return isinstance(content, str) and bool(block) and content.rstrip("\n").endswith(block) and content.count(shell_path.BEGIN) == 1
