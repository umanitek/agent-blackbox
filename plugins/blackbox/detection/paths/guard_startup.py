"""The agent sandbox's PATH block in a shell startup file, as the self-protection guard judges an
agent's change to that file (``guard_settings.detect_guard_tamper`` asks here): the file is the
person's own, only the block (``kernel.shell_path``) is Blackbox's.

An edit is judged on the file it LEAVES (KI-539, E2E full5 2026-11-22: an agent's edit of the
person's own ``alias gs=…`` line was refused): the block must stay once and byte for byte, and no
new line may send an agent round the launcher (``shell_path.undoing_lines``). A plain ``echo … >>``
of harmless text is the person's own line too.

Usage::

    edit_keeps_path_block("~/.zshrc", {"old_string": a, "new_string": b})  # True / False / None (can't apply)
    keeps_path_block("~/.zshrc", {"content": whole_new_text})             # True → the write keeps the block
    plain_startup_append("echo \"alias gl='git log'\" >> ~/.zshrc")       # True → the person's own line
    edit_reaches_path_block("~/.zshrc", [old_text, new_text])             # text-only fallback (a patch)
"""

from __future__ import annotations

import os
import re
from typing import Any, Optional

from ...kernel import shell_path
from ...kernel.bounded_files import read_small_text
from . import guard_commands, shell_files

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
    block exactly as it is now (anywhere in the file) and adds no line that could undo it
    (KI-535/539: the person's own lines stay theirs)."""
    if os.path.basename(os.path.expanduser(str(path))) not in shell_path.STARTUP_FILES:
        return False
    content = args.get("content")
    current = read_small_text(os.path.expanduser(str(path)), MAX_CONFIG_BYTES) or ""
    return isinstance(content, str) and _block_kept(current, content)


def _block_kept(current: str, result: str) -> bool:
    """True when *result* (a startup file's new text) holds the block of *current* once, byte for
    byte, and adds no line that could send an agent round the launcher."""
    block = shell_path.section(current)
    return (bool(block) and result.count(shell_path.BEGIN) == 1 and result.count(shell_path.END) == 1
            and shell_path.section(result) == block and not shell_path.undoing_lines(result, current))


#: The keys an edit tool names its replaced and its new text by (Claude, Gemini, Copilot / OpenCode,
#: Anthropic's text editor); a multi-edit carries a list of them under ``edits``.
OLD_KEYS = ("old_string", "old_str", "oldString")
NEW_KEYS = ("new_string", "new_str", "newString")


def _edit_pairs(args: dict[str, Any]) -> Optional[list[tuple[str, str, bool]]]:
    """The ``(old, new, replace_all)`` replacements an edit tool asks for, or None when its shape is
    not one this rule can apply (a patch, a diff, a missing old text)."""
    items = args.get("edits") if isinstance(args.get("edits"), list) else [args]
    pairs = []
    for item in items:
        if not isinstance(item, dict):
            return None
        old = next((item[key] for key in OLD_KEYS if isinstance(item.get(key), str)), None)
        new = next((item[key] for key in NEW_KEYS if isinstance(item.get(key), str)), None)
        if not old or new is None:
            return None
        pairs.append((old, new, bool(item.get("replace_all") or item.get("replaceAll"))))
    return pairs


def edit_keeps_path_block(path: str, args: dict[str, Any]) -> Optional[bool]:
    """Whether an edit of startup file *path* keeps the PATH block, judged on the RESULT: the edits
    applied to the file as it is now. None when it can not be applied here (a patch, an old text not
    in the file): the caller then judges the edit's own text (:func:`edit_reaches_path_block`)."""
    pairs = _edit_pairs(args)
    current = read_small_text(os.path.expanduser(str(path)), MAX_CONFIG_BYTES)
    if pairs is None or current is None:
        return None
    result = current
    for old, new, every in pairs:
        if old not in result:
            return None
        result = result.replace(old, new) if every else result.replace(old, new, 1)
    return _block_kept(current, result)


#: Words that can make an ``echo``/``printf`` line write something other than its own text.
_EXPANDS = re.compile(r"[$`\\]|<\(|>\(")
_SEPARATORS = (";", "|", "||", "&&", "&", ">", "<")


def plain_startup_append(line: str) -> bool:
    """True for ONE line that only appends plain text to a shell startup file in the home folder —
    ``echo "alias gl='git log'" >> ~/.zshrc`` — with no line that could undo the block and none of
    Blackbox's variables. Anything else — a rewrite (``>``, ``sed -i``, ``mv``), a second command, an
    expansion — is judged by the guard as before."""
    if _EXPANDS.search(line):
        return False
    words = shell_files._words(line)
    if len(words) < 3 or words[0] not in ("echo", "printf") or words[-2] != ">>" or ">>" in words[:-2]:
        return False
    if any(word in _SEPARATORS or word.startswith((">", "<", "&")) for word in words[1:-2]):
        return False
    target = os.path.expanduser(words[-1])
    if os.path.basename(target) not in shell_path.STARTUP_FILES or os.path.dirname(target) != os.path.expanduser("~"):
        return False
    text = "\n".join(words[1:-2]).replace("\\n", "\n")
    return not shell_path.undoing_lines(text) and not guard_commands.sets_environment(text)
