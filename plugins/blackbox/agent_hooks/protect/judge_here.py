"""The hook runner's judgement while the dashboard does not answer: the installed plugin's own.

Copied beside ``runner.py`` into Blackbox's data folder (``agent_hooks.RUNNER_FILES``; standard
library only until it loads the plugin). Private security finding
``2026-11-24-linux-an-agent-stops-blackbox-s-dashboar`` (Linux round L1, High): an agent killed
the dashboard and the hooks then let everything through. :func:`judge_here` loads the plugin
folder ``agent_hooks`` named in :data:`JUDGE_HERE_FILE` and answers with its
``events.record_event`` — the same guard, ruleset file and local checks, offline.

Usage (inside the runner, when ``ask`` failed)::

    answer = judge_here(summary_body)   # {"decision": "block", "message": …} or {} (fail open)
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

#: Beside the runner: where the plugin that installed it lives, and its homes —
#: ``{"plugin": <folder>, "hermes_home": …, "blackbox_home": …}`` (written by ``agent_hooks``).
JUDGE_HERE_FILE = "judge-here.json"
#: The name the plugin is loaded under for :func:`judge_here` (never a name Hermes uses).
_HERE_PACKAGE = "blackbox_judge_here"


def judge_here(body: dict) -> dict:
    """The dashboard's answer to *body*, worked out in this process: the installed plugin's own
    judgement, loaded from the folder :data:`JUDGE_HERE_FILE` names (its package ``__init__`` is
    not run — only the judgement and what it imports). {} when it cannot be loaded."""
    if __package__:   # imported as the plugin's module (tests, the plugin itself)
        from .events import record_event
        return record_event(body)
    import importlib
    import types
    with open(Path(__file__).with_name(JUDGE_HERE_FILE), encoding="utf-8-sig") as handle:
        where = json.loads(handle.read(65536))
    plugin = Path(str(where.get("plugin") or ""))
    if not (plugin / "agent_hooks" / "protect" / "events.py").is_file():
        return {}
    for variable, key in (("HERMES_HOME", "hermes_home"), ("BLACKBOX_HOME", "blackbox_home")):
        if where.get(key):
            os.environ[variable] = str(where[key])   # this process only: the homes the dashboard runs with
    package = types.ModuleType(_HERE_PACKAGE)
    package.__path__ = [str(plugin)]
    package.__package__ = _HERE_PACKAGE
    sys.modules.setdefault(_HERE_PACKAGE, package)
    return importlib.import_module(_HERE_PACKAGE + ".agent_hooks.protect.events").record_event(body)
