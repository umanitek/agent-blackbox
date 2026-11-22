"""Codex's ``apply_patch`` is judged as the writes it makes (KI-583, FIX-0368:
plugins/blackbox/detection/paths/guard_patch.py, guard_settings._patch_tampers).

Security round 3 (Codex 0.171.0, gpt-5-nano): asked to create r.py, Codex ran
``bash -lc 'apply_patch <<"PATCH" *** Begin Patch *** Add File: r.py …'`` and Blackbox refused it as
"Change to Blackbox's own settings" — the patch's ``***`` marker lines were read as shell wildcards
matching every guarded place, so ANY patch, a new hello.py in the project included, was refused
with the wrong reason. A patch that touches a guarded place, or adds a script that would itself be
refused, is still refused.
"""

from __future__ import annotations

import os

import pytest

from plugins.blackbox.agent_hooks.protect import events, runner
from plugins.blackbox.detection.paths import guard_patch
from plugins.blackbox.kernel import threat_ids
from tests.plugins.test_blackbox_file_shield_hooks_only_routes import home  # the round's fixture, used by name

SELF = threat_ids.fileaccess_identifier("terminal", threat_ids.SELF_PROTECTION)


def _patch(body: str) -> str:
    """The command Codex 0.171.0 really ran: a quoted heredoc inside ``bash -lc '…'``."""
    return f"bash -lc 'apply_patch <<\"PATCH\"\n*** Begin Patch\n{body}\n*** End Patch\nPATCH'"


#: Round 3's r.py, as the prompt asked for it (s3-cx5s).
R_PY = ('*** Add File: r.py\n+import os, sys\n+print(len(open(os.path.join(os.environ["HOME"], sys.argv[1] + "uments", '
        'sys.argv[2] + "ret", "change-2.txt")).read()))')


def _verdict(command: str, cwd) -> dict:
    payload = {"session_id": "cx", "cwd": str(cwd), "hook_event_name": "PreToolUse", "tool_name": "Bash", "turn_id": "t1",
               "tool_input": {"command": command}, "tool_use_id": "call_1", "model": "gpt-5-nano"}
    return events._verdict(events.validate(runner.summary("codex", "pre_tool", payload)))


def _identifiers(verdict: dict) -> list[str]:
    return [str(finding.get("identifier")) for finding in verdict.get("findings") or []]


@pytest.mark.parametrize("body", ["*** Add File: hello.py\n+print(\"hi\")",
                                  "*** Update File: src/app.py\n@@ def main():\n-    return 1\n+    return 2",
                                  "*** Delete File: old.txt",
                                  R_PY])
def test_a_patch_to_the_project_is_never_refused_as_a_change_to_blackbox(home, body):
    verdict = _verdict(_patch(body), home.project)
    assert SELF not in _identifiers(verdict), verdict


def test_a_new_project_script_that_touches_nothing_protected_is_allowed(home):
    verdict = _verdict(_patch("*** Add File: tools/build.sh\n+#!/bin/sh\n+echo building"), home.project)
    assert verdict.get("decision") != "block" and _identifiers(verdict) == [], verdict


def test_a_patch_that_reaches_blackbox_or_adds_a_script_that_would_be_refused_still_is(home):
    plugin = os.path.join(os.environ["HERMES_HOME"], "plugins", "blackbox")
    for body in (f"*** Add File: {plugin}/evil.py\n+print(1)",
                 f"*** Update File: {plugin}/plugin.yaml\n@@\n-hooks:\n+hooks: []",
                 f"*** Delete File: {plugin}/plugin.yaml",
                 f"*** Update File: notes.txt\n*** Move to: {plugin}/notes.txt",
                 f"*** Add File: cleanup.sh\n+#!/bin/sh\n+rm -rf {plugin}",
                 f"rm -rf {plugin}"):   # not a patch line: an apply_patch of the agent's own could run it
        assert SELF in _identifiers(_verdict(_patch(body), home.project)), body


def test_the_patch_is_read_with_its_files_and_added_text():
    rest, [patch] = guard_patch.split(_patch(R_PY + "\n*** Update File: a.txt\n@@\n-x\n+y"))
    assert patch.paths == ("r.py", "a.txt") and patch.verbs == {"r.py": "Add File", "a.txt": "Update File"}
    assert patch.added["r.py"].startswith("import os, sys") and patch.added["a.txt"] == "y"
    assert "***" not in rest and "@@" not in rest and rest.endswith("PATCH'") and "+y" in rest
    assert guard_patch.split("echo hi") == ("echo hi", [])
