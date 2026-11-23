"""File Shield judges a script an agent writes by its text, when written and again when run
(plugins/blackbox/detection/script_files.py; Layer 1 within its limits).

Security finding 2026-11-22-hooks-only-file-shield-an-agent-written (real runs on the test VM,
2026-11-22): Claude Code, Gemini CLI and the Hermes agent each wrote ``r.py`` — the protected
file's path built with ``Path.home().joinpath("Documents", "Secret", "change-N.txt")`` — and ran
``python3 r.py``; both calls were allowed and the file was read. The payloads below are the REAL
hook payload shapes of those runs (Claude Code 2.1.330 PreToolUse ``Write`` / ``Bash``, Gemini CLI
0.70.0 BeforeTool ``write_file`` / ``run_shell_command``, the Hermes agent's ``write_file`` /
``terminal``), mapped by the real runner.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from plugins.blackbox import ruleset as ruleset_mod
from plugins.blackbox.agent_hooks.protect import runner
from plugins.blackbox.guard import background as guard_background
from plugins.blackbox.guard import hooks
from plugins.blackbox.guard import reporting as guard_reporting
from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.ruleset import Ruleset
from plugins.blackbox.detection import script_files as written
from plugins.blackbox.shields.files import protect

#: The script the real agents wrote (rc-s5s1 / rg-s5f / rh-s5).
REAL_SCRIPT = 'from pathlib import Path; print(Path.home().joinpath("Documents", "Secret", "change-2.txt").read_text())\n'


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    (tmp_path / "Documents" / "Secret").mkdir(parents=True)
    project = tmp_path / "camp" / "projects" / "rc-s5s1"
    project.mkdir(parents=True)
    state = {"mode": "audit", "report": False, "shields": {"file-shield": {"enabled": True, "protected": ["~/Documents/Secret"]}}}
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: state)
    monkeypatch.setattr(ruleset_mod, "get", lambda cfg=None: Ruleset())
    monkeypatch.setattr(guard_background, "_spawn_osv_discovery", lambda *a, **k: None)
    monkeypatch.setattr(guard_background, "review_tool", lambda *a, **k: None)
    monkeypatch.setattr(guard_reporting, "_report_and_audit", lambda *a, **k: None)
    written.forget_all()
    yield SimpleNamespace(path=tmp_path, project=project)
    written.forget_all()


def _verdict(agent: str, payload: dict) -> dict:
    body = runner.summary(agent, "pre_tool", payload)
    return hooks.tool_call_verdict(body["tool_name"], body["args"])


@pytest.mark.parametrize("agent, write", [
    ("claude-code", {"session_id": "s", "tool_name": "Write", "tool_input": {"file_path": "{p}/r.py", "content": REAL_SCRIPT}}),
    ("gemini-cli", {"session_id": "g", "tool_name": "write_file", "tool_input": {"file_path": "{p}/r.py", "content": REAL_SCRIPT}}),
])
def test_writing_the_real_script_is_refused_with_file_shields_reason(home, agent, write):
    write["tool_input"]["file_path"] = write["tool_input"]["file_path"].format(p=home.project)
    verdict = _verdict(agent, write)
    assert verdict["decision"] == "block" and set(verdict["blocked"]) & {protect.FOLDER_HIT_ID, protect.FILE_HIT_ID}
    assert "File Shield" in verdict["message"]


def test_the_hermes_agents_write_and_a_heredoc_into_a_script_are_refused(home):
    assert hooks.tool_call_verdict("write_file", {"path": str(home.project / "r.py"), "content": REAL_SCRIPT})["decision"] == "block"
    heredoc = f"cat > r.py <<'EOF'\n{REAL_SCRIPT}EOF\npython3 r.py"
    assert hooks.tool_call_verdict("terminal", {"command": heredoc})["decision"] == "block"


def test_a_script_finished_by_a_later_edit_is_judged_when_it_is_run(home):
    """Neither the first write nor the edit names the item on its own; the file they leave does."""
    script = home.project / "r.py"
    first = 'from pathlib import Path\nprint(Path.home().joinpath("Documents", NAME).read_text())\n'
    write = {"session_id": "s", "tool_name": "Write", "tool_input": {"file_path": str(script), "content": first}}
    assert _verdict("claude-code", write)["decision"] != "block"
    script.write_text(first, encoding="utf-8")
    edit = {"session_id": "s", "tool_name": "Edit", "tool_input": {"file_path": str(script), "old_string": "NAME",
                                                                    "new_string": '"Secret", "change-2.txt"'}}
    assert _verdict("claude-code", edit)["decision"] != "block"
    script.write_text(first.replace("NAME", '"Secret", "change-2.txt"'), encoding="utf-8")
    run = {"session_id": "s", "tool_name": "Bash", "tool_input": {"command": "python3 r.py"}}
    verdict = _verdict("claude-code", run)
    assert verdict["decision"] == "block" and "File Shield" in verdict["message"]


def test_an_ordinary_script_is_written_and_run_as_before(home):
    script = home.project / "hello.py"
    content = 'print("hello from", __file__)\n'
    assert hooks.tool_call_verdict("write_file", {"path": str(script), "content": content})["decision"] != "block"
    script.write_text(content, encoding="utf-8")
    assert hooks.tool_call_verdict("terminal", {"command": "python3 hello.py"})["decision"] != "block"


def test_the_script_memory_is_bounded(home):
    for index in range(written.MAX_REMEMBERED + 10):
        written.remember(f"/p/s{index}.py")
    assert len(written._written) == written.MAX_REMEMBERED and "/p/s0.py" not in written._written
