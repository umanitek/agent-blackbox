"""execute_code's optional interpreter launcher (``HERMES_EXECUTE_CODE_LAUNCHER``).

Contract: unset, the local kernel's argv is exactly ``[child_python, runner]``; set to a JSON
array whose first element is an executable file, that array is placed before the interpreter;
a launcher that is missing or a malformed value is ignored and the kernel still starts (a
wrapper that went away never breaks execute_code).
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from tools import code_kernel
from tools.code_execution_tool import execute_code
from tools.code_kernel import INTERPRETER_LAUNCHER_ENV, shutdown_all_kernels

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="the launcher stand-in is a POSIX shell script")


@pytest.fixture(autouse=True)
def _local_strict(monkeypatch):
    monkeypatch.setenv("TERMINAL_ENV", "local")
    monkeypatch.delenv(INTERPRETER_LAUNCHER_ENV, raising=False)
    shutdown_all_kernels()
    with patch("tools.code_execution_tool._load_config", return_value={"mode": "strict", "timeout": 30}):
        yield
    shutdown_all_kernels()


def _run_and_capture(code: str) -> tuple[dict, list[str]]:
    """Runs *code* through the real tool and answers (result, the kernel's spawn argv)."""
    spawned: list[list[str]] = []
    real_popen = subprocess.Popen

    def _capturing(args, **kwargs):
        if Path(str(args[-1])).name == "hermes_kernel_runner.py":
            spawned.append([str(part) for part in args])
        return real_popen(args, **kwargs)

    with patch("tools.code_kernel.subprocess.Popen", side_effect=_capturing):
        result = json.loads(execute_code(code, task_id="launcher-test"))
    assert len(spawned) == 1, spawned
    return result, spawned[0]


def _launcher(tmp_path: Path) -> Path:
    """A stand-in wrapper: marks the child's environment, then runs what it was given."""
    script = tmp_path / "wrap"
    script.write_text('#!/bin/sh\nWRAPPED_BY_LAUNCHER=1; export WRAPPED_BY_LAUNCHER\nexec "$@"\n', encoding="utf-8")
    script.chmod(0o755)
    return script


def test_unset_the_argv_is_exactly_the_interpreter_and_the_runner():
    result, argv = _run_and_capture("print('plain')")
    assert result["status"] == "success", result
    assert len(argv) == 2 and argv[0] == sys.executable


def test_set_the_launcher_comes_first_and_the_code_runs_through_it(tmp_path, monkeypatch):
    wrap = _launcher(tmp_path)
    monkeypatch.setenv(INTERPRETER_LAUNCHER_ENV, json.dumps([str(wrap)]))
    result, argv = _run_and_capture("import os; print(os.environ.get('WRAPPED_BY_LAUNCHER'))")
    assert argv[0] == str(wrap) and argv[1] == sys.executable and len(argv) == 3
    assert result["status"] == "success", result
    assert "1" in result["output"]


def test_a_launcher_with_arguments_keeps_them_in_order(tmp_path):
    wrap = _launcher(tmp_path)
    assert code_kernel.interpreter_launcher({INTERPRETER_LAUNCHER_ENV: json.dumps([str(wrap), "-a", "b c"])}) == \
        [str(wrap), "-a", "b c"]


@pytest.mark.parametrize("value", ["not json", "{}", "[]", '[""]', "[1]", json.dumps(["/no/such/launcher"])])
def test_a_missing_launcher_or_a_malformed_value_leaves_the_old_argv(value, monkeypatch):
    monkeypatch.setenv(INTERPRETER_LAUNCHER_ENV, value)
    assert code_kernel.interpreter_launcher() == []
    result, argv = _run_and_capture("print('still runs')")
    assert result["status"] == "success", result
    assert len(argv) == 2 and argv[0] == sys.executable and os.path.basename(argv[1]) == "hermes_kernel_runner.py"
