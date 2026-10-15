"""Replay the Python matrix commands and prove their combined file coverage."""

from pathlib import Path

from ruamel.yaml import YAML

from scripts import run_tests_parallel as runner
from tests.ci import workflow_steps

ROOT = Path(__file__).resolve().parents[2]


def _workflow(name):
    return YAML(typ="safe").load((ROOT / ".github/workflows" / name).read_text(encoding="utf-8"))


def test_python_matrix_covers_every_discovered_file_once():
    job = _workflow("tests.yml")["jobs"]["test"]
    matrix = job["strategy"]["matrix"]
    assert set(matrix) == {"slice"}, "extra dimensions/exclusions can duplicate or omit files"
    assert len(matrix["slice"]) == 4
    step = next(step for step in job["steps"] if step.get("name") == "Run tests")
    assert int(step["env"]["HERMES_TEST_WORKERS"]) == 4
    files = runner._discover_files([ROOT / "tests"])
    assert files
    selected = []
    for index in matrix["slice"]:
        ctx = {"matrix": {"slice": index}}
        workflow_steps.required(job, ctx)
        _, calls = workflow_steps._run(step, ctx, ROOT, receipt=True)
        assert len(calls) == 1
        command, flag, value = calls[0]
        assert (command, flag) == ("pytest", "--slice"), "no additional test filters"
        part, count = map(int, value.split("/"))
        assert count == len(matrix["slice"])
        # Independent runners may restore different cache generations. Assignment
        # must still agree; durations may only affect order inside each partition.
        durations = {path.relative_to(ROOT).as_posix(): float(i + index)
                     for i, path in enumerate(files[::index])}
        shard = runner._slice_files(files, part, count, durations, ROOT)
        assert shard
        selected.extend(shard)
    assert sorted(selected) == sorted(files), "missing or multiply executed test files"


def test_python_shards_all_finish_and_remain_required():
    job = _workflow("tests.yml")["jobs"]["test"]
    assert job["strategy"]["fail-fast"] is False
    assert job["strategy"]["max-parallel"] == 4
    ctx = {"needs": {"detect": {"outputs": {"python": "true"}}}}
    workflow_steps.required(job, ctx)
    ci = _workflow("ci.yaml")["jobs"]
    workflow_steps.required(ci["tests"], ctx)
    assert ci["tests"]["uses"] == "./.github/workflows/tests.yml"
    gate = ci["all-checks-pass"]
    assert "tests" in gate["needs"]
    # The aggregate must still evaluate a failed dependency.
    ctx["__status__"] = {"always": True, "success": False, "failure": True, "cancelled": False}
    workflow_steps.required(gate, ctx)
