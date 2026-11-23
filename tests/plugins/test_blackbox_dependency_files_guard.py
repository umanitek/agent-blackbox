"""The dependency-file checks in the Hermes hooks (KI-595).

A plain ``npm install`` in a project whose lockfile pins a verified-listed package ran unchecked:
the command names no package. These tests drive the real hooks: the install is BLOCKED and the
message names the package, the version, the file and the chain; a community-listed package only
flags; a named install whose lockfile gains a listed package after it ran raises a critical
alert with the removal command; a write adding a listed package to a manifest is judged at the
write; a file over the size cap lets the call through with a note on the session; and a verdict
asked by another runtime still records nothing.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from _blackbox_loader import load_blackbox

guard = load_blackbox("guard")
hooks = load_blackbox("guard.hooks")
guard_reporting = load_blackbox("guard.reporting")
guard_background = load_blackbox("guard.background")
config_mod = load_blackbox("kernel.config")
ruleset_mod = load_blackbox("ruleset")
registry = load_blackbox("detection.manifests.registry")
verdicts = load_blackbox("detection.manifests.verdicts")
checks = load_blackbox("detection.manifests.checks")

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "blackbox_dependency_files"
VERIFIED = {"npm:bad-pkg@1.2.3": {"identifier": "dep:npm:bad-pkg@1.2.3", "severity": "critical",
                                  "name": "Malicious package", "kind": "malware", "source": "public"}}
COMMUNITY = {"npm:bad-pkg@1.2.3": {**VERIFIED["npm:bad-pkg@1.2.3"], "source": "community"}}


@pytest.fixture
def blackbox(monkeypatch, tmp_path):
    """Blackbox in its own folder, block mode, the given dependency rules, nothing sent anywhere."""
    for cache in (registry.PARSED, verdicts.VERDICTS, checks.SNAPSHOTS):
        cache.clear()
    recorded: list = []

    def use(rules: dict, mode: str = "block"):
        monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes"))
        monkeypatch.setattr(hooks, "_config", lambda: config_mod.BlackboxConfig(mode=mode, report=False))
        rs = ruleset_mod.Ruleset()
        rs.dependency = dict(rules)
        monkeypatch.setattr(ruleset_mod, "get", lambda cfg=None: rs)
        monkeypatch.setattr(guard_background, "_spawn_llm_review", lambda *a, **k: None)
        real = guard_reporting._report_and_audit
        monkeypatch.setattr(guard_reporting, "_report_and_audit",
                            lambda cfg, event, findings, detail: (recorded.append((event, findings, detail)),
                                                                  real(cfg, event, findings, detail)))
        return recorded
    yield use
    for cache in (registry.PARSED, verdicts.VERDICTS, checks.SNAPSHOTS):
        cache.clear()


def _project(tmp_path: Path, fixture: str) -> Path:
    project = tmp_path / "project"
    shutil.copytree(FIXTURES / fixture, project)
    return project


def _audit_rows(tmp_path: Path, event: str) -> list[dict]:
    path = tmp_path / "bb" / "audit.jsonl"
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []
    return [row for row in rows if row.get("event") == event]


@pytest.mark.parametrize("fixture, command", [
    ("npm_v3", "npm install"), ("npm_v3", "npm ci"), ("npm_v1", "npm install"), ("pnpm_v9", "pnpm install"),
    ("yarn_classic", "yarn"), ("yarn_berry", "yarn install"), ("bun", "bun install"),
])
def test_a_plain_install_of_a_lockfile_pinning_a_verified_package_is_blocked(blackbox, tmp_path, fixture, command):
    blackbox(VERIFIED)
    project = _project(tmp_path, fixture)
    answer = guard.on_pre_tool_call(tool_name="terminal", args={"command": command, "workdir": str(project)},
                                    session_id="s1", tool_call_id="t1")
    assert answer is not None and answer["action"] == "block"
    assert "dep:npm:bad-pkg@1.2.3" in answer["message"]
    assert "bad-pkg@1.2.3" in answer["message"] and "express → body-parser → bad-pkg@1.2.3" in answer["message"]


def test_cd_prefix_finds_the_project(blackbox, tmp_path):
    blackbox(VERIFIED)
    project = _project(tmp_path, "npm_v3")
    answer = guard.on_pre_tool_call(tool_name="terminal", args={"command": f"cd {project} && npm ci"}, session_id="s")
    assert answer is not None and answer["action"] == "block"


def test_a_community_listed_package_only_flags(blackbox, tmp_path):
    recorded = blackbox(COMMUNITY)
    project = _project(tmp_path, "npm_v3")
    answer = guard.on_pre_tool_call(tool_name="terminal", args={"command": "npm ci", "workdir": str(project)},
                                    session_id="s", tool_call_id="t")
    assert answer is None
    [finding] = [f for _event, findings, _detail in recorded for f in findings]
    assert finding.source == "community" and finding.confirmed is False
    assert finding.fields["dependency_path"] == "express → body-parser → bad-pkg@1.2.3"


def test_the_verdict_for_another_runtime_is_the_same_and_records_nothing(blackbox, tmp_path):
    blackbox(VERIFIED)
    project = _project(tmp_path, "npm_v3")
    verdict = guard.tool_call_verdict("exec", {"command": "npm ci", "workdir": str(project)})
    assert verdict["decision"] == "block" and verdict["blocked"] == ["dep:npm:bad-pkg@1.2.3"]
    assert not (tmp_path / "bb" / "audit.jsonl").exists()


def test_many_matches_are_summarised_not_listed(blackbox, tmp_path):
    rules = {f"npm:pkg-{i}@1.0.0": {"identifier": f"dep:npm:pkg-{i}@1.0.0", "severity": "critical",
                                    "name": "Malicious package", "kind": "malware"} for i in range(25)}
    blackbox(rules)
    packages = {"": {"dependencies": {f"pkg-{i}": "1.0.0" for i in range(25)}}}
    packages.update({f"node_modules/pkg-{i}": {"version": "1.0.0"} for i in range(25)})
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": packages}), encoding="utf-8")
    verdict = guard.tool_call_verdict("exec", {"command": "npm ci", "workdir": str(tmp_path)})
    assert len(verdict["findings"]) == verdicts.MAX_LISTED
    assert "and 15 more listed packages in package-lock.json" in verdict["findings"][-1]["title"]


def test_a_file_over_the_cap_passes_with_a_note_on_the_session(blackbox, tmp_path, monkeypatch):
    blackbox(VERIFIED)
    monkeypatch.setattr(registry, "MAX_FILE_BYTES", 100)
    project = _project(tmp_path, "npm_v3")
    answer = guard.on_pre_tool_call(tool_name="terminal", args={"command": "npm ci", "workdir": str(project)},
                                    session_id="s-cap", tool_call_id="t")
    assert answer is None
    [row] = _audit_rows(tmp_path, "dependency_check")
    assert row["detail"]["session_id"] == "s-cap"
    assert any(note.startswith("dependencies not checked: package-lock.json is larger than")
               for note in row["detail"]["notes"])


def test_ranges_only_are_said_honestly(blackbox, tmp_path):
    blackbox({})
    project = tmp_path / "p"
    project.mkdir()
    shutil.copy(FIXTURES / "npm_v3" / "package.json", project / "package.json")
    guard.on_pre_tool_call(tool_name="terminal", args={"command": "npm install", "workdir": str(project)}, session_id="s")
    [row] = _audit_rows(tmp_path, "dependency_check")
    assert any("ranges, not exact versions" in note for note in row["detail"]["notes"])


def test_requirements_install_is_blocked_on_an_included_file(blackbox, tmp_path):
    blackbox({"pypi:evil-pkg@0.1.0": {"identifier": "dep:pypi:evil-pkg@0.1.0", "severity": "critical",
                                      "name": "Malicious package", "kind": "malware"}})
    project = _project(tmp_path, "python")
    answer = guard.on_pre_tool_call(tool_name="terminal", session_id="s",
                                    args={"command": "pip install -r requirements.txt", "workdir": str(project)})
    assert answer is not None and "dep:pypi:evil-pkg@0.1.0" in answer["message"]


# ------------------------------------------------------------------ after the install


def _lock_with(path: Path, packages: dict) -> None:
    path.write_text(json.dumps({"lockfileVersion": 3, "packages": packages}), encoding="utf-8")


def test_a_verified_package_landing_through_a_named_install_is_a_critical_alert(blackbox, tmp_path):
    recorded = blackbox(VERIFIED)
    args = {"command": "npm install express", "workdir": str(tmp_path)}
    assert guard.on_pre_tool_call(tool_name="terminal", args=args, session_id="s", tool_call_id="t") is None
    shutil.copy(FIXTURES / "npm_v3" / "package-lock.json", tmp_path / "package-lock.json")   # what npm wrote
    guard.on_post_tool_call(tool_name="terminal", args=args, result="added 4 packages", session_id="s", tool_call_id="t")
    [(_event, [finding], detail)] = [entry for entry in recorded if entry[0] == "post_install_dependencies"]
    assert finding.severity == "critical" and finding.confirmed is True
    assert "express → body-parser → bad-pkg@1.2.3" in finding.title
    assert "npm uninstall express" in finding.advice and "install scripts may already have run" in finding.advice
    assert detail["session_id"] == "s" and detail["decision"] == "flag"


def test_only_packages_the_install_added_are_judged_after_it(blackbox, tmp_path):
    recorded = blackbox(VERIFIED)
    shutil.copy(FIXTURES / "npm_v3" / "package-lock.json", tmp_path / "package-lock.json")   # already there
    args = {"command": "npm install left-pad", "workdir": str(tmp_path)}
    guard.on_pre_tool_call(tool_name="terminal", args=args, session_id="s", tool_call_id="t")
    guard.on_post_tool_call(tool_name="terminal", args=args, result="", session_id="s", tool_call_id="t")
    assert [entry for entry in recorded if entry[0] == "post_install_dependencies"] == []


def test_an_ordinary_call_does_not_ask_for_the_rules_after_it(blackbox, tmp_path, monkeypatch):
    blackbox(VERIFIED)
    asked: list = []
    monkeypatch.setattr(ruleset_mod, "get", lambda cfg=None: asked.append(1) or ruleset_mod.Ruleset())
    guard.on_post_tool_call(tool_name="terminal", args={"command": "ls", "workdir": str(tmp_path)}, session_id="s")
    assert asked == []


# ------------------------------------------------------------------ writes


def test_a_write_adding_a_verified_package_is_blocked(blackbox, tmp_path):
    blackbox(VERIFIED)
    manifest = tmp_path / "package.json"
    manifest.write_text(json.dumps({"dependencies": {"express": "^4.18.2"}}), encoding="utf-8")
    content = json.dumps({"dependencies": {"express": "^4.18.2", "bad-pkg": "1.2.3"}})
    answer = guard.on_pre_tool_call(tool_name="write_file", args={"path": str(manifest), "content": content},
                                    session_id="s")
    assert answer is not None and answer["action"] == "block" and "dep:npm:bad-pkg@1.2.3" in answer["message"]


def test_an_edit_adding_a_verified_requirement_is_blocked_and_one_keeping_it_is_not_new(blackbox, tmp_path):
    blackbox({"pypi:evil-pkg@0.1.0": {"identifier": "dep:pypi:evil-pkg@0.1.0", "severity": "critical",
                                      "name": "Malicious package", "kind": "malware"}})
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests==2.32.3\n", encoding="utf-8")
    edit = {"path": str(requirements), "old_string": "requests==2.32.3", "new_string": "requests==2.32.3\nevil-pkg==0.1.0"}
    answer = guard.on_pre_tool_call(tool_name="edit_file", args=edit, session_id="s")
    assert answer is not None and "dep:pypi:evil-pkg@0.1.0" in answer["message"]
    requirements.write_text("requests==2.32.3\nevil-pkg==0.1.0\n", encoding="utf-8")
    keep = {"path": str(requirements), "old_string": "requests==2.32.3", "new_string": "requests==2.32.4"}
    assert guard.on_pre_tool_call(tool_name="edit_file", args=keep, session_id="s") is None


def test_a_write_adding_a_community_package_flags(blackbox, tmp_path):
    recorded = blackbox(COMMUNITY)
    manifest = tmp_path / "package.json"
    answer = guard.on_pre_tool_call(tool_name="write_file", session_id="s", args={
        "path": str(manifest), "content": json.dumps({"dependencies": {"bad-pkg": "1.2.3"}})})
    assert answer is None
    assert [f.identifier for _e, findings, _d in recorded for f in findings] == ["dep:npm:bad-pkg@1.2.3"]
