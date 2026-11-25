"""The dependency-file readers, their bounds and their cache (KI-595).

Blackbox checked only the package names an install command spelled out; what ``npm ci``,
``uv sync`` or ``pip install -r`` install, and what a named package pulls in, was never checked.
These tests hold each reader to a small, hand-written file in the real format (fixtures under
``fixtures/blackbox_dependency_files/``): the packages and exact versions it pins, the chain from
the project to a package, and the notes on what it could not read. Then the bounds (size cap,
include depth, symlinks, garbage) and the cache: an unchanged file is never opened again, a
touched file with the same content is not parsed again, and a 2,000-package lockfile is judged
inside the hook budget.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from _blackbox_loader import load_blackbox

registry = load_blackbox("detection.manifests.registry")
verdicts = load_blackbox("detection.manifests.verdicts")
checks = load_blackbox("detection.manifests.checks")
ruleset_mod = load_blackbox("ruleset")
threat_ids = load_blackbox("kernel.threat_ids")

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "blackbox_dependency_files"
BAD = {"bad-pkg", "evil-pkg", "evil-crate", "evil-gem"}


@pytest.fixture(autouse=True)
def _fresh_caches():
    registry.PARSED.clear()
    verdicts.VERDICTS.clear()
    checks.SNAPSHOTS.clear()
    yield
    registry.PARSED.clear()
    verdicts.VERDICTS.clear()
    checks.SNAPSHOTS.clear()


def _graph(folder: str, name: str):
    found = registry.read(str(FIXTURES / folder / name))
    assert found.graph is not None, found.note
    return found.graph


def _bad_chain(graph) -> str:
    bad = [node for node, package in graph.nodes.items() if threat_ids.canonical_package_name("pypi", package.name) in BAD]
    assert len(bad) == 1, graph.nodes
    return graph.chains(bad)[bad[0]]


@pytest.mark.parametrize("folder, name, chain", [
    ("npm_v3", "package-lock.json", "express → body-parser → bad-pkg@1.2.3"),
    ("npm_v1", "package-lock.json", "express → body-parser → bad-pkg@1.2.3"),
    ("pnpm_v9", "pnpm-lock.yaml", "express → body-parser → bad-pkg@1.2.3"),
    ("pnpm_v6", "pnpm-lock.yaml", "express → body-parser → bad-pkg@1.2.3"),
    ("yarn_classic", "yarn.lock", "express → body-parser → bad-pkg@1.2.3"),
    ("yarn_berry", "yarn.lock", "express → body-parser → bad-pkg@1.2.3"),
    ("bun", "bun.lock", "express → body-parser → bad-pkg@1.2.3"),
    ("uv", "uv.lock", "requests → evil-pkg@0.1.0"),
    ("poetry", "poetry.lock", "requests → evil-pkg@0.1.0"),
    ("cargo", "Cargo.lock", "serde → evil-crate@0.1.0"),
    ("gem", "Gemfile.lock", "rails-ish → evil-gem@1.0.0"),
])
def test_each_lockfile_gives_the_exact_version_and_the_chain_from_the_project(folder, name, chain):
    graph = _graph(folder, name)
    assert _bad_chain(graph) == chain
    assert all(package.exact for package in graph.nodes.values())


def test_npm_lockfile_reads_a_nested_copy_and_counts_a_git_source_in_a_note():
    graph = _graph("npm_v3", "package-lock.json")
    versions = {package.name: package.version for package in graph.nodes.values()}
    assert versions == {"express": "4.18.2", "body-parser": "1.20.1", "bad-pkg": "1.2.3", "left-pad": "1.3.0"}
    assert any("git, a URL or a local folder" in note for note in graph.notes)


def test_pnpm_reads_a_scoped_package():
    graph = _graph("pnpm_v9", "pnpm-lock.yaml")
    assert ("npm", "@scope/util", "2.0.0") in graph.package_keys()


def test_yarn_berry_skips_the_workspace_itself_and_says_so():
    graph = _graph("yarn_berry", "yarn.lock")
    assert "shop" not in {package.name for package in graph.nodes.values()}
    assert any("workspaces" in note for note in graph.notes)


def test_package_json_is_ranges_honestly_marked():
    graph = _graph("npm_v3", "package.json")
    assert graph.exact is False and any("ranges, not exact versions" in note for note in graph.notes)
    express = next(p for p in graph.nodes.values() if p.name == "express")
    left_pad = next(p for p in graph.nodes.values() if p.name == "left-pad")
    assert (express.exact, express.version) == (False, "^4.18.2")
    assert (left_pad.exact, left_pad.version) == (True, "1.3.0")   # an exact spec is an exact pin


def test_package_json_alias_names_the_real_package_and_git_sources_are_counted():
    found = registry.parse_text(json.dumps({"dependencies": {
        "lp": "npm:left-pad@1.3.0", "thing": "github:someone/thing", "local": "file:../local"}}), "package.json")
    names = {(p.name, p.version) for p in found.graph.nodes.values()}
    assert names == {("left-pad", "1.3.0")}
    assert any("2 dependency(ies)" in note for note in found.graph.notes)


def test_requirements_follow_includes_and_report_direct_sources():
    files = registry._requirements((str(FIXTURES / "python" / "requirements.txt"),))
    packages = {(p.name, p.version, p.exact) for f in files if f.graph for p in f.graph.nodes.values()}
    assert ("requests", "2.32.3", True) in packages            # the --hash continuation is not a package
    assert ("evil_pkg", "0.1.0", True) in packages             # from -r requirements-dev.txt, marker dropped
    assert ("urllib3", "2.2.1", True) in packages              # from its -c constraints.txt
    assert ("Flask", ">=3.0", False) in packages
    notes = [note for f in files if f.graph for note in f.graph.notes]
    assert any("2 install(s)" in note and "unpinned direct sources" in note for note in notes)


def test_requirements_include_depth_is_bounded(tmp_path):
    for depth in range(registry.MAX_INCLUDE_DEPTH + 3):
        (tmp_path / f"r{depth}.txt").write_text(f"pkg{depth}==1.0\n-r r{depth + 1}.txt\n", encoding="utf-8")
    files = registry._requirements((str(tmp_path / "r0.txt"),))
    assert any("deep — not read" in f.note for f in files)
    read = [f for f in files if f.graph is not None]
    assert len(read) == registry.MAX_INCLUDE_DEPTH + 1


def test_an_include_loop_is_read_once(tmp_path):
    (tmp_path / "a.txt").write_text("-r b.txt\nx==1\n", encoding="utf-8")
    (tmp_path / "b.txt").write_text("-r a.txt\ny==1\n", encoding="utf-8")
    assert len(registry._requirements((str(tmp_path / "a.txt"),))) == 2


@pytest.mark.parametrize("folder, name, expected", [
    ("python", "pyproject.toml", {("evil-pkg", "0.1.0", True), ("requests", ">=2.31", False), ("pytest", ">=8", False)}),
    ("pipenv", "Pipfile.lock", {("evil-pkg", "0.1.0", True), ("requests", "2.32.3", True)}),
])
def test_python_manifests(folder, name, expected):
    graph = _graph(folder, name)
    assert {(p.name, p.version, p.exact) for p in graph.nodes.values()} == expected


def test_a_gem_platform_suffix_is_not_part_of_the_version():
    assert ("rubygems", "nokogiri", "1.16.2") in _graph("gem", "Gemfile.lock").package_keys()


# ------------------------------------------------------------------ bounds


def test_a_file_over_the_size_cap_is_a_note_not_a_read(tmp_path, monkeypatch):
    monkeypatch.setattr(registry, "MAX_FILE_BYTES", 64)
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({"lockfileVersion": 3, "packages": {"": {}, "node_modules/x": {"version": "1.0.0"}}}),
                    encoding="utf-8")
    found = registry.read(str(lock))
    assert found.graph is None and "larger than" in found.note


@pytest.mark.parametrize("name, text", [("package-lock.json", "{not json"), ("uv.lock", "[[package]\n"),
                                        ("bun.lock", "[1, 2"), ("package-lock.json", "[1, 2, 3]")])
def test_garbage_is_a_note_never_an_exception(tmp_path, name, text):
    (tmp_path / name).write_text(text, encoding="utf-8")
    found = registry.read(str(tmp_path / name))
    assert found.graph is None and "could not be parsed" in found.note


def test_a_symlinked_lockfile_is_not_followed(tmp_path):
    target = tmp_path / "elsewhere.json"
    target.write_text("{}", encoding="utf-8")
    (tmp_path / "package-lock.json").symlink_to(target)
    found = registry.read(str(tmp_path / "package-lock.json"))
    assert found.graph is None and "could not be read" in found.note


def test_a_binary_bun_lockfile_is_named_as_unsupported(tmp_path):
    (tmp_path / "bun.lockb").write_bytes(b"\x00\x01binary")
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    site = load_blackbox("detection.manifests.commands").InstallSite("bun", str(tmp_path))
    [found] = registry.files_for(site)
    assert found.graph is None and "binary lockfile" in found.note


# ------------------------------------------------------------------ cache


def test_an_unchanged_file_is_answered_without_opening_it(tmp_path, monkeypatch):
    lock = tmp_path / "package-lock.json"
    lock.write_text((FIXTURES / "npm_v3" / "package-lock.json").read_text(encoding="utf-8"), encoding="utf-8")
    opened: list[str] = []
    real = registry.read_small_text
    monkeypatch.setattr(registry, "read_small_text", lambda path, *a, **k: opened.append(path) or real(path, *a, **k))
    first = registry.read(str(lock))
    second = registry.read(str(lock))
    assert opened == [str(lock)] and second.graph is first.graph


def test_a_touched_file_with_the_same_content_is_not_parsed_again(tmp_path, monkeypatch):
    lock = tmp_path / "package-lock.json"
    lock.write_text((FIXTURES / "npm_v3" / "package-lock.json").read_text(encoding="utf-8"), encoding="utf-8")
    first = registry.read(str(lock))
    os.utime(lock, ns=(1, 1))
    assert registry.read(str(lock)).graph is first.graph
    lock.write_text(json.dumps({"lockfileVersion": 3, "packages": {"": {}}}), encoding="utf-8")
    assert registry.read(str(lock)).graph is not first.graph   # new content: parsed again


def _big_lock(path: Path, count: int) -> None:
    packages = {"": {"name": "big", "dependencies": {f"pkg-{i}": "^1.0.0" for i in range(0, count, 10)}}}
    for i in range(count):
        entry = {"version": f"1.0.{i % 50}", "resolved": f"https://registry.npmjs.org/pkg-{i}/-/pkg-{i}.tgz",
                 "integrity": "sha512-" + "A" * 86}
        if i % 10 == 0 and i + 9 < count:
            entry["dependencies"] = {f"pkg-{i + j}": "^1.0.0" for j in range(1, 10)}
        packages[f"node_modules/pkg-{i}"] = entry
    path.write_text(json.dumps({"name": "big", "lockfileVersion": 3, "packages": packages}, indent=2), encoding="utf-8")


def test_a_2000_package_lockfile_is_judged_inside_the_hook_budget(tmp_path):
    """Target: under 50 ms cold and under 1 ms cached (measured numbers are in the KI-595 record).
    The bounds asserted here are looser so a loaded CI machine does not fail them by chance."""
    _big_lock(tmp_path / "package-lock.json", 2000)
    rs = ruleset_mod.Ruleset()
    rs.dependency = {"npm:pkg-1999@1.0.49": {"identifier": "dep:npm:pkg-1999@1.0.49", "severity": "critical",
                                             "name": "Malicious package", "kind": "malware"}}
    call = ("terminal", {"command": "npm ci", "workdir": str(tmp_path)})
    cold = []
    for _ in range(3):
        registry.PARSED.clear()
        verdicts.VERDICTS.clear()
        started = time.perf_counter()
        check = checks.check_install_files(*call, rs)
        cold.append(time.perf_counter() - started)
    assert [f.identifier for f in check.findings] == ["dep:npm:pkg-1999@1.0.49"]
    assert "pkg-1990 → pkg-1999@1.0.49" in check.findings[0].title
    cached = []
    for _ in range(20):
        started = time.perf_counter()
        checks.check_install_files(*call, rs)
        cached.append(time.perf_counter() - started)
    assert min(cold) < 0.25, f"cold {min(cold) * 1000:.1f} ms"
    assert min(cached) < 0.005, f"cached {min(cached) * 1000:.2f} ms"
