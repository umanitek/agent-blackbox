"""Rust's Cargo.lock and Ruby's Gemfile.lock (KI-595).

One reader per format (Strategy — :mod:`.registry` picks it). Both lockfiles pin exact
versions and say who requires whom, so a verdict names the chain. Cargo.toml and a Gemfile
without its lock are not read: their version requirements resolve only when cargo or bundler
runs (the registry says so in a note).
"""

from __future__ import annotations

import re
import tomllib

from .model import DependencyGraph, Package, by_name

CARGO = "cargo"
RUBYGEMS = "rubygems"


def read_cargo_lock(text: str, source: str) -> DependencyGraph:
    """Cargo.lock: ``[[package]]`` entries; a package with no ``source`` is the workspace's own crate
    (its dependencies are the roots); a ``git+`` source is not the registry and is counted in a note."""
    graph = DependencyGraph(source=source)
    wants: dict[str, list[str]] = {}
    project_wants: list[str] = []
    direct = 0
    for entry in tomllib.loads(text).get("package") or []:
        if not isinstance(entry, dict) or not entry.get("name") or not entry.get("version"):
            continue
        dependencies = [str(dep) for dep in entry.get("dependencies") or []]
        origin = str(entry.get("source") or "")
        if not origin:
            project_wants += dependencies
            continue
        if not origin.startswith("registry+") and not origin.startswith("sparse+"):
            direct += 1
            continue
        node = f"{entry['name']}@{entry['version']}"
        graph.nodes[node] = Package(CARGO, str(entry["name"]), str(entry["version"]))
        wants[node] = dependencies
    names = by_name(graph.nodes)

    def resolve(spec: str) -> str:
        # "name", "name 1.2.3" or "name 1.2.3 (registry+…)": a version when two copies are locked.
        parts = spec.split()
        exact = f"{parts[0]}@{parts[1]}" if len(parts) > 1 else ""
        return exact if exact in graph.nodes else names.get(parts[0].lower(), "") if parts else ""

    for node, wanted in wants.items():
        graph.requires[node] = tuple(child for child in map(resolve, wanted) if child)
    roots = [child for child in map(resolve, project_wants) if child]
    required = {child for children in graph.requires.values() for child in children}
    graph.roots = tuple(dict.fromkeys(roots)) or tuple(n for n in graph.nodes if n not in required)
    if direct:
        graph.notes.append(f"{direct} crate(s) in {source} come from git or a path, not crates.io — not checked by name")
    return graph


_GEM_SPEC = re.compile(r"^    (\S+) \(([^)]+)\)\s*$")
_GEM_DEPENDENCY = re.compile(r"^      (\S+)(?: \(.*\))?\s*$")
_GEM_ROOT = re.compile(r"^  (\S+?)!?(?: \(.*\))?\s*$")
#: A platform gem's version carries its platform ("1.13.10-x86_64-darwin"); the rule names the release.
_GEM_RELEASE = re.compile(r"^(\d[^-\s]*)")


def read_gemfile_lock(text: str, source: str) -> DependencyGraph:
    """Gemfile.lock: the ``GEM`` section's specs (four spaces) and their dependencies (six), the
    ``DEPENDENCIES`` section the roots. ``GIT`` and ``PATH`` specs are not the registry (a note)."""
    graph = DependencyGraph(source=source)
    wants: dict[str, list[str]] = {}
    roots: list[str] = []
    section, current, direct = "", "", 0
    for line in text.splitlines():
        if line and not line.startswith(" "):
            section, current = line.strip(), ""
            continue
        spec = _GEM_SPEC.match(line)
        if spec and section in ("GEM", "GIT", "PATH"):
            if section != "GEM":
                direct += 1
                current = ""
                continue
            release = _GEM_RELEASE.match(spec.group(2))
            current = f"{spec.group(1)}@{release.group(1) if release else spec.group(2)}"
            graph.nodes.setdefault(current, Package(RUBYGEMS, spec.group(1), current.rsplit("@", 1)[1]))
            continue
        dependency = _GEM_DEPENDENCY.match(line) if current else None
        if dependency:
            wants.setdefault(current, []).append(dependency.group(1))
            continue
        root = _GEM_ROOT.match(line) if section == "DEPENDENCIES" else None
        if root:
            roots.append(root.group(1))
    names = by_name(graph.nodes)
    for node, wanted in wants.items():
        graph.requires[node] = tuple(names[n.lower()] for n in wanted if n.lower() in names)
    graph.roots = tuple(dict.fromkeys(names[n.lower()] for n in roots if n.lower() in names))
    if direct:
        graph.notes.append(f"{direct} gem(s) in {source} come from git or a path, not rubygems.org — not checked by name")
    return graph
