"""Python's dependency files: requirements*.txt, uv.lock, poetry.lock, Pipfile.lock, Pipfile and
pyproject.toml (KI-595).

One reader per format (Strategy — :mod:`.registry` picks it). Each takes the file's TEXT and
returns a :class:`~.model.DependencyGraph`. A requirements file's ``-r`` / ``-c`` includes are
returned in ``includes`` for the registry to follow (bounded); a URL, VCS or local-path install
cannot be checked by name and version and is counted in a note, never dropped silently.
"""

from __future__ import annotations

import json
import re
import tomllib
from typing import Any, Iterable, Optional

from .model import DependencyGraph, Package, by_name

ECOSYSTEM = "pypi"

#: A PEP 508 requirement: name, optional extras, then the rest (a version spec, ``@ url`` or a marker).
_REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")
_EXACT = re.compile(r"^===?\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)$")
_INCLUDE = re.compile(r"^(?:-r|--requirement|-c|--constraint)(?:\s+|=)(\S+)")
#: Lines that install from somewhere other than the index by name: an editable, a URL, a VCS, a local path.
_DIRECT_SOURCE = re.compile(r"^(?:-e|--editable)\b|^(?:git\+|hg\+|svn\+|bzr\+|https?://|file:|\.{0,2}/|~/)")


def requirement(text: str) -> tuple[Optional[Package], bool]:
    """``(package, from the index)`` for one PEP 508 requirement string ("requests==2.32.3 ; python_version>'3'")."""
    found = _REQUIREMENT.match(text.split(";", 1)[0])
    if not found:
        return None, True
    name, spec = found.group(1), found.group(2).strip()
    if spec.startswith("@"):
        return None, False   # name @ https://… — a direct URL
    exact = _EXACT.match(spec)
    if exact and "*" not in exact.group(1):
        return Package(ECOSYSTEM, name, exact.group(1)), True
    return Package(ECOSYSTEM, name, spec, exact=False), True


def _logical_lines(text: str) -> Iterable[str]:
    """Requirements lines with comments dropped and ``\\`` continuations joined."""
    for line in re.sub(r"\\\r?\n", " ", text).splitlines():
        line = re.sub(r"(^|\s)#.*$", "", line).strip()
        if line:
            yield line


def read_requirements(text: str, source: str) -> DependencyGraph:
    """requirements*.txt / constraints files: pins are exact, ranges are ranges, ``-r`` / ``-c`` followed."""
    packages: list[Package] = []
    includes: list[str] = []
    direct = ranges = 0
    for line in _logical_lines(text):
        include = _INCLUDE.match(line)
        if include:
            includes.append(include.group(1))
            continue
        if _DIRECT_SOURCE.match(line):
            direct += 1
            continue
        if line.startswith("-"):
            continue   # --hash, --index-url, -f …: options, not packages
        package, from_index = requirement(line.split(" --hash", 1)[0])
        if not from_index:
            direct += 1
        elif package is not None:
            packages.append(package)
            ranges += not package.exact
    notes = _source_notes(source, direct)
    if ranges:
        notes.append(f"{ranges} requirement(s) in {source} are ranges, not exact versions: "
                     "only whole-package rules can match them")
    graph = DependencyGraph.flat(source, packages, notes, exact=not ranges)
    graph.includes = tuple(includes)
    return graph


def _source_notes(source: str, direct: int) -> list[str]:
    return [f"{direct} install(s) in {source} come from a URL, VCS or local path (unpinned direct sources) — "
            "not checked by name"] if direct else []


def _toml(text: str) -> dict[str, Any]:
    return tomllib.loads(text)


def _dependency_names(entries: Any) -> list[str]:
    """Names from a uv.lock dependency list (``[{name = "x"}, …]``) or a poetry table (``{x = "^1"}``)."""
    if isinstance(entries, dict):
        return [str(name) for name in entries]
    return [str(entry.get("name")) for entry in entries or () if isinstance(entry, dict) and entry.get("name")]


def _locked_graph(source: str, packages: list[dict[str, Any]], is_project: Any, dependency_tables: Any) -> DependencyGraph:
    """The graph of a TOML lockfile's ``[[package]]`` list (uv.lock, poetry.lock)."""
    graph = DependencyGraph(source=source)
    wants: dict[str, list[str]] = {}
    project_wants: list[str] = []
    direct = 0
    for entry in packages:
        if not isinstance(entry, dict) or not entry.get("name"):
            continue
        names = [name for table in dependency_tables(entry) for name in _dependency_names(table)]
        if is_project(entry):
            project_wants += names
            continue
        source_kind = entry.get("source") if isinstance(entry.get("source"), dict) else {}
        if not entry.get("version") or set(source_kind) & {"git", "url", "path", "directory"} or \
                str(source_kind.get("type", "")) in ("git", "url", "file", "directory"):
            direct += 1
            continue
        node = f"{entry['name']}@{entry['version']}"
        graph.nodes[node] = Package(ECOSYSTEM, str(entry["name"]), str(entry["version"]))
        wants[node] = names
    names = by_name(graph.nodes)
    for node, wanted in wants.items():
        graph.requires[node] = tuple(names[n.lower()] for n in wanted if n.lower() in names)
    roots = [names[n.lower()] for n in project_wants if n.lower() in names]
    required = {child for children in graph.requires.values() for child in children}
    graph.roots = tuple(dict.fromkeys(roots)) or tuple(n for n in graph.nodes if n not in required)
    graph.notes += _source_notes(source, direct)
    return graph


def _uv_tables(entry: dict[str, Any]) -> list[Any]:
    tables = [entry.get("dependencies")]
    for group in ("optional-dependencies", "dev-dependencies"):
        tables += list((entry.get(group) or {}).values())
    return tables


def read_uv_lock(text: str, source: str) -> DependencyGraph:
    """uv.lock: the project's own entry (``source = { editable | virtual = "." }``) names the roots."""
    def is_project(entry: dict[str, Any]) -> bool:
        kind = entry.get("source") or {}
        return isinstance(kind, dict) and bool({"editable", "virtual"} & set(kind))
    return _locked_graph(source, _toml(text).get("package") or [], is_project, _uv_tables)


def read_poetry_lock(text: str, source: str) -> DependencyGraph:
    """poetry.lock: ``[[package]]`` with ``[package.dependencies]``; the roots are what nothing requires."""
    return _locked_graph(source, _toml(text).get("package") or [], lambda entry: False,
                         lambda entry: [entry.get("dependencies")])


def read_pipfile_lock(text: str, source: str) -> DependencyGraph:
    """Pipfile.lock: ``default`` and ``develop`` maps of ``name → {version: "==1.2.3"}``."""
    lock = json.loads(text)
    packages: list[Package] = []
    direct = 0
    for section in ("default", "develop"):
        for name, entry in ((lock.get(section) or {}).items() if isinstance(lock, dict) else ()):
            version = str((entry or {}).get("version") or "") if isinstance(entry, dict) else ""
            if not version.startswith("=="):
                direct += 1   # git / path / file entries carry no index version
                continue
            packages.append(Package(ECOSYSTEM, str(name), version.lstrip("=")))
    return DependencyGraph.flat(source, packages, _source_notes(source, direct))


def _ranges_graph(source: str, specs: Iterable[str]) -> DependencyGraph:
    packages: list[Package] = []
    direct = 0
    for spec in specs:
        package, from_index = requirement(spec)
        if package is not None and from_index:
            packages.append(package)
        direct += not from_index
    notes = [f"{source} holds ranges, not exact versions: only whole-package rules and exact pins can match "
             "until a lockfile exists"] + _source_notes(source, direct)
    return DependencyGraph.flat(source, packages, notes, exact=False)


def _table_specs(table: Any) -> list[str]:
    """``{name = "^1.0"}`` / ``{name = {version = "1.0"}}`` (Pipfile, Poetry) as PEP 508-ish strings."""
    specs: list[str] = []
    for name, value in (table.items() if isinstance(table, dict) else ()):
        if str(name).lower() == "python":
            continue
        if isinstance(value, dict):
            value = "@ direct" if {"git", "path", "url", "file"} & set(value) else value.get("version", "")
        value = "" if str(value).strip() == "*" else str(value).strip()
        specs.append(f"{name} {value}" if value.startswith("@") else f"{name}{value}")
    return specs


def read_pyproject(text: str, source: str) -> DependencyGraph:
    """pyproject.toml: ``[project] dependencies``, ``optional-dependencies``, ``[dependency-groups]``
    and Poetry's ``[tool.poetry.dependencies]`` — ranges, not exact versions."""
    project = _toml(text)
    specs: list[str] = list((project.get("project") or {}).get("dependencies") or [])
    for group in ((project.get("project") or {}).get("optional-dependencies") or {}).values():
        specs += list(group or [])
    for group in (project.get("dependency-groups") or {}).values():
        specs += [item for item in group or [] if isinstance(item, str)]
    poetry = (project.get("tool") or {}).get("poetry") or {}
    specs += _table_specs(poetry.get("dependencies"))
    specs += _table_specs(poetry.get("dev-dependencies"))
    return _ranges_graph(source, [str(spec) for spec in specs])


def read_pipfile(text: str, source: str) -> DependencyGraph:
    """Pipfile (no lock yet): ``[packages]`` and ``[dev-packages]`` — ranges, not exact versions."""
    pipfile = _toml(text)
    return _ranges_graph(source, _table_specs(pipfile.get("packages")) + _table_specs(pipfile.get("dev-packages")))
