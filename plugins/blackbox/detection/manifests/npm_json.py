"""npm's JSON dependency files: package-lock.json (v1, v2, v3), npm-shrinkwrap.json,
``node_modules/.package-lock.json`` and package.json (KI-595).

One reader per format (Strategy — :mod:`.registry` picks it by file name). Each takes the
file's TEXT and returns a :class:`~.model.DependencyGraph`; none reads a disk or a network.

A v2/v3 lockfile's ``packages`` map is keyed by install location (``node_modules/a/
node_modules/b``); a dependency NAME is resolved the way Node resolves it — the nearest
``node_modules`` folder up the tree — so the chain "express → body-parser → bad@1.2.3" is the
one npm itself built. A v1 lockfile's nested ``dependencies`` tree is flattened to the same keys.
"""

from __future__ import annotations

import json
from typing import Any, Iterator

from .model import DependencyGraph, Package

ECOSYSTEM = "npm"
_NM = "node_modules/"
#: The dependency fields a package entry may carry (a root's devDependencies included).
_DEPENDENCY_FIELDS = ("dependencies", "optionalDependencies", "peerDependencies", "devDependencies")
#: package.json fields a person's install reads (peer dependencies are the host's, not installed here).
_MANIFEST_FIELDS = ("dependencies", "devDependencies", "optionalDependencies")
#: Version specs that do not come from the npm registry: their package is not checkable by name and version.
_NOT_REGISTRY = ("git+", "git:", "github:", "gitlab:", "bitbucket:", "http:", "https:", "file:", "link:",
                 "workspace:", "portal:", "patch:")
#: Where a lockfile says a package was fetched from when it is not the registry (an https
#: tarball is still a named, versioned package and is checked).
_NOT_REGISTRY_RESOLVED = ("git+", "git:", "github:", "gitlab:", "bitbucket:", "file:", "link:")


def _object(text: str) -> dict[str, Any]:
    loaded = json.loads(text)
    if not isinstance(loaded, dict):
        raise ValueError("not a JSON object")
    return loaded


def _name_from_key(key: str) -> str:
    """``node_modules/a/node_modules/@s/b`` → ``@s/b``."""
    return key.rsplit(_NM, 1)[-1]


def _resolve(requirer: str, name: str, nodes: dict[str, Package]) -> str:
    """The install location Node would load *name* from, seen from *requirer* ("" = none found)."""
    base = requirer
    while True:
        candidate = f"{base}/{_NM}{name}" if base else f"{_NM}{name}"
        if candidate in nodes:
            return candidate
        if not base:
            return ""
        cut = base.rfind("/" + _NM)
        base = base[:cut] if cut >= 0 else ""


def _dependency_names(entry: dict[str, Any]) -> Iterator[str]:
    for field_name in _DEPENDENCY_FIELDS:
        names = entry.get(field_name)
        if isinstance(names, dict):
            yield from (str(name) for name in names)


def _from_registry(entry: dict[str, Any]) -> bool:
    resolved = str(entry.get("resolved") or "")
    return not resolved.startswith(_NOT_REGISTRY_RESOLVED) and not entry.get("link")


def _link_graph(source: str, entries: dict[str, dict[str, Any]], root_entry: dict[str, Any]) -> DependencyGraph:
    """The graph of a ``packages``-style map (*entries*: install location → entry)."""
    graph = DependencyGraph(source=source)
    unregistered = 0
    for key, entry in entries.items():
        if not key or not isinstance(entry, dict) or _NM not in key:
            continue   # the root and workspace folders are the project itself, not packages
        if not _from_registry(entry) or not entry.get("version"):
            unregistered += 1
            continue
        graph.nodes[key] = Package(ECOSYSTEM, str(entry.get("name") or _name_from_key(key)), str(entry["version"]))
    for key in graph.nodes:
        children = (_resolve(key, name, graph.nodes) for name in _dependency_names(entries[key]))
        graph.requires[key] = tuple(child for child in children if child)
    roots = [_resolve("", name, graph.nodes) for name in _dependency_names(root_entry)]
    graph.roots = tuple(dict.fromkeys(root for root in roots if root)) or _unrequired(graph)
    if unregistered:
        graph.notes.append(f"{unregistered} package(s) in {source} come from git, a URL or a local folder, "
                           "not the npm registry — not checked by name")
    return graph


def _unrequired(graph: DependencyGraph) -> tuple[str, ...]:
    """Nodes nothing else requires — the roots when a file does not name the project's own."""
    required = {child for children in graph.requires.values() for child in children}
    return tuple(node for node in graph.nodes if node not in required)


def _flatten_v1(tree: dict[str, Any], prefix: str, out: dict[str, dict[str, Any]]) -> None:
    """A v1 nested ``dependencies`` tree as a v2-style ``packages`` map (``requires`` as dependencies)."""
    for name, entry in tree.items():
        if not isinstance(entry, dict):
            continue
        key = f"{prefix}{_NM}{name}"
        version = str(entry.get("version") or "")
        flat = {"name": name, "version": version, "dependencies": entry.get("requires") or {}}
        if version.startswith(_NOT_REGISTRY) or str(entry.get("resolved") or "").startswith(_NOT_REGISTRY_RESOLVED):
            flat["link"] = True
        out[key] = flat
        nested = entry.get("dependencies")
        if isinstance(nested, dict):
            _flatten_v1(nested, key + "/", out)


def read_package_lock(text: str, source: str) -> DependencyGraph:
    """package-lock.json / npm-shrinkwrap.json / node_modules/.package-lock.json, any version."""
    lock = _object(text)
    packages = lock.get("packages")
    if isinstance(packages, dict):   # v2 and v3 (v2 also keeps v1's tree; the map is the truth)
        root = packages.get("") if isinstance(packages.get(""), dict) else {}
        return _link_graph(source, packages, root)
    flat: dict[str, dict[str, Any]] = {}
    tree = lock.get("dependencies")
    if isinstance(tree, dict):
        _flatten_v1(tree, "", flat)
    return _link_graph(source, flat, {})   # no root entry: the roots are what nothing requires


def _alias_target(spec: str) -> tuple[str, str]:
    """``npm:@scope/real@^1.0`` → ``("@scope/real", "^1.0")``: an alias installs the package it names."""
    target = spec[len("npm:"):]
    at = target.rfind("@")
    return (target[:at], target[at + 1:]) if at > 0 else (target, "")


def _manifest_package(name: str, spec: str) -> tuple[Package | None, bool]:
    """``(package, from the registry)`` for one package.json entry."""
    if spec.startswith("npm:"):
        name, spec = _alias_target(spec)
    if spec.startswith(_NOT_REGISTRY) or "/" in spec:   # "user/repo" is GitHub shorthand
        return None, False
    bare = spec.lstrip("=v")
    exact = bool(bare) and bare[0].isdigit() and not any(ch in bare for ch in " <>^~*xX|")
    return Package(ECOSYSTEM, name, bare if exact else spec, exact=exact), True


def read_package_json(text: str, source: str) -> DependencyGraph:
    """package.json's dependencies, devDependencies and optionalDependencies — RANGES, not exact
    versions: only an exact spec ("1.2.3") or a whole-package rule can match before npm resolves them."""
    manifest = _object(text)
    packages: list[Package] = []
    unregistered = 0
    for field_name in _MANIFEST_FIELDS:
        entries = manifest.get(field_name)
        for name, spec in (entries.items() if isinstance(entries, dict) else ()):
            package, registry = _manifest_package(str(name), str(spec).strip())
            if package is not None:
                packages.append(package)
            unregistered += not registry
    notes = [f"{source} holds ranges, not exact versions: only whole-package rules and exact pins can match "
             "until a lockfile exists"]
    if unregistered:
        notes.append(f"{unregistered} dependency(ies) in {source} come from git, a URL or a local folder — not checked")
    return DependencyGraph.flat(source, packages, notes, exact=False)
