"""The JavaScript lockfiles that are not npm's JSON: pnpm-lock.yaml, yarn.lock (classic v1
and berry v2+) and bun.lock (text) (KI-595).

Each reader is a line scanner over the file's own layout, not a YAML or JSONC library: the
formats are regular, a scanner reads a 2,000-package lockfile in a few milliseconds, and it
needs no dependency the plugin does not already carry. Only what a verdict needs is read —
each package's name and exact version, and the names it depends on.
"""

from __future__ import annotations

import json
import re
from typing import Optional

from .model import DependencyGraph, Package, by_name
from .npm_json import ECOSYSTEM

# --------------------------------------------------------------------- pnpm-lock.yaml

#: A package key at two spaces under ``packages:`` / ``snapshots:``: ``/name/1.2.3`` (v5),
#: ``/name@1.2.3(peer@1)`` (v6), ``name@1.2.3`` or ``'@scope/name@1.2.3'`` (v9).
_PNPM_KEY = re.compile(r"^  '?/?((?:@[^/@\s']+/)?[^/@\s'(]+)[@/]([0-9][^()\s':]*)[^:]*'?:\s*$")
_PNPM_SECTION = re.compile(r"^(\w[\w-]*):")
_PNPM_DEPENDENCY_BLOCK = re.compile(r"^    (?:dependencies|optionalDependencies):\s*$")
_PNPM_DEPENDENCY = re.compile(r"^      '?((?:@[^/\s']+/)?[^\s':]+)'?:\s*'?([0-9][^()\s']*)")


def read_pnpm_lock(text: str, source: str) -> DependencyGraph:
    """pnpm-lock.yaml (lockfile v5, v6 and v9)."""
    graph = DependencyGraph(source=source)
    section, current, in_dependencies = "", "", False
    pending: dict[str, list[tuple[str, str]]] = {}
    for line in text.splitlines():
        top = _PNPM_SECTION.match(line)
        if top:
            section, current, in_dependencies = top.group(1), "", False
            continue
        if section not in ("packages", "snapshots"):
            continue
        key = _PNPM_KEY.match(line)
        if key:
            current = f"{key.group(1)}@{key.group(2)}"
            graph.nodes.setdefault(current, Package(ECOSYSTEM, key.group(1), key.group(2)))
            in_dependencies = False
            continue
        if current and _PNPM_DEPENDENCY_BLOCK.match(line):
            in_dependencies = True
            continue
        dependency = _PNPM_DEPENDENCY.match(line) if in_dependencies else None
        if dependency:
            pending.setdefault(current, []).append((dependency.group(1), dependency.group(2)))
        elif line.startswith("    ") and not line.startswith("      "):
            in_dependencies = False
    for node, children in pending.items():
        graph.requires[node] = tuple(f"{name}@{version}" for name, version in children
                                     if f"{name}@{version}" in graph.nodes)
    graph.roots = _unrequired(graph)
    return graph


def _unrequired(graph: DependencyGraph) -> tuple[str, ...]:
    required = {child for children in graph.requires.values() for child in children}
    return tuple(node for node in graph.nodes if node not in required)


# --------------------------------------------------------------------- yarn.lock

_YARN_HEADER = re.compile(r"^(\S.*):\s*$")
_YARN_VERSION = re.compile(r'^  version:?\s+"?([^"\s]+)"?\s*$')
_YARN_RESOLUTION = re.compile(r'^  resolution:\s+"?([^"\s]+)"?\s*$')
_YARN_DEPENDENCY_BLOCK = re.compile(r"^  (?:dependencies|optionalDependencies):\s*$")
_YARN_DEPENDENCY = re.compile(r'^    "?((?:@[^@\s"]+/)?[^@\s":]+)"?:?\s+"?([^"\s]+)"?\s*$')
#: Berry protocols that are not the registry: the project itself, a patch, a git or file source.
_YARN_LOCAL = ("@workspace:", "@link:", "@portal:", "@file:", "@patch:", "@git", "@https:", "@http:", "@exec:")


def _descriptor_name(descriptor: str) -> str:
    """``@scope/name@npm:^1`` / ``name@^1`` → its package name."""
    at = descriptor.find("@", 1)
    return descriptor[:at] if at > 0 else descriptor


def _descriptor(name: str, spec: str) -> str:
    return f"{name}@{spec}"


def read_yarn_lock(text: str, source: str) -> DependencyGraph:
    """yarn.lock, classic (``version "1.2.3"``) and berry (``version: 1.2.3`` with ``npm:`` descriptors)."""
    graph = DependencyGraph(source=source)
    owner: dict[str, str] = {}   # descriptor → node
    pending: dict[str, list[str]] = {}
    descriptors: list[str] = []
    current, in_dependencies, local = "", False, 0
    for line in text.splitlines():
        header = _YARN_HEADER.match(line)
        if header and not line.startswith("#"):
            descriptors = [part.strip().strip('"') for part in header.group(1).split(",")]
            current, in_dependencies = "", False
            continue
        version = _YARN_VERSION.match(line)
        if version and descriptors and not current:
            if descriptors[0] == "__metadata" or any(mark in d for d in descriptors for mark in _YARN_LOCAL):
                local += descriptors[0] != "__metadata"
                descriptors = []
                continue
            name = _descriptor_name(descriptors[0])
            current = f"{name}@{version.group(1)}"
            graph.nodes.setdefault(current, Package(ECOSYSTEM, name, version.group(1)))
            owner.update({descriptor: current for descriptor in descriptors})
            continue
        if current and _YARN_DEPENDENCY_BLOCK.match(line):
            in_dependencies = True
            continue
        dependency = _YARN_DEPENDENCY.match(line) if in_dependencies else None
        if dependency:
            pending.setdefault(current, []).append(_descriptor(dependency.group(1), dependency.group(2)))
        elif not line.startswith("    "):
            in_dependencies = False
    names = by_name(graph.nodes)
    for node, wanted in pending.items():
        children = (owner.get(d) or owner.get(_berry_spelling(d)) or names.get(_descriptor_name(d).lower(), "")
                    for d in wanted)
        graph.requires[node] = tuple(child for child in children if child)
    graph.roots = _unrequired(graph)
    if local:
        graph.notes.append(f"{local} entr(ies) in {source} are workspaces, patches, git or file sources — not checked by name")
    return graph


def _berry_spelling(descriptor: str) -> str:
    """Berry writes a dependency as ``name: "npm:^1"`` but keys its entry ``name@npm:^1``; a bare
    range (``name: ^1``) is keyed with ``npm:`` added."""
    name = _descriptor_name(descriptor)
    spec = descriptor[len(name) + 1:]
    return descriptor if ":" in spec else f"{name}@npm:{spec}"


# --------------------------------------------------------------------- bun.lock

#: JSONC trailing commas, which bun writes and :mod:`json` refuses.
_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def _bun_segments(key: str) -> list[str]:
    """``send/@scope/ms`` → ``["send", "@scope/ms"]``: a scoped name is one segment."""
    segments: list[str] = []
    for part in key.split("/"):
        if segments and segments[-1].startswith("@") and "/" not in segments[-1]:
            segments[-1] += "/" + part
        else:
            segments.append(part)
    return segments


def _bun_resolve(requirer: str, name: str, nodes: dict[str, Package]) -> Optional[str]:
    """bun keys a nested copy by its parents (``send/ms``): the nearest copy of *name* up from *requirer*."""
    parents = _bun_segments(requirer)
    for depth in range(len(parents), -1, -1):
        candidate = "/".join(parents[:depth] + [name])
        if candidate in nodes:
            return candidate
    return None


def read_bun_lock(text: str, source: str) -> DependencyGraph:
    """bun.lock (bun's text lockfile; the older binary bun.lockb is not readable — see :mod:`.registry`)."""
    lock = json.loads(_TRAILING_COMMA.sub(r"\1", text))
    graph = DependencyGraph(source=source)
    entries = lock.get("packages") if isinstance(lock, dict) else None
    wants: dict[str, list[str]] = {}
    for key, entry in (entries.items() if isinstance(entries, dict) else ()):
        if not isinstance(entry, list) or not entry or not isinstance(entry[0], str):
            continue
        name, _, version = entry[0].rpartition("@")
        if not name or not version[:1].isdigit():
            continue   # workspace:, git and file sources carry no registry version
        graph.nodes[key] = Package(ECOSYSTEM, name, version)
        info = next((part for part in entry[1:] if isinstance(part, dict)), {})
        wants[key] = [str(dep) for field in ("dependencies", "optionalDependencies")
                      for dep in (info.get(field) or {})]
    for key, names in wants.items():
        graph.requires[key] = tuple(child for child in (_bun_resolve(key, n, graph.nodes) for n in names) if child)
    workspaces = lock.get("workspaces") if isinstance(lock, dict) else None
    root_names = [str(dep) for space in (workspaces.values() if isinstance(workspaces, dict) else ())
                  if isinstance(space, dict) for field in ("dependencies", "devDependencies", "optionalDependencies")
                  for dep in (space.get(field) or {})]
    graph.roots = tuple(dict.fromkeys(n for n in root_names if n in graph.nodes)) or _unrequired(graph)
    return graph
