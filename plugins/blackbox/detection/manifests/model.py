"""The shapes every dependency-file reader returns (KI-595).

A reader turns one manifest or lockfile into a :class:`DependencyGraph`: the packages it
pins or asks for, who requires whom (when the file says), and the notes a person should see
about what could NOT be read from it. Everything downstream — the verdict, the after-install
check, the write check — works on this one shape, whatever the ecosystem.

Usage::

    graph = DependencyGraph.flat(source="requirements.txt", packages=[Package("pypi", "requests", "2.32.3")])
    graph.path_to(node_id)        # ("requests@2.32.3",) — the chain from a root, where the file gives one
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Optional

#: The arrow a dependency chain is written with ("express → body-parser → bad@1.2.3").
CHAIN_ARROW = " → "


@dataclass(frozen=True)
class Package:
    """One package a file names. *version* is exact when *exact* is True; otherwise it is the
    range the manifest wrote ("^4.18.0", ">=2") or "" — only a whole-package rule can match it."""

    ecosystem: str
    name: str
    version: str
    exact: bool = True

    @property
    def label(self) -> str:
        """``name@version`` (``name`` alone when there is no version)."""
        return f"{self.name}@{self.version}" if self.version else self.name


@dataclass
class DependencyGraph:
    """The packages of one file. ``nodes`` maps the reader's own node id (a lockfile key, or
    ``name@version``) to its :class:`Package`; ``requires`` maps a node to the nodes it pulls in;
    ``roots`` are the nodes the project asks for itself. ``notes`` say what was left unread
    (a URL or VCS source, a binary lockfile) — shown to the person, never dropped."""

    source: str
    nodes: dict[str, Package] = field(default_factory=dict)
    requires: dict[str, tuple[str, ...]] = field(default_factory=dict)
    roots: tuple[str, ...] = ()
    notes: list[str] = field(default_factory=list)
    #: False for a manifest of ranges (package.json, pyproject.toml): "ranges, not exact versions".
    exact: bool = True
    #: Other files this one pulls in (a requirements file's ``-r`` / ``-c``), as written, relative to it.
    includes: tuple[str, ...] = ()
    #: Chains already walked (a graph is cached and judged again on every repeat of an install).
    _chains: dict[str, str] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def flat(cls, source: str, packages: Iterable[Package], notes: Optional[list[str]] = None,
             exact: bool = True) -> DependencyGraph:
        """A file with no dependency tree (requirements.txt, Pipfile.lock): every package is a root."""
        nodes = {f"{p.ecosystem}:{p.label}": p for p in packages}
        return cls(source=source, nodes=nodes, roots=tuple(nodes), notes=list(notes or []), exact=exact)

    def package_keys(self) -> frozenset[tuple[str, str, str]]:
        """``(ecosystem, lower-case name, version)`` of every package — what the after-install diff compares."""
        return frozenset(package_key(p) for p in self.nodes.values())

    def chains(self, targets: Iterable[str]) -> dict[str, str]:
        """``{node: "root → … → node"}`` for each of *targets* reachable from a root, by one
        breadth-first walk (shortest chain). A target no root reaches gets its own label only."""
        wanted = set(targets)
        missing = wanted - set(self._chains)
        if missing:
            self._chains.update(self._walk(missing))
        return {target: self._chains[target] for target in wanted if target in self._chains}

    def _walk(self, wanted: set[str]) -> dict[str, str]:
        previous: dict[str, Optional[str]] = {root: None for root in self.roots if root in self.nodes}
        queue = deque(previous)
        while queue and not wanted.issubset(previous):
            node = queue.popleft()
            for child in self.requires.get(node, ()):
                if child not in previous and child in self.nodes:
                    previous[child] = node
                    queue.append(child)
        return {target: self._chain(target, previous) for target in wanted if target in self.nodes}

    def _chain(self, target: str, previous: Mapping[str, Optional[str]]) -> str:
        if target not in previous:
            return self.nodes[target].label
        labels: list[str] = []
        node: Optional[str] = target
        while node is not None:
            package = self.nodes[node]
            labels.append(package.label if node == target else package.name)
            node = previous[node]
        return CHAIN_ARROW.join(reversed(labels))


def package_key(package: Package) -> tuple[str, str, str]:
    """The identity two reads of a lockfile are compared by: ecosystem, lower-case name, version."""
    return package.ecosystem, package.name.lower(), package.version


def by_name(nodes: Mapping[str, Package]) -> dict[str, str]:
    """``{lower-case name: node id}`` (the first node of each name) — how a reader that lists
    dependencies by name only (poetry, Cargo, Gemfile) turns them into node ids."""
    found: dict[str, str] = {}
    for node, package in nodes.items():
        found.setdefault(package.name.lower(), node)
    return found
