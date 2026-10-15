#!/usr/bin/env python3
"""Prove that a refactor moved code without changing it.

Usage::

    PYTHONDONTWRITEBYTECODE=1 python scripts/move_proof.py <old-rev> [--plugin plugins/blackbox]

Two checks, run from anywhere inside the git repository:

1. **Every body, compared by name.** Every function and method under the
   plugin is parsed at ``<old-rev>`` and in the working tree and keyed by
   ``module::Qualified.name`` (a repeated name, such as a property setter,
   gets ``#2``; a def under a module-level ``if``/``try``/``with`` counts).
   Bodies are compared as ASTs (line numbers, comments, formatting and a
   leading docstring do not count). A body found unchanged under another
   module or name is listed as *moved*; a body that kept its name but not its
   content is *changed*, wherever it now lives.
2. **Every module imports, lazy imports included.** The working-tree plugin is
   imported module by module, and every relative import written inside a
   function (which only runs when the function is called) is resolved now, so
   a move that left a stale ``from .old_home import x`` is caught today.

Prints the lists added / removed / changed / moved / broken imports.
Exit status: 0 clean, 1 a body CHANGED, 2 usage or git error,
3 nothing changed but an import is broken.

Bytecode writing is switched off before the plugin is imported (a stale
``.pyc`` must never stand in for the source being proven).
"""

from __future__ import annotations

import argparse
import ast
import importlib
import importlib.util
import os
import subprocess
import sys
import types
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

# Set before the plugin is imported, and inherited by the git children.
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

EXIT_CLEAN, EXIT_CHANGED, EXIT_USAGE, EXIT_BROKEN_IMPORT = 0, 1, 2, 3
_IMPORT_ROOT = "hermes_plugins"  # the package the plugin loader mounts plugins under
_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_BLOCKS = (ast.If, ast.Try, ast.TryStar, ast.With)  # statements whose bodies can define functions at import time


class ProofError(Exception):
    """A git or parse failure that stops the proof (exit 2)."""


@dataclass
class Report:
    """The proof's findings; each entry is a printable ``module::qualname`` line."""

    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    changed: list[str] = field(default_factory=list)
    moved: list[str] = field(default_factory=list)
    broken_imports: list[str] = field(default_factory=list)


# --- bodies ---------------------------------------------------------------


def _fingerprint(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    """AST dump of signature, decorators and body, minus name and docstring."""
    body = node.body
    first = body[0] if body else None
    if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
        body = body[1:]
    parts = [node.args, *node.decorator_list, *body]
    if node.returns is not None:
        parts.append(node.returns)
    kind = "async" if isinstance(node, ast.AsyncFunctionDef) else "def"
    return kind + "|".join(ast.dump(part) for part in parts)


def _bodies(source: str, module: str, origin: str) -> dict[str, str]:
    """Map ``module::Class.method`` to the body fingerprint for one file."""
    try:
        tree = ast.parse(source, filename=origin)
    except SyntaxError as exc:
        raise ProofError(f"cannot parse {origin}: {exc}") from exc
    found: dict[str, str] = {}
    seen: Counter[str] = Counter()

    def visit(nodes: list[ast.stmt], prefix: str) -> None:
        for node in nodes:
            if isinstance(node, _FUNCTIONS):
                key = f"{module}::{prefix}{node.name}"
                seen[key] += 1
                # A property setter or a conditional twin reuses the name: number it, never overwrite it.
                found[key if seen[key] == 1 else f"{key}#{seen[key]}"] = _fingerprint(node)
            elif isinstance(node, ast.ClassDef):
                visit(node.body, f"{prefix}{node.name}.")
            elif isinstance(node, _BLOCKS):  # a def under ``if``/``try``/``with`` is still a module or class body
                for block in (node.body, getattr(node, "orelse", []), getattr(node, "finalbody", [])):
                    visit(block, prefix)
                for handler in getattr(node, "handlers", []):
                    visit(handler.body, prefix)

    visit(tree.body, "")
    return found


def _module_name(relative: Path) -> str:
    """``kernel/settings.py`` -> ``kernel.settings``; a package's ``__init__.py`` -> its folder."""
    parts = list(relative.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts) or "__init__"


def _git(repo: Path, *args: str, stdin: bytes | None = None) -> bytes:
    result = subprocess.run(["git", "-C", str(repo), *args], input=stdin, capture_output=True, check=False)
    if result.returncode != 0:
        raise ProofError(f"git {' '.join(args)} failed: {result.stderr.decode('utf-8', 'replace').strip()}")
    return result.stdout


def bodies_at_revision(repo: Path, rev: str, plugin: str) -> dict[str, str]:
    """Every body under ``plugin`` at ``rev``, read through one ``git cat-file --batch``."""
    listing = _git(repo, "ls-tree", "-r", "-z", "--name-only", rev, "--", plugin).decode("utf-8")
    paths = [path for path in listing.split("\0") if path.endswith(".py")]
    batch = _git(repo, "cat-file", "--batch", stdin="".join(f"{rev}:{path}\n" for path in paths).encode("utf-8"))
    found: dict[str, str] = {}
    offset = 0
    for path in paths:
        header_end = batch.index(b"\n", offset)
        size = int(batch[offset:header_end].split()[2])
        blob = batch[header_end + 1 : header_end + 1 + size]
        offset = header_end + 1 + size + 1  # the blob is followed by one newline
        module = _module_name(Path(path).relative_to(plugin))
        found.update(_bodies(blob.decode("utf-8"), module, f"{rev}:{path}"))
    return found


def _working_files(plugin_dir: Path) -> list[Path]:
    return sorted(path for path in plugin_dir.rglob("*.py") if "__pycache__" not in path.parts)


def bodies_in_working_tree(plugin_dir: Path) -> dict[str, str]:
    """Every body under the plugin folder as it is on disk now."""
    found: dict[str, str] = {}
    for path in _working_files(plugin_dir):
        module = _module_name(path.relative_to(plugin_dir))
        found.update(_bodies(path.read_text(encoding="utf-8-sig"), module, str(path)))
    return found


def compare(old: dict[str, str], new: dict[str, str], report: Report) -> None:
    """Sort every body into unchanged (silent), changed, moved, added or removed."""
    for key in sorted(old.keys() & new.keys()):
        if old[key] != new[key]:
            report.changed.append(key)
    gone = {key: old[key] for key in sorted(old.keys() - new.keys())}
    born = {key: new[key] for key in sorted(new.keys() - old.keys())}
    # Same body somewhere else: a move (a rename counts too). Prefer the same qualified name.
    for prefer_same_name in (True, False):
        for old_key, body in list(gone.items()):
            match = next(
                (key for key, other in born.items() if other == body and (not prefer_same_name or _qualname(key) == _qualname(old_key))),
                None,
            )
            if match is not None:
                report.moved.append(f"{old_key} -> {match}")
                del gone[old_key], born[match]
    # Same name, one candidate each side, different body: moved AND changed — never hidden as added/removed.
    for old_key in list(gone):
        same_name_born = [key for key in born if _qualname(key) == _qualname(old_key)]
        same_name_gone = [key for key in gone if _qualname(key) == _qualname(old_key)]
        if len(same_name_born) == 1 and len(same_name_gone) == 1:
            report.changed.append(f"{old_key} -> {same_name_born[0]}")
            del gone[old_key], born[same_name_born[0]]
    report.removed.extend(gone)
    report.added.extend(born)


def _qualname(key: str) -> str:
    return key.split("::", 1)[1]


# --- imports --------------------------------------------------------------


def _mount_plugin(plugin_dir: Path, repo: Path) -> str:
    """Load the plugin as ``hermes_plugins.<name>`` so its relative imports resolve."""
    if str(repo) not in sys.path:  # the plugin's absolute imports (``hermes_cli`` …) live at the repo root
        sys.path.insert(0, str(repo))
    package = f"{_IMPORT_ROOT}.{plugin_dir.name}"
    root = sys.modules.setdefault(_IMPORT_ROOT, types.ModuleType(_IMPORT_ROOT))
    if not hasattr(root, "__path__"):
        root.__path__ = []
    spec = importlib.util.spec_from_file_location(
        package, plugin_dir / "__init__.py", submodule_search_locations=[str(plugin_dir)]
    )
    if spec is None or spec.loader is None:
        raise ProofError(f"{plugin_dir} is not a Python package (no __init__.py)")
    module = importlib.util.module_from_spec(spec)
    sys.modules[package] = module
    spec.loader.exec_module(module)
    return package


def _lazy_relative_imports(tree: ast.Module) -> list[ast.ImportFrom]:
    """Relative ``from`` imports that sit inside a function (run only when it is called)."""
    found: list[ast.ImportFrom] = []
    for function in ast.walk(tree):
        if isinstance(function, _FUNCTIONS):
            found.extend(
                node for node in ast.walk(function) if isinstance(node, ast.ImportFrom) and node.level > 0
            )
    return sorted(set(found), key=lambda node: node.lineno)


def _resolve(node: ast.ImportFrom, package: str) -> str | None:
    """Import what ``node`` names as if the function ran; return the failure, or None."""
    target = "." * node.level + (node.module or "")
    try:
        module = importlib.import_module(importlib.util.resolve_name(target, package))
        for alias in node.names:
            if alias.name == "*" or hasattr(module, alias.name):
                continue
            importlib.import_module(f"{module.__name__}.{alias.name}")
    except Exception as exc:  # any failure to import is the finding itself
        return f"{type(exc).__name__}: {exc}"
    return None


def check_imports(plugin_dir: Path, repo: Path, report: Report) -> None:
    """Import every working-tree module and force each lazy relative import to resolve."""
    try:
        package = _mount_plugin(plugin_dir, repo)
    except Exception as exc:  # the plugin itself does not import: every check below would be noise
        report.broken_imports.append(f"__init__: {type(exc).__name__}: {exc}")
        return
    for path in _working_files(plugin_dir):
        relative = path.relative_to(plugin_dir)
        module_name = _module_name(relative)
        dotted = package if module_name == "__init__" else f"{package}.{module_name}"
        try:
            importlib.import_module(dotted)
        except Exception as exc:  # report and keep going: one broken module must not hide the rest
            report.broken_imports.append(f"{module_name}: {type(exc).__name__}: {exc}")
            continue
        own_package = dotted if relative.name == "__init__.py" else dotted.rpartition(".")[0]
        for node in _lazy_relative_imports(ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))):
            failure = _resolve(node, own_package)
            if failure is not None:
                names = ", ".join(alias.name for alias in node.names)
                report.broken_imports.append(
                    f"{module_name}:{node.lineno}: from {'.' * node.level}{node.module or ''} import {names} -> {failure}"
                )


# --- command line ---------------------------------------------------------


def _print_report(report: Report, header: str) -> int:
    print(header)
    for title, entries in (
        ("added", report.added),
        ("removed", report.removed),
        ("changed", report.changed),
        ("moved", report.moved),
        ("broken imports", report.broken_imports),
    ):
        print(f"{title} ({len(entries)}):")
        for entry in entries:
            print(f"  {entry}")
    if report.changed:
        print("result: CHANGED — a body differs from the old revision")
        return EXIT_CHANGED
    if report.broken_imports:
        print("result: BROKEN IMPORT — no body changed, but an import does not resolve")
        return EXIT_BROKEN_IMPORT
    print("result: clean — no body changed")
    return EXIT_CLEAN


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("old_rev", help="the revision to compare the working tree against")
    parser.add_argument("--plugin", default="plugins/blackbox", help="plugin folder, relative to the repo root")
    args = parser.parse_args(argv)
    try:
        repo = Path(_git(Path.cwd(), "rev-parse", "--show-toplevel").decode("utf-8").strip())
        plugin_dir = (repo / args.plugin).resolve()
        if not plugin_dir.is_relative_to(repo) or not (plugin_dir / "__init__.py").is_file():
            raise ProofError(f"--plugin {args.plugin} is not a package folder inside {repo}")
        plugin = plugin_dir.relative_to(repo).as_posix()
        sha = _git(repo, "rev-parse", "--verify", f"{args.old_rev}^{{commit}}").decode("utf-8").strip()
        report = Report()
        compare(bodies_at_revision(repo, sha, plugin), bodies_in_working_tree(plugin_dir), report)
    except ProofError as exc:
        print(f"move_proof: {exc}", file=sys.stderr)
        return EXIT_USAGE
    check_imports(plugin_dir, repo, report)
    return _print_report(report, f"move proof: {args.old_rev} ({sha[:10]}) -> working tree, plugin {plugin}")


if __name__ == "__main__":
    sys.exit(main())
