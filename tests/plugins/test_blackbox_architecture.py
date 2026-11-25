"""Structure guards for plugins/blackbox (FMN-V12-STRUCTURE).

The map is plugins/blackbox/ARCHITECTURE.md; these tests hold the code to it:

* MANIFEST — every package on disk is in the map, every mapped path exists.
* BOUNDARIES — a package depends only on the modules its row allows; no
  cycles; outside a package, only its entry (or a name in its ``__all__``)
  is imported; every relative import — lazy ones included — resolves
  (FIX-0017: a broken lazy import fails silently behind the fail-open hooks).
* SIZE — files over 400 lines, folders over 15 files and functions over 50
  lines are failures unless listed in architecture_baseline.json, whose
  numbers may only shrink (lower them in the commit that shrinks the code).
* MONITOR NEVER CHANGES THE SYSTEM — Network Shield's ``monitor/`` and its other
  detection-only modules (``SEE_ONLY``) import nothing from ``protect/`` or
  ``respond/``, name no state-changing command (pfctl, networksetup, launchctl,
  kill, rm, sudo, osascript, systemsetup, …), and call nothing that deletes,
  moves or writes files, kills processes, or reaches C (``ctypes``).

Stdlib only; reads source text, never imports the plugin.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

PLUGIN = Path(__file__).resolve().parents[2] / "plugins" / "blackbox"
MAP = PLUGIN / "ARCHITECTURE.md"
BASELINE = Path(__file__).resolve().parent / "architecture_baseline.json"

MAX_FILE_LINES = 400
MAX_FOLDER_FILES = 15
MAX_FUNCTION_LINES = 50
ROOT_ENTRIES = {"__init__": {"cli", "guard", "kernel"}, "cli": None}  # None = composition root, any module


def _python_files() -> list[Path]:
    return sorted(p for p in PLUGIN.rglob("*.py") if "__pycache__" not in p.parts)


def _packages_on_disk() -> set[str]:
    return {p.parent.name for p in PLUGIN.glob("*/__init__.py")}


def _mapped_modules() -> dict[str, set[str]]:
    """``{module: allowed dependencies}`` from the map's Modules table."""
    rows: dict[str, set[str]] = {}
    for line in MAP.read_text(encoding="utf-8").splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) != 4 or not re.fullmatch(r"`[a-z_]+`", cells[0]):
            continue
        name = cells[0].strip("`")
        allowed = set(re.findall(r"`([a-z_]+)`", cells[3]))
        rows[name] = allowed
    return rows


def _owner(path: Path) -> str:
    """The module a file belongs to: its top-level package, or ``<root:stem>``."""
    rel = path.relative_to(PLUGIN)
    return rel.parts[0] if len(rel.parts) > 1 else f"<root:{rel.stem}>"


def _relative_imports(path: Path):
    """Yield (lineno, resolved dotted target, imported names) for every relative
    import in *path* — module-level and inside functions."""
    rel = path.relative_to(PLUGIN)
    package = list(rel.parent.parts)
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom) and node.level:
            base = package[: len(package) - (node.level - 1)] if node.level > 1 else package
            target = ".".join(base + ([node.module] if node.module else []))
            yield node.lineno, target, [a.name for a in node.names], node.module is None


def _exists(dotted: str) -> bool:
    target = PLUGIN.joinpath(*dotted.split(".")) if dotted else PLUGIN
    return target.with_suffix(".py").is_file() or (target / "__init__.py").is_file()


def _package_all(package: str) -> set[str]:
    init = PLUGIN / package / "__init__.py"
    for node in ast.parse(init.read_text(encoding="utf-8")).body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            target = node.targets[0] if isinstance(node, ast.Assign) else node.target
            if isinstance(target, ast.Name) and target.id == "__all__" and node.value is not None:
                return {elt.value for elt in node.value.elts}  # type: ignore[attr-defined]
    return set()


def _dependency_edges() -> dict[str, dict[str, list[str]]]:
    """``{owner: {target module: [file:line, ...]}}`` across the plugin."""
    edges: dict[str, dict[str, list[str]]] = {}
    for path in _python_files():
        owner = _owner(path)
        for lineno, target, names, bare in _relative_imports(path):
            targets = [f"{target}.{n}" if target else n for n in names] if bare else [target]
            for dotted in targets:
                head = dotted.split(".")[0]
                module = head if (PLUGIN / head).is_dir() else f"<root:{head}>"
                if module != owner:
                    where = f"{path.relative_to(PLUGIN)}:{lineno}"
                    edges.setdefault(owner, {}).setdefault(module, []).append(where)
    return edges


# --------------------------------------------------------------------- MANIFEST


def test_every_package_on_disk_is_in_the_map():
    missing = _packages_on_disk() - set(_mapped_modules())
    assert not missing, f"packages missing from ARCHITECTURE.md: {sorted(missing)}"


def test_every_mapped_module_exists_on_disk():
    absent = set(_mapped_modules()) - _packages_on_disk()
    assert not absent, f"ARCHITECTURE.md lists modules that do not exist: {sorted(absent)}"


def test_root_holds_only_the_composition_layer():
    root_python = {p.stem for p in PLUGIN.glob("*.py")}
    assert root_python == set(ROOT_ENTRIES), f"unexpected root modules: {sorted(root_python - set(ROOT_ENTRIES))}"


# ------------------------------------------------------------------- BOUNDARIES


def test_every_relative_import_resolves():
    """FIX-0017 guard: lazy imports inside functions included."""
    broken = []
    for path in _python_files():
        for lineno, target, names, bare in _relative_imports(path):
            if not bare and not _exists(target):
                broken.append(f"{path.relative_to(PLUGIN)}:{lineno} -> {target}")
            elif bare:
                broken += [f"{path.relative_to(PLUGIN)}:{lineno} -> {target}.{n}".replace("->  .", "-> ")
                           for n in names if not _exists(f"{target}.{n}" if target else n)]
    assert not broken, "relative imports that resolve to nothing:\n" + "\n".join(broken)


def test_dependencies_follow_the_map():
    allowed = _mapped_modules()
    violations = []
    for owner, targets in _dependency_edges().items():
        if owner.startswith("<root:"):
            stem = owner[len("<root:"):-1]
            root_permits = ROOT_ENTRIES.get(stem, set())
            if root_permits is None:
                continue  # cli.py: the composition root may use every module
            permitted = set(root_permits) | {f"<root:{m}>" for m in root_permits}
        else:
            permitted = allowed.get(owner, set())
        for target, where in targets.items():
            if target not in permitted:
                violations.append(f"{owner} -> {target} (not in its ARCHITECTURE.md row): {where[0]}")
    assert not violations, "\n".join(violations)


def test_the_kernel_depends_on_no_feature():
    kernel_edges = _dependency_edges().get("kernel", {})
    assert not kernel_edges, f"kernel imports features: {kernel_edges}"


def test_module_dependencies_have_no_cycles():
    graph = {owner: {t for t in targets if not t.startswith("<root")} for owner, targets in _dependency_edges().items()
             if not owner.startswith("<root")}

    def reaches(start: str, goal: str, seen: frozenset = frozenset()) -> bool:
        return any(nxt == goal or (nxt not in seen and reaches(nxt, goal, seen | {nxt})) for nxt in graph.get(start, ()))

    cycles = sorted({tuple(sorted((a, b))) for a in graph for b in graph[a] if reaches(b, a)})
    assert not cycles, f"module cycles: {cycles}"


def test_packages_are_used_only_through_their_entry():
    """Outside a package: ``from ..pkg import X`` with X in pkg.__all__ only."""
    violations = []
    for path in _python_files():
        owner = _owner(path)
        for lineno, target, names, bare in _relative_imports(path):
            parts = target.split(".") if target else []
            if not parts:
                continue  # `from . import x` / `from .. import x` at plugin root: package-level, fine
            package = parts[0]
            if package == owner or not (PLUGIN / package).is_dir():
                continue
            if package == "kernel":
                # A kernel MODULE (kernel/config.py) is public as a whole; a kernel SUB-PACKAGE
                # (kernel/signing/) is used through its __init__ like any package — 61 sites once
                # bound to kernel/signing internals its surface never exported (review 2026-10-22).
                if len(parts) == 1 or not (PLUGIN / "kernel" / parts[1]).is_dir():
                    continue
                package, parts = "kernel/" + parts[1], parts[1:]
            if len(parts) > 1:
                violations.append(f"{path.relative_to(PLUGIN)}:{lineno} imports {target} (internal)")
                continue
            public = _package_all(package)
            for name in names:
                if name not in public:
                    violations.append(f"{path.relative_to(PLUGIN)}:{lineno} imports {package}.{name} (not in __all__)")
    assert not violations, "\n".join(violations)


# ------------------------------------------------------------------------- SIZE


def _baseline() -> dict:
    return json.loads(BASELINE.read_text(encoding="utf-8"))


def _function_sizes() -> dict[str, int]:
    """``{"path::Outer.inner": lines}`` for every function, nested ones included."""
    sizes: dict[str, int] = {}

    def visit(node: ast.AST, rel: str, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                qualname = f"{prefix}{child.name}"
                if not isinstance(child, ast.ClassDef):
                    sizes[f"{rel}::{qualname}"] = child.end_lineno - child.lineno + 1  # type: ignore[operator]
                visit(child, rel, qualname + ".")
            else:
                visit(child, rel, prefix)

    for path in _python_files():
        visit(ast.parse(path.read_text(encoding="utf-8")), str(path.relative_to(PLUGIN)), "")
    return sizes


def test_no_file_grows_past_the_size_alarm():
    baseline = _baseline()["files"]
    problems = []
    for path in _python_files():
        rel = str(path.relative_to(PLUGIN))
        lines = len(path.read_text(encoding="utf-8").splitlines())
        limit = baseline.get(rel)
        if limit is None and lines > MAX_FILE_LINES:
            problems.append(f"{rel}: {lines} lines (> {MAX_FILE_LINES}; split it)")
        elif limit is not None and lines > limit:
            problems.append(f"{rel}: {lines} lines, baseline {limit} (baselined files may only shrink)")
        elif limit is not None and lines < limit:
            problems.append(f"{rel}: shrank to {lines} — lower its baseline from {limit} to {lines}")
    assert not problems, "\n".join(problems)


def test_no_function_grows_past_the_size_alarm():
    baseline = _baseline()["functions"]
    problems = []
    for key, size in _function_sizes().items():
        limit = baseline.get(key)
        if limit is None and size > MAX_FUNCTION_LINES:
            problems.append(f"{key}: {size} lines (> {MAX_FUNCTION_LINES}; split it)")
        elif limit is not None and size > limit:
            problems.append(f"{key}: {size} lines, baseline {limit} (may only shrink)")
        elif limit is not None and size < limit:
            problems.append(f"{key}: shrank to {size} — lower its baseline from {limit} to {size}")
    stale = set(baseline) - set(_function_sizes())
    problems += [f"{key}: in the baseline but gone — remove it" for key in sorted(stale)]
    assert not problems, "\n".join(problems)


def test_no_folder_exceeds_the_file_alarm():
    crowded = []
    for folder in {p.parent for p in _python_files()}:
        count = len([p for p in folder.glob("*.py")])
        if count > MAX_FOLDER_FILES:
            crowded.append(f"{folder.relative_to(PLUGIN)}: {count} files (> {MAX_FOLDER_FILES}; add a submodule)")
    assert not crowded, "\n".join(crowded)


# ------------------------------------------------------------------ monitor never changes the system

NETWORK = PLUGIN / "shields" / "network"
#: Network Shield's see-only code: all of monitor/, plus the detection-only modules beside it.
SEE_ONLY_FILES = ("system.py", "addresses.py")
#: The packages that act (see-only code must not reach them).
ACTING_PACKAGES = ("protect", "respond")
#: Programs that change the Mac, named anywhere in see-only code (by name or path).
STATE_CHANGING_COMMANDS = frozenset({
    "pfctl", "networksetup", "launchctl", "kill", "killall", "pkill", "rm", "rmdir", "mv", "sudo",
    "osascript", "systemsetup", "socketfilterfw", "dscl", "chmod", "chown", "shutdown", "reboot",
    "csrutil", "spctl", "route", "ifconfig", "tccutil", "sysadminctl",
    # Linux (deep layers step 3: the monitor reads Linux too)
    "nft", "iptables", "conntrack", "nmcli", "resolvectl", "systemctl", "ufw"})
#: Module functions that change state: (module, function).
STATE_CHANGING_FUNCTIONS = frozenset({
    ("os", "kill"), ("os", "killpg"), ("os", "remove"), ("os", "rename"), ("os", "replace"),
    ("os", "unlink"), ("os", "rmdir"), ("os", "removedirs"), ("os", "chmod"), ("os", "chown"),
    ("os", "system"), ("os", "truncate"), ("shutil", "rmtree"), ("shutil", "move"), ("shutil", "copy"),
    ("shutil", "copy2"), ("shutil", "copyfile"), ("shutil", "copytree"), ("shutil", "chown")})
#: Path methods that change files (any call of these attribute names counts).
STATE_CHANGING_METHODS = frozenset({"unlink", "rename", "write_text", "write_bytes", "rmdir", "touch",
                                    "chmod", "symlink_to", "hardlink_to"})
WRITE_MODE = re.compile(r"[wax+]")


def _see_only_files() -> list[Path]:
    return sorted([*NETWORK.glob("monitor/**/*.py"), *(NETWORK / name for name in SEE_ONLY_FILES)])


def _resolved_import(path: Path, node: ast.ImportFrom) -> str:
    """The dotted path, relative to plugins/blackbox, that a ``from … import`` names."""
    base = list(path.relative_to(PLUGIN).with_suffix("").parts)[:-1]
    if node.level:
        base = base[: len(base) - (node.level - 1)] if node.level > 1 else base
        return ".".join([*base, *(node.module.split(".") if node.module else [])])
    return node.module or ""


#: A path under the kernel's process file system is a table that is read (Linux's
#: ``/proc/net/route``), never a command, whatever its last word.
KERNEL_TABLES = "/proc/"


def _changes_the_system(path: Path, source: str) -> list[str]:
    """What in *source* (the file at *path*, inside plugins/blackbox) acts instead of seeing."""
    where = path.relative_to(PLUGIN)
    acting = tuple(f"shields.network.{name}" for name in ACTING_PACKAGES)
    problems = []
    for node in ast.walk(ast.parse(source)):
        line = f"{where}:{getattr(node, 'lineno', 0)}"
        if isinstance(node, ast.ImportFrom):
            target = _resolved_import(path, node)
            names = [target, *(f"{target}.{alias.name}" for alias in node.names)]
            if any(name == pkg or name.startswith(pkg + ".") for name in names for pkg in acting):
                problems.append(f"{line}: imports an acting package ({target})")
            if node.module and node.module.split(".")[0] == "ctypes":
                problems.append(f"{line}: uses ctypes")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] == "ctypes":
                    problems.append(f"{line}: uses ctypes")
                if any(alias.name.endswith(f".network.{pkg}") or f".network.{pkg}." in alias.name for pkg in ACTING_PACKAGES):
                    problems.append(f"{line}: imports an acting package ({alias.name})")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and not node.value.startswith(KERNEL_TABLES):
            words = node.value.split()
            if words and words[0].rsplit("/", 1)[-1] in STATE_CHANGING_COMMANDS:
                problems.append(f"{line}: names a state-changing command ({words[0]})")
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute):
                owner = func.value.id if isinstance(func.value, ast.Name) else ""
                if (owner, func.attr) in STATE_CHANGING_FUNCTIONS:
                    problems.append(f"{line}: calls {owner}.{func.attr}")
                elif func.attr in STATE_CHANGING_METHODS:
                    problems.append(f"{line}: calls .{func.attr}()")
                elif func.attr == "open" and owner not in ("os",):
                    problems += _write_mode(line, node, mode_at=0)
            elif isinstance(func, ast.Name) and func.id == "open":
                problems += _write_mode(line, node, mode_at=1)
    return problems


def _write_mode(line: str, call: ast.Call, *, mode_at: int) -> list[str]:
    """A problem when *call* (``open(path, mode)`` or ``path.open(mode)``) opens for writing."""
    mode = call.args[mode_at] if len(call.args) > mode_at else next(
        (kw.value for kw in call.keywords if kw.arg == "mode"), None)
    if mode is None:
        return []
    if not (isinstance(mode, ast.Constant) and isinstance(mode.value, str)):
        return [f"{line}: opens a file with a mode it does not spell out"]
    return [f"{line}: opens a file to write ({mode.value!r})"] if WRITE_MODE.search(mode.value) else []


def test_network_monitor_never_changes_the_system():
    files = _see_only_files()
    assert any("monitor" in p.parts for p in files) and all(p.is_file() for p in files)
    problems = [problem for path in files for problem in _changes_the_system(path, path.read_text(encoding="utf-8"))]
    assert not problems, "see-only code must not act:\n" + "\n".join(problems)


def test_the_monitor_guard_catches_each_way_of_acting():
    """Self-test: each forbidden form is caught, and plain reading is not."""
    path = NETWORK / "monitor" / "example.py"
    bad = {
        "from ..protect import enforcement": "acting package",
        "from .. import respond": "acting package",
        "from ..protect.posture_fix import plan_part": "acting package",
        "import ctypes": "ctypes",
        "run(['/sbin/pfctl', '-d'])": "pfctl",
        "run(['/sbin/route', 'add', 'x'])": "route",
        "run(['sudo', 'x'])": "sudo",
        "run('launchctl bootout system/x')": "launchctl",
        "os.kill(1, 9)": "os.kill",
        "os.remove(p)": "os.remove",
        "shutil.rmtree(p)": "shutil.rmtree",
        "shutil.move(a, b)": "shutil.move",
        "p.unlink()": ".unlink",
        "p.rename(q)": ".rename",
        "p.write_text('x', encoding='utf-8')": ".write_text",
        "open(p, 'w', encoding='utf-8')": "to write",
        "open(p, mode='ab')": "to write",
        "p.open('r+', encoding='utf-8')": "to write",
    }
    for source, expected in bad.items():
        problems = _changes_the_system(path, source)
        assert problems and expected in problems[0], (source, problems)
    clean = "from ..mode import current\nfrom ...kernel import bounded_files\nopen(p, 'rb')\nrun(['/usr/sbin/lsof', '-i'])\n'a-b'.replace('-', '')\nROUTES = '/proc/net/route'\n"
    assert _changes_the_system(path, clean) == []
