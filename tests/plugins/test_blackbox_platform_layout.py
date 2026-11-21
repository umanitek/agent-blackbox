"""Structure guard for the per-OS layout (Amos 2026-11-21): every program Network Shield runs, and
every system tool its root helper calls, lives in a ``platform/`` folder — one module or folder
per operating system — so a port adds its own and nothing else changes.

* Python, ``plugins/blackbox/shields/network``: outside ``platform/`` no code names a macOS tool
  (a command in a string the code uses; docstrings and comments may still mention one), and no
  code starts a program (``subprocess``, ``os.system`` and the like).
* Rust, ``plugins/blackbox/helper/src``: outside ``platform/`` no code names a macOS tool. The
  crate's own ``tests/platform_guard.rs`` checks the same under ``cargo test``; this one runs in
  the Python suite, which is where CI's Blackbox lane runs.

The scanners are tested on themselves (``test_the_*_scanner_*``), so a broken guard cannot pass.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NETWORK = ROOT / "plugins" / "blackbox" / "shields" / "network"
HELPER_SRC = ROOT / "plugins" / "blackbox" / "helper" / "src"
PLATFORM = "platform"

#: macOS tools only a platform/ module may name (matched on a command's program name).
MACOS_TOOLS = frozenset({
    "pfctl", "networksetup", "launchctl", "scutil", "nettop", "codesign", "spctl", "osascript", "netstat",
    "log", "socketfilterfw", "systemsetup", "fdesetup", "csrutil", "lsof", "ps", "sysadminctl", "plutil",
    "sfltool", "kmutil", "systemextensionsctl", "ipconfig", "route", "defaults", "tailscale", "Tailscale",
})
#: Rust: the same tools, as the names or paths code spells them, and the macOS APIs.
RUST_MACOS_NAMES = (
    "pfctl", "networksetup", "launchctl", "scutil", "nettop", "codesign", "spctl", "osascript", "netstat",
    "/usr/bin/log", "socketfilterfw", "systemsetup", "fdesetup", "csrutil", "sysadminctl", "/usr/bin/defaults",
    "plutil", "sfltool", "kmutil", "systemextensionsctl", "ipconfig", "/sbin/route", "libproc", "proc_pidpath",
    "sysctlbyname", "/library/", "/system/library", "launchdaemons",
)
#: Calls that start a program.
PROGRAM_STARTERS = frozenset({
    ("subprocess", "run"), ("subprocess", "Popen"), ("subprocess", "call"), ("subprocess", "check_call"),
    ("subprocess", "check_output"), ("subprocess", "getoutput"), ("subprocess", "getstatusoutput"),
    ("os", "system"), ("os", "popen"), ("os", "execv"), ("os", "execvp"), ("os", "spawnv"), ("os", "posix_spawn"),
    ("asyncio", "create_subprocess_exec"), ("asyncio", "create_subprocess_shell"),
})


def _docstrings(tree: ast.AST) -> set[int]:
    """ids of the string nodes that are docstrings (they may mention a tool)."""
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                found.add(id(first.value))
    return found


def python_problems(source: str) -> list[str]:
    """Where *source* names a macOS tool in a command string, or starts a program."""
    tree = ast.parse(source)
    docstrings = _docstrings(tree)
    # A string is a command when it is a program's path ("/usr/bin/nettop") or the first item of
    # an argument list (["launchctl", "print"]); a lone word ("ps" as a file extension, a label
    # "Tailscale SSH") is not.
    argv_heads = {id(node.elts[0]) for node in ast.walk(tree) if isinstance(node, (ast.List, ast.Tuple)) and node.elts}
    problems = []
    for node in ast.walk(tree):
        line = getattr(node, "lineno", 0)
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
            words = node.value.split()
            command = words[0] if words and ("/" in words[0] or id(node) in argv_heads) else ""
            if command and command.rsplit("/", 1)[-1] in MACOS_TOOLS:
                problems.append(f"{line}: names {command}")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if (node.func.value.id, node.func.attr) in PROGRAM_STARTERS:
                problems.append(f"{line}: starts a program ({node.func.value.id}.{node.func.attr})")
    return problems


def _rust_code(line: str) -> str:
    """One Rust line without its ``//`` comment (a ``//`` inside a string literal is kept)."""
    quotes = 0
    for index, char in enumerate(line):
        if char == '"' and (index == 0 or line[index - 1] != "\\"):
            quotes += 1
        elif char == "/" and quotes % 2 == 0 and line[index + 1:index + 2] == "/":
            return line[:index]
    return line


def rust_problems(source: str) -> list[str]:
    """Where Rust *source* names a macOS tool, path or API in code."""
    problems = []
    for number, line in enumerate(source.splitlines(), start=1):
        code = _rust_code(line).lower()
        problems += [f"{number}: names {name}" for name in RUST_MACOS_NAMES if name in code]
    return problems


def _outside_platform(root: Path, pattern: str) -> list[Path]:
    return sorted(path for path in root.rglob(pattern) if PLATFORM not in path.relative_to(root).parts and "__pycache__" not in path.parts)


def test_network_shield_runs_programs_only_from_its_platform_modules():
    files = _outside_platform(NETWORK, "*.py")
    assert len(files) > 20 and (NETWORK / "monitor" / PLATFORM / "macos.py").is_file()
    problems = [f"{path.relative_to(ROOT)}:{problem}" for path in files for problem in python_problems(path.read_text(encoding="utf-8"))]
    assert not problems, "move these into a platform/ module (monitor/platform/macos.py):\n" + "\n".join(problems)


def test_the_helper_names_macos_tools_only_under_src_platform():
    files = _outside_platform(HELPER_SRC, "*.rs")
    assert len(files) > 5 and (HELPER_SRC / PLATFORM / "mod.rs").is_file()
    problems = [f"{path.relative_to(ROOT)}:{problem}" for path in files for problem in rust_problems(path.read_text(encoding="utf-8"))]
    assert not problems, "move these into helper/src/platform/macos/:\n" + "\n".join(problems)


def test_the_python_scanner_catches_a_tool_or_a_program_start_and_passes_plain_code():
    assert python_problems('NETTOP = "/usr/bin/nettop"\n') == ["1: names /usr/bin/nettop"]
    assert python_problems("run(['launchctl', 'print'])\n") == ["1: names launchctl"]
    assert python_problems("import subprocess\nsubprocess.run(['x'])\n") == ["2: starts a program (subprocess.run)"]
    assert python_problems("import os\nos.system('x')\n") == ["2: starts a program (os.system)"]
    assert python_problems('TOOLS = ("/Applications/Tailscale.app/Contents/MacOS/Tailscale",)\n') == [
        "1: names /Applications/Tailscale.app/Contents/MacOS/Tailscale"]
    clean = '"""Reads ``nettop`` and ``codesign`` (a docstring may say so)."""\n# lsof too\nEXT = {"ps", "log"}\nLABEL = "Tailscale SSH"\n'
    assert python_problems(clean) == []


def test_the_rust_scanner_ignores_comments_and_catches_code():
    assert rust_problems('let out = Command::new("/sbin/pfctl").arg("-s");') == ["1: names pfctl"]
    assert rust_problems('pub const HOME: &str = "/Library/Application Support/Blackbox";') == ["1: names /library/"]
    assert rust_problems('let url = "http://127.0.0.1"; run("/usr/sbin/netstat");') == ["1: names netstat"]
    assert rust_problems("//! reads pfctl's answer\n    // netstat failing costs nothing\nfn one() -> u8 { 1 }") == []
