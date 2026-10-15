#!/usr/bin/env python3
"""Regenerate the README's "module sizes" and "every file" sections from the code.

The repository README lists every file of ``plugins/blackbox/`` with one line
saying what it does. Typed by hand, that list goes stale with every new file;
this script writes it from the source instead: each file's description is the
first line of its module docstring, and the sizes are counted from disk.

It rewrites only the text between these two markers in README.md::

    <!-- blackbox-inventory:start -->
    <!-- blackbox-inventory:end -->

Usage (from the repository root)::

    python scripts/blackbox-readme-inventory.py           # rewrite README.md
    python scripts/blackbox-readme-inventory.py --check   # exit 1 if it is out of date
"""

from __future__ import annotations

import argparse
import ast
import datetime
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugins" / "blackbox"
README = ROOT / "README.md"
START = "<!-- blackbox-inventory:start -->"
END = "<!-- blackbox-inventory:end -->"
BAR_WIDTH = 20

#: One sentence per module, shown on its collapsed row. A module missing here
#: still gets listed; it just has no sentence until one is added.
MODULE_SUMMARY = {
    "guard": "The hooks. Every tool call and model request passes here first.",
    "detection": "Is this action a threat? Pure functions, no I/O on the hot path.",
    "ruleset": "Compiles graph rows into O(1) lookups and keeps them fresh.",
    "shields": "Opt-in protection packs; Trader Shield's wallets and browser folders as data.",
    "community": "Everything about the community graph: write, sign, read, verify, stage.",
    "sync": "Runs the local DKG node and catches up the verified graph.",
    "audit": "What Blackbox saw, kept locally and redacted.",
    "dashboard": "The loopback web UI and its API.",
    "attach": "Finds every local agent and wires protection into it.",
    "overrides": "The operator's local release valve.",
    "killlist": "Curator-signed disable or warn for installed skills and MCP servers.",
    "curate": "The curator node's tooling.",
    "chat": "The Blackbox operator chat.",
    "kernel": "Shared infrastructure owned by no feature. Depends on nothing.",
}
MODULE_ORDER = list(MODULE_SUMMARY)


def _description(path: Path) -> str:
    """First line of the file's module docstring, without a trailing period; "" if none."""
    try:
        doc = ast.get_docstring(ast.parse(path.read_text(encoding="utf-8-sig")))
    except (SyntaxError, UnicodeDecodeError):
        return ""
    first = (doc or "").strip().splitlines()[0] if doc and doc.strip() else ""
    return first.rstrip(".").replace("|", "\\|")


def _line_count(path: Path) -> int:
    with path.open(encoding="utf-8", errors="replace") as handle:
        return sum(1 for _ in handle)


def _modules() -> dict[str, list[Path]]:
    """Each top-level module folder of the plugin with its Python files, sorted."""
    found: dict[str, list[Path]] = {}
    for path in sorted(PLUGIN.rglob("*.py")):
        relative = path.relative_to(PLUGIN)
        if "__pycache__" in relative.parts or len(relative.parts) < 2:
            continue
        found.setdefault(relative.parts[0], []).append(path)
    order = {name: index for index, name in enumerate(MODULE_ORDER)}
    return dict(sorted(found.items(), key=lambda item: (order.get(item[0], len(order)), item[0])))


def render() -> str:
    """The Markdown that goes between the markers."""
    modules = _modules()
    sizes = {name: (len(files), sum(_line_count(f) for f in files)) for name, files in modules.items()}
    root_files = [p for p in PLUGIN.glob("*.py")]
    total_files = sum(count for count, _ in sizes.values()) + len(root_files)
    total_lines = sum(lines for _, lines in sizes.values()) + sum(_line_count(p) for p in root_files)
    largest = max(lines for _, lines in sizes.values())
    today = datetime.date.today().isoformat()

    out = [START, "", "### Inside the plugin: module sizes", "",
           f"{total_files:,} Python files, {total_lines:,} lines, counted from the code on {today} "
           "(`scripts/blackbox-readme-inventory.py`).", "",
           "| Module | Files | Lines | Share of the code |", "|---|---:|---:|---|"]
    for name, (count, lines) in sorted(sizes.items(), key=lambda item: -item[1][1]):
        bar = "█" * max(1, round(BAR_WIDTH * lines / largest))
        out.append(f"| `{name}/` | {count} | {lines:,} | `{bar}` |")
    out += ["", "### Every file, by module", "", "Click a module to open its file list.", ""]
    for name, files in modules.items():
        count, lines = sizes[name]
        summary = MODULE_SUMMARY.get(name, "")
        out += ["<details>",
                f"<summary><b><code>{name}/</code></b> · {count} files · {lines:,} lines"
                + (f" · {summary}" if summary else "") + "</summary>", "",
                "| File | What it does |", "|---|---|"]
        for path in files:
            relative = path.relative_to(PLUGIN / name).as_posix()
            out.append(f"| `{relative}` | {_description(path)} |")
        out += ["", "</details>", ""]
    out.append(END)
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 when README.md is out of date")
    args = parser.parse_args()
    text = README.read_text(encoding="utf-8-sig")
    if START not in text or END not in text:
        print(f"README.md has no {START} … {END} block", file=sys.stderr)
        return 2
    head, rest = text.split(START, 1)
    _, tail = rest.split(END, 1)
    fresh = render()
    current = START + rest.split(END, 1)[0] + END

    def _undated(block: str) -> str:   # the date alone never makes the list stale
        return "\n".join(line for line in block.splitlines() if "counted from the code on" not in line)

    if args.check:
        stale = _undated(current) != _undated(fresh)
        print("README inventory is out of date" if stale else "README inventory is current")
        return 1 if stale else 0
    README.write_text(head + fresh + tail, encoding="utf-8")
    print(f"README.md inventory rewritten ({len(fresh.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
