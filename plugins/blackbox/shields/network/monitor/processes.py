"""Which processes belong to an AI agent, and which are Blackbox's own.

An agent rarely talks to the network itself only: Claude Code starts ``node``, ``curl``, ``git``,
``npm``. So a process is attributed to the nearest ancestor that is a known agent, recognised by
its program name — the executable, or the script a ``node``/``python`` interpreter runs —
never by a window title or a guess.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Sequence

from . import platform

#: Program names (lower case) and the agent each one is.
AGENTS: dict[str, str] = {
    "claude": "Claude Code", "codex": "Codex", "cursor": "Cursor", "cursor-agent": "Cursor",
    "gemini": "Gemini CLI", "opencode": "OpenCode", "openclaw": "OpenClaw", "copilot": "GitHub Copilot CLI",
    "windsurf": "Windsurf", "hermes": "Hermes", "aider": "Aider", "goose": "Goose",
}
#: Interpreters whose first script argument names the real program.
INTERPRETERS = frozenset({"node", "python", "python3", "bun", "deno"})
#: Paths that mark Blackbox's own processes: the desktop app bundle and its data folder (the DKG
#: node, its store and the engine run from there), and a standalone install's checkout.
BLACKBOX_MARKS = ("Blackbox.app/", "Application Support/Blackbox/", "/agent-blackbox/")
#: Ancestors followed at most (a guard against a corrupted table with a cycle).
MAX_DEPTH = 64


def classify(args: Sequence[str]) -> str:
    """The agent a command line runs, "" for none. Blackbox's own engine is never an agent,
    though it is a Hermes program."""
    if not args or any(mark in " ".join(args) for mark in BLACKBOX_MARKS):
        return ""
    program = _basename(args[0])
    if program in INTERPRETERS:
        script = next((arg for arg in args[1:] if not arg.startswith("-")), "")
        program = _basename(script)
    for suffix in (".js", ".mjs", ".cjs", ".py"):
        program = program.removesuffix(suffix)
    return AGENTS.get(program, "")


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1].lower()


@dataclass
class ProcessTree:
    """``pid -> parent``, the agents, Blackbox's own processes and each process's CPU (percent
    of one core) and resident memory (bytes), from one ``ps`` reading."""

    parent: dict[int, int] = field(default_factory=dict)
    agents: dict[int, str] = field(default_factory=dict)
    blackbox: set[int] = field(default_factory=set)
    cpu: dict[int, float] = field(default_factory=dict)
    memory: dict[int, int] = field(default_factory=dict)

    @classmethod
    def read(cls) -> ProcessTree:
        """Reads the process table; an empty tree when ``ps`` cannot run (nothing attributed)."""
        text = platform.process_table()
        return cls.parse(text) if text is not None else cls()

    @classmethod
    def parse(cls, text: str) -> ProcessTree:
        """Parses ``ps -axo pid=,ppid=,%cpu=,rss=,args=`` output (rss is in KiB)."""
        tree = cls()
        for line in text.splitlines():
            fields = line.split()
            if len(fields) < 5 or not fields[0].isdigit() or not fields[1].isdigit() or not fields[3].isdigit():
                continue
            try:
                cpu = float(fields[2].replace(",", "."))   # some locales print a decimal comma
            except ValueError:
                continue
            pid, ppid, args = int(fields[0]), int(fields[1]), fields[4:]
            tree.parent[pid] = ppid
            tree.cpu[pid], tree.memory[pid] = round(cpu, 1), int(fields[3]) * 1024
            if any(mark in " ".join(args) for mark in BLACKBOX_MARKS):
                tree.blackbox.add(pid)
            agent = classify(args)
            if agent:
                tree.agents[pid] = agent
        return tree

    def _ancestors(self, pid: int):
        current: Optional[int] = pid
        for _ in range(MAX_DEPTH):
            if current is None:
                return
            yield current
            parent = self.parent.get(current)
            current = parent if parent is not None and parent != current and parent > 1 else None

    def agent_of(self, pid: int) -> str:
        """The agent *pid* is, or the nearest agent among its ancestors; "" for none."""
        return next((self.agents[ancestor] for ancestor in self._ancestors(pid) if ancestor in self.agents), "")

    def is_blackbox(self, pid: int) -> bool:
        """True when *pid* is one of Blackbox's own processes, or a child of one."""
        return any(ancestor in self.blackbox for ancestor in self._ancestors(pid))
