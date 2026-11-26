"""The records of the agent-instance view: what ran, inside what, and what it did.

``product`` (Claude Code, Codex…) → ``profile`` (one config home) → ``session`` → ``sub-agent``
(an instance the session spawned; ``parent`` is its session's key) → ``actions`` (tool calls with
Blackbox's verdict). Every id is the hashed key Blackbox already uses for sessions — an agent's
own session id or a file's text is never part of a record, and a prompt's text only while the
person has turned prompt-text recording on (off by default; ``agent_hooks.prompt_text``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

#: How an instance was started.
LAUNCHES = ("interactive", "headless", "sdk", "ide", "background", "sub-agent", "unknown")
#: ``live`` (events or its process seen lately), ``waiting`` (live, and the agent SAID it is
#: waiting for its person — see :data:`WAITING`), ``ended`` (it said so, its process left, or it
#: went quiet), ``unprotected`` (a running agent process Blackbox has no hook in).
STATUSES = ("live", "waiting", "ended", "unprotected")
#: What a waiting instance waits for: ``idle`` — its turn ended, the next message is the person's;
#: ``permission`` — it asked the person to allow something; ``attention`` — it raised a notice.
#: Only agents whose hooks say so can be waiting; the others stay ``live`` until they end.
WAITING = ("idle", "permission", "attention")


@dataclass
class SeenRefusal:
    """One refusal :mod:`.refusals` has seen on an instance, kept WITH the instance (its record in
    ``index.json``) so a dashboard restart does not count it twice. *key*: a hash of how it was
    identified (call id + what, or the kernel record id) — never the agent's own ids; *source*:
    hook / output / kernel; *what*: the refused path or ``<kind>:<name>`` (the timeline shows the
    same); *start*/*end*: the run it belongs to; *call_seq*: the instance's pre_tools so far when
    it was seen; *paired*: a kernel line and an output refusal already matched as one."""

    key: str
    source: str
    what: str
    start: float
    end: float
    call_seq: int
    paired: bool = False


@dataclass
class Instance:
    """One session or sub-agent. ``key`` is ``<agent>:<16 hex>`` (a sub-agent adds ``/<12 hex>``)."""

    key: str
    agent: str
    kind: str                      # "session" | "sub-agent"
    started: float
    last: float
    profile: str = ""              # the config home it ran with ("" = the default one)
    parent: str = ""               # a sub-agent's session key
    type: str = ""                 # a sub-agent's type (Explore, generalPurpose…), an agent's --agent name
    task: str = ""                 # a sub-agent's task title (its spawn call's description), redacted — never its prompt
    folder: str = ""               # the project folder's name
    cwd: str = ""
    model: str = ""
    model_given: bool = False      # *model* is the one its command line named (``--model``): it stays
    launch: str = "unknown"
    sandboxed: bool = False
    shells_sandboxed: bool = False  # only its shell tool's shells run in the OS sandbox (the Hermes agent, KI-580)
    pid: int = 0                   # the agent process, when it could be found
    sandbox_profile: str = ""      # the profile its launcher chose, "<file>#<digest>" (sandbox permissions)
    ended: Optional[float] = None
    end_reason: str = ""           # the agent's own word, "process-exit" or "quiet"
    events: int = 0
    checked: int = 0               # tool calls Blackbox judged
    refused: int = 0               # actions Blackbox stopped (the agent got the refusal in time)
    flagged: int = 0
    too_late: int = 0              # actions Blackbox decided to stop but whose answer came after the hook's limit: they ran
    prompts: int = 0
    waiting: str = ""              # one of WAITING while the agent waits for its person, else ""
    last_action: Optional[Action] = None   # the newest timeline entry (the live tree shows it)
    root: bool = False             # a program this agent started is running as root NOW (root_watch)
    root_runs: int = 0             # how many programs it started ran as root, so far
    root_last: float = 0.0         # when the newest of them was first seen (0 = never)
    seen_refusals: list[SeenRefusal] = field(default_factory=list)   # the count's memory (refusals.py), bounded and pruned
    call_seq: int = 0              # pre_tools seen so far (refusals.py: an output repeat before a new call is one)


@dataclass(frozen=True)
class Action:
    """One thing an instance did, as its timeline shows it. ``what`` is a short redacted summary
    (a command's start, a file's path) — the same text the audit log already keeps. ``reason`` is
    what the agent was told when Blackbox refused the action (it names the rule's source; no
    secret is in it)."""

    ts: float
    kind: str                      # an EVENTS kind
    tool: str = ""
    what: str = ""
    verdict: str = ""              # "", "allow", "flag", "block", "too-late" (decided to stop; the answer came too late: it ran)
    reason: str = ""               # only for verdict "block" / "too-late"
    text: str = ""                 # a prompt's text, redacted — kept ONLY while the person has
    #                                turned prompt-text recording on (agent_hooks.prompt_text)
    late: bool = False             # it arrived after its instance had ended (KI-551): shown, never reopening it


@dataclass(frozen=True)
class Running:
    """One agent process on this machine (read-only observation)."""

    pid: int
    ppid: int
    agent: str
    launch: str
    profile: str = ""              # a moved config home found in its environment
    hooks_skipped: str = ""        # why this run cannot be hooked (e.g. "--bare"), else ""
    started: float = 0.0
    skips_prompts: tuple[str, ...] = ()   # its flags that skip the person's permission prompts (permission_risks)
    folder: str = ""               # the folder it works in (its project), "" when it can not be read
    launched: bool = False         # started by Blackbox's sandbox launcher (observe.launched): a longer grace, never a pass


@dataclass(frozen=True)
class Problem:
    """Something that keeps Blackbox's hooks from running in one profile or project."""

    agent: str
    kind: str                      # "hooks-off" | "managed-only" | "hooks-missing" | "hook-invalid" | "unreadable"
    file: str
    detail: str
    fixable: bool = False


@dataclass
class Profile:
    """One config home of one agent."""

    agent: str
    home: str                      # the folder the config lives in
    config: str                    # the hook config file (or folder)
    default: bool = True
    hooked: bool = False
    problems: list[Problem] = field(default_factory=list)
