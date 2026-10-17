"""The trial's record: one result per step, written as JSON and as Markdown.

A step either PASSes, FAILs (the product did not do what the step checks),
ERRORs (the trial itself could not run the step: the devnet, a timeout in
setup) or is SKIPped (an earlier step it needs did not pass). Each result
carries its evidence: what was asked, what the nodes answered, how long it
took, and the node log lines of the step's time window when it did not pass.

The report never holds a private key or an API token: actors return public
keys only, and :func:`_scrub` drops any evidence field whose name says it is
a secret before anything is written.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

PASS, FAIL, ERROR, SKIP = "PASS", "FAIL", "ERROR", "SKIP"
_SECRET_WORDS = ("token", "private", "secret", "password", "pem")


@dataclass
class StepResult:
    """One step of the trial and what it showed."""

    key: str
    title: str
    status: str = SKIP
    summary: str = ""
    started_at: float = 0.0
    seconds: float = 0.0
    evidence: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    logs: dict[str, list[str]] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return self.status == PASS


class StepFailed(Exception):
    """The product did not do what the step checks (a FAIL, not an ERROR)."""

    def __init__(self, summary: str, **evidence: Any) -> None:
        super().__init__(summary)
        self.summary = summary
        self.evidence = evidence


@dataclass
class TrialReport:
    """Every step result plus the run's facts (versions, topology)."""

    run_dir: Path
    facts: dict[str, Any] = field(default_factory=dict)
    steps: list[StepResult] = field(default_factory=list)

    def add(self, result: StepResult) -> StepResult:
        self.steps.append(result)
        self.write()
        return result

    def result(self, key: str) -> Optional[StepResult]:
        return next((step for step in self.steps if step.key == key), None)

    @property
    def ok(self) -> bool:
        return bool(self.steps) and all(step.status == PASS for step in self.steps)

    def write(self) -> None:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        document = {"facts": _scrub(self.facts), "steps": [_scrub(asdict(step)) for step in self.steps],
                    "written_at": _utc(time.time())}
        (self.run_dir / "report.json").write_text(json.dumps(document, indent=2, sort_keys=True, default=str) + "\n",
                                                  encoding="utf-8")
        (self.run_dir / "report.md").write_text(render_markdown(self), encoding="utf-8")


def render_markdown(report: TrialReport) -> str:
    """The report as Markdown: a table of steps, then each step's evidence."""
    lines = ["# Agent Blackbox one-graph trial", ""]
    for name, value in sorted(_scrub(report.facts).items()):
        lines.append(f"- **{name}**: `{_one_line(value)}`")
    lines += ["", "| # | step | result | time | summary |", "|---|---|---|---|---|"]
    for index, step in enumerate(report.steps, 1):
        lines.append(f"| {index} | {step.title} | {step.status} | {step.seconds:.0f} s | {_cell(step.summary)} |")
    for index, step in enumerate(report.steps, 1):
        lines += ["", f"## {index}. {step.title} — {step.status}", ""]
        if step.summary:
            lines += [step.summary, ""]
        if step.error:
            lines += ["Error:", "", "```", step.error.strip(), "```", ""]
        if step.evidence:
            lines += ["Evidence:", "", "```json", json.dumps(_scrub(step.evidence), indent=2, sort_keys=True,
                                                             default=str), "```", ""]
        for node, excerpt in sorted(step.logs.items()):
            lines += [f"Log lines from {node} during this step:", "", "```", *excerpt, "```", ""]
    return "\n".join(lines).rstrip() + "\n"


def _scrub(value: Any) -> Any:
    """*value* without any mapping entry whose key names a secret."""
    if isinstance(value, dict):
        return {key: _scrub(item) for key, item in value.items()
                if not any(word in str(key).lower() for word in _SECRET_WORDS)}
    if isinstance(value, (list, tuple)):
        return [_scrub(item) for item in value]
    return value


def _one_line(value: Any) -> str:
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=str)
    return text.replace("`", "'").replace("\n", " ")


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _utc(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))
