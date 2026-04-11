from __future__ import annotations
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Optional
from pathlib import Path


@dataclass
class ToolResult:
    tool_name: str
    args: dict
    stdout: str
    stderr: str
    exit_code: int
    timestamp: float = field(default_factory=time.time)


@dataclass
class ReActStep:
    step_id: int
    thought: str
    action: Optional[str] = None
    action_input: Optional[dict] = None
    observation: Optional[str] = None
    tool_results: list[ToolResult] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)


@dataclass
class ChallengeContext:
    name: str
    category: str
    description: str
    files: list[str] = field(default_factory=list)
    url: Optional[str] = None
    port: Optional[int] = None
    hints: list[str] = field(default_factory=list)


class Scratchpad:
    def __init__(self, persist_path: Optional[str] = None):
        self.persist_path = persist_path
        self.challenge: Optional[ChallengeContext] = None
        self.plan: list[str] = []
        self.steps: list[ReActStep] = []
        self.findings: dict[str, Any] = {}
        self.flag_candidates: list[str] = []
        self.validated_flag: Optional[str] = None
        self.answer: Optional[str] = None
        self.errors: list[str] = []
        self.runtime_hints: list[str] = []
        self.human_hints_used: int = 0
        self._step_counter = 0
        self._on_progress: Optional[Any] = None  # callback: (event, detail) -> None

    def set_progress_callback(self, callback):
        self._on_progress = callback

    def _emit(self, event: str, detail: str = ""):
        if self._on_progress:
            try:
                self._on_progress(event, detail)
            except Exception:
                pass

    def set_challenge(self, ctx: ChallengeContext):
        self.challenge = ctx

    def set_plan(self, subtasks: list[str]):
        self.plan = subtasks
        self._emit("plan", f"{len(subtasks)} steps")

    def new_step(self, thought: str) -> ReActStep:
        self._step_counter += 1
        step = ReActStep(step_id=self._step_counter, thought=thought)
        self.steps.append(step)
        self._emit("step", thought[:80])
        return step

    def record_tool_result(self, step: ReActStep, result: ToolResult):
        step.tool_results.append(result)
        step.observation = result.stdout[:4000] if result.stdout else result.stderr[:2000]
        status = "ok" if result.exit_code == 0 else "error"
        self._emit("tool_result", f"{result.tool_name} [{status}]")

    def add_finding(self, key: str, value: Any):
        self.findings[key] = value

    def add_flag_candidate(self, candidate: str):
        if candidate not in self.flag_candidates:
            self.flag_candidates.append(candidate)
            self._emit("flag_candidate", candidate)

    def set_validated_flag(self, flag: str):
        self.validated_flag = flag
        self._emit("flag_validated", flag)

    def set_answer(self, answer: str):
        self.answer = answer

    def add_runtime_hint(self, hint: str):
        self.runtime_hints.append(hint)
        self.human_hints_used += 1

    def add_error(self, error: str):
        self.errors.append(error)
        self._emit("error", error[:80])

    def get_context_window(self, max_steps: int = 10) -> str:
        parts = []
        if self.challenge:
            parts.append(
                f"## Challenge\n"
                f"Name: {self.challenge.name}\n"
                f"Category: {self.challenge.category}\n"
                f"Description: {self.challenge.description}\n"
                f"Files: {', '.join(self.challenge.files) or 'None'}\n"
                f"URL: {self.challenge.url or 'N/A'} Port: {self.challenge.port or 'N/A'}"
            )
        if self.plan:
            parts.append("## Plan\n" + "\n".join(f"  {i+1}. {s}" for i, s in enumerate(self.plan)))
        if self.findings:
            parts.append("## Findings\n" + json.dumps(self.findings, indent=2, default=str))

        # Summarize older steps so early findings aren't lost
        if len(self.steps) > max_steps:
            older = self.steps[:-max_steps]
            summary_lines = []
            for s in older:
                obs_snippet = (s.observation or "")[:120]
                summary_lines.append(
                    f"  Step {s.step_id}: {s.action or 'think'} → {obs_snippet}"
                )
            parts.append("## Earlier Steps (summary)\n" + "\n".join(summary_lines))

        recent = self.steps[-max_steps:]
        if recent:
            step_lines = []
            for s in recent:
                step_lines.append(
                    f"### Step {s.step_id}\n"
                    f"Thought: {s.thought}\n"
                    f"Action: {s.action or 'None'}\n"
                    f"Observation: {(s.observation or 'None')[:2000]}"
                )
            parts.append("## Recent Steps\n" + "\n".join(step_lines))
        if self.runtime_hints:
            parts.append("## HUMAN HINTS (use these)\n" + "\n".join(f"  - {h}" for h in self.runtime_hints))
        if self.flag_candidates:
            parts.append(f"## Flag Candidates: {self.flag_candidates}")
        if self.validated_flag:
            parts.append(f"## VALIDATED FLAG: {self.validated_flag}")
        return "\n\n".join(parts)

    def save(self):
        if not self.persist_path:
            return
        data = {
            "challenge": asdict(self.challenge) if self.challenge else None,
            "plan": self.plan,
            "findings": self.findings,
            "flag_candidates": self.flag_candidates,
            "validated_flag": self.validated_flag,
            "errors": self.errors,
            "steps": [asdict(s) for s in self.steps],
        }
        Path(self.persist_path).write_text(json.dumps(data, indent=2, default=str))

    def load(self) -> bool:
        if not self.persist_path or not Path(self.persist_path).exists():
            return False
        data = json.loads(Path(self.persist_path).read_text())
        if data.get("challenge"):
            self.challenge = ChallengeContext(**data["challenge"])
        self.plan = data.get("plan", [])
        self.findings = data.get("findings", {})
        self.flag_candidates = data.get("flag_candidates", [])
        self.validated_flag = data.get("validated_flag")
        self.errors = data.get("errors", [])
        return True

    def reset(self):
        self.challenge = None
        self.plan = []
        self.steps = []
        self.findings = {}
        self.flag_candidates = []
        self.validated_flag = None
        self.answer = None
        self.errors = []
        self.runtime_hints = []
        self.human_hints_used = 0
        self._step_counter = 0
