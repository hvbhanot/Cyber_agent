from __future__ import annotations
import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from ctf_agent.memory.scratchpad import Scratchpad


@dataclass
class ChallengeMetrics:
    name: str
    category: str
    solved: bool = False
    flag: str = ""
    answer: str = ""
    total_steps: int = 0
    total_tool_calls: int = 0
    hallucinated_flags: int = 0
    valid_flags: int = 0
    errors: int = 0
    human_hints_used: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    wall_time_s: float = 0.0
    replans: int = 0

    @property
    def solve_rate(self) -> float:
        return 1.0 if self.solved else 0.0

    @property
    def hallucination_rate(self) -> float:
        total = self.hallucinated_flags + self.valid_flags
        return self.hallucinated_flags / total if total > 0 else 0.0

    @property
    def tool_efficiency(self) -> float:
        return self.total_tool_calls if self.solved else float("inf")

    @property
    def autonomy_score(self) -> float:
        if self.human_hints_used == 0:
            return 1.0
        return max(0.0, 1.0 - (self.human_hints_used * 0.25))


@dataclass
class BenchmarkResults:
    challenges: list[ChallengeMetrics] = field(default_factory=list)
    config_snapshot: dict = field(default_factory=dict)

    @property
    def aggregate_solve_rate(self) -> float:
        if not self.challenges:
            return 0.0
        return sum(c.solve_rate for c in self.challenges) / len(self.challenges)

    @property
    def aggregate_hallucination_rate(self) -> float:
        total_h = sum(c.hallucinated_flags for c in self.challenges)
        total_v = sum(c.valid_flags for c in self.challenges)
        total = total_h + total_v
        return total_h / total if total > 0 else 0.0

    @property
    def avg_tool_calls_per_solve(self) -> float:
        solved = [c for c in self.challenges if c.solved]
        if not solved:
            return 0.0
        return sum(c.total_tool_calls for c in solved) / len(solved)

    @property
    def avg_autonomy(self) -> float:
        if not self.challenges:
            return 0.0
        return sum(c.autonomy_score for c in self.challenges) / len(self.challenges)

    def summary(self) -> dict:
        return {
            "total_challenges": len(self.challenges),
            "solved": sum(1 for c in self.challenges if c.solved),
            "solve_rate": f"{self.aggregate_solve_rate:.2%}",
            "hallucination_rate": f"{self.aggregate_hallucination_rate:.2%}",
            "avg_tool_calls_per_solve": f"{self.avg_tool_calls_per_solve:.1f}",
            "avg_autonomy_score": f"{self.avg_autonomy:.2f}",
            "by_category": self._by_category(),
        }

    def _by_category(self) -> dict:
        cats: dict[str, list[ChallengeMetrics]] = {}
        for c in self.challenges:
            cats.setdefault(c.category, []).append(c)
        return {
            cat: {
                "total": len(cs),
                "solved": sum(1 for c in cs if c.solved),
                "solve_rate": f"{sum(c.solve_rate for c in cs) / len(cs):.2%}",
            }
            for cat, cs in cats.items()
        }

    def save(self, path: str):
        Path(path).write_text(json.dumps(
            {"summary": self.summary(), "challenges": [asdict(c) for c in self.challenges]},
            indent=2,
        ))


def extract_metrics(pad: Scratchpad, start_time: float) -> ChallengeMetrics:
    end = time.time()
    total_tool_calls = sum(len(s.tool_results) for s in pad.steps)
    valid = 1 if pad.validated_flag else 0
    hallucinated = len(pad.flag_candidates) - valid

    return ChallengeMetrics(
        name=pad.challenge.name if pad.challenge else "unknown",
        category=pad.challenge.category if pad.challenge else "unknown",
        solved=pad.validated_flag is not None,
        flag=pad.validated_flag or "",
        answer=pad.answer or pad.validated_flag or "",
        total_steps=len(pad.steps),
        total_tool_calls=total_tool_calls,
        hallucinated_flags=max(0, hallucinated),
        valid_flags=valid,
        errors=len(pad.errors),
        human_hints_used=pad.human_hints_used,
        start_time=start_time,
        end_time=end,
        wall_time_s=round(end - start_time, 2),
    )
