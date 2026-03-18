from __future__ import annotations
import logging
import time
from typing import Optional
from ctf_agent.config import Config
from ctf_agent.utils.llm import LLMClient
from ctf_agent.memory.scratchpad import Scratchpad, ChallengeContext
from ctf_agent.tools import ToolRegistry
from ctf_agent.agents.planner import PlannerAgent
from ctf_agent.agents.specialist import SpecialistAgent
from ctf_agent.agents.verifier import VerifierAgent
from ctf_agent.metrics import extract_metrics, ChallengeMetrics

log = logging.getLogger(__name__)

CATEGORY_TO_SPECIALTY = {
    "web": "recon",
    "crypto": "crypto",
    "forensics": "forensics",
    "reverse": "reverse",
    "pwn": "exploit",
    "misc": "recon",
}


class Orchestrator:
    def __init__(self, config: Optional[Config] = None):
        self.cfg = config or Config()
        self.llm = LLMClient(self.cfg)
        self.tools = ToolRegistry(timeout=self.cfg.tool_timeout, workspace=self.cfg.workspace_dir)
        self.pad = Scratchpad(persist_path=self.cfg.memory_persist_path)

    def solve(self, challenge: ChallengeContext, max_replans: int = 2) -> ChallengeMetrics:
        start = time.time()
        self.pad.reset()
        log.info(f"=== Solving: {challenge.name} ({challenge.category}) ===")

        planner = PlannerAgent(self.cfg, self.llm, self.pad, self.tools)
        verifier = VerifierAgent(self.cfg, self.llm, self.pad, self.tools)

        subtasks = planner.create_plan(challenge)
        log.info(f"Plan ({len(subtasks)} steps): {subtasks}")

        for replan_attempt in range(max_replans + 1):
            specialty = CATEGORY_TO_SPECIALTY.get(challenge.category, "recon")
            specialist = SpecialistAgent(
                self.cfg, self.llm, self.pad, self.tools, specialty=specialty,
            )

            last_result = ""
            for i, subtask in enumerate(subtasks):
                log.info(f"--- Subtask {i+1}/{len(subtasks)}: {subtask} ---")
                result = specialist.execute_subtask(subtask)
                last_result = result
                log.info(f"Subtask result: {result[:200]}")

                if self.pad.validated_flag:
                    break
                if self.pad.flag_candidates:
                    verification = verifier.verify_candidates()
                    if verification.get("valid"):
                        break

            if last_result:
                self.pad.set_answer(last_result)

            if self.pad.validated_flag:
                log.info(f"FLAG: {self.pad.validated_flag}")
                break

            if self.pad.flag_candidates:
                verification = verifier.verify_candidates()
                if verification.get("valid"):
                    break

            if replan_attempt < max_replans:
                reflection = verifier.self_reflect()
                confidence = reflection.get("confidence_in_approach", 0.5)
                suggestions = reflection.get("suggestions", [])
                log.info(f"[Reflection] confidence={confidence}, suggestions={suggestions}")

                if confidence < 0.5 and suggestions:
                    log.info("[Orchestrator] Replanning...")
                    subtasks = planner.replan(
                        f"Low confidence ({confidence}). Suggestions: {suggestions}"
                    )
                else:
                    break

        self.pad.save()
        metrics = extract_metrics(self.pad, start)
        log.info(f"=== Result: {'SOLVED' if metrics.solved else 'UNSOLVED'} "
                 f"in {metrics.wall_time_s}s, {metrics.total_tool_calls} tool calls ===")
        return metrics

    def solve_batch(self, challenges: list[ChallengeContext]) -> list[ChallengeMetrics]:
        results = []
        for ch in challenges:
            m = self.solve(ch)
            results.append(m)
        return results
