from __future__ import annotations
import json
import logging
import re

from .base import BaseAgent
from ..memory.scratchpad import ChallengeContext

log = logging.getLogger(__name__)

_SYSTEM = """You are the Planner agent in a CTF-solving system. Your job is to:
1. Analyze the challenge description and identify the category (web, crypto, forensics, reverse, pwn, misc)
2. Decompose the challenge into ordered subtasks
3. Assign each subtask to a specialist agent or tool
4. Maintain the overall strategy and adapt when subtasks fail

Respond with a JSON plan:
{
  "category": "web|crypto|forensics|reverse|pwn|misc",
  "difficulty_estimate": "beginner|easy|medium|hard",
  "analysis": "brief analysis of the challenge",
  "plan": [
    {
      "step": 1,
      "description": "what to do",
      "agent": "recon|exploit|crypto|reverse|verifier",
      "tools": ["tool1", "tool2"],
      "depends_on": []
    }
  ],
  "initial_hypotheses": ["hypothesis 1", "hypothesis 2"]
}"""


class PlannerAgent(BaseAgent):
    name = "planner"
    role = "challenge decomposition and task orchestration"

    def system_prompt(self) -> str:
        return _SYSTEM

    def create_plan(self, challenge: ChallengeContext) -> list[str]:
        prompt = f"## CTF Challenge\nName: {challenge.name}\nCategory: {challenge.category}\nDescription: {challenge.description}"
        if challenge.files:
            prompt += f"\nFiles: {', '.join(challenge.files)}"
        if challenge.url:
            prompt += f"\nURL: {challenge.url}"
        if challenge.hints:
            prompt += f"\nHints: {challenge.hints}"

        response = self.llm.chat(_SYSTEM, [{"role": "user", "content": prompt}])
        plan = self._parse_plan(response)
        if not plan:
            log.warning("Failed to parse plan, using fallback")
            plan = self._fallback_plan(f"{challenge.category} {challenge.description}")

        self.pad.set_plan([s["description"] for s in plan.get("plan", [])])
        log.info(f"[Planner] {plan.get('category')} | {len(plan.get('plan', []))} steps")
        return [s["description"] for s in plan.get("plan", [])]

    def replan(self, feedback: str) -> list[str]:
        prior = json.dumps({"plan": self.pad.plan}, indent=2)
        prompt = (
            f"## Prior Plan\n{prior}\n\n"
            f"## Feedback\n{feedback}\n\n"
            "Generate a revised plan addressing the feedback. Same JSON format."
        )
        response = self.llm.chat(_SYSTEM, [{"role": "user", "content": prompt}])
        plan = self._parse_plan(response)
        if not plan:
            plan = self._fallback_plan(feedback)
        subtasks = [s["description"] for s in plan.get("plan", [])]
        self.pad.set_plan(subtasks)
        return subtasks

    def _parse_plan(self, text: str) -> dict | None:
        # strip <think>...</think> blocks (deepseek-r1 style)
        text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
        json_match = re.search(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass
        brace_match = re.search(r"\{.*\}", text, re.DOTALL)
        if brace_match:
            try:
                return json.loads(brace_match.group(0))
            except json.JSONDecodeError:
                pass
        return None

    def _fallback_plan(self, task: str) -> dict:
        tl = task.lower()
        if any(w in tl for w in ["crypto", "cipher", "encode", "decode", "rot", "base64", "hex", "xor", "caesar", "vigenere", "hash"]):
            return {
                "category": "crypto",
                "plan": [
                    {"step": 1, "description": "Run multi-decode on the ciphertext in the challenge description (try ROT13, base64, hex, caesar, xor)", "agent": "crypto", "tools": ["crypto_analysis", "rot13", "base64_decode", "hex_decode"], "depends_on": []},
                    {"step": 2, "description": "If step 1 found a candidate, verify and extract the flag", "agent": "verifier", "tools": [], "depends_on": [1]},
                ],
            }
        return {
            "category": "misc",
            "plan": [
                {"step": 1, "description": "Analyze the challenge and attempt to solve it", "agent": "recon", "tools": ["shell", "python_exec"], "depends_on": []},
                {"step": 2, "description": "Verify and extract the flag", "agent": "verifier", "tools": [], "depends_on": [1]},
            ],
        }
