from __future__ import annotations
import json
import logging
from pathlib import Path

from langchain_core.messages import SystemMessage, HumanMessage
from langchain_core.output_parsers import JsonOutputParser

from .base import BaseAgent
from ..memory.scratchpad import ChallengeContext

_PROJECT_ROOT = Path(__file__).parents[2]


def _load_skill_md() -> str:
    path = _PROJECT_ROOT / "skills" / "SKILL.md"
    try:
        content = path.read_text()
        if content.startswith("---"):
            end = content.find("---", 3)
            if end != -1:
                content = content[end + 3:].lstrip()
        return content
    except OSError:
        return ""


log = logging.getLogger(__name__)

_SKILL_BODY = _load_skill_md()

_SYSTEM = f"""You are the Planner agent in a CTF-solving system. Your job is to:
1. Analyze the challenge description and identify the category (web, crypto, forensics, reverse, pwn, misc)
2. Decompose the challenge into ordered subtasks
3. Assign each subtask to a specialist agent or tool
4. Maintain the overall strategy and adapt when subtasks fail

{_SKILL_BODY}

Respond with a JSON plan:
{{
  "category": "web|crypto|forensics|reverse|pwn|misc",
  "difficulty_estimate": "beginner|easy|medium|hard",
  "analysis": "brief analysis of the challenge",
  "plan": [
    {{
      "step": 1,
      "description": "what to do",
      "agent": "recon|exploit|crypto|reverse|verifier",
      "tools": ["tool1", "tool2"],
      "depends_on": []
    }}
  ],
  "initial_hypotheses": ["hypothesis 1", "hypothesis 2"]
}}"""

_JSON_PARSER = JsonOutputParser()


class PlannerAgent(BaseAgent):
    name = "planner"
    role = "challenge decomposition and task orchestration"

    def system_prompt(self) -> str:
        return _SYSTEM

    def _invoke_plan_chain(self, user_content: str) -> dict | None:
        """Invoke model with system + user messages, parse JSON output."""
        model = self.llm.get_model()
        messages = [
            SystemMessage(content=_SYSTEM),
            HumanMessage(content=user_content),
        ]
        try:
            response = model.invoke(messages)
            return _JSON_PARSER.parse(response.content)
        except Exception as e:
            log.warning(f"Plan chain failed ({e}), trying structured_chat fallback")
            try:
                return self.llm.structured_chat(_SYSTEM, [{"role": "user", "content": user_content}])
            except Exception:
                return None

    def create_plan(self, challenge: ChallengeContext) -> list[str]:
        prompt = f"## CTF Challenge\nName: {challenge.name}\nCategory: {challenge.category}\nDescription: {challenge.description}"
        if challenge.files:
            prompt += f"\nFiles: {', '.join(challenge.files)}"
        if challenge.url:
            prompt += f"\nURL: {challenge.url}"
        if challenge.hints:
            prompt += f"\nHints: {challenge.hints}"

        plan = self._invoke_plan_chain(prompt)

        if not plan:
            log.warning("Failed to parse plan, using fallback")
            plan = self._fallback_plan(f"{challenge.category} {challenge.description}")

        self.pad.set_plan([s["description"] for s in plan.get("plan", [])])
        log.info(f"[Planner] {plan.get('category')} | {len(plan.get('plan', []))} steps")
        return [s["description"] for s in plan.get("plan", [])]

    def replan(self, feedback: str) -> list[str]:
        prior = json.dumps({"plan": self.pad.plan}, indent=2)
        user_content = (
            f"## Prior Plan\n{prior}\n\n"
            f"## Feedback\n{feedback}\n\n"
            "Generate a revised plan addressing the feedback. Same JSON format."
        )

        plan = self._invoke_plan_chain(user_content)

        if not plan:
            plan = self._fallback_plan(feedback)

        subtasks = [s["description"] for s in plan.get("plan", [])]
        self.pad.set_plan(subtasks)
        return subtasks

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
