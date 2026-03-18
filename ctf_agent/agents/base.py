from __future__ import annotations
import json
import logging
import re
from abc import ABC, abstractmethod
from typing import Optional
from ctf_agent.config import Config
from ctf_agent.utils.llm import LLMClient
from ctf_agent.memory.scratchpad import Scratchpad, ReActStep
from ctf_agent.tools import ToolRegistry

log = logging.getLogger(__name__)


class BaseAgent(ABC):
    role: str = "base"

    def __init__(self, config: Config, llm: LLMClient, scratchpad: Scratchpad, tools: ToolRegistry):
        self.cfg = config
        self.llm = llm
        self.pad = scratchpad
        self.tools = tools

    @abstractmethod
    def system_prompt(self) -> str:
        ...

    def react_step(self, user_msg: str) -> dict:
        schema = (
            "Respond with ONLY a JSON object in this exact format:\n"
            '{"thought": "your reasoning here", "action": "tool_name or FINISH", '
            '"action_input": {"arg1": "val1"}, "answer": "only when action is FINISH"}\n'
            "If you are done or cannot proceed, set action to FINISH and provide your answer."
        )
        messages = [{"role": "user", "content": user_msg}]
        result = self.llm.structured_chat(
            self.system_prompt(),
            messages,
            schema_hint=schema,
        )
        return result

    def execute_action(self, step: ReActStep, action: str, action_input: dict) -> str:
        tool = self.tools.get(action)
        if tool is None:
            err = f"Unknown tool: {action}"
            self.pad.add_error(err)
            return err
        if not tool.is_available():
            err = f"Tool not available: {action} (binary: {tool.spec.binary})"
            self.pad.add_error(err)
            return err
        result = tool.execute(**action_input)
        self.pad.record_tool_result(step, result)
        flag_matches = re.findall(self.cfg.flag_format, result.stdout)
        for f in flag_matches:
            self.pad.add_flag_candidate(f)
            log.info(f"Flag candidate found: {f}")
        return result.stdout[:3000] if result.exit_code == 0 else f"ERROR: {result.stderr[:1000]}"

    def run_react_loop(self, task: str, max_steps: Optional[int] = None) -> str:
        steps = max_steps or self.cfg.max_react_steps
        context = self.pad.get_context_window()
        consecutive_failures = 0
        last_action_sig: Optional[str] = None
        repeat_count = 0

        for i in range(steps):
            prompt = (
                f"## Current Context\n{context}\n\n"
                f"## Task\n{task}\n\n"
                f"## Step {i+1}/{steps}\n"
                "Decide: think, act (use a tool), or FINISH."
            )
            try:
                decision = self.react_step(prompt)
                consecutive_failures = 0
            except Exception as e:
                log.error(f"ReAct step failed: {e}")
                self.pad.add_error(str(e))
                consecutive_failures += 1
                if consecutive_failures >= 3:
                    log.warning(f"[{self.role}] 3 consecutive parse failures, stopping")
                    break
                continue

            thought = decision.get("thought", "")
            action = decision.get("action", "FINISH")
            action_input = decision.get("action_input", {})
            answer = decision.get("answer", "")

            # detect infinite loop: same action + same inputs repeated
            action_sig = f"{action}:{json.dumps(action_input, sort_keys=True)}"
            if action_sig == last_action_sig:
                repeat_count += 1
                if repeat_count >= 2:
                    log.warning(f"[{self.role}] Same action repeated {repeat_count+1}x, forcing FINISH")
                    return answer or "Stuck in loop — could not complete task"
            else:
                repeat_count = 0
            last_action_sig = action_sig

            step = self.pad.new_step(thought)
            step.action = action

            if self.cfg.verbose:
                log.info(f"[{self.role}] Step {i+1}: {thought[:120]}")
                log.info(f"[{self.role}] Action: {action} | Input: {json.dumps(action_input)[:200]}")

            if action.upper() == "FINISH":
                step.observation = answer
                return answer

            observation = self.execute_action(step, action, action_input)
            step.observation = observation
            context = self.pad.get_context_window()

            if self.pad.validated_flag:
                return f"FLAG FOUND: {self.pad.validated_flag}"

        return "MAX STEPS REACHED — no definitive answer"
