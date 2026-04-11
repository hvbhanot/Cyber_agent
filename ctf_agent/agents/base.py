from __future__ import annotations
import json
import logging
import re
from abc import ABC, abstractmethod
from typing import Optional
from langgraph.prebuilt import create_react_agent
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.tools import StructuredTool
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

    def _get_langchain_tools(self) -> list[StructuredTool]:
        return self.tools.get_langchain_tools()

    def run_react_loop(self, task: str, max_steps: Optional[int] = None) -> str:
        steps = max_steps or self.cfg.max_react_steps
        context = self.pad.get_context_window()

        lc_tools = self._get_langchain_tools()
        if not lc_tools:
            log.warning(f"[{self.role}] No LangChain tools available, falling back")
            return self._fallback_react_loop(task, steps)

        model = self.llm.get_model()

        # Build the LangGraph ReAct agent
        agent = create_react_agent(
            model,
            lc_tools,
            prompt=SystemMessage(content=self.system_prompt()),
        )

        full_input = f"## Current Context\n{context}\n\n## Task\n{task}"

        try:
            result = agent.invoke(
                {"messages": [HumanMessage(content=full_input)]},
                config={"recursion_limit": steps * 2},
            )

            # Extract answer from the last AI message
            messages = result.get("messages", [])
            answer = ""
            for msg in reversed(messages):
                if hasattr(msg, "content") and msg.content and not hasattr(msg, "tool_calls"):
                    answer = msg.content
                    break

            # Record steps, count tokens, and scan for flags in all messages
            for msg in messages:
                content = str(getattr(msg, "content", ""))

                # Count tokens from AI messages (LangGraph bypasses LLMClient)
                if msg.type == "ai":
                    self.llm.tokens.record(msg)

                if content:
                    flags = re.findall(self.cfg.flag_format, content)
                    for f in flags:
                        self.pad.add_flag_candidate(f)
                        log.info(f"Flag candidate found: {f}")

                # Record tool call steps in scratchpad
                if hasattr(msg, "tool_calls") and msg.tool_calls:
                    for tc in msg.tool_calls:
                        tool_name = tc.get("name", "unknown")
                        step = self.pad.new_step(f"Tool call: {tool_name}")
                        step.action = tool_name
                        step.action_input = tc.get("args", {})

                # Record tool results
                if msg.type == "tool":
                    if self.pad.steps:
                        self.pad.steps[-1].observation = content[:2000]
                        self.pad._emit("tool_result", f"{self.pad.steps[-1].action} [ok]")

        except Exception as e:
            log.error(f"[{self.role}] LangGraph agent error: {e}")
            self.pad.add_error(str(e))
            log.info(f"[{self.role}] Falling back to manual ReAct loop")
            return self._fallback_react_loop(task, steps)

        if self.pad.validated_flag:
            return f"FLAG FOUND: {self.pad.validated_flag}"

        return answer or "No answer produced"

    def _fallback_react_loop(self, task: str, max_steps: int) -> str:
        """Original hand-rolled ReAct loop as fallback."""
        context = self.pad.get_context_window()
        consecutive_failures = 0
        last_action_sig: Optional[str] = None
        repeat_count = 0

        schema = (
            "Respond with ONLY a JSON object in this exact format:\n"
            '{"thought": "your reasoning here", "action": "tool_name or FINISH", '
            '"action_input": {"arg1": "val1"}, "answer": "only when action is FINISH"}\n'
            "If you are done or cannot proceed, set action to FINISH and provide your answer."
        )

        for i in range(max_steps):
            prompt = (
                f"## Current Context\n{context}\n\n"
                f"## Task\n{task}\n\n"
                f"## Step {i+1}/{max_steps}\n"
                "Decide: think, act (use a tool), or FINISH."
            )
            try:
                decision = self.llm.structured_chat(
                    self.system_prompt(),
                    [{"role": "user", "content": prompt}],
                    schema_hint=schema,
                )
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

            if action.upper() == "FINISH":
                step.observation = answer
                return answer

            tool = self.tools.get(action)
            if tool is None:
                step.observation = f"Unknown tool: {action}"
                self.pad.add_error(f"Unknown tool: {action}")
                context = self.pad.get_context_window()
                continue

            result = tool.execute(**action_input)
            self.pad.record_tool_result(step, result)
            flag_matches = re.findall(self.cfg.flag_format, result.stdout)
            for f in flag_matches:
                self.pad.add_flag_candidate(f)
                log.info(f"Flag candidate found: {f}")

            step.observation = result.stdout[:4000] if result.exit_code == 0 else f"ERROR: {result.stderr[:1000]}"
            context = self.pad.get_context_window()

            if self.pad.validated_flag:
                return f"FLAG FOUND: {self.pad.validated_flag}"

        return "MAX STEPS REACHED — no definitive answer"
