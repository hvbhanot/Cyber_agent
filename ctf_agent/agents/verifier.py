from __future__ import annotations
import re
import logging
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_core.output_parsers import JsonOutputParser
from ctf_agent.agents.base import BaseAgent

log = logging.getLogger(__name__)

_VERIFY_SYSTEM = """You are the Verifier Agent. Your job is to validate flag candidates and reduce hallucinations.

Verification steps:
1. FORMAT CHECK: Does the candidate match the expected flag format?
2. PROVENANCE CHECK: Was the flag extracted from actual tool output, or was it fabricated by the LLM?
3. CONSISTENCY CHECK: Does the flag make sense given the challenge context?
4. SUBMISSION CHECK: If a server URL is available, attempt to submit the flag.
5. SELF-REFLECTION: Review the entire reasoning trace for logical gaps or hallucinated steps.

You must be skeptical. Common hallucination patterns:
- Flags that look plausible but weren't in any tool output
- "Guessed" flags based on challenge name/description
- Flags from previous challenges bleeding into current context

Output JSON: {"valid": true/false, "flag": "...", "confidence": 0.0-1.0, "reasoning": "...", "issues": [...]}"""

_JSON_PARSER = JsonOutputParser()


class VerifierAgent(BaseAgent):
    role = "verifier"

    def system_prompt(self) -> str:
        return _VERIFY_SYSTEM

    def verify_candidates(self) -> dict:
        candidates = self.pad.flag_candidates
        if not candidates:
            return {"valid": False, "flag": None, "confidence": 0.0, "reasoning": "No flag candidates found"}

        trace = self.pad.get_context_window(max_steps=10)
        model = self.llm.get_model()
        results = []

        for candidate in candidates:
            format_ok = bool(re.fullmatch(self.cfg.flag_format, candidate))
            provenance = self._check_provenance(candidate)

            user_content = (
                f"## Verification Request\n"
                f"Flag candidate: {candidate}\n"
                f"Format valid: {format_ok}\n"
                f"Found in tool output: {provenance}\n\n"
                f"## Full Reasoning Trace\n{trace}\n\n"
                "Verify this flag. Is it real or hallucinated?\n"
                '{"valid": bool, "flag": "...", "confidence": 0.0-1.0, "reasoning": "...", "issues": [...]}'
            )

            messages = [
                SystemMessage(content=_VERIFY_SYSTEM),
                HumanMessage(content=user_content),
            ]

            try:
                response = model.invoke(messages)
                result = _JSON_PARSER.parse(response.content)
            except Exception as e:
                log.warning(f"Verification chain failed ({e}), falling back to structured_chat")
                result = self.llm.structured_chat(
                    _VERIFY_SYSTEM, [{"role": "user", "content": user_content}]
                )

            result["format_ok"] = format_ok
            result["provenance"] = provenance
            results.append(result)

        best = max(results, key=lambda r: r.get("confidence", 0))
        if best.get("valid") and best.get("confidence", 0) >= 0.7:
            self.pad.set_validated_flag(best["flag"])
            log.info(f"[Verifier] VALIDATED: {best['flag']} (conf={best['confidence']})")
        else:
            log.warning(f"[Verifier] No flag passed verification. Best: {best}")
        return best

    def _check_provenance(self, candidate: str) -> bool:
        for step in self.pad.steps:
            for tr in step.tool_results:
                if candidate in tr.stdout:
                    return True
        return False

    def self_reflect(self) -> dict:
        trace = self.pad.get_context_window(max_steps=15)
        model = self.llm.get_model()

        user_content = (
            "## Self-Reflection\n"
            "Review the full solving trace and identify:\n"
            "1. Logical gaps in reasoning\n"
            "2. Steps that were skipped or assumed\n"
            "3. Tool outputs that were misinterpreted\n"
            "4. Alternative approaches not yet tried\n\n"
            f"{trace}\n\n"
            '{"issues": [...], "suggestions": [...], "confidence_in_approach": 0.0-1.0}'
        )

        messages = [
            SystemMessage(content=_VERIFY_SYSTEM),
            HumanMessage(content=user_content),
        ]

        try:
            response = model.invoke(messages)
            return _JSON_PARSER.parse(response.content)
        except Exception as e:
            log.warning(f"Reflection chain failed ({e}), falling back to structured_chat")
            return self.llm.structured_chat(
                _VERIFY_SYSTEM, [{"role": "user", "content": user_content}]
            )
