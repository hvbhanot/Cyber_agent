from __future__ import annotations
import json
import logging
import re
import threading
from typing import Optional
from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.output_parsers import JsonOutputParser
from ctf_agent.config import Config

log = logging.getLogger(__name__)

_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)


def _strip_think(text: str) -> str:
    return _THINK_RE.sub("", text).strip()


def _extract_json(text: str) -> dict:
    text = _strip_think(text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    cleaned = text
    if "```" in cleaned:
        cleaned = re.sub(r"```(?:json)?", "", cleaned).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    start = cleaned.find("{")
    end = cleaned.rfind("}") + 1
    if start != -1 and end > start:
        return json.loads(cleaned[start:end])
    raise ValueError(f"Could not parse LLM output as JSON: {text[:300]}")


class TokenCounter:
    """Thread-safe counter for LLM token usage."""

    def __init__(self):
        self._lock = threading.Lock()
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.total_tokens = 0
        self.llm_calls = 0

    def record(self, response):
        """Extract token counts from a LangChain AIMessage response."""
        prompt = 0
        completion = 0

        # Try usage_metadata first (standard LangChain)
        meta = getattr(response, "usage_metadata", None)
        if meta and isinstance(meta, dict):
            prompt = meta.get("input_tokens", 0) or meta.get("prompt_tokens", 0)
            completion = meta.get("output_tokens", 0) or meta.get("completion_tokens", 0)

        # Fallback: response_metadata (Ollama often puts it here)
        if not (prompt or completion):
            rmeta = getattr(response, "response_metadata", {}) or {}
            prompt = rmeta.get("prompt_eval_count", 0)
            completion = rmeta.get("eval_count", 0)

        with self._lock:
            self.prompt_tokens += prompt
            self.completion_tokens += completion
            self.total_tokens += prompt + completion
            self.llm_calls += 1

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "prompt_tokens": self.prompt_tokens,
                "completion_tokens": self.completion_tokens,
                "total_tokens": self.total_tokens,
                "llm_calls": self.llm_calls,
            }

    def reset(self):
        with self._lock:
            self.prompt_tokens = 0
            self.completion_tokens = 0
            self.total_tokens = 0
            self.llm_calls = 0


class LLMClient:
    def __init__(self, config: Config):
        self.cfg = config
        self.model = ChatOllama(
            model=self.cfg.llm_model,
            base_url=self.cfg.ollama_base_url,
            temperature=self.cfg.temperature,
            num_predict=4096,
        )
        self._json_parser = JsonOutputParser()
        self.tokens = TokenCounter()

    def get_model(self, **overrides) -> ChatOllama:
        if not overrides:
            return self.model
        kwargs = {
            "model": self.cfg.llm_model,
            "base_url": self.cfg.ollama_base_url,
            "temperature": overrides.get("temperature", self.cfg.temperature),
            "num_predict": overrides.get("max_tokens", 4096),
        }
        return ChatOllama(**kwargs)

    def chat(
        self,
        system: str,
        messages: list[dict],
        temperature: Optional[float] = None,
        max_tokens: int = 4096,
    ) -> str:
        model = self.model
        if temperature is not None and temperature != self.cfg.temperature:
            model = self.get_model(temperature=temperature, max_tokens=max_tokens)

        lc_messages = [SystemMessage(content=system)]
        for m in messages:
            if m["role"] == "user":
                lc_messages.append(HumanMessage(content=m["content"]))
            else:
                from langchain_core.messages import AIMessage
                lc_messages.append(AIMessage(content=m["content"]))

        response = model.invoke(lc_messages)
        self.tokens.record(response)
        return _strip_think(response.content)

    def structured_chat(
        self,
        system: str,
        messages: list[dict],
        schema_hint: str = "",
    ) -> dict:
        augmented_system = (
            f"{system}\n\n"
            f"IMPORTANT: Your entire response must be a single valid JSON object. "
            f"Do not include any text, explanation, or markdown outside the JSON.\n"
            f"{schema_hint}"
        )

        # first attempt — use format="json" via model config
        json_model = ChatOllama(
            model=self.cfg.llm_model,
            base_url=self.cfg.ollama_base_url,
            temperature=self.cfg.temperature,
            num_predict=4096,
            format="json",
        )

        lc_messages = [SystemMessage(content=augmented_system)]
        for m in messages:
            if m["role"] == "user":
                lc_messages.append(HumanMessage(content=m["content"]))
            else:
                from langchain_core.messages import AIMessage
                lc_messages.append(AIMessage(content=m["content"]))

        response = json_model.invoke(lc_messages)
        self.tokens.record(response)
        raw = _strip_think(response.content)

        try:
            return _extract_json(raw)
        except (ValueError, json.JSONDecodeError):
            log.warning("LLM returned non-JSON, retrying without format constraint")

        # retry without format: json
        raw2 = self.chat(augmented_system, messages)
        try:
            return _extract_json(raw2)
        except (ValueError, json.JSONDecodeError):
            raise ValueError(f"Could not parse LLM output as JSON: {raw2[:200]}")
