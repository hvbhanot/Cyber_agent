from __future__ import annotations
import json
import logging
import re
from typing import Optional
import httpx
from ctf_agent.config import Config

log = logging.getLogger(__name__)

_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)


def _strip_think(text: str) -> str:
    return _THINK_RE.sub("", text).strip()


def _extract_json(text: str) -> dict:
    # try direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # strip markdown fences
    cleaned = text
    if "```" in cleaned:
        cleaned = re.sub(r"```(?:json)?", "", cleaned).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    # extract first {...} block
    start = cleaned.find("{")
    end = cleaned.rfind("}") + 1
    if start != -1 and end > start:
        return json.loads(cleaned[start:end])
    raise ValueError(f"Could not parse LLM output as JSON: {text[:300]}")


class LLMClient:
    def __init__(self, config: Config):
        self.cfg = config
        self._client = httpx.Client(base_url=self.cfg.ollama_base_url, timeout=180)

    def chat(
        self,
        system: str,
        messages: list[dict],
        temperature: Optional[float] = None,
        max_tokens: int = 4096,
    ) -> str:
        temp = temperature if temperature is not None else self.cfg.temperature
        payload = {
            "model": self.cfg.llm_model,
            "messages": [{"role": "system", "content": system}] + messages,
            "stream": False,
            "options": {"temperature": temp, "num_predict": max_tokens},
        }
        resp = self._client.post("/api/chat", json=payload)
        resp.raise_for_status()
        return resp.json()["message"]["content"]

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

        # first attempt — with json format enforced
        payload = {
            "model": self.cfg.llm_model,
            "messages": [{"role": "system", "content": augmented_system}] + messages,
            "stream": False,
            "format": "json",
            "options": {"temperature": self.cfg.temperature, "num_predict": 4096},
        }
        resp = self._client.post("/api/chat", json=payload)
        resp.raise_for_status()
        raw = _strip_think(resp.json()["message"]["content"])

        try:
            return _extract_json(raw)
        except (ValueError, json.JSONDecodeError):
            log.warning("LLM returned non-JSON, retrying without format constraint")

        # retry without format: json (some models ignore it)
        raw2 = _strip_think(self.chat(augmented_system, messages))
        try:
            return _extract_json(raw2)
        except (ValueError, json.JSONDecodeError):
            raise ValueError(f"Could not parse LLM output as JSON: {raw2[:200]}")
