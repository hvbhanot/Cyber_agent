from __future__ import annotations
import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Config:
    llm_model: str = ""
    ollama_base_url: str = "http://localhost:11434"
    temperature: float = 0.2
    max_react_steps: int = 15
    max_tool_calls_per_step: int = 3
    flag_format: str = r"(?:picoCTF|flag|ctf|CTF)\{[A-Za-z0-9_!'@#$%^&*()\-+=]+\}"
    workspace_dir: str = "/tmp/ctf_workspace"
    memory_persist_path: str = "/tmp/ctf_agent_memory.json"
    tool_timeout: int = 120
    verbose: bool = True
    challenge_categories: list[str] = field(
        default_factory=lambda: [
            "web", "crypto", "forensics", "reverse", "pwn", "misc"
        ]
    )

    def __post_init__(self):
        os.makedirs(self.workspace_dir, exist_ok=True)
