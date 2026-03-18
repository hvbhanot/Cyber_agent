from __future__ import annotations
import subprocess
import shlex
import shutil
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional
from ctf_agent.memory.scratchpad import ToolResult

log = logging.getLogger(__name__)


@dataclass
class ToolSpec:
    name: str
    description: str
    parameters: dict
    binary: Optional[str] = None


class BaseTool(ABC):
    spec: ToolSpec

    def __init__(self, timeout: int = 30, workspace: str = "/tmp/ctf_workspace"):
        self.timeout = timeout
        self.workspace = workspace

    @abstractmethod
    def build_command(self, **kwargs) -> list[str]:
        ...

    def is_available(self) -> bool:
        if self.spec.binary is None:
            return True
        return shutil.which(self.spec.binary) is not None

    def execute(self, **kwargs) -> ToolResult:
        cmd = self.build_command(**kwargs)
        log.info(f"[{self.spec.name}] Running: {' '.join(cmd)}")
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=self.workspace,
            )
            return ToolResult(
                tool_name=self.spec.name,
                args=kwargs,
                stdout=proc.stdout[:5000],
                stderr=proc.stderr[:2000],
                exit_code=proc.returncode,
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool_name=self.spec.name,
                args=kwargs,
                stdout="",
                stderr=f"TIMEOUT after {self.timeout}s",
                exit_code=-1,
            )
        except FileNotFoundError:
            return ToolResult(
                tool_name=self.spec.name,
                args=kwargs,
                stdout="",
                stderr=f"Binary not found: {self.spec.binary}",
                exit_code=-1,
            )


class ShellTool(BaseTool):
    spec = ToolSpec(
        name="shell",
        description="Execute an arbitrary shell command in the workspace",
        parameters={"command": "str"},
    )

    def build_command(self, command: str = "", **kwargs) -> list[str]:
        return ["bash", "-c", command]


class PythonExecTool(BaseTool):
    spec = ToolSpec(
        name="python_exec",
        description="Execute a Python script/snippet",
        parameters={"code": "str"},
    )

    def build_command(self, code: str = "", **kwargs) -> list[str]:
        return ["python3", "-c", code]
