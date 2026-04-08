from __future__ import annotations
import inspect
import subprocess
import shlex
import shutil
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional
from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field, create_model
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

    def _build_args_schema(self) -> type[BaseModel]:
        """Build a Pydantic model from spec.parameters so the LLM knows what args to pass."""
        fields = {}
        sig = inspect.signature(self.build_command)
        for param_name, param_desc in self.spec.parameters.items():
            default = inspect.Parameter.empty
            if param_name in sig.parameters:
                p = sig.parameters[param_name]
                if p.default is not inspect.Parameter.empty:
                    default = p.default

            is_optional = "optional" in str(param_desc).lower()
            if default is not inspect.Parameter.empty:
                fields[param_name] = (str, Field(default=default, description=str(param_desc)))
            elif is_optional:
                fields[param_name] = (str, Field(default="", description=str(param_desc)))
            else:
                fields[param_name] = (str, Field(description=str(param_desc)))

        model_name = f"{self.spec.name}_args"
        return create_model(model_name, **fields)

    def as_langchain_tool(self) -> StructuredTool:
        """Convert this tool to a LangChain StructuredTool with typed parameter schema."""
        tool_instance = self

        def _run(**kwargs) -> str:
            result = tool_instance.execute(**kwargs)
            if result.exit_code == 0:
                return result.stdout[:3000] if result.stdout else "(no output)"
            return f"ERROR (exit {result.exit_code}): {result.stderr[:1000]}"

        return StructuredTool.from_function(
            func=_run,
            name=self.spec.name,
            description=self.spec.description,
            args_schema=self._build_args_schema(),
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
