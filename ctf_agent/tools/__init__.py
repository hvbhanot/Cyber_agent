from __future__ import annotations
import logging
from typing import Optional
from ctf_agent.tools.base import BaseTool, ShellTool, PythonExecTool
from ctf_agent.tools.recon import RECON_TOOLS
from ctf_agent.tools.exploit import EXPLOIT_TOOLS
from ctf_agent.tools.crypto import CRYPTO_TOOLS
from ctf_agent.tools.reverse import REVERSE_TOOLS
from ctf_agent.tools.forensics import FORENSICS_TOOLS

log = logging.getLogger(__name__)

CATEGORY_MAP = {
    "recon": RECON_TOOLS,
    "exploit": EXPLOIT_TOOLS,
    "crypto": CRYPTO_TOOLS,
    "reverse": REVERSE_TOOLS,
    "forensics": FORENSICS_TOOLS,
}


class ToolRegistry:
    def __init__(self, timeout: int = 30, workspace: str = "/tmp/ctf_workspace"):
        self._tools: dict[str, BaseTool] = {}
        self.timeout = timeout
        self.workspace = workspace
        self._register_defaults()

    def _register_defaults(self):
        self.register(ShellTool(self.timeout, self.workspace))
        self.register(PythonExecTool(self.timeout, self.workspace))
        for category_tools in CATEGORY_MAP.values():
            for tool_cls in category_tools:
                self.register(tool_cls(self.timeout, self.workspace))

    def register(self, tool: BaseTool):
        self._tools[tool.spec.name] = tool

    def get(self, name: str) -> Optional[BaseTool]:
        return self._tools.get(name)

    def list_tools(self) -> list[dict]:
        return [
            {
                "name": t.spec.name,
                "description": t.spec.description,
                "parameters": t.spec.parameters,
                "available": t.is_available(),
            }
            for t in self._tools.values()
        ]

    def list_available(self) -> list[dict]:
        return [t for t in self.list_tools() if t["available"]]

    def get_tools_for_category(self, category: str) -> list[str]:
        mapping = {
            "web": ["nmap", "gobuster", "curl", "whatweb", "dirb", "sqlmap", "curl_exploit"],
            "crypto": ["base64_decode", "hex_decode", "crypto_analysis", "hash_identify"],
            "forensics": ["exiftool", "binwalk", "steghide", "foremost", "zsteg", "strings", "file", "hexdump"],
            "reverse": ["strings", "file", "objdump", "readelf", "hexdump"],
            "pwn": ["pwntools_exec", "netcat", "strings", "objdump", "readelf"],
            "misc": ["shell", "python_exec", "file", "strings", "base64_decode"],
        }
        tool_names = mapping.get(category, ["shell", "python_exec"])
        return [n for n in tool_names if n in self._tools]

    def get_tool_descriptions(self, names: Optional[list[str]] = None) -> str:
        tools = self._tools.values() if names is None else [
            self._tools[n] for n in names if n in self._tools
        ]
        lines = []
        for t in tools:
            avail = "YES" if t.is_available() else "NO (not installed)"
            lines.append(
                f"- {t.spec.name}: {t.spec.description}\n"
                f"  Parameters: {t.spec.parameters}\n"
                f"  Available: {avail}"
            )
        return "\n".join(lines)
