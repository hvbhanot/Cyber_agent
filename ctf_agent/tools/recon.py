from __future__ import annotations
from ctf_agent.tools.base import BaseTool, ToolSpec


class NmapTool(BaseTool):
    spec = ToolSpec(
        name="nmap",
        description="Port scan and service detection",
        parameters={"target": "str", "flags": "str (optional)"},
        binary="nmap",
    )

    def build_command(self, target: str = "", flags: str = "-sV -sC", **kw) -> list[str]:
        return ["nmap"] + flags.split() + [target]


class GobusterTool(BaseTool):
    spec = ToolSpec(
        name="gobuster",
        description="Directory/file brute-force enumeration",
        parameters={"url": "str", "wordlist": "str", "flags": "str (optional)"},
        binary="gobuster",
    )

    def build_command(
        self, url: str = "", wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        flags: str = "", **kw,
    ) -> list[str]:
        cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-q"]
        if flags:
            cmd += flags.split()
        return cmd


class CurlTool(BaseTool):
    spec = ToolSpec(
        name="curl",
        description="HTTP requests for web recon",
        parameters={"url": "str", "flags": "str (optional)"},
        binary="curl",
    )

    def build_command(self, url: str = "", flags: str = "-s -i", **kw) -> list[str]:
        return ["curl"] + flags.split() + [url]


class WhatWebTool(BaseTool):
    spec = ToolSpec(
        name="whatweb",
        description="Web technology fingerprinting",
        parameters={"url": "str"},
        binary="whatweb",
    )

    def build_command(self, url: str = "", **kw) -> list[str]:
        return ["whatweb", "--color=never", url]


class DirbTool(BaseTool):
    spec = ToolSpec(
        name="dirb",
        description="Web content scanner",
        parameters={"url": "str", "wordlist": "str (optional)"},
        binary="dirb",
    )

    def build_command(
        self, url: str = "", wordlist: str = "/usr/share/wordlists/dirb/common.txt", **kw,
    ) -> list[str]:
        return ["dirb", url, wordlist, "-S"]


RECON_TOOLS = [NmapTool, GobusterTool, CurlTool, WhatWebTool, DirbTool]
