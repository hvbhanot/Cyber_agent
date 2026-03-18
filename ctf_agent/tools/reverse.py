from __future__ import annotations
from ctf_agent.tools.base import BaseTool, ToolSpec


class StringsTool(BaseTool):
    spec = ToolSpec(
        name="strings",
        description="Extract printable strings from a binary",
        parameters={"filepath": "str", "min_len": "int (optional, default 4)"},
        binary="strings",
    )

    def build_command(self, filepath: str = "", min_len: int = 4, **kw) -> list[str]:
        return ["strings", f"-n{min_len}", filepath]


class FileTool(BaseTool):
    spec = ToolSpec(
        name="file",
        description="Identify file type",
        parameters={"filepath": "str"},
        binary="file",
    )

    def build_command(self, filepath: str = "", **kw) -> list[str]:
        return ["file", filepath]


class ObjdumpTool(BaseTool):
    spec = ToolSpec(
        name="objdump",
        description="Disassemble binary sections",
        parameters={"filepath": "str", "flags": "str (optional)"},
        binary="objdump",
    )

    def build_command(self, filepath: str = "", flags: str = "-d -M intel", **kw) -> list[str]:
        return ["objdump"] + flags.split() + [filepath]


class ReadelfTool(BaseTool):
    spec = ToolSpec(
        name="readelf",
        description="Display ELF file headers and sections",
        parameters={"filepath": "str", "flags": "str (optional)"},
        binary="readelf",
    )

    def build_command(self, filepath: str = "", flags: str = "-a", **kw) -> list[str]:
        return ["readelf"] + flags.split() + [filepath]


class HexdumpTool(BaseTool):
    spec = ToolSpec(
        name="hexdump",
        description="Hex dump of a file",
        parameters={"filepath": "str", "length": "int (optional)"},
        binary="xxd",
    )

    def build_command(self, filepath: str = "", length: int = 256, **kw) -> list[str]:
        return ["xxd", "-l", str(length), filepath]


REVERSE_TOOLS = [StringsTool, FileTool, ObjdumpTool, ReadelfTool, HexdumpTool]
