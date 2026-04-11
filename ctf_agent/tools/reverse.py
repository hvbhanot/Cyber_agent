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


class LtraceTool(BaseTool):
    spec = ToolSpec(
        name="ltrace",
        description="Trace library calls — shows strcmp, printf, malloc args (reveals passwords, keys)",
        parameters={"filepath": "str", "args": "str (optional — arguments to pass to the binary)"},
        binary="ltrace",
    )

    def build_command(self, filepath: str = "", args: str = "", **kw) -> list[str]:
        cmd = ["ltrace", "-s", "200", filepath]
        if args:
            cmd += args.split()
        return cmd


class StraceTool(BaseTool):
    spec = ToolSpec(
        name="strace",
        description="Trace system calls — shows file access, network, reads/writes",
        parameters={"filepath": "str", "args": "str (optional — arguments to pass to the binary)"},
        binary="strace",
    )

    def build_command(self, filepath: str = "", args: str = "", **kw) -> list[str]:
        cmd = ["strace", "-f", "-s", "200", filepath]
        if args:
            cmd += args.split()
        return cmd


class Radare2Tool(BaseTool):
    spec = ToolSpec(
        name="radare2",
        description="Reverse engineering framework — disassemble, analyze control flow, find functions",
        parameters={"filepath": "str", "commands": "str — r2 commands separated by ;"},
        binary="r2",
    )

    def build_command(self, filepath: str = "", commands: str = "aaa;afl;pdf @main", **kw) -> list[str]:
        return ["r2", "-q", "-c", commands, filepath]


class UncompyleTool(BaseTool):
    spec = ToolSpec(
        name="uncompyle6",
        description="Decompile Python .pyc bytecode back to source code",
        parameters={"filepath": "str"},
        binary="uncompyle6",
    )

    def build_command(self, filepath: str = "", **kw) -> list[str]:
        return ["uncompyle6", filepath]


REVERSE_TOOLS = [StringsTool, FileTool, ObjdumpTool, ReadelfTool, HexdumpTool,
                 LtraceTool, StraceTool, Radare2Tool, UncompyleTool]
