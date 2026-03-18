from __future__ import annotations
from ctf_agent.tools.base import BaseTool, ToolSpec


class ExiftoolTool(BaseTool):
    spec = ToolSpec(
        name="exiftool",
        description="Extract metadata from files (images, docs, etc.)",
        parameters={"filepath": "str"},
        binary="exiftool",
    )

    def build_command(self, filepath: str = "", **kw) -> list[str]:
        return ["exiftool", filepath]


class BinwalkTool(BaseTool):
    spec = ToolSpec(
        name="binwalk",
        description="Scan for embedded files and data in a binary",
        parameters={"filepath": "str", "extract": "bool (optional)"},
        binary="binwalk",
    )

    def build_command(self, filepath: str = "", extract: bool = False, **kw) -> list[str]:
        cmd = ["binwalk"]
        if extract:
            cmd.append("-e")
        cmd.append(filepath)
        return cmd


class SteghideTool(BaseTool):
    spec = ToolSpec(
        name="steghide",
        description="Extract hidden data from JPEG/BMP/WAV/AU files",
        parameters={"filepath": "str", "passphrase": "str (optional, default empty)"},
        binary="steghide",
    )

    def build_command(self, filepath: str = "", passphrase: str = "", **kw) -> list[str]:
        return [
            "steghide", "extract", "-sf", filepath,
            "-p", passphrase, "-f",
        ]


class ForemostTool(BaseTool):
    spec = ToolSpec(
        name="foremost",
        description="Carve files from binary data",
        parameters={"filepath": "str"},
        binary="foremost",
    )

    def build_command(self, filepath: str = "", **kw) -> list[str]:
        return ["foremost", "-i", filepath, "-o", f"{self.workspace}/foremost_out", "-T"]


class ZstegTool(BaseTool):
    spec = ToolSpec(
        name="zsteg",
        description="Detect steganography in PNG/BMP files",
        parameters={"filepath": "str"},
        binary="zsteg",
    )

    def build_command(self, filepath: str = "", **kw) -> list[str]:
        return ["zsteg", filepath]


FORENSICS_TOOLS = [ExiftoolTool, BinwalkTool, SteghideTool, ForemostTool, ZstegTool]
