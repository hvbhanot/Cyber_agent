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


class PdfToTextTool(BaseTool):
    spec = ToolSpec(
        name="pdftotext",
        description="Extract text from PDF files — reveals hidden text, embedded strings",
        parameters={"filepath": "str", "flags": "str (optional)"},
        binary="pdftotext",
    )

    def build_command(self, filepath: str = "", flags: str = "-layout", **kw) -> list[str]:
        return ["pdftotext"] + flags.split() + [filepath, "-"]


class TesseractTool(BaseTool):
    spec = ToolSpec(
        name="tesseract",
        description="OCR — extract text from images (PNG, JPEG, TIFF)",
        parameters={"filepath": "str"},
        binary="tesseract",
    )

    def build_command(self, filepath: str = "", **kw) -> list[str]:
        return ["tesseract", filepath, "stdout"]


class VolatilityTool(BaseTool):
    spec = ToolSpec(
        name="volatility",
        description="Memory forensics — analyze RAM dumps for processes, network, registry, etc.",
        parameters={"filepath": "str", "plugin": "str — e.g. pslist, netscan, filescan, dumpfiles, hashdump"},
        binary="volatility",
    )

    def build_command(self, filepath: str = "", plugin: str = "imageinfo", **kw) -> list[str]:
        return ["volatility", "-f", filepath, plugin]


class DdTool(BaseTool):
    spec = ToolSpec(
        name="dd_extract",
        description="Extract bytes from a file at a specific offset — useful for carving embedded data",
        parameters={"filepath": "str", "skip": "str — byte offset to start", "count": "str — bytes to extract"},
        binary="dd",
    )

    def build_command(self, filepath: str = "", skip: str = "0", count: str = "512", **kw) -> list[str]:
        return ["dd", f"if={filepath}", "bs=1", f"skip={skip}", f"count={count}", "status=none"]


FORENSICS_TOOLS = [ExiftoolTool, BinwalkTool, SteghideTool, ForemostTool, ZstegTool,
                   PdfToTextTool, TesseractTool, VolatilityTool, DdTool]
