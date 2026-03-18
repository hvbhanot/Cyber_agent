from __future__ import annotations
import logging
import re
from pathlib import Path
from ctf_agent.agents.base import BaseAgent

# Map specialty → reference file (relative to project root, two levels up from this file)
_SKILL_REF_FILES: dict[str, str] = {
    "crypto":    "crypto.md",
    "forensics": "forensics.md",
    "reverse":   "reverse.md",
    "recon":     "web.md",
    "exploit":   "pwn_reference.md",
}

_PROJECT_ROOT = Path(__file__).parents[2]


def _load_skill_ref(specialty: str) -> str:
    filename = _SKILL_REF_FILES.get(specialty)
    if not filename:
        return ""
    path = _PROJECT_ROOT / "skills" / filename
    try:
        return path.read_text()
    except OSError:
        return ""

log = logging.getLogger(__name__)

SPECIALIST_PROMPTS = {
    "recon": """You are the Recon Specialist Agent. Your job is network and web reconnaissance.
Key techniques:
- Port scanning with nmap (service versions, scripts)
- Directory enumeration with gobuster/dirb
- HTTP header analysis with curl
- Technology fingerprinting with whatweb
- Always start broad, then narrow down on interesting findings.
- Report all open ports, services, hidden paths, interesting headers, and technologies found.""",

    "exploit": """You are the Exploit Specialist Agent. Your job is to exploit discovered vulnerabilities.
Key techniques:
- SQL injection detection and exploitation with sqlmap
- Crafted HTTP requests (parameter tampering, cookie manipulation, header injection)
- Binary exploitation with pwntools (buffer overflows, format strings, ROP chains)
- Command injection, SSRF, path traversal, LFI/RFI
- Always validate exploitation success before claiming a flag.""",

    "crypto": """You are the Crypto Specialist Agent.

The pre-analysis results above already show what each tool returned for the challenge ciphertext.
Your job is to:
1. Read the pre-analysis results carefully
2. Identify which result looks like a decoded flag or readable text
3. If a result contains picoCTF{{...}} or flag{{...}}, report it immediately with FINISH
4. If no clear flag was found, try ONE additional tool with the exact ciphertext from the challenge
5. Do NOT invent or modify the ciphertext — use it exactly as shown in the challenge description

Available tools: crypto_analysis (method=multi|caesar|vigenere|xor|freq), rot13, base64_decode, hex_decode, hash_identify
IMPORTANT: When you find the answer, set action=FINISH and put the answer in the answer field.""",

    "reverse": """You are the Reverse Engineering Specialist Agent. Your job is to analyze binaries.
Key techniques:
- file command to identify binary type
- strings extraction for embedded data, passwords, flags
- readelf for ELF headers, sections, symbols
- objdump for disassembly (focus on main, check_password, flag functions)
- Look for: strcmp comparisons, XOR loops, hardcoded values, obfuscation patterns
- For scripts: deobfuscation, eval unpacking, bytecode disassembly""",

    "forensics": """You are the Forensics Specialist Agent. Your job is to extract hidden data.
Key techniques:
- exiftool for metadata (GPS, comments, author fields often hide flags)
- binwalk for embedded files and firmware extraction
- steghide for JPEG/BMP/WAV steganography (try empty passphrase first)
- zsteg for PNG/BMP LSB steganography
- foremost for file carving from raw data
- Check file headers (magic bytes), look for appended data after EOF
- Strings with grep for flag format""",
}

# Patterns to extract candidate ciphertexts from a challenge description
_CANDIDATE_PATTERNS = [
    re.compile(r"[A-Za-z0-9+/]{20,}={0,2}"),   # base64-like
    re.compile(r"[0-9a-fA-F]{16,}"),             # hex-like
    re.compile(r"\S+\{[^}]{4,}\}"),              # flag-shaped (encoded prefix + braces)
]


def _extract_candidates(description: str) -> list[str]:
    """Pull out strings that are likely the encoded/ciphered payload."""
    seen = set()
    results = []
    for pat in _CANDIDATE_PATTERNS:
        for m in pat.finditer(description):
            s = m.group(0)
            if s not in seen and len(s) >= 8:
                seen.add(s)
                results.append(s)
    # also try the whole description stripped of the human-readable prefix
    # (e.g. "Decode this: <ciphertext>" → take everything after the colon)
    colon_split = re.split(r"[:\?]\s+", description)
    if len(colon_split) > 1:
        tail = colon_split[-1].strip()
        if tail and tail not in seen:
            results.append(tail)
    return results


class SpecialistAgent(BaseAgent):
    role = "specialist"

    def __init__(self, *args, specialty: str = "recon", **kwargs):
        super().__init__(*args, **kwargs)
        self.specialty = specialty

    def system_prompt(self) -> str:
        base = SPECIALIST_PROMPTS.get(self.specialty, SPECIALIST_PROMPTS["recon"])
        category_tools = self.tools.get_tools_for_category(self.specialty)
        tool_desc = self.tools.get_tool_descriptions(category_tools)
        ref = _load_skill_ref(self.specialty)
        ref_section = f"\n\n## Reference Playbook\n{ref}" if ref else ""
        return (
            f"{base}\n\n"
            f"Available Tools:\n{tool_desc}\n\n"
            "You also have access to 'shell' and 'python_exec' for arbitrary commands.\n"
            "If you find a flag candidate, report it immediately with FINISH.\n"
            f"Flag format regex: {self.cfg.flag_format}"
            f"{ref_section}"
        )

    def _auto_crypto(self) -> str | None:
        """
        For crypto challenges: extract candidate strings from the description,
        run crypto_analysis multi on each, scan for flags.
        Returns the flag/answer if found, else None.
        """
        if not self.pad.challenge:
            return None

        desc = self.pad.challenge.description
        candidates = _extract_candidates(desc)
        if not candidates:
            candidates = [desc]

        tool = self.tools.get("crypto_analysis")
        rot_tool = self.tools.get("rot13")
        if not tool:
            return None

        pre_results = []
        for candidate in candidates:
            result = tool.execute(ciphertext=candidate, method="multi")
            output = result.stdout.strip()
            pre_results.append(f"Input: {candidate[:80]}\nResult:\n{output}")

            # scan for flag patterns
            import re as _re
            flags = _re.findall(self.cfg.flag_format, output)
            for f in flags:
                self.pad.add_flag_candidate(f)
                log.info(f"[auto_crypto] Flag found: {f}")
                return f

            # also try explicit rot13
            if rot_tool:
                rot_result = rot_tool.execute(data=candidate)
                rot_out = rot_result.stdout.strip()
                rot_flags = _re.findall(self.cfg.flag_format, rot_out)
                for f in rot_flags:
                    self.pad.add_flag_candidate(f)
                    log.info(f"[auto_crypto] ROT13 flag found: {f}")
                    return f
                pre_results.append(f"ROT13({candidate[:40]}): {rot_out[:100]}")

        # store pre-analysis in findings so the LLM can see it
        self.pad.add_finding("pre_analysis", "\n\n".join(pre_results)[:2000])
        return None

    def execute_subtask(self, subtask: str) -> str:
        log.info(f"[Specialist:{self.specialty}] Executing: {subtask}")

        # for crypto: run tools directly first before involving the LLM
        if self.specialty == "crypto":
            found = self._auto_crypto()
            if found:
                self.pad.set_answer(found)
                return f"FLAG/ANSWER: {found}"

        # build task prompt with full challenge context
        task = subtask
        if self.pad.challenge:
            ch = self.pad.challenge
            task = (
                f"## Challenge: {ch.name} ({ch.category})\n"
                f"Description: {ch.description}\n"
            )
            if ch.files:
                task += f"Files: {', '.join(ch.files)}\n"
            if ch.url:
                task += f"URL: {ch.url}\n"

            if self.specialty == "crypto" and self.pad.findings.get("pre_analysis"):
                task += f"\n## Pre-analysis Results\n{self.pad.findings['pre_analysis']}\n"

            task += f"\n## Your subtask\n{subtask}"

        return self.run_react_loop(task, max_steps=self.cfg.max_react_steps)
