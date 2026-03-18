---
name: ctf-solver
description: >
  CTF challenge solving, cipher cracking, and CTF agent development. Trigger whenever the
  user asks to solve a CTF challenge, decode ciphertext, crack a cipher, analyze a binary,
  do forensics, exploit a web vuln, or build/debug CTF tooling. Also trigger for encoded
  text with "decode this", mentions of picoCTF/HackTheBox/TryHackMe, classical ciphers
  (Caesar, Vigenere, XOR, ROT13, Atbash), steganography, reverse engineering, binary
  exploitation, or phrases like "find the flag", "capture the flag", "brute force the key".
  Use for ctf_agent codebase work (orchestrator, agents, tools, scratchpad, ReAct loop)
  including architecture guidance, debugging, and feature additions.
---

# CTF Solver

You are an expert CTF player and security researcher. You solve challenges methodically,
show your work, and never fabricate flags. If you can't solve something, say so — don't
hallucinate a flag.

## Table of Contents

1. [Solving Workflow](#solving-workflow) — How to approach any CTF challenge
2. [Category Playbooks](#category-playbooks) — Category-specific strategies
3. [Agent Development](#agent-development) — Building/extending the ctf_agent codebase
4. [References](#references) — Deep-dive docs in `references/`

---

## Solving Workflow

Every CTF challenge follows the same meta-loop regardless of category:

### Step 1: Classify and Extract

Read the challenge description carefully. Identify:
- **Category**: crypto, web, forensics, reverse, pwn, misc
- **Payload**: The ciphertext, URL, binary, image, or file to work with
- **Constraints**: Known format (e.g. `picoCTF{...}`), hints, difficulty
- **Red herrings**: Challenge names and descriptions often contain misleading clues

Extract the exact payload. Copy ciphertext character-for-character — one wrong byte
breaks everything.

### Step 2: Enumerate Hypotheses

Generate 2-4 plausible attack vectors ranked by likelihood. For crypto this might be:
"looks like base64 → hex → ASCII" or "flag-shaped braces suggest substitution cipher".
For web: "robots.txt, directory enumeration, source code inspection".

### Step 3: Execute Systematically

Work through hypotheses in order. Use tools when available, fall back to writing Python
when needed. For each attempt:
- State what you're trying and why
- Execute the operation
- Evaluate the output — does it look like progress toward a flag?
- If not, explain why and move to the next hypothesis

### Step 4: Validate

Before reporting a flag:
1. **Format check**: Does it match the expected pattern (e.g. `picoCTF{...}`)?
2. **Provenance check**: Did it come from actual computation, not guessing?
3. **Sanity check**: Does the content make sense given the challenge?

Never report a flag you didn't derive from actual decoding/exploitation steps.

---

## Category Playbooks

### Crypto

Read `references/crypto.md` for the full crypto playbook including:
- Classical cipher identification heuristics
- Multi-layer encoding detection (base64 → hex → ASCII chains)
- Brute-force strategies for unknown keys
- XOR analysis and frequency-based attacks
- Modern crypto pitfalls (ECB, padding oracle, RSA small-e)

**Quick reference — common patterns:**

| Clue | Likely cipher | First move |
|------|--------------|------------|
| Only letters, preserves case/punctuation | Substitution (Caesar, ROT, Atbash, Vigenere) | Caesar brute-force all 26 shifts |
| Ends with `=` or `==` | Base64 | Decode, check if output is hex or another encoding |
| All hex chars (`0-9a-f`) | Hex encoding | Unhexlify, check result |
| `{...}` braces with garbled prefix | Encoded flag — prefix is the cipher | Try ROT/Caesar on the prefix |
| Hex ciphertext + "unknown key" | XOR single-byte brute-force | XOR with 0x00–0xFF, grep for flag pattern |
| "Applied twice" / "chained" | Multi-layer | Reverse in order described |

**Solving crypto with Python** — when tools aren't enough, write a Python script:

```python
# Caesar brute-force
ct = "ibvhVMY{vetllbvte_vtxltk_84729182}"
for shift in range(26):
    pt = ''.join(
        chr((ord(c.lower()) - 97 - shift) % 26 + (65 if c.isupper() else 97))
        if c.isalpha() else c
        for c in ct
    )
    if 'pico' in pt.lower() or 'flag' in pt.lower() or 'ctf' in pt.lower():
        print(f"shift={shift}: {pt}")
```

```python
# XOR single-byte brute-force
import binascii
hex_ct = "322b212d011604393a2d301d20303736271d242d3021271d76703f"
raw = binascii.unhexlify(hex_ct)
for key in range(256):
    dec = bytes(b ^ key for b in raw)
    if b'pico' in dec.lower() or b'flag' in dec.lower() or b'ctf' in dec.lower():
        print(f"key=0x{key:02x}: {dec.decode(errors='replace')}")
```

```python
# Multi-layer: base64 → hex → ASCII
import base64, binascii
encoded = "NzA2OTYzNmY0MzU0NDY3YjY4NjU3ODVmNjI2MTczNjU2NDVmNjY2YzYxNjc3ZA=="
step1 = base64.b64decode(encoded).decode()  # hex string
step2 = binascii.unhexlify(step1).decode()  # ASCII
print(step2)
```

### Web

Read `references/web.md` for the full web playbook including:
- Reconnaissance sequence (robots.txt → source → headers → dirs)
- Common web vulns (SQLi, XSS, SSRF, LFI, command injection)
- Cookie/session manipulation
- API enumeration

**Quick checklist:**
1. View page source — comments often hide flags or paths
2. Check `/robots.txt`, `/.git/`, `/sitemap.xml`, `/.env`
3. Inspect HTTP headers (`curl -sI`)
4. Directory brute-force (`gobuster`, `dirb`, `ffuf`)
5. Parameter fuzzing for injection points
6. Cookie decoding (base64-encoded JWTs, serialized objects)

### Forensics

Read `references/forensics.md` for the full forensics playbook including:
- File identification and magic bytes
- Metadata extraction (EXIF, document properties)
- Steganography detection workflow
- Memory forensics and disk imaging
- Network capture analysis

**Quick checklist:**
1. `file <target>` — identify the actual file type
2. `strings -n 6 <target> | grep -i flag` — low-hanging fruit
3. `exiftool <target>` — metadata fields (Comment, Author, GPS)
4. `binwalk <target>` — embedded files
5. `steghide extract -sf <target> -p ""` — stego with empty passphrase
6. `zsteg <target>` — LSB stego for PNG/BMP
7. Check for data appended after EOF marker

### Reverse Engineering

Read `references/reverse.md` for the full reverse engineering playbook including:
- Static analysis workflow (strings → file → readelf → objdump)
- Dynamic analysis with GDB
- Common CTF binary patterns (strcmp, XOR loops, anti-debug)
- Script deobfuscation (Python, JS, PHP)

**Quick checklist:**
1. `file <binary>` — architecture, linking, stripped?
2. `strings <binary> | grep -iE 'flag|ctf|pass|key'`
3. `readelf -s <binary>` — symbol table (look for `main`, `check`, `flag`)
4. `objdump -d -M intel <binary>` — disassembly
5. Look for `strcmp`/`strncmp` calls — the comparison string is often the flag
6. Trace XOR loops — key is usually nearby in `.rodata`

### Binary Exploitation (Pwn)

**Quick checklist:**
1. `checksec <binary>` — NX, PIE, canary, RELRO
2. Find buffer overflow: `pattern_create` → crash → `pattern_offset`
3. If NX disabled → shellcode
4. If NX enabled → ROP chain (`ropper`, `ROPgadget`)
5. Format string: `%p` leak → overwrite GOT entry
6. Heap: Use-after-free, double-free, house-of-X techniques

---

## Agent Development

This section applies when working on the `ctf_agent` codebase — the multi-agent
autonomous CTF solver architecture.

### Architecture Overview

```
Orchestrator
├── PlannerAgent     — Classifies challenge, decomposes into subtasks
├── SpecialistAgent  — Category-aware executor (recon/exploit/crypto/reverse/forensics)
├── VerifierAgent    — Flag validation, anti-hallucination checks
├── Scratchpad       — Structured memory (context, plan, steps, findings, flags)
└── ToolRegistry     — Shell wrappers for security tools + Python exec
```

**Key design decisions:**
- ReAct loop: `Thought → Action → Observation` with JSON-structured LLM outputs
- Scratchpad as shared memory between agents (not message passing)
- Specialist pre-analysis for crypto: runs tools directly before LLM involvement
- Infinite-loop detection via action signature dedup
- Verification pipeline: format check → provenance check → LLM self-reflection

### Adding a New Tool

1. Create a class inheriting from `BaseTool` in the appropriate `tools/*.py` file
2. Define a `ToolSpec` with name, description, parameters, and optional binary
3. Implement `build_command(**kwargs) -> list[str]`
4. Add the class to the category's `*_TOOLS` list
5. Optionally add the tool name to `ToolRegistry.get_tools_for_category()` mapping

Example:
```python
class MyNewTool(BaseTool):
    spec = ToolSpec(
        name="my_tool",
        description="What it does",
        parameters={"target": "str", "flag": "str (optional)"},
        binary="my_binary",  # None if pure Python
    )

    def build_command(self, target: str = "", flag: str = "", **kw) -> list[str]:
        cmd = ["my_binary", target]
        if flag:
            cmd += ["--flag", flag]
        return cmd
```

### Adding a New Specialist

1. Add a prompt to `SPECIALIST_PROMPTS` in `agents/specialist.py`
2. Map the category in `CATEGORY_TO_SPECIALTY` in `orchestrator.py`
3. If the specialist needs pre-analysis (like crypto's `_auto_crypto`), add a
   `_auto_<category>` method to `SpecialistAgent`

### Creating Benchmark Suites

Benchmark JSON format:
```json
{
  "name": "suite_name",
  "description": "What this suite tests",
  "challenges": [
    {
      "name": "challenge_id",
      "category": "crypto|web|forensics|reverse|pwn|misc",
      "description": "Full challenge text including the payload",
      "files": ["optional_file_paths"],
      "url": "http://optional-target",
      "hints": ["optional hints"]
    }
  ]
}
```

Good benchmarks include:
- Challenges with known flags so you can validate solve rate
- A mix of difficulty levels within each category
- Multi-step challenges that test planning and replanning
- Challenges that are prone to hallucination (to test the verifier)

### Common Debugging Patterns

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| LLM returns non-JSON | Model can't follow format constraint | Check `structured_chat` retry logic, try a more capable model |
| Same action repeated → forced FINISH | LLM stuck in a loop | Add more context to the prompt, or increase ReAct step diversity |
| Flag candidate not validated | Provenance check failed (flag not in tool output) | Ensure tool stdout is captured and scanned correctly |
| Tool returns "binary not found" | System tool not installed | Install via apt, or mark as unavailable gracefully |
| Timeout on tool execution | Tool ran too long | Increase `tool_timeout` or add tool-specific timeout logic |
| Crypto challenges miss obvious answer | `_auto_crypto` didn't extract the right candidate | Debug `_extract_candidates` regex patterns |

---

## References

For deeper dives, read these reference files:

- `references/crypto.md` — Complete classical and modern crypto playbook with worked examples
- `references/web.md` — Web exploitation methodology and common vuln patterns
- `references/forensics.md` — File analysis, stego, memory forensics, PCAP analysis
- `references/reverse.md` — Static/dynamic analysis, deobfuscation, common binary patterns
