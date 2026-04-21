# CTF Agent — Agentic LLM for Autonomous CTF Solving

Multi-agent architecture for autonomously solving beginner-to-intermediate Capture-the-Flag challenges using structured ReAct reasoning, tool integration, persistent scratchpad memory, and verification loops. Runs fully locally via [Ollama](https://ollama.com).

**COSC 6338 Project — Texas A&M University-Corpus Christi**

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Orchestrator                        │
│  ┌────────────┐   ┌──────────────┐   ┌──────────────┐  │
│  │  Planner   │ → │  Specialist  │ → │   Verifier   │  │
│  │  Agent     │   │  Agent(s)    │   │   Agent      │  │
│  └────────────┘   └──────────────┘   └──────────────┘  │
│        ↕                ↕                  ↕            │
│  ┌────────────────────────────────────────────────────┐ │
│  │              Scratchpad Memory                     │ │
│  │   challenge ctx · plan · steps · findings · flags  │ │
│  └────────────────────────────────────────────────────┘ │
│        ↕                ↕                               │
│  ┌────────────────────────────────────────────────────┐ │
│  │        Tool Registry (44 tools)                    │ │
│  │   nmap · gobuster · ffuf · nikto · sqlmap · hydra  │ │
│  │   pwntools · gdb · checksec · ropper · radare2     │ │
│  │   binwalk · steghide · exiftool · volatility       │ │
│  │   openssl · hashcat · john · tesseract · ...       │ │
│  └────────────────────────────────────────────────────┘ │
│        ↕                                                │
│  ┌────────────────────────────────────────────────────┐ │
│  │   Live Progress UI (Rich) + Token Counter          │ │
│  └────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

### Agents

| Agent | Role |
|-------|------|
| **Planner** | Classifies challenge, decomposes into subtasks, assigns tools, replans on failure |
| **Specialist** | Category-aware executor (recon, exploit, crypto, reverse, forensics) with domain-specific prompts and reference playbooks |
| **Verifier** | Validates flag candidates via format check, provenance check (was it in tool output?), and self-reflection to catch hallucinations |

### ReAct Loop

Each agent runs a **Thought -> Action -> Observation** loop:
1. LLM produces structured JSON: `{thought, action, action_input}`
2. Tool is executed via subprocess with timeout
3. Output is recorded in scratchpad and scanned for flag patterns
4. Context window is updated for the next step

### Memory

The **Scratchpad** maintains:
- Challenge context (name, category, files, URLs)
- Ordered plan of subtasks
- Full reasoning trace (thoughts, actions, observations)
- Extracted findings (ports, paths, keys, decoded data)
- Flag candidates and validated flag
- Error log and runtime hints

Persisted to JSON between runs for post-mortem analysis.

## Quick Start

```bash
git clone https://github.com/hvbhanot/CTF-Agent.git
cd Cyber_agent
chmod +x setup.sh
./setup.sh
```

The setup script will:
- Check Python 3.10+ and Ollama
- Create a virtual environment and install all dependencies
- Check which CTF tools are installed on your system
- Suggest Ollama models by RAM tier

### Manual Installation

**1. Install Ollama**

Download from [ollama.com](https://ollama.com) and pull a model:
```bash
ollama pull qwen2.5:7b
ollama list
```

**2. Install ctf-agent**

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

**3. Install system tools** (optional but recommended)

Ubuntu / Kali:
```bash
apt install nmap gobuster dirb whatweb nikto ffuf sqlmap hydra \
  binwalk foremost steghide exiftool zsteg \
  gdb ltrace strace radare2 \
  hashcat john pdftotext tesseract-ocr
```

macOS (Homebrew):
```bash
brew install nmap nikto ffuf sqlmap hydra \
  binwalk exiftool \
  radare2 hashcat john \
  poppler tesseract
```

## Usage

### Global Flags

These flags go **before** the subcommand (`solve`, `benchmark`, `tools`):

| Flag | Required | Description |
|------|----------|-------------|
| `--model MODEL` | **Yes** | Ollama model name (e.g. `qwen2.5:7b`, `llama3.1:8b`) |
| `--ollama-url URL` | No | Ollama API base URL (default: `http://localhost:11434`) |
| `--verbose` / `-v` | No | Print debug logs to stderr (logs always go to `ctf_agent.log`) |

### `solve` — Solve a Single Challenge

```bash
python -m ctf_agent --model qwen2.5:7b solve \
  --name "robots" \
  --category web \
  --desc "Find the hidden admin panel and retrieve the flag." \
  --url "http://target.ctf:8080" \
  --port 8080 \
  --files challenge.zip hint.txt \
  --hints "Check the robots.txt file" "Try directory brute-forcing" \
  --output results.json \
  -v
```

| Flag | Required | Description |
|------|----------|-------------|
| `--name NAME` | **Yes** | Challenge name |
| `--category CAT` | **Yes** | One of: `web`, `crypto`, `forensics`, `reverse`, `pwn`, `misc` |
| `--desc DESC` | **Yes** | Challenge description / prompt |
| `--url URL` | No | Target URL for web challenges |
| `--port PORT` | No | Target port number |
| `--files FILE [FILE ...]` | No | Challenge files (local paths or URLs — auto-downloaded) |
| `--hints HINT [HINT ...]` | No | Initial hints to seed the scratchpad |
| `--output` / `-o FILE` | No | Save results to a JSON file |

### `benchmark` — Run a Benchmark Suite

```bash
python -m ctf_agent --model qwen2.5:7b benchmark \
  --suite benchmarks/picoctf_easy.json \
  --output results.json \
  -v
```

| Flag | Required | Description |
|------|----------|-------------|
| `--suite FILE` | **Yes** | Path to benchmark JSON file |
| `--output` / `-o FILE` | No | Save full results (default: `benchmark_results.json`) |

### `tools` — List Available Tools

```bash
python -m ctf_agent --model qwen2.5:7b tools
```

No additional flags. Shows all 44 tools and whether each is installed on your system.

### Full Examples

**Web challenge with target URL:**
```bash
python -m ctf_agent --model qwen2.5:7b solve \
  --name "SQL Login" \
  --category web \
  --desc "Bypass the login page and find the flag" \
  --url "http://challenges.ctf.com:5000"
```

**Crypto challenge (no files, just a description):**
```bash
python -m ctf_agent --model qwen2.5:7b solve \
  --name "caesar_cipher" \
  --category crypto \
  --desc "Decrypt this: cvpbPGS{abg_gbb_onq_bs_n_ceboyrz}"
```

**Forensics challenge with a file to analyze:**
```bash
python -m ctf_agent --model qwen2.5:7b solve \
  --name "hidden_data" \
  --category forensics \
  --desc "There is something hidden in this image. Find the flag." \
  --files /path/to/suspicious_image.png
```

**Reverse engineering with remote file download:**
```bash
python -m ctf_agent --model qwen2.5:7b solve \
  --name "crackme" \
  --category reverse \
  --desc "Find the password that makes this binary print the flag" \
  --files https://challenges.ctf.com/files/crackme
```

**Pwn challenge with host and port:**
```bash
python -m ctf_agent --model qwen2.5:7b solve \
  --name "buffer_overflow" \
  --category pwn \
  --desc "Exploit the buffer overflow to get a shell and read flag.txt" \
  --url "challenges.ctf.com" \
  --port 9001 \
  --files https://challenges.ctf.com/files/vuln
```

**Using a different Ollama server:**
```bash
python -m ctf_agent --model llama3.3:70b \
  --ollama-url http://192.168.1.100:11434 \
  solve --name "test" --category misc --desc "Find the flag"
```

### Provide Hints at Runtime

While the agent is solving, type a hint and press Enter. The hint is injected into the scratchpad and picked up on the next reasoning step.

### Python API

```python
from ctf_agent import Orchestrator, Config
from ctf_agent.memory.scratchpad import ChallengeContext

orch = Orchestrator(Config(llm_model="qwen2.5:7b"))
metrics = orch.solve(ChallengeContext(
    name="base64_flag",
    category="crypto",
    description="Decode this: cGljb0NURntCQVNFNjRfMVNfRUFTWX0=",
))
print(metrics.flag)
print(f"Tokens used: {metrics.total_tokens:,}")
```

## Tools (44)

### Recon & Web
| Tool | Description |
|------|-------------|
| `nmap` | Port scanning and service detection |
| `gobuster` | Directory / file brute-force |
| `dirb` | Web content scanner |
| `whatweb` | Web technology fingerprinting |
| `curl` | HTTP requests |
| `nikto` | Web vulnerability scanner |
| `ffuf` | Fast web fuzzer |
| `sslscan` | SSL/TLS configuration scanner |

### Exploit & Pwn
| Tool | Description |
|------|-------------|
| `sqlmap` | SQL injection detection and exploitation |
| `netcat` | TCP/UDP connections |
| `pwntools_exec` | Pwntools Python scripts |
| `curl_exploit` | Crafted HTTP requests (POST, cookies, headers) |
| `hydra` | Network login brute-forcer |
| `gdb_script` | Batch GDB commands on binaries |
| `checksec` | Binary security properties (NX, PIE, canary) |
| `ropper` | ROP gadget finder |

### Crypto
| Tool | Description |
|------|-------------|
| `base64_decode` | Base64 decoding |
| `hex_decode` | Hex to ASCII |
| `rot13` | ROT13 encode/decode |
| `crypto_analysis` | Classical cipher analysis (caesar, vigenere, xor, atbash, freq) |
| `hash_identify` | Hash type identification + basic cracking |
| `openssl` | Encrypt/decrypt, certs, hashes |
| `john` | John the Ripper password cracker |
| `hashcat` | GPU-accelerated hash cracker |

### Forensics & Stego
| Tool | Description |
|------|-------------|
| `exiftool` | Metadata extraction |
| `binwalk` | Embedded file detection and extraction |
| `steghide` | JPEG/BMP/WAV steganography |
| `zsteg` | PNG/BMP LSB steganography |
| `foremost` | File carving |
| `pdftotext` | PDF text extraction |
| `tesseract` | OCR (image to text) |
| `volatility` | Memory forensics |
| `dd_extract` | Byte-level extraction at offset |

### Reverse Engineering
| Tool | Description |
|------|-------------|
| `strings` | Printable string extraction |
| `file` | File type identification |
| `objdump` | Disassembly |
| `readelf` | ELF headers and sections |
| `hexdump` | Hex dump |
| `ltrace` | Library call tracing |
| `strace` | System call tracing |
| `radare2` | Disassembly and analysis framework |
| `uncompyle6` | Python bytecode decompilation |

### General
| Tool | Description |
|------|-------------|
| `shell` | Arbitrary shell commands |
| `python_exec` | Python script execution |

## Suggested Ollama Models

| Size | Model | Notes |
|------|-------|-------|
| **Small** (4-8GB) | `qwen2.5:7b` | Best small model for tool use |
| | `llama3.1:8b` | Solid all-rounder |
| | `deepseek-r1:8b` | Chain-of-thought reasoning |
| | `gemma3:4b` | Lightweight and fast |
| **Medium** (12-24GB) | `qwen2.5:14b` | Strong reasoning + tool use |
| | `gemma3:12b` | Great quality/speed balance |
| | `deepseek-r1:32b` | Best reasoning at this tier |
| | `codestral:22b` | Code-specialized |
| **Large** (32-64GB+) | `qwen2.5:72b` | Best open tool-use model |
| | `llama3.3:70b` | Meta's strongest open model |
| | `deepseek-r1:70b` | Top-tier reasoning |

## Evaluation Metrics

| Metric | Definition |
|--------|-----------|
| **Solve Rate** | % of challenges with validated flag |
| **Hallucination Rate** | Unverified flag candidates / total candidates |
| **Tool Efficiency** | Tool calls per successful solve |
| **Autonomy Score** | 1.0 if no human hints used, -0.25 per hint |
| **Token Usage** | Prompt + completion tokens across all LLM calls |

## Live Progress UI

The CLI displays a real-time Rich panel during solving:
- Current phase (Planning, Executing, Verifying, Reflecting)
- Subtask progress with step and tool call counters
- Token usage (prompt + completion breakdown)
- Scrolling activity log
- Flag candidates highlighted as they appear
- Runtime hint injection via stdin

## Project Structure

```
Cyber_agent/
├── setup.sh                 # One-command setup script
├── pyproject.toml           # Package config & dependencies
├── LICENSE                  # MIT License
├── README.md
├── ctf_agent/
│   ├── __init__.py          # Package exports
│   ├── __main__.py          # CLI with Rich live progress UI
│   ├── config.py            # Configuration dataclass
│   ├── orchestrator.py      # Top-level coordination
│   ├── metrics.py           # Evaluation metrics & benchmarking
│   ├── agents/
│   │   ├── base.py          # ReAct loop, LangGraph integration
│   │   ├── planner.py       # Challenge decomposition
│   │   ├── specialist.py    # Category-specific execution
│   │   └── verifier.py      # Flag validation, anti-hallucination
│   ├── memory/
│   │   └── scratchpad.py    # Structured persistent memory + progress callbacks
│   ├── tools/
│   │   ├── __init__.py      # Tool registry (44 tools)
│   │   ├── base.py          # BaseTool, ShellTool, PythonExecTool
│   │   ├── recon.py         # nmap, gobuster, curl, whatweb, dirb, nikto, ffuf, sslscan
│   │   ├── exploit.py       # sqlmap, netcat, pwntools, curl_exploit, hydra, gdb, checksec, ropper
│   │   ├── crypto.py        # base64, hex, rot13, cipher analysis, hash id, openssl, john, hashcat
│   │   ├── reverse.py       # strings, file, objdump, readelf, hexdump, ltrace, strace, radare2, uncompyle6
│   │   └── forensics.py     # exiftool, binwalk, steghide, foremost, zsteg, pdftotext, tesseract, volatility, dd
│   └── utils/
│       └── llm.py           # Ollama LLM client + TokenCounter
├── skills/                  # Reference playbooks per category
└── benchmarks/
    └── picoctf_easy.json    # Sample benchmark suite
```

## References

- CTFBench: A Benchmark for Evaluating LLMs on CTF Tasks (NYU, 2024)
- AutoPentest: Automated Penetration Testing Using LLM Agents (arXiv:2308.06782)
- ReAct: Synergizing Reasoning and Acting in Language Models (Yao et al., 2023)

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
