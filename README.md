# CTF Agent — Agentic LLM for Autonomous CTF Solving

Multi-agent architecture for autonomously solving beginner-to-intermediate Capture-the-Flag challenges using structured ReAct reasoning, tool integration, persistent scratchpad memory, and verification loops. Runs fully locally via [Ollama](https://ollama.com).

**COSC 6338 Project — Texas A&M University–Corpus Christi**

## Architecture

```
┌──────────────────────────────────────────────────┐
│                  Orchestrator                     │
│  ┌────────────┐  ┌──────────────┐  ┌──────────┐ │
│  │  Planner   │→ │  Specialist  │→ │ Verifier │ │
│  │  Agent     │  │  Agent(s)    │  │  Agent   │ │
│  └────────────┘  └──────────────┘  └──────────┘ │
│        ↕               ↕                ↕        │
│  ┌─────────────────────────────────────────────┐ │
│  │           Scratchpad Memory                 │ │
│  │  (challenge ctx, plan, steps, findings)     │ │
│  └─────────────────────────────────────────────┘ │
│        ↕               ↕                         │
│  ┌─────────────────────────────────────────────┐ │
│  │            Tool Registry                    │ │
│  │  nmap, gobuster, sqlmap, pwntools, binwalk  │ │
│  │  steghide, exiftool, strings, objdump, ...  │ │
│  └─────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────┘
```

### Agents

| Agent | Role |
|-------|------|
| **Planner** | Classifies challenge, decomposes into subtasks, assigns tools, replans on failure |
| **Specialist** | Category-aware executor (recon, exploit, crypto, reverse, forensics) with domain-specific prompts |
| **Verifier** | Validates flag candidates via format check, provenance check (was it in tool output?), and self-reflection to catch hallucinations |

### ReAct Loop

Each agent runs a **Thought → Action → Observation** loop:
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
- Error log

Persisted to JSON between runs for post-mortem analysis.

## Installation

**1. Install Ollama**

Download from [ollama.com](https://ollama.com) and pull a model:
```bash
ollama pull llama3
# or any model you prefer
ollama list   # see what you have
```

**2. Install ctf-agent**

```bash
git clone <repo>
cd ctf_agent
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

**3. Install system tools** (Ubuntu/Kali — optional but recommended)

```bash
apt install nmap gobuster dirb whatweb sqlmap binwalk foremost steghide exiftool
```

## Usage

`--model` is required — pass the name of any model you have in Ollama.

### Solve a single challenge

```bash
ctf-agent --model llama3 solve \
  --name "robots" \
  --category web \
  --desc "Find the hidden admin panel on the web server and retrieve the flag." \
  --url "http://target.ctf:8080" \
  -v
```

### Run a benchmark suite

```bash
ctf-agent --model llama3 benchmark \
  --suite benchmarks/picoctf_easy.json \
  --output results.json \
  -v
```

### List available tools

```bash
ctf-agent --model llama3 tools
```

### Python API

```python
from ctf_agent import Orchestrator, Config
from ctf_agent.memory.scratchpad import ChallengeContext

orch = Orchestrator(Config(llm_model="llama3", verbose=True))
metrics = orch.solve(ChallengeContext(
    name="base64_flag",
    category="crypto",
    description="Decode this: cGljb0NURntCQVNFNjRfMVNfRUFTWX0=",
))
print(metrics.flag)
```

### Options

| Flag | Description |
|------|-------------|
| `--model` | **(required)** Ollama model name |
| `--ollama-url` | Ollama base URL (default: `http://localhost:11434`) |
| `--verbose` / `-v` | Show debug logs |
| `--output` / `-o` | Save results to JSON file |

### Challenge categories

`web`, `crypto`, `forensics`, `reverse`, `pwn`, `misc`

## Evaluation Metrics

| Metric | Definition |
|--------|-----------|
| **Solve Rate** | % of challenges with validated flag |
| **Hallucination Rate** | Unverified flag candidates / total candidates |
| **Tool Efficiency** | Tool calls per successful solve |
| **Autonomy Score** | 1.0 if no human hints used, -0.25 per hint |

## Project Structure

```
ctf_agent/
├── __init__.py          # Package exports
├── __main__.py          # CLI entry point
├── config.py            # Configuration dataclass
├── orchestrator.py      # Top-level coordination
├── metrics.py           # Evaluation metrics & benchmarking
├── agents/
│   ├── base.py          # ReAct loop, tool dispatch
│   ├── planner.py       # Challenge decomposition
│   ├── specialist.py    # Category-specific execution
│   └── verifier.py      # Flag validation, anti-hallucination
├── memory/
│   └── scratchpad.py    # Structured persistent memory
├── tools/
│   ├── __init__.py      # Tool registry
│   ├── base.py          # BaseTool, shell, python exec
│   ├── recon.py         # nmap, gobuster, curl, whatweb, dirb
│   ├── exploit.py       # sqlmap, netcat, pwntools, curl_exploit
│   ├── crypto.py        # base64, hex, cipher analysis, hash id
│   ├── reverse.py       # strings, file, objdump, readelf, hexdump
│   └── forensics.py     # exiftool, binwalk, steghide, foremost, zsteg
└── utils/
    └── llm.py           # Ollama LLM client
benchmarks/
└── picoctf_easy.json    # Sample benchmark suite
```

## References

- CTFBench: A Benchmark for Evaluating LLMs on CTF Tasks (NYU, 2024)
- AutoPentest: Automated Penetration Testing Using LLM Agents (arXiv:2308.06782)
- ReAct: Synergizing Reasoning and Acting in Language Models (Yao et al., 2023)
