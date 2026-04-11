#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────
#  CTF Agent — Setup Script
# ─────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

info()  { echo -e "  ${CYAN}[*]${RESET} $1"; }
ok()    { echo -e "  ${GREEN}[+]${RESET} $1"; }
warn()  { echo -e "  ${YELLOW}[!]${RESET} $1"; }
fail()  { echo -e "  ${RED}[-]${RESET} $1"; }

echo ""
echo -e "  ${BOLD}CTF Agent Setup${RESET}"
echo -e "  ${DIM}─────────────────────────────────────${RESET}"
echo ""

# ── Check Python ──────────────────────────────────────────
info "Checking Python..."
if ! command -v python3 &>/dev/null; then
    fail "Python 3 not found. Install Python 3.10+ first."
    exit 1
fi

PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)

if [ "$PY_MAJOR" -lt 3 ] || ([ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]); then
    fail "Python 3.10+ required (found $PY_VERSION)"
    exit 1
fi
ok "Python $PY_VERSION"

# ── Check Ollama ──────────────────────────────────────────
info "Checking Ollama..."
if command -v ollama &>/dev/null; then
    ok "Ollama found: $(ollama --version 2>/dev/null || echo 'installed')"
else
    warn "Ollama not found. Install from https://ollama.com"
    warn "You'll need it to run the agent with local models."
fi

# ── Create venv ───────────────────────────────────────────
VENV_DIR=".venv"
if [ -d "$VENV_DIR" ]; then
    info "Virtual environment already exists at $VENV_DIR"
else
    info "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
    ok "Created $VENV_DIR"
fi

# ── Activate and install ─────────────────────────────────
info "Installing dependencies..."
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

pip install --upgrade pip --quiet 2>/dev/null
pip install -e ".[dev]" --quiet 2>&1 | tail -1
ok "Python dependencies installed"

# ── Check CTF tools ──────────────────────────────────────
echo ""
info "Checking CTF tools..."
echo ""

echo -e "  ${BOLD}Recon & Web${RESET}"
RECON_TOOLS=(
    "nmap:Network scanner / port enumeration"
    "gobuster:Directory & DNS brute-forcer"
    "dirb:Web content scanner"
    "whatweb:Web technology fingerprinting"
    "curl:HTTP client"
    "nikto:Web vulnerability scanner"
    "ffuf:Fast web fuzzer"
    "wfuzz:Web fuzzer (parameter & path)"
    "hydra:Network login brute-forcer"
    "sslscan:SSL/TLS scanner"
)

MISSING=0
for entry in "${RECON_TOOLS[@]}"; do
    tool="${entry%%:*}"
    desc="${entry#*:}"
    if command -v "$tool" &>/dev/null; then
        ok "$tool — $desc"
    else
        warn "$tool — $desc ${DIM}(not installed)${RESET}"
        MISSING=$((MISSING + 1))
    fi
done

echo ""
echo -e "  ${BOLD}Exploit & Pwn${RESET}"
EXPLOIT_TOOLS=(
    "sqlmap:SQL injection tool"
    "nc:Netcat — TCP/UDP connections"
    "python3:Python 3 (pwntools host)"
    "gdb:GNU debugger"
    "ltrace:Library call tracer"
    "strace:System call tracer"
    "ropper:ROP gadget finder"
    "checksec:Binary security checker"
)

for entry in "${EXPLOIT_TOOLS[@]}"; do
    tool="${entry%%:*}"
    desc="${entry#*:}"
    if command -v "$tool" &>/dev/null; then
        ok "$tool — $desc"
    else
        warn "$tool — $desc ${DIM}(not installed)${RESET}"
        MISSING=$((MISSING + 1))
    fi
done

echo ""
echo -e "  ${BOLD}Crypto${RESET}"
CRYPTO_TOOLS=(
    "openssl:Crypto toolkit (enc/dec, certs, hashes)"
    "hashcat:Password / hash cracker (GPU)"
    "john:John the Ripper — password cracker"
)

for entry in "${CRYPTO_TOOLS[@]}"; do
    tool="${entry%%:*}"
    desc="${entry#*:}"
    if command -v "$tool" &>/dev/null; then
        ok "$tool — $desc"
    else
        warn "$tool — $desc ${DIM}(not installed)${RESET}"
        MISSING=$((MISSING + 1))
    fi
done

echo ""
echo -e "  ${BOLD}Forensics & Stego${RESET}"
FORENSICS_TOOLS=(
    "exiftool:Metadata extractor"
    "binwalk:Firmware / embedded file analyzer"
    "steghide:JPEG/BMP/WAV steganography"
    "zsteg:PNG/BMP LSB steganography"
    "foremost:File carving from raw data"
    "volatility:Memory forensics framework"
    "pdftotext:PDF text extraction"
    "tesseract:OCR — image to text"
)

for entry in "${FORENSICS_TOOLS[@]}"; do
    tool="${entry%%:*}"
    desc="${entry#*:}"
    if command -v "$tool" &>/dev/null; then
        ok "$tool — $desc"
    else
        warn "$tool — $desc ${DIM}(not installed)${RESET}"
        MISSING=$((MISSING + 1))
    fi
done

echo ""
echo -e "  ${BOLD}Reverse Engineering${RESET}"
REVERSE_TOOLS=(
    "strings:Binary string extractor"
    "file:File type identifier"
    "objdump:Disassembler"
    "readelf:ELF header/section viewer"
    "xxd:Hex dumper"
    "radare2:Reverse engineering framework"
    "ghidra:NSA decompiler (check ghidraRun)"
    "uncompyle6:Python bytecode decompiler"
    "jadx:Android/Java decompiler"
)

for entry in "${REVERSE_TOOLS[@]}"; do
    tool="${entry%%:*}"
    desc="${entry#*:}"
    if command -v "$tool" &>/dev/null; then
        ok "$tool — $desc"
    else
        warn "$tool — $desc ${DIM}(not installed)${RESET}"
        MISSING=$((MISSING + 1))
    fi
done

# ── Create workspace dir ─────────────────────────────────
mkdir -p /tmp/ctf_workspace

# ── Model suggestions ────────────────────────────────────
echo ""
echo -e "  ${DIM}─────────────────────────────────────${RESET}"
echo -e "  ${BOLD}Suggested Ollama Models${RESET}"
echo -e "  ${DIM}─────────────────────────────────────${RESET}"

if command -v ollama &>/dev/null; then
    echo ""
    info "Currently installed models:"
    if ollama list 2>/dev/null | grep -qE "[a-z]"; then
        ollama list 2>/dev/null | while read -r line; do
            echo -e "      ${DIM}$line${RESET}"
        done
    else
        warn "No models installed yet"
    fi
fi

echo ""
echo -e "  ${BOLD}${CYAN}Small (4-8GB RAM)${RESET} — fast, good for easy CTFs"
echo -e "    ${DIM}ollama pull qwen2.5:7b             ${RESET}# Best small model for tool use"
echo -e "    ${DIM}ollama pull llama3.1:8b             ${RESET}# Meta — solid all-rounder"
echo -e "    ${DIM}ollama pull deepseek-r1:8b          ${RESET}# Chain-of-thought reasoning"
echo -e "    ${DIM}ollama pull gemma3:4b               ${RESET}# Google — lightweight & fast"
echo -e "    ${DIM}ollama pull phi4-mini:3.8b          ${RESET}# Microsoft — tiny but capable"
echo -e "    ${DIM}ollama pull mistral:7b              ${RESET}# Mistral — fast inference"
echo -e "    ${DIM}ollama pull qwen3:8b                ${RESET}# Alibaba — latest Qwen 3"

echo ""
echo -e "  ${BOLD}${CYAN}Medium (12-24GB RAM)${RESET} — good balance, recommended"
echo -e "    ${DIM}ollama pull qwen2.5:14b             ${RESET}# Strong reasoning + tool use"
echo -e "    ${DIM}ollama pull gemma3:12b              ${RESET}# Google — great quality/speed"
echo -e "    ${DIM}ollama pull phi4:14b                ${RESET}# Microsoft — strong reasoner"
echo -e "    ${DIM}ollama pull deepseek-r1:14b         ${RESET}# Deep reasoning, slower"
echo -e "    ${DIM}ollama pull mistral-small:24b       ${RESET}# Mistral — tool-use optimized"
echo -e "    ${DIM}ollama pull codestral:22b           ${RESET}# Mistral — code-specialized"
echo -e "    ${DIM}ollama pull command-r:35b           ${RESET}# Cohere — tool use & RAG"
echo -e "    ${DIM}ollama pull deepseek-r1:32b         ${RESET}# Best open reasoning at this size"

echo ""
echo -e "  ${BOLD}${CYAN}Large (32-64GB+ RAM)${RESET} — best quality, needs beefy hardware"
echo -e "    ${DIM}ollama pull qwen2.5:72b             ${RESET}# Best open tool-use model"
echo -e "    ${DIM}ollama pull llama3.3:70b            ${RESET}# Meta's strongest open model"
echo -e "    ${DIM}ollama pull deepseek-r1:70b         ${RESET}# Top-tier reasoning"
echo -e "    ${DIM}ollama pull mistral-large:123b      ${RESET}# Mistral flagship (needs 80GB+)"
echo -e "    ${DIM}ollama pull qwen3:32b               ${RESET}# Latest Qwen 3 — large"

echo ""
echo -e "  ${BOLD}${CYAN}Specialized${RESET} — models tuned for specific tasks"
echo -e "    ${DIM}ollama pull starcoder2:15b          ${RESET}# Code generation & analysis"
echo -e "    ${DIM}ollama pull dolphin-mixtral:8x7b    ${RESET}# Uncensored, good for CTF prompts"
echo -e "    ${DIM}ollama pull wizard-vicuna-uncensored:30b  ${RESET}# Uncensored reasoning"
echo -e "    ${DIM}ollama pull solar:10.7b             ${RESET}# Upstage — strong instruction following"
echo -e "    ${DIM}ollama pull yi:34b                  ${RESET}# 01.AI — multilingual + reasoning"

# ── Summary ──────────────────────────────────────────────
echo ""
echo -e "  ${DIM}─────────────────────────────────────${RESET}"
echo -e "  ${BOLD}${GREEN}Setup complete!${RESET}"
echo -e "  ${DIM}─────────────────────────────────────${RESET}"
echo ""
echo -e "  ${BOLD}Quick start:${RESET}"
echo -e "    source $VENV_DIR/bin/activate"
echo -e "    python -m ctf_agent --model qwen2.5:7b solve \\"
echo -e "      --name 'My Challenge' --category crypto \\"
echo -e "      --desc 'Decode this: aGVsbG8gd29ybGQ='"
echo ""
echo -e "  ${BOLD}Other commands:${RESET}"
echo -e "    python -m ctf_agent --model qwen2.5:7b tools          ${DIM}# List available tools${RESET}"
echo -e "    python -m ctf_agent --model qwen2.5:7b benchmark \\    ${DIM}# Run benchmark suite${RESET}"
echo -e "      --suite benchmarks/picoctf_easy.json"
echo ""

if [ "$MISSING" -gt 0 ]; then
    warn "$MISSING optional CTF tools not found — the agent will still work but some"
    warn "categories may have reduced capability. Install them for best results."
    echo ""
fi
