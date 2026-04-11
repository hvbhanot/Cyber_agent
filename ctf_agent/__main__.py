#!/usr/bin/env python3
"""
ctf_agent CLI — Autonomous CTF solver (local model via Ollama)

Usage:
    python -m ctf_agent solve --name "Challenge" --category web --desc "Find the flag" --url http://target
    python -m ctf_agent benchmark --suite picoctf_easy.json --output results.json
    python -m ctf_agent tools
"""
from __future__ import annotations
import argparse
import json
import logging
import select
import sys
import threading
import time
from pathlib import Path
from ctf_agent.config import Config
from ctf_agent.memory.scratchpad import ChallengeContext
from ctf_agent.orchestrator import Orchestrator
from ctf_agent.tools import ToolRegistry
from ctf_agent.metrics import BenchmarkResults, ChallengeMetrics

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.spinner import Spinner
from rich.layout import Layout
from rich.columns import Columns

LOG_FILE = Path("ctf_agent.log")
console = Console()

PHASE_ICONS = {
    "Initializing": "[dim]>>>[/]",
    "Planning": "[magenta]>>>[/]",
    "Reflecting": "[yellow]>>>[/]",
    "Verifying flag candidates": "[green]>>>[/]",
    "Replanning": "[red]>>>[/]",
}


def setup_logging(verbose: bool):
    log_level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

    file_handler = logging.FileHandler(LOG_FILE, mode="w")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(fmt, datefmt="%H:%M:%S"))

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.addHandler(file_handler)

    if verbose:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(log_level)
        console_handler.setFormatter(logging.Formatter(fmt, datefmt="%H:%M:%S"))
        root.addHandler(console_handler)
    else:
        logging.getLogger().handlers = [file_handler]


class ProgressState:
    """Thread-safe progress state updated by scratchpad callbacks."""

    def __init__(self, token_counter=None):
        self._lock = threading.Lock()
        self.phase = "Initializing"
        self.subtask = ""
        self.step_count = 0
        self.tool_calls = 0
        self.last_tool = ""
        self.findings_count = 0
        self.flag_candidates: list[str] = []
        self.validated_flag = ""
        self.errors = 0
        self.last_event = ""
        self.start_time = time.time()
        self.events: list[tuple[float, str]] = []
        self._token_counter = token_counter  # reference to LLMClient.tokens
        self.spinner = Spinner("dots")

    def update(self, event: str, detail: str):
        with self._lock:
            now = time.time()
            if event == "phase":
                self.phase = detail
            elif event == "subtask":
                self.subtask = detail
            elif event == "step":
                self.step_count += 1
                self.last_event = f"Step {self.step_count}: {detail}"
            elif event == "tool_result":
                self.tool_calls += 1
                self.last_tool = detail
                self.last_event = f"Tool: {detail}"
            elif event == "plan":
                self.last_event = f"Plan created ({detail})"
            elif event == "flag_candidate":
                if detail not in self.flag_candidates:
                    self.flag_candidates.append(detail)
                self.last_event = f"Flag candidate: {detail}"
            elif event == "flag_validated":
                self.validated_flag = detail
                self.last_event = f"FLAG VALIDATED: {detail}"
            elif event == "error":
                self.errors += 1
                self.last_event = f"Error: {detail}"

            self.events.append((now, self.last_event))
            # Keep only last 20 events
            if len(self.events) > 20:
                self.events = self.events[-20:]

    def elapsed(self) -> str:
        e = int(time.time() - self.start_time)
        m, s = divmod(e, 60)
        return f"{m:02d}:{s:02d}"

    def snapshot(self) -> dict:
        with self._lock:
            tokens = self._token_counter.snapshot() if self._token_counter else {}
            return {
                "phase": self.phase,
                "subtask": self.subtask,
                "step_count": self.step_count,
                "tool_calls": self.tool_calls,
                "last_tool": self.last_tool,
                "flag_candidates": list(self.flag_candidates),
                "validated_flag": self.validated_flag,
                "errors": self.errors,
                "last_event": self.last_event,
                "elapsed": self.elapsed(),
                "events": list(self.events[-8:]),
                "prompt_tokens": tokens.get("prompt_tokens", 0),
                "completion_tokens": tokens.get("completion_tokens", 0),
                "total_tokens": tokens.get("total_tokens", 0),
                "llm_calls": tokens.get("llm_calls", 0),
            }


def build_progress_display(state: ProgressState, challenge_name: str) -> Panel:
    """Build a Rich renderable showing current progress."""
    snap = state.snapshot()

    # Header table with stats
    stats = Table.grid(padding=(0, 2))
    stats.add_column(style="bold cyan", min_width=14)
    stats.add_column()

    phase_icon = PHASE_ICONS.get(snap["phase"], "[cyan]>>>[/]")
    stats.add_row("Challenge", challenge_name)
    stats.add_row("Phase", f"{phase_icon} [bold yellow]{snap['phase']}[/]")
    stats.add_row("Elapsed", f"[dim]{snap['elapsed']}[/]")

    if snap["subtask"]:
        stats.add_row("Subtask", snap["subtask"])

    stats.add_row("Steps", str(snap["step_count"]))
    stats.add_row("Tool calls", str(snap["tool_calls"]))
    stats.add_row("LLM calls", str(snap["llm_calls"]))

    if snap["total_tokens"]:
        token_str = (
            f"[bold]{snap['total_tokens']:,}[/] "
            f"[dim](in: {snap['prompt_tokens']:,}  out: {snap['completion_tokens']:,})[/]"
        )
        stats.add_row("Tokens", token_str)

    if snap["last_tool"]:
        stats.add_row("Last tool", f"[dim]{snap['last_tool']}[/]")

    if snap["errors"]:
        stats.add_row("Errors", f"[red]{snap['errors']}[/]")

    if snap["flag_candidates"]:
        for i, fc in enumerate(snap["flag_candidates"]):
            label = "Flag candidate" if i == 0 else ""
            stats.add_row(label, f"[bold green]{fc}[/]")

    if snap["validated_flag"]:
        stats.add_row("FLAG", f"[bold white on green] {snap['validated_flag']} [/]")

    # Activity log
    log_lines = Text()
    for ts, evt in snap["events"]:
        elapsed = int(ts - state.start_time)
        m, s = divmod(elapsed, 60)
        log_lines.append(f"  {m:02d}:{s:02d}  ", style="dim")
        if "Error" in evt:
            log_lines.append(f"{evt}\n", style="red")
        elif "Flag" in evt or "FLAG" in evt:
            log_lines.append(f"{evt}\n", style="bold green")
        elif "Tool:" in evt:
            log_lines.append(f"{evt}\n", style="cyan")
        else:
            log_lines.append(f"{evt}\n", style="")

    # Combine
    body = Text()
    body.append("")

    inner = Table.grid(padding=(1, 0))
    inner.add_row(stats)
    if snap["events"]:
        inner.add_row(Text("\n Activity Log", style="bold"))
        inner.add_row(log_lines)

    spinner_text = Text.assemble(
        ("  ", ""),
        state.spinner.render(time.time()),
        (f"  {snap['phase']}...", "bold yellow"),
    ) if not snap["validated_flag"] else Text("  Done!", style="bold green")

    outer = Table.grid()
    outer.add_row(spinner_text)
    outer.add_row(inner)

    return Panel(
        outer,
        title="[bold]CTF Agent[/]",
        border_style="bright_blue",
        padding=(1, 2),
    )


class SolveRunner:
    """
    Runs orch.solve() in a background thread with Rich live progress.
    Main thread handles stdin hints and display refresh.
    """

    def __init__(self, label: str, orch: Orchestrator, challenge: ChallengeContext):
        self.label = label
        self.orch = orch
        self.challenge = challenge
        self.metrics = None
        self._done = threading.Event()
        self.progress = ProgressState(token_counter=orch.llm.tokens)

    def _on_progress(self, event: str, detail: str):
        self.progress.update(event, detail)

    def _solve(self):
        self.metrics = self.orch.solve(self.challenge)
        self._done.set()

    def run(self):
        self.orch.pad.set_progress_callback(self._on_progress)

        solve_t = threading.Thread(target=self._solve, daemon=True)
        solve_t.start()

        console.print(f"\n  [dim]Logs -> tail -f {LOG_FILE}[/]")
        console.print(f"  [dim]Type a hint and press Enter, or just wait[/]\n")

        with Live(
            build_progress_display(self.progress, self.challenge.name),
            console=console,
            refresh_per_second=4,
            transient=False,
        ) as live:
            while not self._done.is_set():
                live.update(build_progress_display(self.progress, self.challenge.name))
                ready, _, _ = select.select([sys.stdin], [], [], 0.25)
                if ready:
                    line = sys.stdin.readline()
                    hint = line.strip()
                    if hint and not self._done.is_set():
                        self.orch.pad.add_runtime_hint(hint)
                        self.progress.update("step", f"Hint injected: {hint[:50]}")

            # Final update
            live.update(build_progress_display(self.progress, self.challenge.name))

        solve_t.join()
        return self.metrics


def print_results(metrics: ChallengeMetrics, pad=None):
    # Status
    if metrics.solved:
        status = "[bold white on green] SOLVED [/]"
    elif metrics.answer:
        status = "[bold yellow] COMPLETE (no flag pattern matched) [/]"
    else:
        status = "[bold white on red] UNSOLVED [/]"

    # Results table
    table = Table(show_header=False, padding=(0, 2), border_style="bright_blue",
                  title="Results", title_style="bold")
    table.add_column("Label", style="bold cyan", min_width=16)
    table.add_column("Value")

    table.add_row("Challenge", metrics.name)
    table.add_row("Category", metrics.category.upper())
    table.add_row("Status", status)

    if metrics.flag:
        table.add_row("FLAG", f"[bold green]{metrics.flag}[/]")
    elif metrics.answer and metrics.answer not in (
        "MAX STEPS REACHED — no definitive answer",
        "Stuck in loop — could not complete task",
    ):
        table.add_row("Answer", metrics.answer[:200])
    else:
        table.add_row("Answer", "[dim]No result found[/]")

    table.add_row("", "")
    table.add_row("Steps", str(metrics.total_steps))
    table.add_row("Tool calls", str(metrics.total_tool_calls))
    table.add_row("LLM calls", str(metrics.llm_calls))
    if metrics.total_tokens:
        table.add_row("Tokens", f"[bold]{metrics.total_tokens:,}[/]  "
                       f"[dim](in: {metrics.prompt_tokens:,}  out: {metrics.completion_tokens:,})[/]")
    table.add_row("Wall time", f"{metrics.wall_time_s}s")
    table.add_row("Errors", str(metrics.errors))
    table.add_row("Autonomy", f"{metrics.autonomy_score:.2f}")

    if pad and pad.flag_candidates and not metrics.flag:
        candidates = ", ".join(pad.flag_candidates)
        table.add_row("Candidates", f"[yellow]{candidates}[/]")

    if pad and pad.findings:
        items = list(pad.findings.items())[:6]
        for i, (k, v) in enumerate(items):
            label = "Findings" if i == 0 else ""
            table.add_row(label, f"[dim]{k}:[/] {str(v)[:50]}")

    if metrics.errors > 0 and pad and pad.errors:
        for i, e in enumerate(pad.errors[:3]):
            label = "Errors" if i == 0 else ""
            table.add_row(label, f"[red]{e[:60]}[/]")

    if pad and pad.runtime_hints:
        for i, h in enumerate(pad.runtime_hints):
            label = "Hints used" if i == 0 else ""
            table.add_row(label, h)

    console.print()
    console.print(Panel(table, border_style="bright_blue"))
    console.print()


def cmd_solve(args):
    if not args.model:
        console.print("[red]Error:[/] --model is required for solve")
        sys.exit(1)
    cfg = Config(
        llm_model=args.model,
        ollama_base_url=args.ollama_url,
        verbose=args.verbose,
    )
    orch = Orchestrator(cfg)
    challenge = ChallengeContext(
        name=args.name,
        category=args.category,
        description=args.desc,
        files=args.files or [],
        url=args.url,
        port=args.port,
        hints=args.hints or [],
    )

    metrics = SolveRunner(f"Solving {args.name} ({args.category})", orch, challenge).run()
    print_results(metrics, pad=orch.pad)

    if args.output:
        data = {
            "solved": metrics.solved,
            "flag": metrics.flag,
            "answer": metrics.answer,
            "steps": metrics.total_steps,
            "tool_calls": metrics.total_tool_calls,
            "wall_time_s": metrics.wall_time_s,
            "errors": metrics.errors,
            "hints_used": metrics.human_hints_used,
            "prompt_tokens": metrics.prompt_tokens,
            "completion_tokens": metrics.completion_tokens,
            "total_tokens": metrics.total_tokens,
            "llm_calls": metrics.llm_calls,
            "findings": orch.pad.findings,
            "flag_candidates": orch.pad.flag_candidates,
        }
        Path(args.output).write_text(json.dumps(data, indent=2))
        console.print(f"  [dim]Results saved to {args.output}[/]\n")


def cmd_benchmark(args):
    if not args.model:
        console.print("[red]Error:[/] --model is required for benchmark")
        sys.exit(1)
    cfg = Config(
        llm_model=args.model,
        ollama_base_url=args.ollama_url,
        verbose=args.verbose,
    )
    suite_data = json.loads(Path(args.suite).read_text())
    challenges = [ChallengeContext(**ch) for ch in suite_data["challenges"]]

    orch = Orchestrator(cfg)
    bench = BenchmarkResults(config_snapshot={"model": cfg.llm_model, "backend": "ollama"})
    total = len(challenges)

    for i, ch in enumerate(challenges, 1):
        console.rule(f"[bold]{i}/{total} {ch.name} ({ch.category})[/]")
        m = SolveRunner(f"[{i}/{total}] {ch.name}", orch, ch).run()
        bench.challenges.append(m)
        print_results(m, pad=orch.pad)

    summary = bench.summary()

    table = Table(title="Benchmark Summary", border_style="bright_blue",
                  show_header=False, padding=(0, 2))
    table.add_column("Label", style="bold cyan", min_width=16)
    table.add_column("Value")

    table.add_row("Challenges", str(summary["total_challenges"]))
    table.add_row("Solved", str(summary["solved"]))
    table.add_row("Solve rate", summary["solve_rate"])
    table.add_row("Hallucination", summary["hallucination_rate"])
    table.add_row("Avg tool calls", summary["avg_tool_calls_per_solve"])
    table.add_row("Avg autonomy", summary["avg_autonomy_score"])

    if summary.get("by_category"):
        table.add_row("", "")
        for cat, stats in summary["by_category"].items():
            table.add_row(cat, f"{stats['solved']}/{stats['total']}  ({stats['solve_rate']})")

    console.print()
    console.print(Panel(table, border_style="bright_blue"))
    console.print()

    if args.output:
        bench.save(args.output)
        console.print(f"  [dim]Full results saved to {args.output}[/]\n")


def cmd_tools(args):
    registry = ToolRegistry()
    tools = registry.list_tools()

    table = Table(title="Available Tools", border_style="bright_blue")
    table.add_column("Tool", style="bold cyan", min_width=20)
    table.add_column("Available", justify="center")
    table.add_column("Description")

    for t in tools:
        avail = "[green]YES[/]" if t["available"] else "[dim]no[/]"
        table.add_row(t["name"], avail, t["description"][:50])

    console.print()
    console.print(table)
    console.print()


def main():
    parser = argparse.ArgumentParser(description="Agentic LLM CTF Solver (local via Ollama)")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--model", default=None, help="Ollama model name (required for solve/benchmark)")
    parser.add_argument("--ollama-url", default="http://localhost:11434")
    sub = parser.add_subparsers(dest="command", required=True)

    solve_p = sub.add_parser("solve")
    solve_p.add_argument("--name", required=True)
    solve_p.add_argument("--category", required=True,
                         choices=["web", "crypto", "forensics", "reverse", "pwn", "misc"])
    solve_p.add_argument("--desc", required=True)
    solve_p.add_argument("--url", default=None)
    solve_p.add_argument("--port", type=int, default=None)
    solve_p.add_argument("--files", nargs="*", default=None)
    solve_p.add_argument("--hints", nargs="*", default=None)
    solve_p.add_argument("--output", "-o", default=None)

    bench_p = sub.add_parser("benchmark")
    bench_p.add_argument("--suite", required=True)
    bench_p.add_argument("--output", "-o", default="benchmark_results.json")

    sub.add_parser("tools")

    args = parser.parse_args()
    setup_logging(args.verbose)

    if args.command == "solve":
        cmd_solve(args)
    elif args.command == "benchmark":
        cmd_benchmark(args)
    elif args.command == "tools":
        cmd_tools(args)


if __name__ == "__main__":
    main()
