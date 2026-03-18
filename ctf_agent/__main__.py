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
from pathlib import Path
from ctf_agent.config import Config
from ctf_agent.memory.scratchpad import ChallengeContext
from ctf_agent.orchestrator import Orchestrator
from ctf_agent.tools import ToolRegistry
from ctf_agent.metrics import BenchmarkResults, ChallengeMetrics

W = 64
LOG_FILE = Path("ctf_agent.log")


def setup_logging(verbose: bool):
    log_level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

    # always write full logs to file
    file_handler = logging.FileHandler(LOG_FILE, mode="w")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(fmt, datefmt="%H:%M:%S"))

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.addHandler(file_handler)

    if verbose:
        # also print to stderr so it doesn't mix with stdout
        console = logging.StreamHandler(sys.stderr)
        console.setLevel(log_level)
        console.setFormatter(logging.Formatter(fmt, datefmt="%H:%M:%S"))
        root.addHandler(console)
    else:
        # silence everything on stdout/stderr — logs go to file only
        logging.getLogger().handlers = [file_handler]


def _row(label: str, value: str) -> str:
    return f"  {label:<14}{value}"


def _divider(char: str = "─") -> str:
    return char * W


class SolveRunner:
    """
    Runs orch.solve() in a background thread.
    Main thread waits on stdin with select() — no background stdout writes,
    so terminal line-editing (backspace, cursor keys) works normally.
    """

    def __init__(self, label: str, orch, challenge):
        self.label = label
        self.orch = orch
        self.challenge = challenge
        self.metrics = None
        self._done = threading.Event()

    def _solve(self):
        self.metrics = self.orch.solve(self.challenge)
        self._done.set()

    def run(self):
        solve_t = threading.Thread(target=self._solve, daemon=True)
        solve_t.start()

        print(f"\n  {_divider()}")
        print(f"  Solving: {self.label}")
        print(f"  {_divider()}")
        print(f"  Hint: (type a hint and press Enter, or just wait)\n")

        while not self._done.is_set():
            # wait up to 1s for stdin input; re-checks _done each iteration
            ready, _, _ = select.select([sys.stdin], [], [], 1.0)
            if ready:
                line = sys.stdin.readline()
                hint = line.strip()
                if hint and not self._done.is_set():
                    self.orch.pad.add_runtime_hint(hint)
                    print(f"  ✓  Hint injected: {hint[:60]}\n")

        solve_t.join()
        return self.metrics


def print_results(metrics: ChallengeMetrics, pad=None):
    print()
    print(_divider("━"))
    print("  CTF AGENT RESULTS")
    print(_divider())

    print(_row("Challenge:", metrics.name))
    print(_row("Category:", metrics.category.upper()))

    if metrics.solved:
        status = "SOLVED"
    elif metrics.answer:
        status = "COMPLETE (no flag pattern matched)"
    else:
        status = "UNSOLVED"
    print(_row("Status:", status))

    print(_divider())

    if metrics.flag:
        print(_row("FLAG:", metrics.flag))
    elif metrics.answer and metrics.answer not in (
        "MAX STEPS REACHED — no definitive answer",
        "Stuck in loop — could not complete task",
    ):
        answer_lines = [metrics.answer[i:i+46] for i in range(0, min(len(metrics.answer), 300), 46)]
        print(_row("ANSWER:", answer_lines[0]))
        for line in answer_lines[1:]:
            print(_row("", line))
    else:
        print(_row("ANSWER:", "No result found"))

    if pad and pad.flag_candidates and not metrics.flag:
        print(_divider())
        print("  Flag candidates (unverified):")
        for c in pad.flag_candidates:
            print(f"    • {c}")

    if pad and pad.findings:
        print(_divider())
        print("  Findings:")
        for k, v in list(pad.findings.items())[:8]:
            print(f"    {k}: {str(v)[:46]}")

    if metrics.errors > 0 and pad and pad.errors:
        print(_divider())
        print(f"  Errors ({metrics.errors}):")
        for e in pad.errors[:3]:
            print(f"    • {e[:60]}")

    if pad and pad.runtime_hints:
        print(_divider())
        print(f"  Hints used ({metrics.human_hints_used}):")
        for h in pad.runtime_hints:
            print(f"    • {h}")

    print(_divider())
    print(_row("Steps:", str(metrics.total_steps)))
    print(_row("Tool calls:", str(metrics.total_tool_calls)))
    print(_row("Wall time:", f"{metrics.wall_time_s}s"))
    print(_row("Errors:", str(metrics.errors)))
    print(_row("Autonomy:", f"{metrics.autonomy_score:.2f}"))
    print(_divider("━"))
    print()


def cmd_solve(args):
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

    print(f"  Logs → tail -f {LOG_FILE}\n")
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
            "findings": orch.pad.findings,
            "flag_candidates": orch.pad.flag_candidates,
        }
        Path(args.output).write_text(json.dumps(data, indent=2))
        print(f"  Results saved to {args.output}\n")


def cmd_benchmark(args):
    cfg = Config(
        llm_model=args.model,
        ollama_base_url=args.ollama_url,
        verbose=args.verbose,
    )
    suite_data = json.loads(Path(args.suite).read_text())
    challenges = [ChallengeContext(**ch) for ch in suite_data["challenges"]]

    print(f"  Logs → tail -f {LOG_FILE}\n")

    orch = Orchestrator(cfg)
    bench = BenchmarkResults(config_snapshot={"model": cfg.llm_model, "backend": "ollama"})
    total = len(challenges)

    for i, ch in enumerate(challenges, 1):
        label = f"[{i}/{total}] {ch.name} ({ch.category})"
        m = SolveRunner(label, orch, ch).run()
        bench.challenges.append(m)
        print_results(m, pad=orch.pad)

    summary = bench.summary()
    print(_divider("━"))
    print("  BENCHMARK SUMMARY")
    print(_divider())
    print(_row("Challenges:", str(summary["total_challenges"])))
    print(_row("Solved:", str(summary["solved"])))
    print(_row("Solve rate:", summary["solve_rate"]))
    print(_row("Hallucination:", summary["hallucination_rate"]))
    print(_row("Avg tool calls:", summary["avg_tool_calls_per_solve"]))
    print(_row("Avg autonomy:", summary["avg_autonomy_score"]))
    if summary.get("by_category"):
        print(_divider())
        print("  By category:")
        for cat, stats in summary["by_category"].items():
            print(f"    {cat:<12} {stats['solved']}/{stats['total']}  ({stats['solve_rate']})")
    print(_divider("━"))
    print()

    if args.output:
        bench.save(args.output)
        print(f"  Full results saved to {args.output}\n")


def cmd_tools(args):
    registry = ToolRegistry()
    tools = registry.list_tools()
    print()
    print(_divider("━"))
    print("  AVAILABLE TOOLS")
    print(_divider())
    print(f"  {'Tool':<20} {'Available':<10} Description")
    print(_divider())
    for t in tools:
        avail = "YES" if t["available"] else "no"
        print(f"  {t['name']:<20} {avail:<10} {t['description'][:40]}")
    print(_divider("━"))
    print()


def main():
    parser = argparse.ArgumentParser(description="Agentic LLM CTF Solver (local via Ollama)")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--model", required=True, help="Ollama model name")
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
