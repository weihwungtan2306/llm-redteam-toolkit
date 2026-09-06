#!/usr/bin/env python3
"""
Command-line entrypoint for the LLM red-teaming toolkit.

Usage:
    python cli.py run --target http://127.0.0.1:5001 --out reports/latest_report.md
    python cli.py run --target http://127.0.0.1:5001 --json reports/latest_run.json
    python cli.py list
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from redteam.runner import load_attacks, run_suite  # noqa: E402
from redteam.report import render_report  # noqa: E402


def cmd_list(args):
    cases = load_attacks()
    for c in cases:
        print(f"{c['id']:8} {c['category']:20} {c['technique']}")
    print(f"\n{len(cases)} attack cases loaded.")


def cmd_run(args):
    cases = load_attacks(Path(args.library)) if args.library else None
    print(f"Running {'custom' if cases else 'default'} attack suite against {args.target} ...")
    run = run_suite(args.target, cases=cases, timeout=args.timeout, delay=args.delay)

    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(run, indent=2))
        print(f"Raw results written to {args.json}")

    report_md = render_report(run)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report_md)
    print(f"Report written to {out_path}")

    findings = run["findings"]
    print(f"\n{len(findings)}/{run['total']} attack attempts succeeded.")
    if findings:
        for f in findings:
            print(f"  [{f['severity']:8}] {f['id']} - {f['technique']}")


def main():
    parser = argparse.ArgumentParser(description="LLM red-teaming toolkit")
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="Run the attack suite against a target and generate a report")
    p_run.add_argument("--target", required=True, help="Base URL of the target app, e.g. http://127.0.0.1:5001")
    p_run.add_argument("--out", default="reports/latest_report.md", help="Path to write the Markdown report")
    p_run.add_argument("--json", default=None, help="Optional path to also write raw JSON results")
    p_run.add_argument("--library", default=None, help="Path to a custom attacks YAML file")
    p_run.add_argument("--timeout", type=float, default=30.0, help="Per-request timeout in seconds")
    p_run.add_argument("--delay", type=float, default=0.0, help="Delay between attack cases, in seconds")
    p_run.set_defaults(func=cmd_run)

    p_list = sub.add_parser("list", help="List the attack cases in the library")
    p_list.set_defaults(func=cmd_list)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
