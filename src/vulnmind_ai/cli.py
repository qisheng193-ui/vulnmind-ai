from __future__ import annotations

import argparse
from pathlib import Path

from .agents import VulnMindAI


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnmind",
        description="AI-assisted secure code review agent for source repositories.",
    )
    parser.add_argument("target", help="Target source directory to scan.")
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory used to store generated reports.",
    )
    parser.add_argument(
        "--extensions",
        nargs="+",
        default=[".php", ".py", ".js"],
        help="File extensions to include in the scan.",
    )
    parser.add_argument(
        "--formats",
        nargs="+",
        choices=["text", "markdown", "json"],
        default=["text", "markdown", "json"],
        help="Output report formats.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    target = Path(args.target).expanduser().resolve()
    if not target.exists() or not target.is_dir():
        parser.error(f"Target directory does not exist: {target}")

    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    agent = VulnMindAI(extensions=tuple(args.extensions))
    results = agent.run(target)

    print(f"[VulnMind AI] Scanned: {target}")
    print(f"[VulnMind AI] Findings: {len(results)}")

    reporter = agent.reporter
    written_files: list[Path] = []

    if "text" in args.formats:
        text_path = output_dir / "vulnmind_report.txt"
        text_path.write_text(reporter.build_text(results, str(target)), encoding="utf-8")
        written_files.append(text_path)

    if "markdown" in args.formats:
        markdown_path = output_dir / "vulnmind_report.md"
        markdown_path.write_text(reporter.build_markdown(results, str(target)), encoding="utf-8")
        written_files.append(markdown_path)

    if "json" in args.formats:
        json_path = output_dir / "vulnmind_report.json"
        json_path.write_text(reporter.build_json(results, str(target)), encoding="utf-8")
        written_files.append(json_path)

    for report_file in written_files:
        print(f"[+] Report saved: {report_file}")

    return 0
