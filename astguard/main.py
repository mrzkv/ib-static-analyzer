"""Main module for running the static analyzer via CLI."""

import argparse
import sys
from pathlib import Path

from .analyzer import StaticAnalyzer
from .reporter import ReportGenerator


def main() -> None:
    """Run the CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="astguard",
        description="A tool for static security analysis of Python code.",
        epilog="""
Using configuration:
  You can use .astguardignore or pyproject.toml to configure the analyzer.

.astguardignore:
  Create this file to exclude specific files or directories.
  The format is similar to .gitignore.

pyproject.toml:
  Add a [tool.astguard] section to your pyproject.toml:
  [tool.astguard]
  include = ["src"]
  exclude = ["pattern1", "pattern2"]
  ignore = ["CWE-78", "CWE-94"]

Inline ignores:
  You can ignore specific lines using comments:
  - # noqa
  - # astguard: ignore
  - # noqa: CWE-78
  - # astguard: ignore CWE-78
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version="astguard 0.1.0")

    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to the file or directory for analysis (default: .)",
    )
    parser.add_argument(
        "-s",
        "--short",
        action="store_true",
        help="Output a short report (one line per finding)",
    )

    args = parser.parse_args()

    path = Path(args.path)
    run_check(path, short=args.short)


def run_check(path: Path, *, short: bool) -> None:
    """Start the analysis process."""
    if not path.exists():
        print(f"Error: Path '{path}' does not exist.", file=sys.stderr)
        sys.exit(2)

    analyzer = StaticAnalyzer()
    report_gen = ReportGenerator()

    # Start analysis
    try:
        findings = analyzer.run_analysis(path)
    except Exception as e:  # noqa: BLE001
        print(f"Critical error during analysis: {e}", file=sys.stderr)
        sys.exit(2)

    report_gen.add_findings(findings)

    # Generate and output report
    report = report_gen.generate_text_report(short=short)
    print(report)

    if findings:
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
