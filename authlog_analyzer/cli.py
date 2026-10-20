"""Command line interface.

Exit codes: 0 = no findings, 1 = findings, 2 = input or usage error.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from typing import Sequence

from . import __version__
from .detectors import DetectionConfig, detect_all
from .parser import parse_lines
from .report import FORMATS, render

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

# One year in minutes. Keeps timedelta well inside its range.
MAX_WINDOW_MINUTES = 525_600


def _positive_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a whole number") from None
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


def _window_minutes(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a number") from None
    if not 0 < value <= MAX_WINDOW_MINUTES:
        raise argparse.ArgumentTypeError(f"must be greater than 0 and at most {MAX_WINDOW_MINUTES}")
    return value


def _year(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a year") from None
    if not 1970 <= value <= 9999:
        raise argparse.ArgumentTypeError("must be between 1970 and 9999")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="authlog_analyzer",
        description="Detect SSH brute force, password spraying and success-after-failure "
        "patterns in a Linux sshd auth.log file.",
        epilog="Exit codes: 0 no findings, 1 findings, 2 input error.",
    )
    parser.add_argument("logfile", help="path to an sshd auth.log style file")
    parser.add_argument(
        "--threshold", type=_positive_int, default=5, metavar="N",
        help="failures from one IP that make a brute-force finding (default: 5)",
    )
    parser.add_argument(
        "--window", type=_window_minutes, default=10, metavar="MIN",
        help="sliding window in minutes, inclusive (default: 10)",
    )
    parser.add_argument(
        "--spray-users", type=_positive_int, default=5, metavar="K",
        help="distinct usernames from one IP that make a spraying finding (default: 5)",
    )
    parser.add_argument(
        "--year", type=_year, default=datetime.now().year, metavar="YYYY",
        help="year to assume, since syslog timestamps have none (default: current year)",
    )
    parser.add_argument(
        "--format", choices=FORMATS, default="table",
        help="output format (default: table)",
    )
    parser.add_argument(
        "--output", metavar="PATH",
        help="write the report to PATH (overwrites) instead of standard output",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _error(message: str) -> int:
    print(f"authlog_analyzer: error: {message}", file=sys.stderr)
    return EXIT_ERROR


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse exits 2 on bad usage, 0 for --help/--version
        return exc.code if isinstance(exc.code, int) else EXIT_ERROR

    config = DetectionConfig(
        threshold=args.threshold,
        window_minutes=args.window,
        spray_users=args.spray_users,
    )

    try:
        # errors="replace" so stray bytes never crash the run.
        with open(args.logfile, "r", encoding="utf-8", errors="replace") as handle:
            result = parse_lines(handle, args.year)
    except OSError as exc:
        return _error(f"cannot read {args.logfile!r}: {exc.strerror or exc}")

    findings = detect_all(result.events, config)
    report = render(findings, args.format, result.stats)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8", newline="") as out:
                out.write(report)
        except OSError as exc:
            return _error(f"cannot write {args.output!r}: {exc.strerror or exc}")
        print(f"Wrote {args.format} report to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(report)

    print(result.stats.describe(), file=sys.stderr)
    if result.stats.malformed_lines:
        numbers = ", ".join(str(n) for n in result.stats.malformed_line_numbers)
        more = " (first ones shown)" if result.stats.malformed_lines > len(result.stats.malformed_line_numbers) else ""
        print(f"Skipped malformed lines at line numbers: {numbers}{more}", file=sys.stderr)

    return EXIT_FINDINGS if findings else EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
