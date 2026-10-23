"""Command-line interface.

Usage:
    python -m pii_sanitizer sanitize input.txt
    python -m pii_sanitizer sanitize input.txt --report report.json
    python -m pii_sanitizer sanitize input.txt --report   # report -> stderr
    cat input.txt | python -m pii_sanitizer sanitize -   # stdin
    python -m pii_sanitizer sanitize input.txt --format json
"""

from __future__ import annotations

import argparse
import json
import sys

from .models import SanitizerConfig
from .sanitizer import Sanitizer


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pii-sanitizer",
        description="Fail-closed PII redaction (offline, standard library only).",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    san = sub.add_parser("sanitize", help="redact PII from a file or stdin")
    san.add_argument("input", help="input file path, or '-' for stdin")
    san.add_argument("--report", nargs="?", const="-", default=None,
                     metavar="PATH",
                     help="write the JSON report to PATH; with no PATH, "
                          "print it to stderr so stdout stays clean")
    san.add_argument("--format", choices=("text", "json"), default="text",
                     help="'json' prints {redacted_text, report} on stdout")
    san.add_argument("--output", metavar="PATH",
                     help="write redacted text to PATH instead of stdout")
    san.add_argument("--no-fail-closed", action="store_true",
                     help="strict mode: only checksum/structure-valid "
                          "findings are redacted")
    san.add_argument("--allow", action="append", default=[], metavar="VALUE",
                     help="exact value to never redact (repeatable)")
    san.add_argument("--disable", action="append", default=[], metavar="TYPE",
                     help="detector type to disable, e.g. PHONE (repeatable)")
    return parser


def _read_input(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command != "sanitize":  # pragma: no cover - argparse enforces
        return 2
    try:
        text = _read_input(args.input)
    except OSError as exc:
        print(f"error: cannot read input: {exc}", file=sys.stderr)
        return 2

    config = SanitizerConfig(
        disabled_types=frozenset(t.upper() for t in args.disable),
        allowlist=tuple(args.allow),
        fail_closed=not args.no_fail_closed,
    )
    result = Sanitizer(config).sanitize(text)
    report_json = json.dumps(result.report.to_dict(), indent=2)

    if args.format == "json":
        payload = {"redacted_text": result.text, "report": result.report.to_dict()}
        print(json.dumps(payload, indent=2))
    elif args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(result.text)
    else:
        sys.stdout.write(result.text)
        if not result.text.endswith("\n"):
            sys.stdout.write("\n")

    if args.report is not None:
        if args.report == "-":
            print(report_json, file=sys.stderr)
        else:
            with open(args.report, "w", encoding="utf-8") as handle:
                handle.write(report_json + "\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
