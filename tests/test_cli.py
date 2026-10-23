"""CLI: file input, stdin, --report, --format json, flags."""

import io
import json
import sys

from pii_sanitizer.cli import main

SAMPLE = "mail a@example.com, ssn 123-45-6789, ref 99887766554433\n"


def _write(tmp_path, text=SAMPLE):
    path = tmp_path / "input.txt"
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_cli_file_input_prints_redacted(tmp_path, capsys):
    assert main(["sanitize", _write(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "a@example.com" not in out
    assert "[EMAIL_1]" in out
    assert "[SSN_1]" in out
    assert "[REDACTED_NUMBER_1]" in out


def test_cli_stdin_input(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO("mail a@example.com\n"))
    assert main(["sanitize", "-"]) == 0
    assert capsys.readouterr().out == "mail [EMAIL_1]\n"


def test_cli_report_written_to_file(tmp_path, capsys):
    report_path = tmp_path / "report.json"
    assert main(["sanitize", _write(tmp_path),
                 "--report", str(report_path)]) == 0
    data = json.loads(report_path.read_text(encoding="utf-8"))
    assert data["total_findings"] == 3
    assert data["counts_by_type"]["EMAIL"] == 1
    # stdout still carries only the redacted text
    assert "[EMAIL_1]" in capsys.readouterr().out


def test_cli_report_bare_flag_goes_to_stderr(tmp_path, capsys):
    assert main(["sanitize", _write(tmp_path), "--report"]) == 0
    captured = capsys.readouterr()
    assert "[EMAIL_1]" in captured.out
    assert "a@example.com" not in captured.out
    err = json.loads(captured.err)
    assert err["total_findings"] == 3


def test_cli_format_json(tmp_path, capsys):
    assert main(["sanitize", _write(tmp_path), "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["redacted_text"].startswith("mail [EMAIL_1]")
    assert payload["report"]["total_findings"] == 3


def test_cli_output_file(tmp_path, capsys):
    out_path = tmp_path / "out.txt"
    assert main(["sanitize", _write(tmp_path),
                 "--output", str(out_path)]) == 0
    assert "[SSN_1]" in out_path.read_text(encoding="utf-8")
    assert capsys.readouterr().out == ""


def test_cli_no_fail_closed_flag(tmp_path, capsys):
    assert main(["sanitize", _write(tmp_path), "--no-fail-closed"]) == 0
    out = capsys.readouterr().out
    assert "99887766554433" in out        # ambiguous number passes in strict
    assert "[SSN_1]" in out              # strict findings still redacted


def test_cli_disable_flag(tmp_path, capsys):
    assert main(["sanitize", _write(tmp_path), "--disable", "EMAIL"]) == 0
    out = capsys.readouterr().out
    assert "a@example.com" in out
    assert "[SSN_1]" in out


def test_cli_allow_flag(tmp_path, capsys):
    assert main(["sanitize", _write(tmp_path),
                 "--allow", "a@example.com"]) == 0
    out = capsys.readouterr().out
    assert "a@example.com" in out
    assert "[SSN_1]" in out


def test_cli_missing_file_returns_error(tmp_path, capsys):
    assert main(["sanitize", str(tmp_path / "nope.txt")]) == 2
    assert "error" in capsys.readouterr().err


def test_cli_empty_file(tmp_path, capsys):
    assert main(["sanitize", _write(tmp_path, "")]) == 0
    assert capsys.readouterr().out == "\n"
