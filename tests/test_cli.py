import json
import random
import subprocess
import sys
from pathlib import Path

import pytest

from authlog_analyzer.cli import main
from authlog_analyzer.parser import parse_lines
from tests.helpers import accepted_line, failed_line

REPO_ROOT = Path(__file__).resolve().parent.parent
ATTACKER = "203.0.113.50"


def write_log(tmp_path, lines, name="auth.log"):
    path = tmp_path / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


def attack_log(tmp_path, n=6):
    lines = [failed_line(ATTACKER, stamp=f"Oct 20 12:00:{i * 5:02d}") for i in range(n)]
    return write_log(tmp_path, lines)


# ------------------------------------------------------------ exit codes

def test_exit_1_when_findings(tmp_path, capsys):
    assert main([attack_log(tmp_path)]) == 1
    out = capsys.readouterr()
    assert "AUTH-BRUTE-001" in out.out
    assert ATTACKER in out.out


def test_exit_0_when_no_findings(tmp_path, capsys):
    log = write_log(tmp_path, [failed_line("192.0.2.1"), accepted_line("198.51.100.4")])
    assert main([log]) == 0
    assert "No findings." in capsys.readouterr().out


def test_exit_0_on_empty_file(tmp_path, capsys):
    path = tmp_path / "empty.log"
    path.write_text("")
    assert main([str(path)]) == 0
    captured = capsys.readouterr()
    assert "No findings." in captured.out
    assert "Read 0 lines" in captured.err


def test_exit_2_on_missing_file(tmp_path, capsys):
    assert main([str(tmp_path / "nope.log")]) == 2
    assert "cannot read" in capsys.readouterr().err


def test_exit_2_when_input_is_a_directory(tmp_path, capsys):
    assert main([str(tmp_path)]) == 2
    assert "cannot read" in capsys.readouterr().err


@pytest.mark.parametrize(
    "extra",
    [
        ["--threshold", "0"],
        ["--threshold", "abc"],
        ["--window", "abc"],
        ["--window", "0"],
        ["--window", "-5"],
        ["--window", "nan"],
        ["--window", "inf"],
        ["--spray-users", "0"],
        ["--year", "1800"],
        ["--year", "next"],
        ["--format", "xml"],
    ],
)
def test_exit_2_on_invalid_arguments(tmp_path, extra, capsys):
    assert main([attack_log(tmp_path), *extra]) == 2
    capsys.readouterr()


def test_exit_2_when_no_arguments(capsys):
    assert main([]) == 2
    capsys.readouterr()


def test_help_and_version_exit_0(capsys):
    assert main(["--help"]) == 0
    assert main(["--version"]) == 0
    out = capsys.readouterr().out
    assert "Exit codes" in out
    assert "0.1.0" in out


# ---------------------------------------------------------------- formats

def test_json_format_to_stdout(tmp_path, capsys):
    assert main([attack_log(tmp_path), "--format", "json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["findings"] == 1
    assert data["findings"][0]["source_ip"] == ATTACKER


def test_csv_format_to_stdout(tmp_path, capsys):
    assert main([attack_log(tmp_path), "--format", "csv"]) == 1
    out = capsys.readouterr().out
    assert out.splitlines()[0].startswith("rule_id,rule_name")
    assert ATTACKER in out.splitlines()[1]


def test_summary_goes_to_stderr_so_stdout_stays_machine_readable(tmp_path, capsys):
    main([attack_log(tmp_path), "--format", "json"])
    captured = capsys.readouterr()
    json.loads(captured.out)  # would raise if the summary leaked into stdout
    assert "auth events" in captured.err


def test_output_file_is_written_and_stdout_is_quiet(tmp_path, capsys):
    out_path = tmp_path / "report.json"
    code = main([attack_log(tmp_path), "--format", "json", "--output", str(out_path)])
    assert code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(out_path.read_text())["summary"]["findings"] == 1
    assert "Wrote json report" in captured.err


def test_output_to_unwritable_path_is_exit_2(tmp_path, capsys):
    bad = tmp_path / "missing_dir" / "report.csv"
    assert main([attack_log(tmp_path), "--output", str(bad)]) == 2
    assert "cannot write" in capsys.readouterr().err


# -------------------------------------------------------------- tuning

def test_threshold_option_changes_the_outcome(tmp_path, capsys):
    log = attack_log(tmp_path, n=6)
    assert main([log, "--threshold", "7"]) == 0
    assert main([log, "--threshold", "6"]) == 1
    capsys.readouterr()


def test_window_option_changes_the_outcome(tmp_path, capsys):
    lines = [failed_line(ATTACKER, stamp=f"Oct 20 12:{m:02d}:00") for m in (0, 4, 8, 12, 16)]
    log = write_log(tmp_path, lines)
    assert main([log]) == 0  # 16 minutes spread, default window is 10
    assert main([log, "--window", "16"]) == 1
    capsys.readouterr()


def test_spray_users_option(tmp_path, capsys):
    users = ["admin", "test", "oracle"]
    lines = [failed_line(ATTACKER, u, f"Oct 20 12:00:{i:02d}") for i, u in enumerate(users)]
    log = write_log(tmp_path, lines)
    assert main([log, "--format", "json"]) == 0
    capsys.readouterr()
    assert main([log, "--format", "json", "--threshold", "99", "--spray-users", "3"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["findings"][0]["rule_id"] == "AUTH-SPRAY-001"


def test_year_option_is_applied(tmp_path, capsys):
    main([attack_log(tmp_path), "--format", "json", "--year", "2024"])
    data = json.loads(capsys.readouterr().out)
    assert data["findings"][0]["first_seen"].startswith("2024-10-20")


def test_default_year_is_the_current_year(tmp_path, capsys):
    from datetime import datetime

    main([attack_log(tmp_path), "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data["findings"][0]["first_seen"].startswith(str(datetime.now().year))


# ------------------------------------------------------- odd input

def test_malformed_lines_are_skipped_counted_and_reported(tmp_path, capsys):
    lines = [failed_line("192.0.2.1"), "total garbage", "Oct 99 99:99:99 x sshd[1]: Failed password for"]
    code = main([write_log(tmp_path, lines), "--format", "json"])
    assert code == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["summary"]["malformed_lines"] == 2
    assert "2 malformed" in captured.err
    assert "line numbers: 2, 3" in captured.err


def test_findings_still_reported_alongside_malformed_lines(tmp_path, capsys):
    lines = ["junk"] + [failed_line(ATTACKER, stamp=f"Oct 20 12:00:{i:02d}") for i in range(5)] + ["more junk"]
    assert main([write_log(tmp_path, lines)]) == 1
    assert "2 malformed" in capsys.readouterr().err


def test_binary_and_invalid_utf8_input_does_not_crash(tmp_path, capsys):
    path = tmp_path / "binary.log"
    path.write_bytes(b"\x00\xff\xfe\x80garbage\n" + bytes(range(256)) * 8 + b"\n\xc3\x28\n")
    assert main([str(path)]) == 0
    capsys.readouterr()


def test_non_ascii_username_in_log_is_handled(tmp_path, capsys):
    lines = [failed_line(ATTACKER, "josé", f"Oct 20 12:00:{i:02d}") for i in range(5)]
    assert main([write_log(tmp_path, lines), "--format", "json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["findings"][0]["usernames"] == ["josé"]


def test_lines_with_only_unrelated_syslog_chatter(tmp_path, capsys):
    lines = ["Oct 20 12:00:00 synthetic-host CRON[1]: session opened"] * 20
    assert main([write_log(tmp_path, lines)]) == 0
    assert "20 ignored" in capsys.readouterr().err


def test_parser_never_raises_on_random_input():
    rng = random.Random(20261021)
    alphabet = "abcXYZ 0123456789:.-_[]()#\x00\x1bé中\t\r"
    fragments = ["Oct ", "sshd[", "Failed password for ", "Accepted ", "Invalid user ", " from ", " port ", "::1", "999.1.1.1"]
    lines = []
    for _ in range(2000):
        pieces = [rng.choice(fragments) if rng.random() < 0.4 else rng.choice(alphabet) for _ in range(rng.randint(0, 40))]
        lines.append("".join(pieces))
    result = parse_lines(lines, 2026)
    assert result.stats.total_lines == 2000
    stats = result.stats
    assert stats.events + stats.ignored_lines + stats.malformed_lines + stats.blank_lines + stats.comment_lines == 2000


# ----------------------------------------------------- real subprocess

def run_module(*args):
    return subprocess.run(
        [sys.executable, "-m", "authlog_analyzer", *args],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=30,
    )


def test_python_dash_m_entry_point_exit_codes(tmp_path):
    log = attack_log(tmp_path)
    found = run_module(log)
    assert found.returncode == 1
    assert "AUTH-BRUTE-001" in found.stdout
    assert run_module(log, "--threshold", "50").returncode == 0
    assert run_module(str(tmp_path / "missing")).returncode == 2
