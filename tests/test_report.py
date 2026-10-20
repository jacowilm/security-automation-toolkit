import csv
import io
import json
from datetime import datetime

import pytest

from authlog_analyzer.detectors import detect_all
from authlog_analyzer.models import Finding
from authlog_analyzer.parser import ParseStats
from authlog_analyzer.report import (
    CSV_COLUMNS,
    csv_safe,
    display_safe,
    render,
    render_csv,
    render_json,
    render_table,
)
from tests.helpers import accepted, failed


def make_finding(**overrides) -> Finding:
    base = dict(
        rule_id="AUTH-BRUTE-001",
        rule_name="SSH brute force",
        severity="medium",
        source_ip="203.0.113.50",
        usernames=("admin", "root"),
        first_seen=datetime(2026, 10, 20, 12, 0, 0),
        last_seen=datetime(2026, 10, 20, 12, 3, 0),
        count=7,
        technique_id="T1110.001",
        technique_name="Brute Force: Password Guessing",
        detail="7 failed logins",
    )
    base.update(overrides)
    return Finding(**base)


# ------------------------------------------------------------------ CSV

def test_csv_has_header_and_one_row_per_finding():
    out = render_csv([make_finding(), make_finding(source_ip="203.0.113.51")])
    rows = list(csv.reader(io.StringIO(out)))
    assert tuple(rows[0]) == CSV_COLUMNS
    assert len(rows) == 3
    record = dict(zip(CSV_COLUMNS, rows[1]))
    assert record["rule_id"] == "AUTH-BRUTE-001"
    assert record["usernames"] == "admin;root"
    assert record["first_seen"] == "2026-10-20T12:00:00"
    assert record["count"] == "7"
    assert record["technique_id"] == "T1110.001"


def test_csv_with_no_findings_is_just_the_header():
    rows = list(csv.reader(io.StringIO(render_csv([]))))
    assert rows == [list(CSV_COLUMNS)]


@pytest.mark.parametrize("prefix", ["=", "+", "-", "@", "\t", "\r"])
def test_csv_formula_prefixes_are_neutralised(prefix):
    assert csv_safe(prefix + "cmd") == "'" + prefix + "cmd"


def test_csv_safe_leaves_normal_text_alone():
    assert csv_safe("root") == "root"
    assert csv_safe("") == ""


def test_csv_injection_in_username_is_neutralised_end_to_end():
    out = render_csv([make_finding(usernames=("=HYPERLINK(\"http://x\")",))])
    cell = list(csv.reader(io.StringIO(out)))[1][CSV_COLUMNS.index("usernames")]
    assert cell.startswith("'=")


def test_csv_commas_and_quotes_survive_round_trip():
    out = render_csv([make_finding(detail='has, comma and "quotes"')])
    row = list(csv.reader(io.StringIO(out)))[1]
    assert row[CSV_COLUMNS.index("detail")] == 'has, comma and "quotes"'


# ----------------------------------------------------------------- JSON

def test_json_structure_and_types():
    stats = ParseStats(total_lines=10, events=6, ignored_lines=2, malformed_lines=1, blank_lines=1)
    data = json.loads(render_json([make_finding()], stats))
    assert data["summary"] == {
        "findings": 1,
        "lines_read": 10,
        "auth_events": 6,
        "ignored_lines": 2,
        "malformed_lines": 1,
        "blank_or_comment_lines": 1,
    }
    finding = data["findings"][0]
    assert finding["usernames"] == ["admin", "root"]
    assert finding["count"] == 7
    assert finding["first_seen"] == "2026-10-20T12:00:00"
    assert finding["technique_id"] == "T1110.001"


def test_json_without_stats_still_has_finding_count():
    data = json.loads(render_json([]))
    assert data == {"summary": {"findings": 0}, "findings": []}


def test_json_escapes_control_characters():
    out = render_json([make_finding(usernames=("\x1b[31mred",))])
    assert "\x1b" not in out
    assert json.loads(out)["findings"][0]["usernames"] == ["\x1b[31mred"]


# ---------------------------------------------------------------- table

def test_table_has_aligned_header_rows_and_tally():
    out = render_table([make_finding(), make_finding(severity="high", rule_id="AUTH-SUCCESS-001")])
    lines = out.splitlines()
    assert lines[0].startswith("SEVERITY")
    assert set(lines[1].replace(" ", "")) == {"-"}
    assert "AUTH-BRUTE-001" in out and "T1110.001" in out
    assert lines[-1] == "2 finding(s): 1 high, 1 medium"
    # Columns stay aligned: every data row starts the RULE column at the same offset.
    offsets = {line.index("AUTH-") for line in lines if "AUTH-" in line}
    assert len(offsets) == 1


def test_table_with_no_findings():
    assert render_table([]) == "No findings.\n"


def test_table_replaces_control_characters_in_usernames():
    out = render_table([make_finding(usernames=("\x1b[2Jroot",))])
    assert "\x1b" not in out
    assert "?[2Jroot" in out


def test_table_truncates_long_username_lists():
    names = tuple(f"user{i:03d}" for i in range(40))
    out = render_table([make_finding(usernames=names)])
    assert "..." in out
    assert all(len(line) < 200 for line in out.splitlines())


def test_display_safe_keeps_printable_unicode():
    assert display_safe("josé") == "josé"
    assert display_safe("a\x00b\nc") == "a?b?c"


# --------------------------------------------------------------- render

def test_render_dispatches_by_format():
    findings = detect_all([failed("203.0.113.9", seconds=i) for i in range(5)] + [accepted("198.51.100.4")])
    assert render(findings, "table").startswith("SEVERITY")
    assert render(findings, "csv").startswith("rule_id,")
    assert json.loads(render(findings, "json"))["summary"]["findings"] == len(findings)


def test_render_rejects_unknown_format():
    with pytest.raises(ValueError):
        render([], "xml")
