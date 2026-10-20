"""Structural checks on the KQL files.

IMPORTANT: these tests do not execute KQL and cannot prove a query is correct
against a real Sentinel workspace. They check that every file has the required
header, a single non-empty query that starts from a known table, balanced
brackets and quotes, a time bound, and an entry in kql/README.md.
"""

import re
from pathlib import Path

import pytest

KQL_DIR = Path(__file__).resolve().parent.parent / "kql"
FILES = sorted(KQL_DIR.glob("*.kql"))

HEADER_LABELS = (
    "Title",
    "Data source table",
    "What it detects",
    "Likely false positives",
    "MITRE ATT&CK technique",
    "Tuning notes",
    "Status",
)
KNOWN_TABLES = {"SigninLogs", "SecurityEvent", "DeviceProcessEvents", "AuditLogs", "OfficeActivity"}
TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def split_file(path):
    """Return (header_text, body_text) where the header is the leading // comment block."""
    lines = path.read_text(encoding="utf-8").splitlines()
    header, i = [], 0
    while i < len(lines) and lines[i].startswith("//"):
        header.append(lines[i])
        i += 1
    return "\n".join(header), "\n".join(lines[i:])


def header_fields(header):
    fields, current = {}, None
    for line in header.splitlines():
        text = line[2:]
        m = re.match(r"\s*(" + "|".join(re.escape(l) for l in HEADER_LABELS) + r"):\s*(.*)$", text)
        if m and not text.startswith("   "):
            current = m.group(1)
            fields[current] = m.group(2).strip()
        elif current:
            fields[current] += " " + text.strip()
    return fields


def test_there_are_exactly_ten_numbered_kql_files():
    assert len(FILES) == 10
    assert [f.name[:2] for f in FILES] == [f"{n:02d}" for n in range(1, 11)]


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_header_has_every_required_field_in_order(path):
    header, _ = split_file(path)
    positions = []
    for label in HEADER_LABELS:
        matches = [i for i, line in enumerate(header.splitlines()) if line.startswith(f"// {label}:")]
        assert len(matches) == 1, f"{path.name}: expected one '{label}:' line"
        positions.append(matches[0])
    assert positions == sorted(positions)
    fields = header_fields(header)
    short_ok = {"Title", "Data source table"}
    for label in HEADER_LABELS:
        minimum = 5 if label in short_ok else 20
        assert len(fields[label]) >= minimum, f"{path.name}: '{label}' is empty or too short"


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_header_names_a_known_table_and_an_attack_technique(path):
    fields = header_fields(split_file(path)[0])
    assert fields["Data source table"] in KNOWN_TABLES
    assert TECHNIQUE_RE.search(fields["MITRE ATT&CK technique"])


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_status_line_is_honest_about_not_being_run(path):
    fields = header_fields(split_file(path)[0])
    assert "Not yet run" in fields["Status"]


def strip_strings_and_comments(body):
    out, i, n = [], 0, len(body)
    while i < n:
        if body.startswith("//", i):
            while i < n and body[i] != "\n":
                i += 1
            continue
        if body.startswith('@"', i):
            i += 2
            while i < n:
                if body.startswith('""', i):
                    i += 2
                    continue
                if body[i] == '"':
                    break
                i += 1
            i += 1
            continue
        if body[i] == '"':
            i += 1
            while i < n:
                if body[i] == "\\":
                    i += 2
                    continue
                if body[i] == '"':
                    break
                i += 1
            i += 1
            continue
        out.append(body[i])
        i += 1
    return "".join(out)


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_query_body_is_present_bounded_and_balanced(path):
    header, body = split_file(path)
    assert body.strip(), "no query after the header"
    assert "ago(" in body, "query has no time bound"
    table = header_fields(header)["Data source table"]
    assert re.search(rf"(?m)^{table}\s*$", body), "query should start a pipeline from the named table"
    cleaned = strip_strings_and_comments(body)
    stack, pairs = [], {")": "(", "]": "[", "}": "{"}
    for ch in cleaned:
        if ch in "([{":
            stack.append(ch)
        elif ch in ")]}":
            assert stack and stack.pop() == pairs[ch], "unbalanced brackets"
    assert not stack, "unclosed bracket"
    # Every continuation line of the pipeline starts with a pipe, and a query never ends on one.
    assert not cleaned.rstrip().endswith("|")


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_each_file_has_a_single_statement_query(path):
    _, body = split_file(path)
    cleaned = strip_strings_and_comments(body)
    # let statements end in ';' and the final tabular statement must not.
    last = cleaned.rstrip().splitlines()[-1]
    assert not last.rstrip().endswith(";")
    tabular = re.split(r";\s*\n", cleaned)[-1]
    assert tabular.count(";") == 0


def test_readme_lists_every_file_with_a_matching_technique():
    readme = (KQL_DIR / "README.md").read_text(encoding="utf-8")
    rows = {}
    for line in readme.splitlines():
        m = re.search(r"`(\d\d-[\w-]+\.kql)`", line)
        if m:
            rows[m.group(1)] = line
    assert set(rows) == {f.name for f in FILES}
    for path in FILES:
        header_ids = set(TECHNIQUE_RE.findall(header_fields(split_file(path)[0])["MITRE ATT&CK technique"]))
        row_ids = set(TECHNIQUE_RE.findall(rows[path.name]))
        assert row_ids and row_ids <= header_ids, f"{path.name}: README techniques {row_ids} vs header {header_ids}"
        table = header_fields(split_file(path)[0])["Data source table"]
        assert table in rows[path.name]


def test_readme_states_the_queries_have_not_been_run_live():
    readme = (KQL_DIR / "README.md").read_text(encoding="utf-8")
    assert "not yet run in a live sentinel workspace" in readme.lower()
