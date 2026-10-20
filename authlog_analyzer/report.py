"""Report formatters: aligned text table, CSV and JSON.

Log data is attacker controlled (a username is whatever the client typed), so
the formatters defend the people who read the output:

* CSV cells that begin with ``= + - @`` (or a tab or carriage return) get a
  leading apostrophe so spreadsheets do not evaluate them as formulas.
* The text table replaces control characters (for example terminal escape
  sequences hidden in a username) with ``?``.
* JSON escapes everything by construction.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Iterable

from .models import SEVERITIES, Finding
from .parser import ParseStats

FORMATS = ("table", "csv", "json")

CSV_COLUMNS = (
    "rule_id",
    "rule_name",
    "severity",
    "source_ip",
    "usernames",
    "first_seen",
    "last_seen",
    "count",
    "technique_id",
    "technique_name",
    "detail",
)

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

# Maximum width of the USERNAMES column in the text table.
_USERNAMES_WIDTH = 40


def csv_safe(value: str) -> str:
    """Neutralise spreadsheet formula injection in a CSV cell."""
    if value and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def display_safe(value: str) -> str:
    """Replace non-printable characters so they cannot drive a terminal."""
    return "".join(ch if ch.isprintable() else "?" for ch in value)


def _stamp(finding_time) -> str:
    return finding_time.strftime("%Y-%m-%d %H:%M:%S")


def render_csv(findings: Iterable[Finding]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for f in findings:
        writer.writerow(
            [
                csv_safe(f.rule_id),
                csv_safe(f.rule_name),
                csv_safe(f.severity),
                csv_safe(f.source_ip),
                csv_safe(";".join(f.usernames)),
                f.first_seen.isoformat(),
                f.last_seen.isoformat(),
                f.count,
                csv_safe(f.technique_id),
                csv_safe(f.technique_name),
                csv_safe(f.detail),
            ]
        )
    return buffer.getvalue()


def _summary_dict(findings: list[Finding], stats: ParseStats | None) -> dict:
    summary: dict = {"findings": len(findings)}
    if stats is not None:
        summary.update(
            lines_read=stats.total_lines,
            auth_events=stats.events,
            ignored_lines=stats.ignored_lines,
            malformed_lines=stats.malformed_lines,
            blank_or_comment_lines=stats.blank_lines + stats.comment_lines,
        )
    return summary


def render_json(findings: Iterable[Finding], stats: ParseStats | None = None) -> str:
    items = list(findings)
    payload = {
        "summary": _summary_dict(items, stats),
        "findings": [f.to_dict() for f in items],
    }
    return json.dumps(payload, indent=2) + "\n"


def _usernames_cell(names: tuple[str, ...]) -> str:
    text = display_safe(",".join(names))
    if len(text) > _USERNAMES_WIDTH:
        text = text[: _USERNAMES_WIDTH - 3] + "..."
    return text


def render_table(findings: Iterable[Finding]) -> str:
    items = list(findings)
    if not items:
        return "No findings.\n"

    headers = ("SEVERITY", "RULE", "SOURCE IP", "USERNAMES", "FIRST SEEN", "LAST SEEN", "COUNT", "ATT&CK")
    rows = [
        (
            f.severity,
            f.rule_id,
            display_safe(f.source_ip),
            _usernames_cell(f.usernames),
            _stamp(f.first_seen),
            _stamp(f.last_seen),
            str(f.count),
            f.technique_id,
        )
        for f in items
    ]
    widths = [max(len(headers[i]), *(len(row[i]) for row in rows)) for i in range(len(headers))]

    def line(cells) -> str:
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(cells)).rstrip()

    out = [line(headers), line(["-" * w for w in widths])]
    out.extend(line(row) for row in rows)

    tally = ", ".join(
        f"{sum(1 for f in items if f.severity == sev)} {sev}"
        for sev in SEVERITIES
        if any(f.severity == sev for f in items)
    )
    out.append("")
    out.append(f"{len(items)} finding(s): {tally}")
    return "\n".join(out) + "\n"


def render(findings: Iterable[Finding], fmt: str, stats: ParseStats | None = None) -> str:
    items = list(findings)
    if fmt == "table":
        return render_table(items)
    if fmt == "csv":
        return render_csv(items)
    if fmt == "json":
        return render_json(items, stats)
    raise ValueError(f"unknown format: {fmt!r} (expected one of {', '.join(FORMATS)})")
