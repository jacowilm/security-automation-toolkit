"""Parser for Linux sshd auth.log lines (traditional syslog format).

The traditional syslog timestamp has no year ("Oct 20 03:12:45"), so the
caller supplies one. Lines are classified three ways:

* an :class:`AuthEvent` for the sshd messages the analyzer cares about,
* ``None`` for valid syslog lines that are not tracked (cron, PAM, other
  sshd chatter), which are counted as "ignored",
* a :class:`MalformedLine` error for lines that cannot be interpreted
  (not syslog at all, impossible dates, bad IP addresses and so on).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable

from .models import AuthEvent, EventKind

# Longer lines are treated as malformed. rsyslog truncates at 8 KiB by default,
# so anything bigger is either corrupt or hostile.
MAX_LINE_LENGTH = 16384

# How many malformed line numbers to remember for the report.
MAX_MALFORMED_REPORTED = 10

_MONTHS = {
    name: idx
    for idx, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        start=1,
    )
}

_SSHD_PROCESSES = {"sshd", "sshd-session"}  # OpenSSH 9.8+ logs from sshd-session

_SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[A-Za-z0-9_.\-/]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$",
    re.ASCII,
)

_FAILED_RE = re.compile(
    r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)",
    re.ASCII,
)
_ACCEPTED_RE = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)",
    re.ASCII,
)
_INVALID_USER_RE = re.compile(
    r"^Invalid user\s+(?:(?P<user>\S+)\s+)?from\s+(?P<ip>\S+)(?:\s+port\s+(?P<port>\d+))?",
    re.ASCII,
)


class MalformedLine(ValueError):
    """Raised when a line cannot be parsed as a syslog or sshd auth line."""


@dataclass
class ParseStats:
    """Counters describing what happened while reading a log."""

    total_lines: int = 0
    blank_lines: int = 0
    comment_lines: int = 0
    ignored_lines: int = 0
    malformed_lines: int = 0
    events: int = 0
    malformed_line_numbers: list[int] = field(default_factory=list)

    def describe(self) -> str:
        """One line human summary."""
        return (
            f"Read {self.total_lines} lines: {self.events} auth events, "
            f"{self.ignored_lines} ignored, {self.malformed_lines} malformed, "
            f"{self.blank_lines + self.comment_lines} blank or comment."
        )


@dataclass
class ParseResult:
    events: list[AuthEvent]
    stats: ParseStats


def _validate_ip(raw: str) -> str:
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        raise MalformedLine(f"invalid IP address: {raw[:64]!r}") from None


def _validate_port(raw: str | None) -> int | None:
    if raw is None:
        return None
    port = int(raw)
    if not 0 <= port <= 65535:
        raise MalformedLine(f"port out of range: {port}")
    return port


def _parse_timestamp(mon: str, day: str, clock: str, year: int) -> datetime:
    month = _MONTHS.get(mon)
    if month is None:
        raise MalformedLine(f"unknown month: {mon!r}")
    hour, minute, second = (int(part) for part in clock.split(":"))
    try:
        return datetime(year, month, int(day), hour, minute, second)
    except ValueError as exc:
        raise MalformedLine(f"invalid date or time: {exc}") from None


def parse_line(line: str, year: int, line_number: int = 0) -> AuthEvent | None:
    """Parse one log line.

    Returns an :class:`AuthEvent`, or ``None`` if the line is valid syslog but
    not one of the tracked sshd messages. Raises :class:`MalformedLine` if the
    line cannot be interpreted.
    """
    line = line.rstrip("\r\n")
    if len(line) > MAX_LINE_LENGTH:
        raise MalformedLine("line too long")

    match = _SYSLOG_RE.match(line)
    if match is None:
        raise MalformedLine("not a syslog line")

    timestamp = _parse_timestamp(match["mon"], match["day"], match["time"], year)

    if match["proc"] not in _SSHD_PROCESSES:
        return None

    message = match["msg"]
    host = match["host"]

    if message.startswith("Failed "):
        m = _FAILED_RE.match(message)
        if m is None:
            raise MalformedLine("unrecognised 'Failed' message")
        return AuthEvent(
            timestamp=timestamp,
            kind=EventKind.FAILED,
            username=m["user"],
            source_ip=_validate_ip(m["ip"]),
            port=_validate_port(m["port"]),
            method=m["method"],
            host=host,
            line_number=line_number,
            invalid_user=m["invalid"] is not None,
        )

    if message.startswith("Accepted "):
        m = _ACCEPTED_RE.match(message)
        if m is None:
            raise MalformedLine("unrecognised 'Accepted' message")
        return AuthEvent(
            timestamp=timestamp,
            kind=EventKind.ACCEPTED,
            username=m["user"],
            source_ip=_validate_ip(m["ip"]),
            port=_validate_port(m["port"]),
            method=m["method"],
            host=host,
            line_number=line_number,
        )

    if message.startswith("Invalid user"):
        m = _INVALID_USER_RE.match(message)
        if m is None:
            raise MalformedLine("unrecognised 'Invalid user' message")
        return AuthEvent(
            timestamp=timestamp,
            kind=EventKind.INVALID_USER,
            username=m["user"] or "",
            source_ip=_validate_ip(m["ip"]),
            port=_validate_port(m["port"]),
            host=host,
            line_number=line_number,
            invalid_user=True,
        )

    return None


def parse_lines(lines: Iterable[str], year: int) -> ParseResult:
    """Parse many lines, never raising on bad input.

    Blank lines and lines starting with ``#`` (used to label the synthetic
    sample file) are counted separately and skipped.
    """
    stats = ParseStats()
    events: list[AuthEvent] = []

    for number, raw in enumerate(lines, start=1):
        stats.total_lines += 1
        text = raw.strip()
        if not text:
            stats.blank_lines += 1
            continue
        if text.startswith("#"):
            stats.comment_lines += 1
            continue
        try:
            event = parse_line(raw, year, number)
        except MalformedLine:
            stats.malformed_lines += 1
            if len(stats.malformed_line_numbers) < MAX_MALFORMED_REPORTED:
                stats.malformed_line_numbers.append(number)
            continue
        if event is None:
            stats.ignored_lines += 1
        else:
            stats.events += 1
            events.append(event)

    return ParseResult(events=events, stats=stats)
