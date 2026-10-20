from datetime import datetime

import pytest

from authlog_analyzer.models import EventKind
from authlog_analyzer.parser import (
    MAX_LINE_LENGTH,
    MAX_MALFORMED_REPORTED,
    MalformedLine,
    parse_line,
    parse_lines,
)
from tests.helpers import accepted_line, failed_line, syslog

YEAR = 2026


def test_failed_password_valid_user():
    line = syslog("Failed password for root from 192.0.2.10 port 51234 ssh2", "Oct 20 03:12:45")
    ev = parse_line(line, YEAR)
    assert ev.kind is EventKind.FAILED
    assert ev.username == "root"
    assert ev.source_ip == "192.0.2.10"
    assert ev.port == 51234
    assert ev.method == "password"
    assert ev.invalid_user is False
    assert ev.host == "synthetic-host"
    assert ev.timestamp == datetime(2026, 10, 20, 3, 12, 45)


def test_failed_password_invalid_user():
    line = syslog("Failed password for invalid user admin from 192.0.2.10 port 51234 ssh2")
    ev = parse_line(line, YEAR)
    assert ev.kind is EventKind.FAILED
    assert ev.username == "admin"
    assert ev.invalid_user is True


def test_username_literally_invalid_is_not_confused_with_invalid_user_marker():
    ev = parse_line(syslog("Failed password for invalid from 192.0.2.10 port 22 ssh2"), YEAR)
    assert ev.username == "invalid"
    assert ev.invalid_user is False


def test_failed_other_methods_are_failures_too():
    ev = parse_line(syslog("Failed publickey for deploy from 192.0.2.11 port 2200 ssh2"), YEAR)
    assert ev.kind is EventKind.FAILED
    assert ev.method == "publickey"


def test_failed_password_ipv6():
    line = syslog("Failed password for invalid user guest from 2001:db8::bad:1 port 40022 ssh2")
    ev = parse_line(line, YEAR)
    assert ev.source_ip == "2001:db8::bad:1"
    assert ev.invalid_user is True


def test_ipv6_is_normalised_so_spellings_group_together():
    a = parse_line(failed_line("2001:0DB8:0000:0000:0000:0000:0BAD:0001"), YEAR)
    b = parse_line(failed_line("2001:db8::bad:1"), YEAR)
    assert a.source_ip == b.source_ip == "2001:db8::bad:1"


def test_accepted_password_and_publickey():
    pw = parse_line(syslog("Accepted password for bob from 198.51.100.7 port 50000 ssh2"), YEAR)
    pk = parse_line(syslog("Accepted publickey for alice from 198.51.100.8 port 50001 ssh2"), YEAR)
    assert (pw.kind, pw.username, pw.method) == (EventKind.ACCEPTED, "bob", "password")
    assert (pk.kind, pk.username, pk.method) == (EventKind.ACCEPTED, "alice", "publickey")


def test_accepted_with_trailing_key_fingerprint_text():
    line = syslog("Accepted publickey for alice from 198.51.100.8 port 50001 ssh2: RSA SHA256:AAAA")
    ev = parse_line(line, YEAR)
    assert ev.username == "alice"
    assert ev.port == 50001


def test_invalid_user_line_with_and_without_port():
    with_port = parse_line(syslog("Invalid user oracle from 192.0.2.20 port 33000"), YEAR)
    without_port = parse_line(syslog("Invalid user oracle from 192.0.2.20"), YEAR)
    assert with_port.kind is EventKind.INVALID_USER
    assert with_port.username == "oracle"
    assert with_port.port == 33000
    assert without_port.port is None
    assert without_port.invalid_user is True


def test_invalid_user_with_empty_username():
    ev = parse_line(syslog("Invalid user  from 192.0.2.20 port 33000"), YEAR)
    assert ev.kind is EventKind.INVALID_USER
    assert ev.username == ""


def test_single_digit_day_with_padded_syslog_timestamp():
    ev = parse_line(failed_line("192.0.2.1", stamp="Oct  5 03:12:45"), YEAR)
    assert ev.timestamp == datetime(2026, 10, 5, 3, 12, 45)


def test_year_argument_is_applied():
    ev = parse_line(failed_line("192.0.2.1"), 2024)
    assert ev.timestamp.year == 2024


def test_leap_day_valid_in_leap_year_malformed_otherwise():
    line = failed_line("192.0.2.1", stamp="Feb 29 10:00:00")
    assert parse_line(line, 2024).timestamp == datetime(2024, 2, 29, 10, 0, 0)
    with pytest.raises(MalformedLine):
        parse_line(line, 2026)


def test_sshd_session_process_name_is_accepted():
    line = syslog("Failed password for root from 192.0.2.1 port 22 ssh2", proc="sshd-session")
    assert parse_line(line, YEAR).kind is EventKind.FAILED


def test_crlf_line_endings_are_handled():
    ev = parse_line(failed_line("192.0.2.1") + "\r\n", YEAR)
    assert ev.source_ip == "192.0.2.1"


@pytest.mark.parametrize(
    "line",
    [
        "Oct 20 12:00:00 synthetic-host CRON[200]: pam_unix(cron:session): session opened for user root",
        "Oct 20 12:00:00 synthetic-host sshd[1]: Server listening on 0.0.0.0 port 22.",
        "Oct 20 12:00:00 synthetic-host sshd[1]: Connection closed by 192.0.2.1 port 22 [preauth]",
        "Oct 20 12:00:00 synthetic-host sshd[1]: pam_unix(sshd:auth): authentication failure; rhost=192.0.2.1",
        "Oct 20 12:00:00 synthetic-host sudo: alice : TTY=pts/0 ; COMMAND=/bin/ls",
    ],
)
def test_valid_syslog_but_untracked_lines_return_none(line):
    assert parse_line(line, YEAR) is None


@pytest.mark.parametrize(
    "line",
    [
        "this is not a log line",
        "Oct 20",
        "Xyz 20 12:00:00 host sshd[1]: Failed password for root from 192.0.2.1 port 22 ssh2",
        "Oct 32 12:00:00 host sshd[1]: Failed password for root from 192.0.2.1 port 22 ssh2",
        "Oct 20 25:00:00 host sshd[1]: Failed password for root from 192.0.2.1 port 22 ssh2",
        "Oct 20 12:61:00 host sshd[1]: Failed password for root from 192.0.2.1 port 22 ssh2",
        "Oct 20 12:00:00 host sshd[1]: Failed password for root from not-an-ip port 22 ssh2",
        "Oct 20 12:00:00 host sshd[1]: Failed password for root from 192.0.2.256 port 22 ssh2",
        "Oct 20 12:00:00 host sshd[1]: Failed password for root from 192.0.2.1 port 99999 ssh2",
        "Oct 20 12:00:00 host sshd[1]: Failed password for",
        "Oct 20 12:00:00 host sshd[1]: Accepted publickey for alice",
        "Oct 20 12:00:00 host sshd[1]: Invalid user admin from not-an-ip",
        "\x00\x01\x02 binary junk",
    ],
)
def test_malformed_lines_raise(line):
    with pytest.raises(MalformedLine):
        parse_line(line, YEAR)


def test_overlong_line_is_malformed():
    line = failed_line("192.0.2.1", user="a" * MAX_LINE_LENGTH)
    with pytest.raises(MalformedLine):
        parse_line(line, YEAR)


def test_control_characters_in_username_are_preserved_for_later_sanitising():
    ev = parse_line(failed_line("192.0.2.1", user="\x1b[31mroot"), YEAR)
    assert ev.username == "\x1b[31mroot"


def test_parse_lines_counts_every_category():
    lines = [
        "# SYNTHETIC sample header",
        "",
        failed_line("192.0.2.1"),
        accepted_line("192.0.2.2"),
        "Oct 20 12:00:00 synthetic-host CRON[1]: nothing to see",
        "garbage line",
        "Oct 20 12:00:00 host sshd[1]: Failed password for root from bad-ip port 22 ssh2",
    ]
    result = parse_lines(lines, YEAR)
    s = result.stats
    assert s.total_lines == 7
    assert s.comment_lines == 1
    assert s.blank_lines == 1
    assert s.events == 2
    assert s.ignored_lines == 1
    assert s.malformed_lines == 2
    assert s.malformed_line_numbers == [6, 7]
    assert len(result.events) == 2
    assert [e.line_number for e in result.events] == [3, 4]


def test_parse_lines_empty_input():
    result = parse_lines([], YEAR)
    assert result.events == []
    assert result.stats.total_lines == 0
    assert result.stats.malformed_lines == 0


def test_parse_lines_only_blank_lines():
    result = parse_lines(["", "   ", "\n"], YEAR)
    assert result.stats.blank_lines == 3
    assert result.events == []


def test_malformed_line_numbers_are_capped_but_count_is_exact():
    result = parse_lines(["junk"] * (MAX_MALFORMED_REPORTED + 15), YEAR)
    assert result.stats.malformed_lines == MAX_MALFORMED_REPORTED + 15
    assert len(result.stats.malformed_line_numbers) == MAX_MALFORMED_REPORTED


def test_describe_mentions_malformed_count():
    result = parse_lines([failed_line("192.0.2.1"), "junk"], YEAR)
    text = result.stats.describe()
    assert "1 malformed" in text
    assert "1 auth events" in text
