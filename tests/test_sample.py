"""Integration tests against the synthetic sample log in samples/."""

import ipaddress
import re
from collections import Counter
from pathlib import Path

from authlog_analyzer.detectors import detect_all
from authlog_analyzer.parser import parse_lines

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "auth.log.sample"

# RFC 5737 and RFC 3849 documentation ranges, plus the unspecified/loopback
# addresses that appear in "Server listening on" lines.
DOC_NETWORKS = [
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "0.0.0.0/32", "::/128")
]


def load():
    with open(SAMPLE, encoding="utf-8") as fh:
        return parse_lines(fh, 2026)


def test_sample_is_labelled_synthetic():
    assert "SYNTHETIC SAMPLE DATA" in SAMPLE.read_text(encoding="utf-8").splitlines()[0]


def test_sample_size_is_reasonable():
    assert 60 <= len(SAMPLE.read_text(encoding="utf-8").splitlines()) <= 120


def test_every_address_in_the_sample_is_a_documentation_address():
    text = SAMPLE.read_text(encoding="utf-8")
    candidates = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))
    candidates |= set(re.findall(r"\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b", text, re.IGNORECASE))
    assert candidates, "expected to find addresses"
    for raw in candidates:
        try:
            addr = ipaddress.ip_address(raw)
        except ValueError:
            continue  # e.g. a clock time such as 06:00:01 matched the IPv6 pattern
        assert any(addr in net for net in DOC_NETWORKS), f"{raw} is not a documentation address"


def test_sample_parses_with_exactly_one_malformed_line():
    stats = load().stats
    assert stats.malformed_lines == 1
    assert stats.events > 50
    assert stats.ignored_lines > 0


def test_sample_produces_the_documented_findings():
    findings = detect_all(load().events)
    by_rule = Counter(f.rule_id for f in findings)
    assert by_rule == {"AUTH-BRUTE-001": 3, "AUTH-SPRAY-001": 1, "AUTH-SUCCESS-001": 1}

    success = next(f for f in findings if f.rule_id == "AUTH-SUCCESS-001")
    assert success.source_ip == "198.51.100.150"
    assert success.severity == "high"

    spray = next(f for f in findings if f.rule_id == "AUTH-SPRAY-001")
    assert spray.source_ip == "203.0.113.99"
    assert len(spray.usernames) == 8

    big = next(f for f in findings if f.source_ip == "203.0.113.50")
    assert big.severity == "high"
    assert big.count >= 25


def test_benign_noise_is_not_flagged():
    flagged = {f.source_ip for f in detect_all(load().events)}
    assert "203.0.113.77" not in flagged  # slow drip, never inside one window
    assert "2001:db8::bad:1" not in flagged  # three guesses, below threshold
    assert "198.51.100.77" not in flagged  # a user who mistyped a password
    assert "198.51.100.23" not in flagged
