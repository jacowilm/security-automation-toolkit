"""Tests for the detection rules. Synthetic events only (RFC 5737 / 3849 addresses)."""

import pytest

from authlog_analyzer.detectors import (
    BRUTE_FORCE_HIGH_FACTOR,
    DetectionConfig,
    detect_all,
    detect_brute_force,
)
from authlog_analyzer.models import AuthEvent, EventKind
from tests.helpers import accepted, at, failed

ATTACKER = "203.0.113.50"
OTHER = "203.0.113.51"


def burst(ip, n, step_seconds=10, user="root", start=0):
    return [failed(ip, user, seconds=start + i * step_seconds) for i in range(n)]


# ---------------------------------------------------------------- config

@pytest.mark.parametrize(
    "kwargs",
    [{"threshold": 0}, {"window_minutes": 0}, {"window_minutes": -1}, {"spray_users": 0}],
)
def test_config_rejects_invalid_values(kwargs):
    with pytest.raises(ValueError):
        DetectionConfig(**kwargs)


def test_config_defaults_match_spec():
    cfg = DetectionConfig()
    assert (cfg.threshold, cfg.window_minutes, cfg.spray_users) == (5, 10, 5)


# ----------------------------------------------------------- brute force

def test_no_events_no_findings():
    assert detect_brute_force([]) == []
    assert detect_all([]) == []


def test_exactly_threshold_failures_in_window_is_a_finding():
    findings = detect_brute_force(burst(ATTACKER, 5))
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "AUTH-BRUTE-001"
    assert f.technique_id == "T1110.001"
    assert f.count == 5
    assert f.source_ip == ATTACKER
    assert f.severity == "medium"
    assert f.usernames == ("root",)
    assert f.first_seen == at(0)
    assert f.last_seen == at(40)


def test_one_below_threshold_is_not_a_finding():
    assert detect_brute_force(burst(ATTACKER, 4)) == []


def test_failures_outside_the_window_do_not_count():
    # Five failures, 3 minutes apart: any 10 minute window holds at most 4.
    events = [failed(ATTACKER, minutes=3 * i) for i in range(5)]
    assert detect_brute_force(events) == []


def test_window_boundary_is_inclusive():
    # First and fifth failure exactly 10 minutes apart: still one window.
    events = [failed(ATTACKER, minutes=m) for m in (0, 2.5, 5, 7.5, 10)]
    assert len(detect_brute_force(events)) == 1


def test_one_second_past_the_window_is_not_a_finding():
    events = [failed(ATTACKER, seconds=s) for s in (0, 150, 300, 450, 601)]
    assert detect_brute_force(events) == []


def test_threshold_is_per_source_ip():
    events = burst(ATTACKER, 3) + burst(OTHER, 3, start=5)
    assert detect_brute_force(events) == []


def test_two_separate_bursts_from_one_ip_are_two_findings():
    events = burst(ATTACKER, 5) + burst(ATTACKER, 5, start=3600)
    findings = detect_brute_force(events)
    assert len(findings) == 2
    assert findings[0].last_seen < findings[1].first_seen


def test_long_attack_is_one_merged_finding_with_full_count():
    events = burst(ATTACKER, 60, step_seconds=20)  # 20 minutes of failures
    findings = detect_brute_force(events)
    assert len(findings) == 1
    assert findings[0].count == 60
    assert findings[0].first_seen == at(0)
    assert findings[0].last_seen == at(59 * 20)


def test_slow_tail_overlapping_a_burst_is_merged_not_duplicated():
    # Burst, then a slower trickle whose windows overlap the burst's last event.
    events = burst(ATTACKER, 5) + [failed(ATTACKER, seconds=40 + 100 * i) for i in range(1, 8)]
    findings = detect_brute_force(events)
    assert len(findings) == 1


def test_input_order_does_not_matter():
    events = burst(ATTACKER, 6)
    assert detect_brute_force(list(reversed(events))) == detect_brute_force(events)


def test_only_failed_events_count():
    events = burst(ATTACKER, 3) + [
        accepted(ATTACKER, seconds=5),
        AuthEvent(at(6), EventKind.INVALID_USER, "admin", ATTACKER),
        AuthEvent(at(7), EventKind.INVALID_USER, "admin", ATTACKER),
    ]
    assert detect_brute_force(events) == []


def test_usernames_are_sorted_and_unique():
    users = ["root", "admin", "root", "test", "admin"]
    events = [failed(ATTACKER, u, seconds=i) for i, u in enumerate(users)]
    f = detect_brute_force(events)[0]
    assert f.usernames == ("admin", "root", "test")


def test_severity_escalates_to_high_at_five_times_threshold():
    cfg = DetectionConfig(threshold=5)
    just_below = burst(ATTACKER, BRUTE_FORCE_HIGH_FACTOR * 5 - 1)
    at_limit = burst(ATTACKER, BRUTE_FORCE_HIGH_FACTOR * 5)
    assert detect_brute_force(just_below, cfg)[0].severity == "medium"
    assert detect_brute_force(at_limit, cfg)[0].severity == "high"


def test_custom_threshold_and_window():
    events = [failed(ATTACKER, seconds=s) for s in (0, 20, 40)]
    assert detect_brute_force(events) == []
    assert len(detect_brute_force(events, DetectionConfig(threshold=3))) == 1
    wide = [failed(ATTACKER, minutes=m) for m in (0, 20, 40)]
    assert detect_brute_force(wide, DetectionConfig(threshold=3)) == []
    assert len(detect_brute_force(wide, DetectionConfig(threshold=3, window_minutes=40))) == 1


def test_threshold_of_one_flags_every_failure_cluster():
    assert len(detect_brute_force([failed(ATTACKER)], DetectionConfig(threshold=1))) == 1


def test_ipv6_source_is_supported():
    findings = detect_brute_force(burst("2001:db8::bad:1", 5))
    assert findings[0].source_ip == "2001:db8::bad:1"


def test_windows_that_overlap_on_a_shared_failure_merge_into_one_episode():
    # The window dips below the threshold between minute 2 and minute 12 but
    # the two qualifying windows share the failure at minute 2.
    cfg = DetectionConfig(threshold=3)
    events = [failed(ATTACKER, minutes=m) for m in (0, 1, 2, 11.5, 12)]
    findings = detect_brute_force(events, cfg)
    assert len(findings) == 1
    assert findings[0].count == 5
