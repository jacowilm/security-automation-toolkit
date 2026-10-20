"""Tests for the detection rules. Synthetic events only (RFC 5737 / 3849 addresses)."""

import pytest

from authlog_analyzer.detectors import (
    BRUTE_FORCE_HIGH_FACTOR,
    SPRAY_HIGH_FACTOR,
    DetectionConfig,
    detect_all,
    detect_brute_force,
    detect_password_spraying,
    detect_success_after_failures,
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


# ------------------------------------------------------ password spraying

def spray(ip, users, step_seconds=30, start=0):
    return [failed(ip, u, seconds=start + i * step_seconds) for i, u in enumerate(users)]


USERS = ["admin", "test", "oracle", "ubuntu", "postgres", "deploy", "guest", "support"]


def test_spray_exactly_k_distinct_users_is_a_finding():
    findings = detect_password_spraying(spray(ATTACKER, USERS[:5]))
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "AUTH-SPRAY-001"
    assert f.technique_id == "T1110.003"
    assert f.usernames == tuple(sorted(USERS[:5]))
    assert f.count == 5
    assert f.severity == "medium"


def test_spray_one_below_k_is_not_a_finding():
    assert detect_password_spraying(spray(ATTACKER, USERS[:4])) == []


def test_many_failures_against_few_users_is_brute_force_not_spray():
    events = burst(ATTACKER, 30, user="root") + burst(ATTACKER, 30, user="admin", start=1)
    assert detect_password_spraying(events) == []
    assert len(detect_brute_force(events)) == 1


def test_spray_users_outside_the_window_do_not_count():
    # Five distinct users but spread over 40 minutes: no 10 minute window has 5.
    events = [failed(ATTACKER, u, minutes=10 * i) for i, u in enumerate(USERS[:5])]
    assert detect_password_spraying(events) == []


def test_spray_window_boundary_is_inclusive():
    inside = [failed(ATTACKER, u, minutes=m) for u, m in zip(USERS[:5], (0, 2, 4, 6, 10))]
    outside = [failed(ATTACKER, u, seconds=s) for u, s in zip(USERS[:5], (0, 120, 240, 360, 601))]
    assert len(detect_password_spraying(inside)) == 1
    assert detect_password_spraying(outside) == []


def test_spray_is_counted_per_source_ip():
    events = spray(ATTACKER, USERS[:3]) + spray(OTHER, USERS[3:6], start=5)
    assert detect_password_spraying(events) == []


def test_same_user_repeated_does_not_inflate_distinct_count():
    users = ["admin", "admin", "test", "test", "oracle", "oracle", "ubuntu", "ubuntu"]
    assert detect_password_spraying(spray(ATTACKER, users, step_seconds=5)) == []


def test_spray_severity_escalates_with_more_users():
    cfg = DetectionConfig(spray_users=4)
    below = spray(ATTACKER, USERS[: SPRAY_HIGH_FACTOR * 4 - 1])
    at_limit = spray(ATTACKER, USERS[: SPRAY_HIGH_FACTOR * 4])
    assert detect_password_spraying(below, cfg)[0].severity == "medium"
    assert detect_password_spraying(at_limit, cfg)[0].severity == "high"


def test_spray_custom_k():
    events = spray(ATTACKER, USERS[:3])
    assert detect_password_spraying(events) == []
    assert len(detect_password_spraying(events, DetectionConfig(spray_users=3))) == 1


def test_a_sprayer_is_reported_by_both_spray_and_brute_force_rules():
    findings = detect_all(spray(ATTACKER, USERS[:6]))
    assert {f.rule_id for f in findings} == {"AUTH-BRUTE-001", "AUTH-SPRAY-001"}


def test_two_spray_episodes_far_apart():
    events = spray(ATTACKER, USERS[:5]) + spray(ATTACKER, USERS[:5], start=7200)
    assert len(detect_password_spraying(events)) == 2


# ------------------------------------------------ success after failures

def test_success_after_threshold_failures_is_high_priority():
    events = burst(ATTACKER, 5, user="alice") + [accepted(ATTACKER, "alice", seconds=60)]
    findings = detect_success_after_failures(events)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "AUTH-SUCCESS-001"
    assert f.severity == "high"
    assert f.technique_id == "T1078"
    assert f.source_ip == ATTACKER
    assert f.count == 5
    assert f.first_seen == at(0)
    assert f.last_seen == at(60)
    assert f.usernames == ("alice",)
    assert "Possible compromise" in f.detail


def test_success_one_below_threshold_is_not_flagged():
    events = burst(ATTACKER, 4) + [accepted(ATTACKER, seconds=60)]
    assert detect_success_after_failures(events) == []


def test_success_with_failures_outside_lookback_is_not_flagged():
    # Five failures, then a login 10 minutes and 1 second after the last one,
    # but the earliest failures have also aged out.
    events = burst(ATTACKER, 5) + [accepted(ATTACKER, seconds=40 + 601)]
    assert detect_success_after_failures(events) == []


def test_success_lookback_boundary_is_inclusive():
    # The oldest failure is exactly 10 minutes before the login: still counted.
    events = [failed(ATTACKER, seconds=s) for s in (0, 1, 2, 3, 4)]
    login_inside = events + [accepted(ATTACKER, seconds=600)]
    login_outside = events + [accepted(ATTACKER, seconds=601)]
    assert len(detect_success_after_failures(login_inside)) == 1
    assert detect_success_after_failures(login_outside) == []


def test_failures_after_the_login_do_not_count():
    events = [accepted(ATTACKER, seconds=0)] + burst(ATTACKER, 6, start=1)
    assert detect_success_after_failures(events) == []


def test_success_from_a_different_ip_is_not_flagged():
    events = burst(ATTACKER, 8) + [accepted(OTHER, seconds=30)]
    assert detect_success_after_failures(events) == []


def test_success_after_failures_against_other_accounts_still_flags_the_ip():
    events = spray(ATTACKER, USERS[:6], step_seconds=10) + [accepted(ATTACKER, "alice", seconds=90)]
    f = detect_success_after_failures(events)[0]
    assert "alice" in f.usernames
    assert set(USERS[:6]) <= set(f.usernames)
    assert "0 against the same account" in f.detail


def test_each_qualifying_login_is_its_own_finding():
    events = burst(ATTACKER, 5) + [accepted(ATTACKER, seconds=60), accepted(ATTACKER, seconds=90)]
    assert len(detect_success_after_failures(events)) == 2


def test_login_at_same_timestamp_before_failures_in_file_order_is_not_flagged():
    # File order breaks timestamp ties: the Accepted line came first.
    events = [accepted(ATTACKER, seconds=0)] + burst(ATTACKER, 5, step_seconds=0)
    assert detect_success_after_failures(events) == []


def test_success_custom_threshold_and_window():
    events = burst(ATTACKER, 2) + [accepted(ATTACKER, seconds=30)]
    assert detect_success_after_failures(events) == []
    assert len(detect_success_after_failures(events, DetectionConfig(threshold=2))) == 1


def test_success_detection_ignores_invalid_user_events():
    noise = [AuthEvent(at(i), EventKind.INVALID_USER, "x", ATTACKER) for i in range(10)]
    assert detect_success_after_failures(noise + [accepted(ATTACKER, seconds=20)]) == []


def test_detect_all_sorts_high_severity_first():
    events = (
        burst(OTHER, 6, start=0)  # medium brute force
        + burst(ATTACKER, 5, user="alice", start=3600)
        + [accepted(ATTACKER, "alice", seconds=3700)]
    )
    findings = detect_all(events)
    assert findings[0].severity == "high"
    assert findings[0].rule_id == "AUTH-SUCCESS-001"
    assert [f.severity for f in findings] == sorted(
        (f.severity for f in findings), key=["high", "medium", "low"].index
    )
