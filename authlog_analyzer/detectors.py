"""Detection rules over parsed sshd authentication events.

Window semantics: a window is *inclusive*. Two failures exactly
``window_minutes`` apart are inside the same window; one second more and they
are not. Events may arrive in any order, they are sorted by timestamp first
(a stable sort, so file order breaks ties).
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import timedelta
from typing import Iterable

from .models import (
    BRUTE_FORCE,
    SEVERITIES,
    AuthEvent,
    EventKind,
    Finding,
)

# A brute-force finding is raised to "high" when the burst is this many times
# bigger than the configured threshold.
BRUTE_FORCE_HIGH_FACTOR = 5


@dataclass(frozen=True)
class DetectionConfig:
    """Tunable thresholds. Defaults: 5 failures in 10 minutes, 5 usernames."""

    threshold: int = 5
    window_minutes: float = 10
    spray_users: int = 5

    def __post_init__(self) -> None:
        if self.threshold < 1:
            raise ValueError("threshold must be at least 1")
        if self.window_minutes <= 0:
            raise ValueError("window_minutes must be greater than 0")
        if self.spray_users < 1:
            raise ValueError("spray_users must be at least 1")

    @property
    def window(self) -> timedelta:
        return timedelta(minutes=self.window_minutes)


def _failures_by_ip(events: Iterable[AuthEvent]) -> dict[str, list[AuthEvent]]:
    """Group FAILED events by source IP, each list sorted by time."""
    grouped: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in sorted(events, key=lambda e: e.timestamp):
        if event.kind is EventKind.FAILED:
            grouped[event.source_ip].append(event)
    return grouped


def _find_episodes(
    failures: list[AuthEvent],
    window: timedelta,
    min_events: int,
    min_users: int,
) -> list[tuple[int, int]]:
    """Find episodes of qualifying activity in a time-sorted list of failures.

    A sliding window ends at every failure. The window qualifies when it holds
    at least ``min_events`` failures and at least ``min_users`` distinct
    usernames. Overlapping qualifying windows are merged into one episode so a
    long attack yields one finding, not hundreds. Returns inclusive
    ``(start, end)`` index pairs into ``failures``.
    """
    episodes: list[list[int]] = []
    users: Counter[str] = Counter()
    left = 0
    for right, event in enumerate(failures):
        users[event.username] += 1
        while event.timestamp - failures[left].timestamp > window:
            gone = failures[left].username
            users[gone] -= 1
            if users[gone] == 0:
                del users[gone]
            left += 1
        if right - left + 1 >= min_events and len(users) >= min_users:
            if episodes and left <= episodes[-1][1]:
                episodes[-1][1] = right
            else:
                episodes.append([left, right])
    return [(start, end) for start, end in episodes]


def _usernames(events: Iterable[AuthEvent]) -> tuple[str, ...]:
    return tuple(sorted({e.username for e in events}))


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def detect_brute_force(events: Iterable[AuthEvent], config: DetectionConfig | None = None) -> list[Finding]:
    """AUTH-BRUTE-001: at least ``threshold`` failures from one IP in the window."""
    config = config or DetectionConfig()
    findings: list[Finding] = []
    for ip, failures in _failures_by_ip(events).items():
        for start, end in _find_episodes(failures, config.window, config.threshold, 1):
            burst = failures[start : end + 1]
            count = len(burst)
            severity = "high" if count >= BRUTE_FORCE_HIGH_FACTOR * config.threshold else "medium"
            names = _usernames(burst)
            findings.append(
                Finding(
                    rule_id=BRUTE_FORCE.rule_id,
                    rule_name=BRUTE_FORCE.name,
                    severity=severity,
                    source_ip=ip,
                    usernames=names,
                    first_seen=burst[0].timestamp,
                    last_seen=burst[-1].timestamp,
                    count=count,
                    technique_id=BRUTE_FORCE.technique_id,
                    technique_name=BRUTE_FORCE.technique_name,
                    detail=(
                        f"{_plural(count, 'failed login')} from {ip} against "
                        f"{_plural(len(names), 'account')} "
                        f"(threshold: {config.threshold} in {config.window_minutes:g} minutes)"
                    ),
                )
            )
    return findings


def detect_all(events: Iterable[AuthEvent], config: DetectionConfig | None = None) -> list[Finding]:
    """Run every rule and return findings sorted by severity, then time."""
    config = config or DetectionConfig()
    events = list(events)
    findings = detect_brute_force(events, config)
    order = {name: rank for rank, name in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: (order[f.severity], f.first_seen, f.rule_id, f.source_ip))
    return findings
