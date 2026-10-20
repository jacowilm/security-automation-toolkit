"""Detection rules over parsed sshd authentication events.

Window semantics: a window is *inclusive*. Two failures exactly
``window_minutes`` apart are inside the same window; one second more and they
are not. Events may arrive in any order, they are sorted by timestamp first
(a stable sort, so file order breaks ties).
"""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import timedelta
from typing import Iterable

from .models import (
    BRUTE_FORCE,
    PASSWORD_SPRAY,
    SEVERITIES,
    SUCCESS_AFTER_FAILURES,
    AuthEvent,
    EventKind,
    Finding,
)

# A brute-force finding is raised to "high" when the burst is this many times
# bigger than the configured threshold.
BRUTE_FORCE_HIGH_FACTOR = 5

# A spray finding is raised to "high" when it hits this many times more
# distinct usernames than the configured minimum.
SPRAY_HIGH_FACTOR = 2


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


def detect_password_spraying(events: Iterable[AuthEvent], config: DetectionConfig | None = None) -> list[Finding]:
    """AUTH-SPRAY-001: one IP failing against ``spray_users`` or more usernames in the window.

    A sprayer normally also trips AUTH-BRUTE-001 because it is many failures
    from one address. The two findings carry different ATT&CK techniques and
    this one is the more specific.
    """
    config = config or DetectionConfig()
    findings: list[Finding] = []
    for ip, failures in _failures_by_ip(events).items():
        for start, end in _find_episodes(failures, config.window, 1, config.spray_users):
            episode = failures[start : end + 1]
            names = _usernames(episode)
            severity = "high" if len(names) >= SPRAY_HIGH_FACTOR * config.spray_users else "medium"
            findings.append(
                Finding(
                    rule_id=PASSWORD_SPRAY.rule_id,
                    rule_name=PASSWORD_SPRAY.name,
                    severity=severity,
                    source_ip=ip,
                    usernames=names,
                    first_seen=episode[0].timestamp,
                    last_seen=episode[-1].timestamp,
                    count=len(episode),
                    technique_id=PASSWORD_SPRAY.technique_id,
                    technique_name=PASSWORD_SPRAY.technique_name,
                    detail=(
                        f"{_plural(len(episode), 'failed login')} from {ip} across "
                        f"{_plural(len(names), 'distinct username')} "
                        f"(threshold: {config.spray_users} usernames in "
                        f"{config.window_minutes:g} minutes)"
                    ),
                )
            )
    return findings


def detect_success_after_failures(
    events: Iterable[AuthEvent], config: DetectionConfig | None = None
) -> list[Finding]:
    """AUTH-SUCCESS-001: an Accepted login from an IP with enough recent failures.

    "Recent" means within ``window_minutes`` before the login (inclusive), and
    "enough" means at least ``threshold`` failures from the same source IP,
    whatever account they targeted. One finding per qualifying login. Always
    high severity: the attacker may have guessed a working credential.
    """
    config = config or DetectionConfig()
    recent: dict[str, deque[AuthEvent]] = defaultdict(deque)
    findings: list[Finding] = []
    for event in sorted(events, key=lambda e: e.timestamp):
        if event.kind not in (EventKind.FAILED, EventKind.ACCEPTED):
            continue
        queue = recent[event.source_ip]
        # Events are processed in time order, so anything older than the
        # window now is older than the window for every later event too.
        while queue and event.timestamp - queue[0].timestamp > config.window:
            queue.popleft()
        if event.kind is EventKind.FAILED:
            queue.append(event)
            continue
        if len(queue) < config.threshold:
            continue
        same_account = sum(1 for f in queue if f.username == event.username)
        names = tuple(sorted({f.username for f in queue} | {event.username}))
        findings.append(
            Finding(
                rule_id=SUCCESS_AFTER_FAILURES.rule_id,
                rule_name=SUCCESS_AFTER_FAILURES.name,
                severity="high",
                source_ip=event.source_ip,
                usernames=names,
                first_seen=queue[0].timestamp,
                last_seen=event.timestamp,
                count=len(queue),
                technique_id=SUCCESS_AFTER_FAILURES.technique_id,
                technique_name=SUCCESS_AFTER_FAILURES.technique_name,
                detail=(
                    f"Accepted {event.method or 'login'} for '{event.username}' from "
                    f"{event.source_ip} after {_plural(len(queue), 'failed login')} from the "
                    f"same address in the previous {config.window_minutes:g} minutes "
                    f"({same_account} against the same account). Possible compromise."
                ),
            )
        )
    return findings


def detect_all(events: Iterable[AuthEvent], config: DetectionConfig | None = None) -> list[Finding]:
    """Run every rule and return findings sorted by severity, then time."""
    config = config or DetectionConfig()
    events = list(events)
    findings = (
        detect_brute_force(events, config)
        + detect_password_spraying(events, config)
        + detect_success_after_failures(events, config)
    )
    order = {name: rank for rank, name in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: (order[f.severity], f.first_seen, f.rule_id, f.source_ip))
    return findings
