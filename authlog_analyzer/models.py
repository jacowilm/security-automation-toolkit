"""Data models and the rule catalogue shared across the analyzer."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class EventKind(str, Enum):
    """The kinds of sshd authentication events the parser recognises."""

    FAILED = "failed"
    ACCEPTED = "accepted"
    INVALID_USER = "invalid_user"


@dataclass(frozen=True)
class AuthEvent:
    """One parsed sshd authentication event."""

    timestamp: datetime
    kind: EventKind
    username: str
    source_ip: str
    port: int | None = None
    method: str | None = None
    host: str = ""
    line_number: int = 0
    # True when sshd said "invalid user", i.e. the account does not exist.
    invalid_user: bool = False


# Severity labels, highest priority first. Used to sort findings.
SEVERITIES = ("high", "medium", "low")


@dataclass(frozen=True)
class Rule:
    """Static metadata for a detection rule."""

    rule_id: str
    name: str
    technique_id: str
    technique_name: str


BRUTE_FORCE = Rule(
    rule_id="AUTH-BRUTE-001",
    name="SSH brute force",
    technique_id="T1110.001",
    technique_name="Brute Force: Password Guessing",
)
PASSWORD_SPRAY = Rule(
    rule_id="AUTH-SPRAY-001",
    name="SSH password spraying",
    technique_id="T1110.003",
    technique_name="Brute Force: Password Spraying",
)
SUCCESS_AFTER_FAILURES = Rule(
    rule_id="AUTH-SUCCESS-001",
    name="SSH login success after repeated failures",
    technique_id="T1078",
    technique_name="Valid Accounts",
)

RULES = {r.rule_id: r for r in (BRUTE_FORCE, PASSWORD_SPRAY, SUCCESS_AFTER_FAILURES)}


@dataclass(frozen=True)
class Finding:
    """A detection result."""

    rule_id: str
    rule_name: str
    severity: str
    source_ip: str
    usernames: tuple[str, ...]
    first_seen: datetime
    last_seen: datetime
    count: int
    technique_id: str
    technique_name: str
    detail: str = ""

    def to_dict(self) -> dict:
        """JSON friendly representation (timestamps as ISO 8601 strings)."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "usernames": list(self.usernames),
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "count": self.count,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "detail": self.detail,
        }
