"""Small builders shared by the test modules. All data is synthetic."""

from __future__ import annotations

from datetime import datetime, timedelta

from authlog_analyzer.models import AuthEvent, EventKind

BASE = datetime(2026, 10, 20, 12, 0, 0)


def at(seconds: float = 0, minutes: float = 0) -> datetime:
    """A timestamp offset from BASE."""
    return BASE + timedelta(seconds=seconds, minutes=minutes)


def failed(ip: str, user: str = "root", seconds: float = 0, minutes: float = 0) -> AuthEvent:
    return AuthEvent(
        timestamp=at(seconds, minutes),
        kind=EventKind.FAILED,
        username=user,
        source_ip=ip,
        port=40000,
        method="password",
    )


def accepted(ip: str, user: str = "alice", seconds: float = 0, minutes: float = 0) -> AuthEvent:
    return AuthEvent(
        timestamp=at(seconds, minutes),
        kind=EventKind.ACCEPTED,
        username=user,
        source_ip=ip,
        port=40001,
        method="publickey",
    )


def syslog(message: str, stamp: str = "Oct 20 12:00:00", host: str = "synthetic-host",
           proc: str = "sshd", pid: int = 1000) -> str:
    """Build a traditional syslog line around a message."""
    return f"{stamp} {host} {proc}[{pid}]: {message}"


def failed_line(ip: str, user: str = "root", stamp: str = "Oct 20 12:00:00") -> str:
    return syslog(f"Failed password for {user} from {ip} port 40000 ssh2", stamp)


def accepted_line(ip: str, user: str = "alice", stamp: str = "Oct 20 12:00:00") -> str:
    return syslog(f"Accepted publickey for {user} from {ip} port 40001 ssh2", stamp)
