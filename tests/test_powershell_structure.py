"""Structural checks on powershell/Export-SecurityEvents.ps1.

IMPORTANT: these tests do not run or parse PowerShell. They only read the file
as text to catch accidental edits (a dropped #Requires line, a renamed
parameter, unbalanced brackets). The script itself needs Windows, an elevated
session and a real Security log to be exercised properly.
"""

import re
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "powershell" / "Export-SecurityEvents.ps1"


@pytest.fixture(scope="module")
def text():
    return SCRIPT.read_text(encoding="utf-8")


def test_file_is_plain_ascii_so_windows_powershell_5_1_reads_it_correctly(text):
    text.encode("ascii")


def test_requires_statements(text):
    assert re.search(r"(?m)^#Requires -RunAsAdministrator\s*$", text)
    assert re.search(r"(?m)^#Requires -Version 5\.1\s*$", text)


def test_advanced_function_with_comment_based_help(text):
    assert "function Export-SecurityEvents" in text
    assert "[CmdletBinding(" in text
    for keyword in (".SYNOPSIS", ".DESCRIPTION", ".PARAMETER Hours", ".PARAMETER EventId",
                    ".PARAMETER OutputPath", ".EXAMPLE"):
        assert keyword in text, keyword


def test_parameters_and_defaults(text):
    assert re.search(r"\[int\]\$Hours\s*=\s*24", text)
    assert re.search(r"\[int\[\]\]\$EventId\s*=\s*@\(4624,\s*4625,\s*4672,\s*4720,\s*4732\)", text)
    assert "[string]$OutputPath" in text


def test_uses_filter_hashtable_on_the_security_log(text):
    assert "Get-WinEvent -FilterHashtable" in text
    assert re.search(r"LogName\s*=\s*'Security'", text)


def test_extracts_fields_from_event_xml(text):
    assert "ToXml()" in text
    for field in ("TargetUserName", "SubjectUserName", "IpAddress", "WorkstationName", "LogonType"):
        assert field in text, field


def test_handles_no_events_cleanly_and_exports_csv(text):
    assert "NoMatchingEventsFound" in text
    assert "Export-Csv" in text


def _strip_comments_and_strings(src: str) -> str:
    src = re.sub(r"<#.*?#>", lambda m: "\n" * m.group(0).count("\n"), src, flags=re.S)
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if c == "#":
            while i < n and src[i] != "\n":
                i += 1
            continue
        if c == "'":
            i += 1
            while i < n:
                if src[i] == "'":
                    if i + 1 < n and src[i + 1] == "'":
                        i += 2
                        continue
                    break
                i += 1
            i += 1
            continue
        if c == '"':
            i += 1
            while i < n:
                if src[i] == "`":
                    i += 2
                    continue
                if src[i] == '"':
                    break
                i += 1
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def test_brackets_are_balanced_outside_strings_and_comments(text):
    stack = []
    pairs = {")": "(", "]": "[", "}": "{"}
    for ch in _strip_comments_and_strings(text):
        if ch in "([{":
            stack.append(ch)
        elif ch in ")]}":
            assert stack and stack.pop() == pairs[ch]
    assert not stack
