"""Repository hygiene: house style and a cheap local secret scan.

The CI gitleaks job is the real secrets scan; this is a fast first line of
defence that also runs on a developer machine.
"""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {".git", ".venv", "venv", ".pytest_cache", "__pycache__", "htmlcov", ".mypy_cache"}
TEXT_SUFFIXES = {".py", ".ps1", ".kql", ".md", ".yml", ".yaml", ".toml", ".txt", ".sample", ".cfg", ".ini"}
TEXT_NAMES = {"LICENSE", ".gitignore"}

# House style: no em dash (U+2014) or en dash (U+2013) anywhere. Written as
# code points so this file does not contain the characters itself.
FORBIDDEN_DASHES = (chr(0x2014), chr(0x2013))

SECRET_PATTERNS = {
    "AWS access key id": re.compile(r"AKIA[0-9A-Z]{16}"),
    "OpenAI-style secret key": re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}"),
    "private key block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "hard-coded password assignment": re.compile(r"(?i)\bpassword\s*=\s*['\"]?[^\s'\"]+"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"),
}


def _git_listed_files():
    """Files git would commit: tracked plus untracked-but-not-ignored."""
    if shutil.which("git") is None or not (ROOT / ".git").exists():
        return None
    out = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT, capture_output=True, text=True, check=True, timeout=30,
    )
    return [ROOT / name for name in out.stdout.splitlines()]


def _walked_files():
    for path in ROOT.rglob("*"):
        parts = path.relative_to(ROOT).parts
        if any(part in SKIP_DIRS for part in parts):
            continue
        yield path


def text_files():
    listed = _git_listed_files()
    for path in listed if listed is not None else _walked_files():
        if not path.is_file():
            continue
        if path.suffix in TEXT_SUFFIXES or path.name in TEXT_NAMES:
            yield path


def test_scan_actually_covers_the_repo():
    names = {p.name for p in text_files()}
    assert {"README.md", "LICENSE", "ci.yml", "Export-SecurityEvents.ps1", "auth.log.sample"} <= names


def test_no_em_or_en_dashes_anywhere():
    offenders = []
    for path in text_files():
        text = path.read_text(encoding="utf-8")
        for number, line in enumerate(text.splitlines(), start=1):
            if any(dash in line for dash in FORBIDDEN_DASHES):
                offenders.append(f"{path.relative_to(ROOT)}:{number}")
    assert not offenders, f"em or en dash found at: {offenders}"


@pytest.mark.parametrize("label", sorted(SECRET_PATTERNS))
def test_no_obvious_secrets_in_text_files(label):
    pattern = SECRET_PATTERNS[label]
    hits = []
    for path in text_files():
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if pattern.search(line):
                hits.append(f"{path.relative_to(ROOT)}:{number}")
    assert not hits, f"{label} pattern matched at: {hits}"


def tracked_files():
    if shutil.which("git") is None or not (ROOT / ".git").exists():
        pytest.skip("not a git checkout")
    out = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True, timeout=30
    )
    return out.stdout.splitlines()


def test_no_virtualenv_env_or_key_files_are_tracked():
    bad = [
        f for f in tracked_files()
        if f.startswith((".venv/", "venv/")) or f.endswith((".pem", ".key", ".p12", ".pfx"))
        or Path(f).name == ".env" or Path(f).name.startswith(".env.")
    ]
    assert not bad, f"files that should never be committed: {bad}"


def test_no_generated_output_is_tracked():
    bad = [f for f in tracked_files() if f.endswith(".csv") or "__pycache__" in f or f.endswith(".pyc")]
    assert not bad, f"generated files tracked: {bad}"
