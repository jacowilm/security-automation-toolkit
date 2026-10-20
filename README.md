# security-automation-toolkit

A small, local toolkit of security automation exercises:

- **`authlog_analyzer`**: a Python command line tool that reads Linux `sshd`
  `auth.log` files and flags SSH brute force, password spraying and
  login-success-after-failures, each mapped to a MITRE ATT&CK technique.
- **`powershell/Export-SecurityEvents.ps1`**: a PowerShell function that exports
  selected Windows Security log events to CSV for triage.
- **`kql/`**: ten Kusto Query Language detections for Microsoft Sentinel and
  Microsoft Defender XDR.

It is portfolio evidence for a cybersecurity student's professional learning
plan. It is a learning project, not a production security product.

## How this was built (please read)

This toolkit was built with **AI assistance** (Claude, from Anthropic) under
the direction and review of the repository owner, Jacobo Miranda Baudot. The AI
wrote most of the code, tests and prose; the owner set the scope and reviews and
owns the result. Where something has not been verified, this README says so.
In particular:

| Component | What has and has not been checked |
|-----------|-----------------------------------|
| Python analyser | 219 automated tests pass locally (see [Testing](#testing)). Run on Python 3.11.2 and 3.14 on macOS. **Not** run on 3.10 or 3.12 locally. |
| GitHub Actions workflow | Written and parsed as YAML, but **has not run yet** because the repository had not been pushed when this was written. |
| PowerShell script | **Not executed and not parsed by PowerShell.** `pwsh` is not installed on the development Mac, so the parser check was not run. Only text-level structure checks were done (bracket balance, required parameters). It must be run on Windows as an administrator. |
| KQL queries | Written against Microsoft's documented table schemas. **Not yet run in a live Microsoft Sentinel workspace**; that is a planned next step. File structure is checked by tests, query correctness is not. |
| Sample data | All synthetic (see [Sample data](#sample-data)). |

## Repository layout

```
authlog_analyzer/        Python package (standard library only at runtime)
  parser.py              sshd auth.log line parser
  detectors.py           brute force, spraying, success-after-failures
  report.py              table, CSV and JSON output
  cli.py                 command line interface and exit codes
  models.py              events, findings, ATT&CK rule catalogue
samples/auth.log.sample  synthetic log with known scenarios
tests/                   pytest suite
powershell/              Export-SecurityEvents.ps1
kql/                     10 detections + README table
.github/workflows/ci.yml pytest (3.11, 3.12) and gitleaks secrets scan
SECURITY.md              reporting and data handling
```

## Quick start

Requires Python 3.10 or newer (CI targets 3.11 and 3.12).

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt     # pytest and pytest-cov, the only dependencies
pytest                                  # run the test suite

# analyse the synthetic sample log
python -m authlog_analyzer samples/auth.log.sample --year 2026
```

The analyser itself needs no third-party packages. `pip install .` also works and
adds an `authlog-analyzer` command.

### Command line

```
python -m authlog_analyzer <logfile> [--threshold N] [--window MIN]
                           [--spray-users K] [--year YYYY]
                           [--format table|csv|json] [--output PATH]
```

| Option | Default | Meaning |
|--------|---------|---------|
| `--threshold N` | 5 | Failures from one IP that make a brute-force finding |
| `--window MIN` | 10 | Sliding window in minutes (inclusive) |
| `--spray-users K` | 5 | Distinct usernames from one IP that make a spraying finding |
| `--year YYYY` | current year | Syslog timestamps carry no year, so one is assumed |
| `--format` | table | `table`, `csv` or `json` |
| `--output PATH` | stdout | Write the report to a file (overwrites) |

**Exit codes:** `0` no findings, `1` findings, `2` input or usage error (missing
file, unreadable file, bad option value, unwritable output path). The one-line
summary and any malformed-line notice go to stderr, so stdout stays clean for
`csv` and `json`.

## What each part detects

### SSH log analyser

| Rule | Severity | Logic | ATT&CK |
|------|----------|-------|--------|
| `AUTH-BRUTE-001` SSH brute force | medium; high at 5x the threshold | At least `--threshold` failed logins from one source IP inside any `--window` minute window | T1110.001 Password Guessing |
| `AUTH-SPRAY-001` SSH password spraying | medium; high at 2x `--spray-users` | One source IP failing against at least `--spray-users` distinct usernames inside the window | T1110.003 Password Spraying |
| `AUTH-SUCCESS-001` Success after failures | high | An `Accepted` login from an IP that had at least `--threshold` failures in the preceding window. Possible compromise. | T1078 Valid Accounts |

Each finding carries the rule id, severity, source IP, usernames, first and last
seen, count, ATT&CK technique and a one-sentence detail.

How it works, so the output is predictable:

- **Parsed lines:** `Failed <method> for [invalid user] X from IP port N`,
  `Accepted <method> for X from IP port N` and `Invalid user X from IP`. IPv4 and
  IPv6 are supported. Process names `sshd` and `sshd-session` (OpenSSH 9.8+) are
  accepted. Other valid syslog lines (cron, PAM, other sshd messages) are
  counted as "ignored". Lines that cannot be parsed are counted as "malformed",
  skipped, and their line numbers reported.
- **What counts as a failure:** only `Failed ...` lines. `Invalid user ...` lines
  are parsed but not counted, because sshd normally also logs a matching
  `Failed password for invalid user` line for the same attempt and counting both
  would double the total.
- **Windows are inclusive:** two failures exactly `--window` minutes apart are in
  the same window; one second more and they are not.
- **One finding per episode:** overlapping qualifying windows are merged, so a
  long attack is one finding with the full count, not hundreds.
- **A sprayer also trips brute force:** a source that fails against many users is
  also many failures from one IP. Both findings are reported; they carry
  different ATT&CK techniques and the spray finding is the more specific one.
- **Success after failures is per login:** one finding for every `Accepted` login
  that qualifies. The failures are counted by source IP, whichever account they
  targeted, and the detail says how many hit the same account.
- **Defensive output:** log data is attacker-controlled. CSV cells starting with
  `=`, `+`, `-` or `@` get a leading apostrophe so spreadsheets do not run them
  as formulas, and the text table replaces control characters (for example
  terminal escape sequences in a username) with `?`.

### PowerShell Windows event exporter

`powershell/Export-SecurityEvents.ps1` defines the advanced function
`Export-SecurityEvents` (comment-based help included). It queries the Security
log with `Get-WinEvent -FilterHashtable`, extracts time, event id, account,
source IP, workstation and logon type from each event's XML, and writes a CSV.

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `-Hours` | 24 | How far back to look (1 to 8760) |
| `-EventId` | 4624, 4625, 4672, 4720, 4732 | Logon success, logon failure, special privileges, user created, member added to a local group |
| `-OutputPath` | `SecurityEvents_<timestamp>.csv` | CSV to write |

```powershell
# Windows only, in an elevated (Run as administrator) PowerShell session
. .\powershell\Export-SecurityEvents.ps1
Export-SecurityEvents -Hours 48 -OutputPath C:\Temp\events.csv
Get-Help Export-SecurityEvents -Full
```

`#Requires -RunAsAdministrator` stops the file loading in a non-elevated session.
If no events match, it writes a warning and creates no file. It supports `-WhatIf`
and `-Verbose`. **It must be run on Windows as an administrator and has not been
executed or syntax-checked by PowerShell** (see the table at the top).

### KQL detections for Microsoft Sentinel

Ten queries, each with a header covering title, data source table, what it
detects, likely false positives, ATT&CK technique and tuning notes. Full table in
[`kql/README.md`](kql/README.md).

| # | Detection | Table | ATT&CK |
|---|-----------|-------|--------|
| 01 | Failed sign-in brute force | SigninLogs | T1110.001 |
| 02 | Password spray across users | SigninLogs | T1110.003 |
| 03 | Impossible travel | SigninLogs | T1078.004 |
| 04 | Sign-in success after many failures | SigninLogs | T1110, T1078.004 |
| 05 | New local admin added (4732) | SecurityEvent | T1098 |
| 06 | New user account created (4720) | SecurityEvent | T1136.001 |
| 07 | Security log cleared (1102) | SecurityEvent | T1070.001 |
| 08 | Suspicious encoded PowerShell | DeviceProcessEvents | T1059.001, T1027.010 |
| 09 | Office app spawning a shell | DeviceProcessEvents | T1204.002 |
| 10 | MFA disabled or auth method removed | AuditLogs | T1556.006 |

**These have not yet been run in a live Sentinel workspace.** Treat them as
reviewed drafts to validate and tune, not as proven detections.

## Example output

Real output from the committed sample, run with
`python -m authlog_analyzer samples/auth.log.sample --year 2026` (exit code 1):

```
SEVERITY  RULE              SOURCE IP       USERNAMES                                 FIRST SEEN           LAST SEEN            COUNT  ATT&CK
--------  ----------------  --------------  ----------------------------------------  -------------------  -------------------  -----  ---------
high      AUTH-BRUTE-001    203.0.113.50    admin,root                                2026-10-20 13:12:00  2026-10-20 13:14:58  26     T1110.001
high      AUTH-SUCCESS-001  198.51.100.150  erin                                      2026-10-20 15:20:10  2026-10-20 15:24:12  7      T1078
medium    AUTH-BRUTE-001    203.0.113.99    admin,deploy,guest,oracle,postgres,su...  2026-10-20 14:03:21  2026-10-20 14:07:58  8      T1110.001
medium    AUTH-SPRAY-001    203.0.113.99    admin,deploy,guest,oracle,postgres,su...  2026-10-20 14:03:21  2026-10-20 14:07:58  8      T1110.003
medium    AUTH-BRUTE-001    198.51.100.150  erin                                      2026-10-20 15:20:10  2026-10-20 15:23:19  7      T1110.001

5 finding(s): 2 high, 3 medium
```

and on stderr:

```
Read 108 lines: 76 auth events, 26 ignored, 1 malformed, 5 blank or comment.
Skipped malformed lines at line numbers: 108
```

The sample contains one deliberately truncated last line (hence "1 malformed"),
benign noise, a slow drip of failures that never fills a window, a user who
mistyped a password, and three IPv6 guesses below the threshold. None of those is
flagged. The `--format json` output starts like this:

```json
{
  "summary": {
    "findings": 5,
    "lines_read": 108,
    "auth_events": 76,
    "ignored_lines": 26,
    "malformed_lines": 1,
    "blank_or_comment_lines": 5
  },
  "findings": [
    {
      "rule_id": "AUTH-BRUTE-001",
      "rule_name": "SSH brute force",
      "severity": "high",
      "source_ip": "203.0.113.50",
      ...
```

## Sample data

`samples/auth.log.sample` is **synthetic**. It was generated for this project and
is not taken from any real system. Hostnames and usernames are invented, and every
address comes from the documentation ranges reserved by RFC 5737 (`192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`) or RFC 3849 (`2001:db8::/32`). A test checks
that every address in the file is inside one of those ranges (the only exceptions
are the unspecified addresses `0.0.0.0` and `::` in the "Server listening" lines).

## Testing

```bash
pytest                                                    # 219 tests
pytest --cov=authlog_analyzer --cov-report=term-missing   # with coverage
```

- **Python package (149 tests):** parsing (valid user, invalid user, IPv6,
  year-less timestamps, leap days, malformed input), each rule including boundary
  conditions (exactly at the threshold, one below, exactly at the window edge, one
  second outside it), output formats, CLI exit codes, tuning flags, binary and
  invalid-UTF-8 input, a seeded random-input test, and an integration test
  asserting the sample log produces exactly the documented findings. Line coverage
  of `authlog_analyzer` was 100 percent when measured. Coverage shows the lines
  ran, not that every behaviour is right.
- **PowerShell and KQL (61 tests):** structural checks only. They read the
  files as text (required header fields, balanced brackets, required parameters,
  README table consistency). They do **not** run PowerShell or KQL.
- **Hygiene (9 tests):** no em or en dashes anywhere, a local secret-pattern scan, and no
  virtualenv, key or `.env` files tracked. CI additionally runs gitleaks over the
  full git history.

## Limitations

- **Single year:** syslog timestamps have no year. One `--year` applies to the
  whole file, so a log that spans New Year's Eve is mis-dated on one side.
- **Format coverage:** only the traditional syslog timestamp is parsed. rsyslog's
  ISO 8601 timestamps are counted as malformed. `message repeated N times`
  summaries are ignored, which undercounts failures on busy hosts. A hostname in
  place of an IP in the `from` field is treated as malformed.
- **Failures are `Failed ...` lines only.** Attempts that log only `Invalid user`
  or `Connection closed ... [preauth]` without a `Failed` line are not counted.
- **Per-IP view:** a distributed attack spread over many addresses is not
  correlated, and many users behind one NAT address can look like one attacker.
  There is no allow-list, no GeoIP and no state between runs.
- **Success after failures is noisy by design.** A user who fat-fingers a password
  five times and then succeeds is flagged. It is a triage prompt, not a verdict.
- **Severities are simple rules of thumb** (documented above), not risk scores.
- **PowerShell:** unexecuted, Windows only, administrator only. Event field names
  follow Microsoft's documented schemas for the five default events but can vary
  by Windows version, and the whole result set is held in memory. The "no events"
  handling relies on the error id `NoMatchingEventsFound` that `Get-WinEvent`
  raises.
- **KQL:** unvalidated against real data. Some queries use tumbling time buckets
  that can split a burst across a boundary. The tables need the matching
  connectors (Microsoft Entra ID sign-in and audit logs, Windows Security Events,
  Microsoft Defender XDR). Thresholds are placeholders to tune.
- **CI hardening:** actions are pinned to major-version tags, not commit SHAs.
  Pinning SHAs would be a sensible next step.
- **Scope:** educational. Do not rely on it as your only monitoring.

## Professional learning plan mapping

This repository is evidence of work toward the following goals. It shows the
skills in use; it does not claim the goals are complete.

### Goal 3: Git/GitHub, Python security automation, PowerShell, secure development hygiene

| Skill | Where it shows up |
|-------|-------------------|
| Git and GitHub workflow | Small, specific commits, a feature branch (`feature/kql-detections`) merged with `--no-ff`, a `.gitignore` that excludes secrets and output, a CI workflow on push and pull request |
| Python security automation | `authlog_analyzer`: log parsing, sliding-window detections, exit-code driven CLI, CSV/JSON output |
| PowerShell | `Export-SecurityEvents.ps1`: advanced function, comment-based help, `Get-WinEvent -FilterHashtable`, XML field extraction, `ShouldProcess` (not yet executed, see above) |
| Secure development hygiene | Standard-library-only runtime, pinned dev dependency, tests including boundary and hostile-input cases, CSV formula and terminal-escape neutralisation, synthetic data only, local and CI secret scanning, least-privilege workflow permissions, `SECURITY.md` |

### Goal 4: KQL detections, triage, MITRE ATT&CK mapping

| Skill | Where it shows up |
|-------|-------------------|
| KQL detections | `kql/`: ten queries over SigninLogs, SecurityEvent, DeviceProcessEvents and AuditLogs (not yet run in a live workspace) |
| Triage | Every KQL header lists likely false positives and tuning notes. The analyser ranks findings by severity and its success-after-failure rule is framed as a prompt for investigation |
| MITRE ATT&CK mapping | Each analyser rule and each KQL query names its technique (for example T1110.001, T1110.003, T1078, T1070.001, T1556.006), and tests keep the KQL README table consistent with the file headers |

## AI assistance statement

This repository was created with the assistance of an AI model (Claude, by
Anthropic), working under the direction and review of Jacobo Miranda Baudot. The
AI produced the initial code, tests, queries and documentation. Commits carry a
`Co-Authored-By` trailer for that reason. The statements about what has and has
not been tested in this README are intended to be literal: anything not listed as
tested should be treated as untested.

## License

MIT, see [LICENSE](LICENSE).
