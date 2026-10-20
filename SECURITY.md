# Security policy

This is a personal learning project, not production software. It has no
supported releases and no security SLA.

## Reporting a problem

If you find a security issue in the code (for example a way to crash the
analyser or abuse its output), please open a GitHub issue describing it, or
contact the maintainer privately if it should not be public. Do not include
real credentials, real log data or personal information in a report.

## Data handling

- All sample data in this repository is synthetic. Addresses come from the
  RFC 5737 and RFC 3849 documentation ranges and the usernames are invented.
- Do not commit real logs, exported event CSVs, `.env` files or keys. The
  `.gitignore` excludes the common cases and CI runs a gitleaks scan.
- Log content is attacker controlled. The analyser neutralises spreadsheet
  formulas in CSV and control characters in the text table; keep that in mind
  when opening output from real logs.

## Safe use

- Run the PowerShell exporter only on systems you are authorised to
  administer. It is read-only against the event log.
- Treat exported event data as sensitive: it contains account names and
  addresses.
