# KQL detections

Ten Kusto Query Language (KQL) detections for Microsoft Sentinel and Microsoft
Defender XDR. Each file starts with a comment header (title, data source table,
what it detects, likely false positives, MITRE ATT&CK technique, tuning notes
and status) followed by the query.

**Status: not yet run in a live Sentinel workspace.** The queries were written
against Microsoft's documented table schemas (SigninLogs, SecurityEvent,
DeviceProcessEvents, AuditLogs). Running them against real data, fixing any
column or syntax problems and tuning thresholds is a planned next step. The
automated checks in `tests/test_kql_files.py` only verify the file structure
(header fields, balanced brackets, one query per file); they do not execute KQL.

| # | File | Detects | Table | MITRE ATT&CK |
|---|------|---------|-------|--------------|
| 01 | `01-failed-signin-brute-force.kql` | Many failed sign-ins for one account from one IP in a 10 minute bucket | SigninLogs | T1110.001 Password Guessing |
| 02 | `02-password-spray-across-users.kql` | One IP failing against 10 or more different users with few tries each | SigninLogs | T1110.003 Password Spraying |
| 03 | `03-impossible-travel.kql` | Successful sign-ins from two countries within 2 hours for the same user | SigninLogs | T1078.004 Cloud Accounts |
| 04 | `04-signin-success-after-failures.kql` | Success from an IP that just failed 10 or more times for the account | SigninLogs | T1110 Brute Force, T1078.004 Cloud Accounts |
| 05 | `05-new-local-admin-added.kql` | Event 4732: member added to the local Administrators group | SecurityEvent | T1098 Account Manipulation |
| 06 | `06-new-user-account-created.kql` | Event 4720: a user account was created | SecurityEvent | T1136.001 Local Account |
| 07 | `07-security-log-cleared.kql` | Event 1102: the Security audit log was cleared | SecurityEvent | T1070.001 Clear Windows Event Logs |
| 08 | `08-suspicious-encoded-powershell.kql` | PowerShell with -enc / -EncodedCommand or FromBase64String | DeviceProcessEvents | T1059.001 PowerShell, T1027.010 Command Obfuscation |
| 09 | `09-office-app-spawning-shell.kql` | Word, Excel, PowerPoint or Outlook starting cmd, PowerShell or a script host | DeviceProcessEvents | T1204.002 Malicious File |
| 10 | `10-mfa-disabled-or-auth-method-removed.kql` | MFA disabled or a registered authentication method deleted | AuditLogs | T1556.006 Multi-Factor Authentication |

## How to use one

1. In the Azure portal open your Microsoft Sentinel workspace and go to
   **Logs**.
2. Paste the whole file below the header (the `let` statements and the query).
3. Run it. Adjust the `let` values at the top (lookback, thresholds) to suit
   your tenant.
4. To make it a detection, save it as a scheduled analytics rule and map the
   entities (account, IP, host) in the rule wizard.

## Notes

- The Defender tables (08 and 09) use `TimeGenerated`, which is correct in
  Sentinel. In the Microsoft Defender portal's advanced hunting, replace it with
  `Timestamp`.
- Queries 01, 02 and 04 use tumbling time buckets for simplicity. A burst that
  straddles a bucket edge can be split; overlapping scheduled runs cover that.
- Tune before alerting. Every header lists likely false positives to exclude.
