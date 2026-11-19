# AuthSentry

**A lightweight SSH authentication log analyser for brute-force triage and incident reporting.**

AuthSentry parses common Linux OpenSSH authentication records, detects bursts of failed logins by source IP, looks for a subsequent successful login from that same IP, and exports structured reports for review.

> **Scope:** AuthSentry is a local, defensive log-analysis project. It does not attempt logins, scan networks, block IP addresses, or change firewall rules. A detection is an investigative lead, not proof of compromise.

## Highlights

- **Log parsing:** Extracts timestamps, source IPs, usernames, authentication methods, and outcomes from common Linux `sshd` records.
- **Input validation:** Normalises IPv4/IPv6 addresses with Python's standard `ipaddress` module.
- **Rolling-window detection:** Finds bursts of failed SSH logins per source IP within a configurable time window.
- **Login correlation:** Raises a higher-priority alert when a successful login follows a qualifying failed-login burst from the same IP within a configurable correlation window.
- **Severity triage:** Assigns MEDIUM, HIGH, or CRITICAL based on the configured threshold and observed follow-up authentication.
- **Source-IP inventory:** Reports all observed IPs, including those that did not cross the alert threshold.
- **Analyst exports:** Generates JSON incident data, an alert CSV, and a per-IP activity CSV.
- **Test coverage:** Includes standard-library unit tests for parsing, detection thresholds, time-window behaviour, correlation, validation, and IP summaries.

## Requirements

- Python 3.10+
- No third-party dependencies

## Quick start

Clone or download the repository, then run from the project directory:

```bash
python authsentry.py --log sample_auth.log --year 2026
```

On Windows, the Python launcher can be used:

```powershell
py authsentry.py --log sample_auth.log --year 2026
```

Default outputs:

- `authsentry_report.json` — full report, source-IP activity, and alerts
- `authsentry_alerts.csv` — alert-level findings
- `authsentry_ip_summary.csv` — activity summary for every observed source IP

The bundled sample is synthetic and demonstrates six failed SSH attempts followed by a successful login from the same documentation-range IP. AuthSentry should raise a HIGH-priority correlated alert for this sequence.

## Configuration

```bash
python authsentry.py \
  --log sample_auth.log \
  --threshold 5 \
  --window 10 \
  --correlation-window 30 \
  --year 2026 \
  --json reports/report.json \
  --csv reports/alerts.csv \
  --summary-csv reports/source_ips.csv
```

| Argument | Default | Purpose |
|---|---:|---|
| `--log` | Required | Input Linux authentication log |
| `--threshold` | `5` | Failed attempts required to trigger detection (minimum 2) |
| `--window` | `10` | Rolling failed-login window in minutes |
| `--correlation-window` | `30` | Time after the failed burst to look for a same-IP successful login |
| `--year` | Current year | Year added to traditional syslog timestamps that omit it |
| `--json` | `authsentry_report.json` | JSON report path |
| `--csv` | `authsentry_alerts.csv` | Alert CSV path |
| `--summary-csv` | `authsentry_ip_summary.csv` | Per-IP summary CSV path |

## Detection logic

1. Read each input line and identify supported OpenSSH `sshd` authentication records.
2. Parse failed and accepted password/public-key events; validate and normalise each source IP.
3. Group events by source IP and sort them by timestamp.
4. Use a sliding-window algorithm to find the largest cluster of failed attempts within the configured window.
5. Create an alert if the cluster meets the threshold.
6. Search for a successful login from the same IP after the end of that failed-login cluster and within the correlation window.
7. Export alerts and activity summaries for all source IPs.

### Severity heuristics

- **MEDIUM:** The failed-login threshold is met.
- **HIGH:** A successful login follows the qualifying failed burst from the same IP within the correlation window, or the burst reaches twice the threshold.
- **CRITICAL:** The burst reaches three times the threshold.

These simple heuristics are configurable starting points for a portfolio project, not universal production rules. Real environments require tuning, baselining, allowlists, identity context, endpoint telemetry, and analyst review.

## Example output

The bundled synthetic log is expected to produce an alert similar to:

```text
=== AuthSentry | SSH Authentication Report ===
Parsed events : 10 (failed: 8, accepted: 2)
Source IPs    : 3
Skipped lines : 0
Alert count   : 1

[HIGH] 203.0.113.10 — 6 failed attempts
  Usernames : admin, deploy, root, test
  Window    : 2026-11-19 18:00:01 to 2026-11-19 18:05:27
  Follow-up : successful login for deploy
  Mapping   : T1110 — Brute Force
```

`203.0.113.10`, `192.0.2.44`, and `198.51.100.25` are documentation/example address ranges; they do not identify real attackers.

## Run tests

```bash
python -m unittest discover -s tests -v
```

On Windows:

```powershell
py -m unittest discover -s tests -v
```

## MITRE ATT&CK context

The repeated authentication failures are associated with **T1110 — Brute Force**. The available log evidence does not establish a specific T1110 sub-technique. Multiple usernames alone are not enough to prove password spraying.

## Limitations

- Supports common OpenSSH `Failed password`, `Failed publickey`, and `Accepted` log messages; other authentication modules and distributions may format events differently.
- Traditional syslog timestamps omit the year. Use `--year` when analysing historical logs; year-boundary handling is not inferred automatically.
- Correlation is based on source IP and time only. Shared NAT, jump hosts, proxies, and legitimate administrators can produce misleading relationships.
- The tool identifies threshold patterns; it does not establish whether a login was malicious or whether an account was compromised.
- It is an offline file analyser, not a real-time SIEM or endpoint detection platform.

## Resume-ready description

**AuthSentry | Python, Cybersecurity, Log Analysis, Threat Detection**

- Built a Python-based SSH authentication log analyser to parse Linux OpenSSH records, validate source IPs, and normalise failed and successful login events.
- Implemented rolling-window brute-force detection and same-source-IP success correlation, with configurable thresholds and severity triage.
- Generated JSON and CSV incident reports, including per-IP activity summaries, targeted usernames, timestamps, and MITRE ATT&CK context; validated behaviour with automated unit tests.

Only include this project on your resume after you have run it locally and can accurately explain its detection logic and limitations.

## Repository structure

```text
AuthSentry/
├── authsentry.py
├── sample_auth.log
├── tests/
│   └── test_authsentry.py
├── .github/
│   └── workflows/
│       └── tests.yml
├── .gitignore
├── LICENSE
└── README.md
```
