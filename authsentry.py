#!/usr/bin/env python3
"""AuthSentry: defensive SSH authentication log analyser.

Parses common Linux OpenSSH authentication records, detects bursts of failed
logins by source IP, correlates subsequent successful logins, and exports
analyst-friendly incident reports.
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable

SYSLOG_PREFIX = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<clock>\d{2}:\d{2}:\d{2})\s+.*?sshd(?:\[\d+\])?:\s+(?P<message>.*)$"
)
FAILED_LOGIN = re.compile(
    r"Failed\s+(?P<method>password|publickey)\s+for\s+"
    r"(?P<invalid>invalid user\s+)?(?P<username>\S+)\s+"
    r"from\s+(?P<ip>[0-9a-fA-F:.]+)\s+port\s+\d+",
    re.IGNORECASE,
)
ACCEPTED_LOGIN = re.compile(
    r"Accepted\s+(?P<method>password|publickey)\s+for\s+"
    r"(?P<username>\S+)\s+from\s+(?P<ip>[0-9a-fA-F:.]+)\s+port\s+\d+",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime
    source_ip: str
    username: str
    outcome: str
    method: str


@dataclass
class Alert:
    source_ip: str
    failed_attempts: int
    usernames_targeted: list[str]
    successful_login_after_failures: bool
    successful_usernames: list[str]
    first_seen: str
    last_seen: str
    severity: str
    title: str
    mitre_attack: str
    recommendation: str


@dataclass
class IPActivity:
    source_ip: str
    total_events: int
    failed_attempts: int
    successful_logins: int
    unique_usernames: list[str]
    first_seen: str
    last_seen: str
    alert_triggered: bool


def parse_line(line: str, year: int) -> AuthEvent | None:
    """Parse one common Linux auth.log sshd record; ignore unrelated lines."""
    prefix = SYSLOG_PREFIX.match(line.strip())
    if not prefix:
        return None

    message = prefix.group("message")
    match = FAILED_LOGIN.search(message)
    outcome = "failed"
    if not match:
        match = ACCEPTED_LOGIN.search(message)
        outcome = "accepted"
    if not match:
        return None

    try:
        source_ip = str(ipaddress.ip_address(match.group("ip")))
        timestamp = datetime.strptime(
            f"{year} {prefix.group('month')} {prefix.group('day')} {prefix.group('clock')}",
            "%Y %b %d %H:%M:%S",
        )
    except ValueError:
        return None

    return AuthEvent(
        timestamp=timestamp,
        source_ip=source_ip,
        username=match.group("username"),
        outcome=outcome,
        method=match.group("method").lower(),
    )


def parse_log(lines: Iterable[str], year: int) -> tuple[list[AuthEvent], int]:
    """Parse log lines and return chronologically sorted events and skipped count."""
    events: list[AuthEvent] = []
    skipped = 0
    for line in lines:
        event = parse_line(line, year)
        if event is None:
            skipped += 1
        else:
            events.append(event)
    return sorted(events, key=lambda event: event.timestamp), skipped


def detect_brute_force(
    events: list[AuthEvent],
    threshold: int = 5,
    window_minutes: int = 10,
    correlation_minutes: int = 30,
) -> list[Alert]:
    """Detect failed-login bursts and correlate a later success from the same IP.

    A HIGH alert is raised when a successful login follows a qualifying failed
    burst from the same source IP within ``correlation_minutes``. A burst at
    twice the configured threshold is also HIGH; at three times the threshold
    it is CRITICAL. These are triage heuristics, not proof of compromise.
    """
    if threshold < 2:
        raise ValueError("threshold must be at least 2")
    if window_minutes < 1:
        raise ValueError("window_minutes must be at least 1")
    if correlation_minutes < 0:
        raise ValueError("correlation_minutes cannot be negative")

    events_by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        events_by_ip[event.source_ip].append(event)

    alerts: list[Alert] = []
    window = timedelta(minutes=window_minutes)
    correlation_window = timedelta(minutes=correlation_minutes)

    for source_ip, ip_events in events_by_ip.items():
        failures = [event for event in ip_events if event.outcome == "failed"]
        successes = [event for event in ip_events if event.outcome == "accepted"]
        if not failures:
            continue

        # Evaluate every rolling candidate. Prefer a qualifying cluster that
        # has a subsequent same-IP success; then prefer more failures and the
        # most recent cluster. This avoids hiding a correlated login merely
        # because another uncorrelated burst occurred later from the same IP.
        left = 0
        best_window: list[AuthEvent] = []
        best_correlated_successes: list[AuthEvent] = []
        best_key: tuple[int, int, datetime] = (-1, -1, datetime.min)
        for right, current in enumerate(failures):
            while current.timestamp - failures[left].timestamp > window:
                left += 1
            candidate = failures[left : right + 1]
            if len(candidate) < threshold:
                continue
            candidate_end = candidate[-1].timestamp
            candidate_successes = [
                event for event in successes
                if candidate_end < event.timestamp <= candidate_end + correlation_window
            ]
            candidate_key = (int(bool(candidate_successes)), len(candidate), candidate_end)
            if candidate_key > best_key:
                best_key = candidate_key
                best_window = candidate
                best_correlated_successes = candidate_successes

        if len(best_window) < threshold:
            continue

        burst_end = best_window[-1].timestamp
        correlated_successes = best_correlated_successes
        correlated = bool(correlated_successes)
        count = len(best_window)
        if count >= threshold * 3:
            severity = "CRITICAL"
        elif correlated or count >= threshold * 2:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        if correlated:
            title = "SSH failures followed by successful authentication"
            recommendation = (
                "Treat as a potential account compromise: preserve relevant logs, verify the "
                "successful session with the account owner, review subsequent activity and "
                "follow the organisation's incident-response process. Revoke sessions or "
                "disable credentials only under the approved response procedure."
            )
        else:
            title = "Repeated SSH authentication failures"
            recommendation = (
                "Review SSH authentication logs; verify whether the source is expected; "
                "check for related successful logins; restrict SSH exposure and enforce "
                "key-based authentication/MFA where supported."
            )

        alerts.append(
            Alert(
                source_ip=source_ip,
                failed_attempts=count,
                usernames_targeted=sorted({event.username for event in best_window}),
                successful_login_after_failures=correlated,
                successful_usernames=sorted({event.username for event in correlated_successes}),
                first_seen=best_window[0].timestamp.isoformat(sep=" "),
                last_seen=burst_end.isoformat(sep=" "),
                severity=severity,
                title=title,
                mitre_attack="T1110 — Brute Force",
                recommendation=recommendation,
            )
        )

    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    return sorted(alerts, key=lambda alert: (severity_rank[alert.severity], -alert.failed_attempts, alert.source_ip))


def summarize_by_ip(events: list[AuthEvent], alerts: list[Alert]) -> list[IPActivity]:
    """Summarise all observed source IPs, including those below alert threshold."""
    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        by_ip[event.source_ip].append(event)
    alerted_ips = {alert.source_ip for alert in alerts}

    summaries: list[IPActivity] = []
    for source_ip, ip_events in by_ip.items():
        ordered = sorted(ip_events, key=lambda event: event.timestamp)
        summaries.append(
            IPActivity(
                source_ip=source_ip,
                total_events=len(ordered),
                failed_attempts=sum(event.outcome == "failed" for event in ordered),
                successful_logins=sum(event.outcome == "accepted" for event in ordered),
                unique_usernames=sorted({event.username for event in ordered}),
                first_seen=ordered[0].timestamp.isoformat(sep=" "),
                last_seen=ordered[-1].timestamp.isoformat(sep=" "),
                alert_triggered=source_ip in alerted_ips,
            )
        )
    return sorted(summaries, key=lambda item: (-item.failed_attempts, item.source_ip))


def _prepare_output(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def write_json(
    path: Path,
    events: list[AuthEvent],
    alerts: list[Alert],
    ip_summaries: list[IPActivity],
    skipped: int,
    threshold: int,
    window_minutes: int,
    correlation_minutes: int,
) -> None:
    report = {
        "tool": "AuthSentry",
        "report_generated_at": datetime.now().isoformat(timespec="seconds"),
        "detection_config": {
            "failed_attempt_threshold": threshold,
            "window_minutes": window_minutes,
            "success_correlation_minutes": correlation_minutes,
        },
        "summary": {
            "parsed_authentication_events": len(events),
            "failed_events": sum(event.outcome == "failed" for event in events),
            "accepted_events": sum(event.outcome == "accepted" for event in events),
            "unique_source_ips": len(ip_summaries),
            "skipped_lines": skipped,
            "alerts_generated": len(alerts),
        },
        "source_ip_activity": [asdict(summary) for summary in ip_summaries],
        "alerts": [asdict(alert) for alert in alerts],
    }
    _prepare_output(path)
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")


def write_csv(path: Path, alerts: list[Alert]) -> None:
    fieldnames = [
        "source_ip", "failed_attempts", "usernames_targeted",
        "successful_login_after_failures", "successful_usernames",
        "first_seen", "last_seen", "severity", "title", "mitre_attack",
        "recommendation",
    ]
    _prepare_output(path)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for alert in alerts:
            row = asdict(alert)
            row["usernames_targeted"] = ";".join(alert.usernames_targeted)
            row["successful_usernames"] = ";".join(alert.successful_usernames)
            writer.writerow(row)


def write_summary_csv(path: Path, summaries: list[IPActivity]) -> None:
    fieldnames = [
        "source_ip", "total_events", "failed_attempts", "successful_logins",
        "unique_usernames", "first_seen", "last_seen", "alert_triggered",
    ]
    _prepare_output(path)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for summary in summaries:
            row = asdict(summary)
            row["unique_usernames"] = ";".join(summary.unique_usernames)
            writer.writerow(row)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyse Linux SSH authentication logs for suspicious login activity."
    )
    parser.add_argument("--log", type=Path, required=True, help="Path to Linux auth.log")
    parser.add_argument("--threshold", type=int, default=5,
                        help="Failed attempts needed to trigger an alert (default: 5)")
    parser.add_argument("--window", type=int, default=10,
                        help="Rolling failed-login detection window in minutes (default: 10)")
    parser.add_argument("--correlation-window", type=int, default=30,
                        help="Minutes after a failed burst to look for a same-IP success (default: 30)")
    parser.add_argument("--year", type=int, default=datetime.now().year,
                        help="Year for syslog timestamps that omit the year")
    parser.add_argument("--json", dest="json_path", type=Path, default=Path("authsentry_report.json"),
                        help="JSON report output path")
    parser.add_argument("--csv", dest="csv_path", type=Path, default=Path("authsentry_alerts.csv"),
                        help="CSV alert output path")
    parser.add_argument("--summary-csv", type=Path, default=Path("authsentry_ip_summary.csv"),
                        help="Per-source-IP activity CSV output path")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.threshold < 2:
        parser.error("--threshold must be at least 2")
    if args.window < 1:
        parser.error("--window must be at least 1")
    if args.correlation_window < 0:
        parser.error("--correlation-window cannot be negative")
    if not args.log.is_file():
        print(f"[ERROR] Log file not found: {args.log}", file=sys.stderr)
        return 2

    try:
        with args.log.open("r", encoding="utf-8", errors="replace") as handle:
            events, skipped = parse_log(handle, args.year)
        alerts = detect_brute_force(events, args.threshold, args.window, args.correlation_window)
        summaries = summarize_by_ip(events, alerts)
        write_json(args.json_path, events, alerts, summaries, skipped,
                   args.threshold, args.window, args.correlation_window)
        write_csv(args.csv_path, alerts)
        write_summary_csv(args.summary_csv, summaries)
    except OSError as exc:
        print(f"[ERROR] Could not read or write a file: {exc}", file=sys.stderr)
        return 2

    failed = sum(event.outcome == "failed" for event in events)
    accepted = sum(event.outcome == "accepted" for event in events)
    print("\n=== AuthSentry | SSH Authentication Report ===")
    print(f"Parsed events : {len(events)} (failed: {failed}, accepted: {accepted})")
    print(f"Source IPs    : {len(summaries)}")
    print(f"Skipped lines : {skipped}")
    print(f"Alert count   : {len(alerts)}")
    if alerts:
        for alert in alerts:
            print(f"\n[{alert.severity}] {alert.source_ip} — {alert.failed_attempts} failed attempts")
            print(f"  Usernames : {', '.join(alert.usernames_targeted)}")
            print(f"  Window    : {alert.first_seen} to {alert.last_seen}")
            if alert.successful_login_after_failures:
                print(f"  Follow-up : successful login for {', '.join(alert.successful_usernames)}")
            else:
                print("  Follow-up : no same-IP successful login found in correlation window")
            print(f"  Mapping   : {alert.mitre_attack}")
    else:
        print("No brute-force threshold was met in the supplied log.")
    print(f"\nJSON report : {args.json_path}")
    print(f"Alert CSV   : {args.csv_path}")
    print(f"IP summary  : {args.summary_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
