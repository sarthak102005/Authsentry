import unittest
from datetime import datetime

from authsentry import (
    AuthEvent,
    detect_brute_force,
    parse_line,
    summarize_by_ip,
)


class ParseLineTests(unittest.TestCase):
    def test_parses_failed_login(self):
        line = "Nov 19 10:15:30 host sshd[123]: Failed password for invalid user admin from 203.0.113.7 port 52000 ssh2"
        event = parse_line(line, 2026)
        self.assertIsNotNone(event)
        self.assertEqual(event.source_ip, "203.0.113.7")
        self.assertEqual(event.username, "admin")
        self.assertEqual(event.outcome, "failed")

    def test_parses_successful_login(self):
        line = "Nov 19 10:16:30 host sshd[124]: Accepted publickey for analyst from 198.51.100.8 port 52001 ssh2"
        event = parse_line(line, 2026)
        self.assertIsNotNone(event)
        self.assertEqual(event.outcome, "accepted")
        self.assertEqual(event.method, "publickey")

    def test_ignores_irrelevant_line(self):
        self.assertIsNone(parse_line("Nov 19 10:15:30 host CRON[100]: job started", 2026))

    def test_rejects_invalid_ip(self):
        line = "Nov 19 10:15:30 host sshd[123]: Failed password for admin from 999.999.1.1 port 52000 ssh2"
        self.assertIsNone(parse_line(line, 2026))


class DetectionTests(unittest.TestCase):
    def make_event(self, minute, source="203.0.113.7", outcome="failed", user="admin", second=0):
        return AuthEvent(datetime(2026, 11, 19, 10, minute, second), source, user, outcome, "password")

    def test_detects_threshold_inside_window(self):
        events = [self.make_event(m) for m in [0, 1, 2, 3, 4]]
        alerts = detect_brute_force(events, threshold=5, window_minutes=10)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "MEDIUM")
        self.assertFalse(alerts[0].successful_login_after_failures)

    def test_does_not_alert_when_attempts_are_spread_out(self):
        events = [self.make_event(m) for m in [0, 15, 30, 45, 59]]
        self.assertEqual(detect_brute_force(events, threshold=5, window_minutes=10), [])

    def test_high_severity_for_double_threshold(self):
        events = [self.make_event(m) for m in range(10)]
        alerts = detect_brute_force(events, threshold=5, window_minutes=10)
        self.assertEqual(alerts[0].severity, "HIGH")

    def test_critical_severity_for_triple_threshold(self):
        events = [self.make_event(m, second=m) for m in range(15)]
        alerts = detect_brute_force(events, threshold=5, window_minutes=20)
        self.assertEqual(alerts[0].severity, "CRITICAL")

    def test_correlates_success_after_failed_burst(self):
        events = [self.make_event(m) for m in range(5)]
        events.append(self.make_event(5, outcome="accepted", user="deploy"))
        alert = detect_brute_force(events, threshold=5, window_minutes=10)[0]
        self.assertEqual(alert.severity, "HIGH")
        self.assertTrue(alert.successful_login_after_failures)
        self.assertEqual(alert.successful_usernames, ["deploy"])

    def test_does_not_correlate_success_before_failed_burst(self):
        events = [self.make_event(0, outcome="accepted", user="deploy")]
        events.extend(self.make_event(m) for m in range(1, 6))
        alert = detect_brute_force(events, threshold=5, window_minutes=10)[0]
        self.assertFalse(alert.successful_login_after_failures)
        self.assertEqual(alert.severity, "MEDIUM")

    def test_prefers_later_qualifying_burst_for_success_correlation(self):
        # Two separate five-failure bursts from one source; only the later
        # burst is followed by a successful login.
        events = [self.make_event(m) for m in range(0, 5)]
        events.extend(self.make_event(m) for m in range(20, 25))
        events.append(self.make_event(26, outcome="accepted", user="deploy"))
        alert = detect_brute_force(events, threshold=5, window_minutes=10)[0]
        self.assertTrue(alert.successful_login_after_failures)
        self.assertEqual(alert.last_seen, "2026-11-19 10:24:00")
        self.assertEqual(alert.successful_usernames, ["deploy"])

    def test_does_not_hide_correlated_login_if_another_burst_occurs_later(self):
        # The first burst is followed by a success; a later burst must not
        # cause the earlier high-priority sequence to be discarded.
        events = [self.make_event(m) for m in range(0, 5)]
        events.append(self.make_event(6, outcome="accepted", user="deploy"))
        events.extend(self.make_event(m) for m in range(20, 25))
        alert = detect_brute_force(events, threshold=5, window_minutes=10)[0]
        self.assertTrue(alert.successful_login_after_failures)
        self.assertEqual(alert.last_seen, "2026-11-19 10:04:00")
        self.assertEqual(alert.successful_usernames, ["deploy"])

    def test_rejects_invalid_threshold(self):
        with self.assertRaises(ValueError):
            detect_brute_force([], threshold=1, window_minutes=10)

    def test_rejects_negative_correlation_window(self):
        with self.assertRaises(ValueError):
            detect_brute_force([], correlation_minutes=-1)

    def test_ip_summary_includes_non_alerting_sources(self):
        events = [self.make_event(m) for m in range(5)]
        events.append(self.make_event(8, source="192.0.2.44", user="guest"))
        alerts = detect_brute_force(events)
        summaries = summarize_by_ip(events, alerts)
        self.assertEqual(len(summaries), 2)
        self.assertTrue(summaries[0].alert_triggered)
        self.assertFalse(summaries[1].alert_triggered)


if __name__ == "__main__":
    unittest.main(verbosity=2)
