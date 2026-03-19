---

## 2) `detector.py`

```python
#!/usr/bin/env python3
"""
Abuse Investigation Lab

This script reads local JSON logs, analyzes suspicious behavioral patterns,
prints a structured console report, and writes a machine-readable
investigation report to investigation_report.json.

Run:
    python3 detector.py
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Set


BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "sample_logs.json"
REPORT_FILE = BASE_DIR / "investigation_report.json"

THRESHOLDS = {
    "login_fail_count": 5,
    "high_value_transaction": 10000.0,
    "password_reset_count": 3,
    "shared_ip_medium_accounts": 2,
    "shared_ip_high_accounts": 3,
}


def load_logs(file_path: Path) -> List[Dict[str, Any]]:
    """
    Load JSON logs from disk.

    Returns an empty list if the file is missing or invalid.
    """
    if not file_path.exists():
        print(f"ERROR: Log file not found: {file_path}")
        return []

    try:
        with file_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as exc:
        print(f"ERROR: Failed to parse JSON from {file_path}: {exc}")
        return []
    except OSError as exc:
        print(f"ERROR: Failed to read {file_path}: {exc}")
        return []

    if not isinstance(data, list):
        print(f"ERROR: Expected a list of events in {file_path}")
        return []

    sanitized_events: List[Dict[str, Any]] = []
    for event in data:
        if isinstance(event, dict):
            sanitized_events.append(event)

    return sanitized_events


def normalize_str(value: Any, default: str = "unknown") -> str:
    """Return a safe string representation for potentially missing fields."""
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def normalize_float(value: Any, default: float = 0.0) -> float:
    """Return a safe float representation for potentially missing numeric fields."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def severity_rank(level: str) -> int:
    """Support sorting alerts by severity."""
    order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    return order.get(level.upper(), 0)


def analyze_logs(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyze events and generate a structured report dictionary.
    """
    login_fail_counts: Counter[str] = Counter()
    password_reset_counts: Counter[str] = Counter()
    transactions_by_user: Dict[str, List[float]] = defaultdict(list)
    ip_to_users: Dict[str, Set[str]] = defaultdict(set)
    user_to_ips: Dict[str, Set[str]] = defaultdict(set)
    alerts: List[Dict[str, Any]] = []

    for event in events:
        user = normalize_str(event.get("user"))
        action = normalize_str(event.get("action"))
        ip_address = normalize_str(event.get("ip"))
        amount = normalize_float(event.get("amount"), 0.0)

        # Track user/IP relationships when available.
        if ip_address != "unknown":
            ip_to_users[ip_address].add(user)
        if user != "unknown" and ip_address != "unknown":
            user_to_ips[user].add(ip_address)

        # Detection logic by action.
        if action == "login_fail":
            login_fail_counts[user] += 1

        elif action == "password_reset":
            password_reset_counts[user] += 1

        elif action == "transaction":
            transactions_by_user[user].append(amount)

            if amount > THRESHOLDS["high_value_transaction"]:
                alerts.append(
                    {
                        "severity": "HIGH",
                        "type": "high_value_transaction",
                        "user": user,
                        "ip": ip_address,
                        "message": (
                            f"High-value transaction detected for user '{user}' "
                            f"(amount={amount})"
                        ),
                        "evidence": {
                            "amount": amount,
                            "threshold": THRESHOLDS["high_value_transaction"],
                        },
                    }
                )

    # Post-processing rules based on aggregates.
    for user, count in login_fail_counts.items():
        if count >= THRESHOLDS["login_fail_count"]:
            alerts.append(
                {
                    "severity": "HIGH",
                    "type": "excessive_login_failures",
                    "user": user,
                    "ip": None,
                    "message": (
                        f"Excessive login failures detected for user '{user}' "
                        f"(count={count})"
                    ),
                    "evidence": {
                        "count": count,
                        "threshold": THRESHOLDS["login_fail_count"],
                    },
                }
            )

    for user, count in password_reset_counts.items():
        if count >= THRESHOLDS["password_reset_count"]:
            alerts.append(
                {
                    "severity": "MEDIUM",
                    "type": "excessive_password_resets",
                    "user": user,
                    "ip": None,
                    "message": (
                        f"Excessive password reset attempts detected for user '{user}' "
                        f"(count={count})"
                    ),
                    "evidence": {
                        "count": count,
                        "threshold": THRESHOLDS["password_reset_count"],
                    },
                }
            )

    for ip_address, users in ip_to_users.items():
        account_count = len(users)

        if account_count >= THRESHOLDS["shared_ip_high_accounts"]:
            severity = "MEDIUM"
        elif account_count >= THRESHOLDS["shared_ip_medium_accounts"]:
            severity = "LOW"
        else:
            continue

        alerts.append(
            {
                "severity": severity,
                "type": "shared_ip_multiple_accounts",
                "user": None,
                "ip": ip_address,
                "message": (
                    f"Shared IP detected: '{ip_address}' interacted with "
                    f"{account_count} accounts"
                ),
                "evidence": {
                    "account_count": account_count,
                    "users": sorted(users),
                },
            }
        )

    alerts.sort(
        key=lambda item: (
            -severity_rank(item.get("severity", "")),
            item.get("type", ""),
            item.get("message", ""),
        )
    )

    severity_counts = Counter(alert["severity"] for alert in alerts)

    users_summary: Dict[str, Any] = {}
    all_users = set(login_fail_counts) | set(password_reset_counts) | set(transactions_by_user)

    for user in sorted(all_users):
        users_summary[user] = {
            "login_failures": login_fail_counts.get(user, 0),
            "password_resets": password_reset_counts.get(user, 0),
            "transaction_count": len(transactions_by_user.get(user, [])),
            "max_transaction_amount": (
                max(transactions_by_user[user]) if transactions_by_user.get(user) else 0.0
            ),
            "ips_seen": sorted(user_to_ips.get(user, set())),
        }

    ip_summary: Dict[str, Any] = {}
    for ip_address in sorted(ip_to_users):
        ip_summary[ip_address] = {
            "distinct_users": sorted(ip_to_users[ip_address]),
            "distinct_user_count": len(ip_to_users[ip_address]),
        }

    report = {
        "analysis_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "total_events_analyzed": len(events),
        "total_alerts": len(alerts),
        "severity_counts": dict(severity_counts),
        "thresholds": THRESHOLDS,
        "users": users_summary,
        "ips": ip_summary,
        "alerts": alerts,
    }

    return report


def print_report(report: Dict[str, Any]) -> None:
    """
    Print a structured human-readable investigation summary.
    """
    print("=" * 60)
    print("ABUSE INVESTIGATION SUMMARY")
    print("=" * 60)
    print(f"Total events analyzed: {report.get('total_events_analyzed', 0)}")
    print(f"Total alerts generated: {report.get('total_alerts', 0)}")
    print()

    alerts = report.get("alerts", [])
    if not alerts:
        print("No suspicious activity detected.")
        print()
        return

    for alert in alerts:
        severity = normalize_str(alert.get("severity")).upper()
        message = normalize_str(alert.get("message"))
        print(f"[{severity}] {message}")

    print()


def write_report(report: Dict[str, Any], file_path: Path) -> None:
    """
    Write the structured JSON report to disk.
    """
    try:
        with file_path.open("w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
        print(f"JSON report written to: {file_path.name}")
    except OSError as exc:
        print(f"ERROR: Failed to write report to {file_path}: {exc}")


def main() -> None:
    """
    Main program entrypoint.
    """
    events = load_logs(LOG_FILE)
    report = analyze_logs(events)
    print_report(report)
    write_report(report, REPORT_FILE)


if __name__ == "__main__":
    main()