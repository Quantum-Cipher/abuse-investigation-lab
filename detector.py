import json
from collections import defaultdict

THRESHOLDS = {
    "login_fail": 5,
    "transaction_amount": 10000
}

def load_logs():
    with open("sample_logs.json", "r") as f:
        return json.load(f)

def analyze_logs(logs):
    login_attempts = defaultdict(int)
    alerts = []

    for log in logs:
        user = log.get("user")
        action = log.get("action")

        if action == "login_fail":
            login_attempts[user] += 1
            if login_attempts[user] >= THRESHOLDS["login_fail"]:
                alerts.append(f"[ALERT] Excessive login failures: {user}")

        if action == "transaction":
            amount = log.get("amount", 0)
            if amount > THRESHOLDS["transaction_amount"]:
                alerts.append(f"[ALERT] High-value transaction: {user} (${amount})")

    return alerts

def main():
    logs = load_logs()
    alerts = analyze_logs(logs)

    print("\n=== Abuse Detection Report ===")
    if not alerts:
        print("No suspicious activity detected.")
    else:
        for alert in alerts:
            print(alert)

if __name__ == "__main__":
    main()
