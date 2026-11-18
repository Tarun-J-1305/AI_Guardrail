import os
import re
from collections import Counter

LOG_FILE = "security_audit.log"

def generate_report():
    if not os.path.exists(LOG_FILE):
        print("No audit log found yet.")
        return

    counts = Counter()
    blocked_events = []

    with open(LOG_FILE, "r") as f:
        for line in f:
            line = line.strip()
            match = re.match(r"^\[(.*?)\] \[(INFO|WARNING|BLOCKED|ALLOWED)\] (.*)$", line)
            if match:
                timestamp, level, msg = match.groups()
                counts[level] += 1
                if level == "BLOCKED":
                    blocked_events.append((timestamp, msg))

    total_events = sum(counts.values())
    print("\n" + "=" * 62)
    print("         AI GUARDRAIL MIDDLEWARE - SECURITY AUDIT REPORT")
    print("=" * 62)
    print(f"Total Logged Events      : {total_events}")
    print(f"  [INFO]    Intercepted  : {counts['INFO']}")
    print(f"  [ALLOWED] Permitted    : {counts['ALLOWED']}")
    print(f"  [WARNING] Taint Alerts : {counts['WARNING']}")
    print(f"  [BLOCKED] Attacks Stop : {counts['BLOCKED']}")
    print("-" * 62)
    print("RECENT BLOCKED SECURITY VIOLATIONS (Last 5):")
    print("-" * 62)
    for ts, msg in blocked_events[-5:]:
        print(f"  [{ts}] {msg}")
    print("=" * 62 + "\n")

if __name__ == "__main__":
    generate_report()
