#!/usr/bin/env python3

import argparse
import os
import re
import sys
import time
from collections import defaultdict, deque

RULES = [
    {
        "name": "failed_ssh_login",
        "description": "Multiple failed SSH login attempts",
        "pattern": re.compile(r"(Failed password|authentication failure).*from (?P<ip>\d+\.\d+\.\d+\.\d+)", re.IGNORECASE),
        "threshold": 5,
        "window": 300,
    },
    {
        "name": "invalid_user",
        "description": "Repeated invalid user login attempts",
        "pattern": re.compile(r"Invalid user .* from (?P<ip>\d+\.\d+\.\d+\.\d+)", re.IGNORECASE),
        "threshold": 3,
        "window": 300,
    },
    {
        "name": "possible_port_scan",
        "description": "Many connections from the same IP in a short time",
        "pattern": re.compile(r"(Connection|Accepted|Denied).*(from|src=)(?P<ip>\d+\.\d+\.\d+\.\d+)", re.IGNORECASE),
        "threshold": 15,
        "window": 60,
    },
]


def is_valid_ip(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def parse_args():
    parser = argparse.ArgumentParser(description="Simple log-based IDS for basic intrusion detection")
    parser.add_argument("--file", "-f", required=True, help="Path to the log file to scan")
    parser.add_argument("--live", "-l", action="store_true", help="Monitor the file continuously")
    parser.add_argument("--rule", action="append", help="Only enable a specific rule name (can be repeated)")
    parser.add_argument("--threshold", type=int, help="Override the default threshold for all rules")
    parser.add_argument("--window", type=int, help="Override the default time window (seconds) for all rules")
    return parser.parse_args()


def tail_file(path):
    with open(path, "r", errors="ignore") as handle:
        handle.seek(0, os.SEEK_END)
        while True:
            line = handle.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line.rstrip("\n")


def scan_lines(lines, rules):
    state = {rule["name"]: defaultdict(lambda: deque()) for rule in rules}
    alerts = []

    for line in lines:
        timestamp = int(time.time())
        for rule in rules:
            match = rule["pattern"].search(line)
            if not match:
                continue
            ip = match.group("ip")
            if not is_valid_ip(ip):
                continue

            queue = state[rule["name"]][ip]
            queue.append(timestamp)
            cutoff = timestamp - rule["window"]
            while queue and queue[0] < cutoff:
                queue.popleft()

            if len(queue) >= rule["threshold"]:
                alert = {
                    "rule": rule["name"],
                    "description": rule["description"],
                    "ip": ip,
                    "count": len(queue),
                    "window": rule["window"],
                    "line": line,
                }
                alerts.append(alert)
                queue.clear()

    return alerts


def print_alert(alert):
    print("[ALERT] {}: {} | ip={} | count={} | window={}s".format(
        alert["rule"], alert["description"], alert["ip"], alert["count"], alert["window"]
    ))
    print("  sample: {}".format(alert["line"]))


def main():
    args = parse_args()
    if not os.path.isfile(args.file):
        print("Error: file does not exist: {}".format(args.file), file=sys.stderr)
        sys.exit(1)

    enabled_rules = [rule.copy() for rule in RULES]
    if args.rule:
        names = set(args.rule)
        enabled_rules = [rule for rule in enabled_rules if rule["name"] in names]
        if not enabled_rules:
            print("Error: no matching rules found for {}".format(args.rule), file=sys.stderr)
            sys.exit(1)

    if args.threshold is not None:
        for rule in enabled_rules:
            rule["threshold"] = args.threshold
    if args.window is not None:
        for rule in enabled_rules:
            rule["window"] = args.window

    if args.live:
        for line in tail_file(args.file):
            alerts = scan_lines([line], enabled_rules)
            for alert in alerts:
                print_alert(alert)
    else:
        with open(args.file, "r", errors="ignore") as handle:
            alerts = scan_lines((line.rstrip("\n") for line in handle), enabled_rules)
        for alert in alerts:
            print_alert(alert)


if __name__ == "__main__":
    main()
