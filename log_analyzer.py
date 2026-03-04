#!/usr/bin/env python3
"""
Security Log Analyzer
- Parses Linux auth logs (auth.log style) and Windows Security logs (CSV export)
- Flags:
  1) Brute force (many failed logins from one IP)
  2) Password spraying (one IP failing across many usernames)
  3) Suspicious success after multiple failures
Outputs a short report to the console.
"""

from __future__ import annotations

import argparse
import csv
import re
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional


# -------------------------
# Helpers
# -------------------------

def safe_int(val: str, default: int = 0) -> int:
    try:
        return int(val)
    except Exception:
        return default


@dataclass
class Event:
    timestamp: datetime
    source: str          # "linux" | "windows"
    outcome: str         # "FAIL" | "SUCCESS"
    username: str
    ip: str
    raw: str


def parse_linux_auth_log(path: Path, year: Optional[int] = None) -> list[Event]:
    """
    Parses common OpenSSH auth.log lines like:
    'Mar  4 11:12:01 host sshd[123]: Failed password for invalid user bob from 1.2.3.4 port 12345 ssh2'
    'Mar  4 11:12:10 host sshd[123]: Accepted password for rocco from 1.2.3.4 port 2222 ssh2'
    """
    # Month Day Time ...
    # We'll assume current year if not provided.
    year = year or datetime.now().year

    failed_re = re.compile(
        r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d\d:\d\d:\d\d).+sshd\[\d+\]:\s+Failed password for (invalid user )?(?P<user>[\w\-\.\@]+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
    )
    success_re = re.compile(
        r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d\d:\d\d:\d\d).+sshd\[\d+\]:\s+Accepted (password|publickey) for (?P<user>[\w\-\.\@]+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
    )

    month_map = {
        "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
        "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
    }

    events: list[Event] = []

    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue

        m = failed_re.match(line)
        if m:
            mon = month_map.get(m.group("mon"), 1)
            day = safe_int(m.group("day"), 1)
            t = m.group("time")
            ts = datetime.strptime(f"{year}-{mon:02d}-{day:02d} {t}", "%Y-%m-%d %H:%M:%S")
            events.append(Event(ts, "linux", "FAIL", m.group("user"), m.group("ip"), line))
            continue

        m = success_re.match(line)
        if m:
            mon = month_map.get(m.group("mon"), 1)
            day = safe_int(m.group("day"), 1)
            t = m.group("time")
            ts = datetime.strptime(f"{year}-{mon:02d}-{day:02d} {t}", "%Y-%m-%d %H:%M:%S")
            events.append(Event(ts, "linux", "SUCCESS", m.group("user"), m.group("ip"), line))
            continue

    return sorted(events, key=lambda e: e.timestamp)


def parse_windows_security_csv(path: Path) -> list[Event]:
    """
    Windows Security logs exported as CSV commonly have columns like:
    TimeCreated, Id, Message, ...
    We will look for:
    - 4625 (failed logon)
    - 4624 (successful logon)
    We'll attempt to extract username and IP from the Message field.
    """
    events: list[Event] = []

    # Common patterns inside Windows event messages
    ip_re = re.compile(r"Source Network Address:\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
    user_re = re.compile(r"Account Name:\s*(?P<user>.+)")
    # Some exports might use "TargetUserName"
    alt_user_re = re.compile(r"TargetUserName:\s*(?P<user>.+)")

    with path.open("r", encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Try a few possible header names
            time_str = row.get("TimeCreated") or row.get("TimeCreated(System)") or row.get("Date and Time") or row.get("Timestamp")
            event_id = row.get("Id") or row.get("EventID") or row.get("Event Id") or row.get("Event ID")
            message = row.get("Message") or row.get("Description") or ""

            if not time_str or not event_id:
                continue

            # Parse timestamp flexibly
            ts = None
            for fmt in ("%m/%d/%Y %I:%M:%S %p", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S"):
                try:
                    ts = datetime.strptime(time_str.strip(), fmt)
                    break
                except Exception:
                    pass
            if ts is None:
                continue

            eid = safe_int(str(event_id).strip(), 0)
            if eid not in (4624, 4625):
                continue

            ip = "unknown"
            mi = ip_re.search(message)
            if mi:
                ip = mi.group("ip").strip()

            user = "unknown"
            mu = alt_user_re.search(message) or user_re.search(message)
            if mu:
                user = mu.group("user").strip()
                # Clean common noise
                user = user.replace("\t", " ").strip()
                if user.lower() in ("-", "anonymous logon", "null"):
                    user = "unknown"

            outcome = "SUCCESS" if eid == 4624 else "FAIL"
            events.append(Event(ts, "windows", outcome, user, ip, message[:200].replace("\n", " ")))

    return sorted(events, key=lambda e: e.timestamp)


# -------------------------
# Detections
# -------------------------

@dataclass
class Finding:
    title: str
    severity: str  # Low/Med/High
    details: str


def detect_bruteforce(events: list[Event], window_minutes: int, fail_threshold: int) -> list[Finding]:
    """
    Many FAIL events from a single IP within a short time window.
    """
    findings: list[Finding] = []
    events_by_ip: dict[str, list[Event]] = defaultdict(list)

    for e in events:
        if e.outcome == "FAIL" and e.ip != "unknown":
            events_by_ip[e.ip].append(e)

    window = timedelta(minutes=window_minutes)

    for ip, ip_events in events_by_ip.items():
        dq = deque()
        max_in_window = 0
        max_end = None

        for e in ip_events:
            dq.append(e)
            while dq and (e.timestamp - dq[0].timestamp) > window:
                dq.popleft()
            if len(dq) > max_in_window:
                max_in_window = len(dq)
                max_end = e.timestamp

        if max_in_window >= fail_threshold:
            start = (max_end - window) if max_end else ip_events[0].timestamp
            details = (
                f"IP {ip} had {max_in_window} failed logins within ~{window_minutes} minutes "
                f"(approx window: {start} to {max_end})."
            )
            findings.append(Finding("Possible brute force attempt", "High", details))

    return findings


def detect_password_spraying(events: list[Event], window_minutes: int, unique_users_threshold: int, min_fails: int) -> list[Finding]:
    """
    One IP failing across many different usernames in a short time window.
    """
    findings: list[Finding] = []
    events_by_ip: dict[str, list[Event]] = defaultdict(list)

    for e in events:
        if e.outcome == "FAIL" and e.ip != "unknown" and e.username != "unknown":
            events_by_ip[e.ip].append(e)

    window = timedelta(minutes=window_minutes)

    for ip, ip_events in events_by_ip.items():
        # Sliding window: track usernames in the window
        dq = deque()
        user_counts = defaultdict(int)

        best_unique = 0
        best_total = 0
        best_end = None

        for e in ip_events:
            dq.append(e)
            user_counts[e.username] += 1

            while dq and (e.timestamp - dq[0].timestamp) > window:
                old = dq.popleft()
                user_counts[old.username] -= 1
                if user_counts[old.username] <= 0:
                    del user_counts[old.username]

            unique_users = len(user_counts)
            total_fails = len(dq)

            if unique_users > best_unique or (unique_users == best_unique and total_fails > best_total):
                best_unique = unique_users
                best_total = total_fails
                best_end = e.timestamp

        if best_unique >= unique_users_threshold and best_total >= min_fails:
            start = (best_end - window) if best_end else ip_events[0].timestamp
            details = (
                f"IP {ip} failed logins against {best_unique} different usernames "
                f"({best_total} total fails) within ~{window_minutes} minutes "
                f"(approx window: {start} to {best_end})."
            )
            findings.append(Finding("Possible password spraying", "High", details))

    return findings


def detect_success_after_fail(events: list[Event], window_minutes: int, fail_count: int) -> list[Finding]:
    """
    SUCCESS from an IP after multiple FAILs from the same IP in a short window.
    """
    findings: list[Finding] = []
    window = timedelta(minutes=window_minutes)

    # Track recent failures per IP
    recent_fails: dict[str, deque[datetime]] = defaultdict(deque)

    for e in events:
        if e.ip == "unknown":
            continue

        if e.outcome == "FAIL":
            recent_fails[e.ip].append(e.timestamp)
            # prune old
            while recent_fails[e.ip] and (e.timestamp - recent_fails[e.ip][0]) > window:
                recent_fails[e.ip].popleft()

        elif e.outcome == "SUCCESS":
            # prune based on current time
            while recent_fails[e.ip] and (e.timestamp - recent_fails[e.ip][0]) > window:
                recent_fails[e.ip].popleft()

            if len(recent_fails[e.ip]) >= fail_count:
                details = (
                    f"IP {e.ip} had a successful login for '{e.username}' after "
                    f"{len(recent_fails[e.ip])} failures within ~{window_minutes} minutes "
                    f"(success at {e.timestamp})."
                )
                findings.append(Finding("Suspicious success after repeated failures", "Medium", details))
                # reset to avoid spamming findings
                recent_fails[e.ip].clear()

    return findings


# -------------------------
# Main
# -------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Security Log Analyzer (Linux auth.log + Windows Security CSV)")
    parser.add_argument("--linux", type=str, help="Path to Linux auth log (auth.log style)")
    parser.add_argument("--windows", type=str, help="Path to Windows Security log exported as CSV")
    parser.add_argument("--window-min", type=int, default=10, help="Detection window in minutes (default: 10)")
    parser.add_argument("--bruteforce-fails", type=int, default=8, help="Fails from 1 IP to flag bruteforce (default: 8)")
    parser.add_argument("--spray-users", type=int, default=5, help="Unique usernames from 1 IP to flag spraying (default: 5)")
    parser.add_argument("--spray-min-fails", type=int, default=8, help="Min fails in window to flag spraying (default: 8)")
    parser.add_argument("--success-fails", type=int, default=5, help="Fails before success to flag (default: 5)")
    args = parser.parse_args()

    events: list[Event] = []

    if args.linux:
        linux_path = Path(args.linux)
        if not linux_path.exists():
            print(f"[!] Linux log not found: {linux_path}")
            return 1
        events.extend(parse_linux_auth_log(linux_path))

    if args.windows:
        win_path = Path(args.windows)
        if not win_path.exists():
            print(f"[!] Windows CSV not found: {win_path}")
            return 1
        events.extend(parse_windows_security_csv(win_path))

    if not events:
        print("[!] No events loaded. Provide --linux and/or --windows.")
        return 1

    events = sorted(events, key=lambda e: e.timestamp)

    findings: list[Finding] = []
    findings.extend(detect_bruteforce(events, args.window_min, args.bruteforce_fails))
    findings.extend(detect_password_spraying(events, args.window_min, args.spray_users, args.spray_min_fails))
    findings.extend(detect_success_after_fail(events, args.window_min, args.success_fails))

    # Report
    print("\n=== Security Log Analyzer Report ===")
    print(f"Events loaded: {len(events)}")
    print(f"Time range: {events[0].timestamp}  →  {events[-1].timestamp}\n")

    if not findings:
        print("No suspicious patterns detected with current thresholds.\n")
        return 0

    # Group by severity
    severity_order = {"High": 0, "Medium": 1, "Low": 2}
    findings.sort(key=lambda f: severity_order.get(f.severity, 99))

    for i, f in enumerate(findings, 1):
        print(f"[{i}] {f.severity} — {f.title}")
        print(f"    {f.details}\n")

    print("Tip: adjust thresholds with flags like --bruteforce-fails or --window-min.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())