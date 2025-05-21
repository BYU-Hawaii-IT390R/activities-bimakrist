"""Template script for IT 390R log‑analysis lab

Students: complete the **TODO** sections in `analyze_failed_logins` and
`analyze_successful_creds`.  All other tasks already work, so you can run the
script right away to explore the output format.

Run examples
------------
# Once you fill in the failed‑login logic
python analyze_log.py cowrie-tiny.log --task failed-logins --min-count 5

# Connection volume task (already functional)
python analyze_log.py cowrie-tiny.log --task connections

# Identify bot clients by shared fingerprint (already functional)
python analyze_log.py cowrie-tiny.log --task identify-bots --min-ips 3
"""

import argparse
import re
from collections import Counter, defaultdict
from datetime import datetime

# ── Regex patterns ──────────────────────────────────────────────────────────
FAILED_LOGIN_PATTERN = re.compile(
    r"\[HoneyPotSSHTransport,\d+,(?P<ip>\d+\.\d+\.\d+\.\d+)\].*?"
    r"login attempt \[.*?/.*?\] failed"
)

NEW_CONN_PATTERN = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)Z "
    r"\[cowrie\.ssh\.factory\.CowrieSSHFactory\] New connection: "
    r"(?P<ip>\d+\.\d+\.\d+\.\d+):\d+"
)

SUCCESS_LOGIN_PATTERN = re.compile(
    r"\[HoneyPotSSHTransport,\d+,(?P<ip>\d+\.\d+\.\d+\.\d+)\].*?"
    r"login attempt \[(?P<user>[^/]+)/(?P<pw>[^\]]+)\] succeeded"
)

FINGERPRINT_PATTERN = re.compile(
    r"\[HoneyPotSSHTransport,\d+,(?P<ip>\d+\.\d+\.\d+\.\d+)\].*?"
    r"SSH client hassh fingerprint: (?P<fp>[0-9a-f:]{32})"
)

# ── Extra Credit ──────────────────────────────────────────────────────────────
# regex assisted by Qwen: prompt "session-times regex for cowrie log"
# Note: this regex is not perfect, but it works for the provided log file.
SESSION_START_PATTERN = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)Z "
    r"\[cowrie\.ssh\.factory\.CowrieSSHFactory\] New connection: "
    r"(?P<ip>\d+\.\d+\.\d+\.\d+):\d+"
)

SESSION_END_PATTERN = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)Z "
    r"\[HoneyPotSSHTransport,\d+,(?P<ip>\d+\.\d+\.\d+\.\d+)\] connection lost"
)

# ── Helper to print tables ──────────────────────────────────────────────────

def _print_counter(counter: Counter, head1: str, head2: str, sort_keys=False):
    """Nicely format a Counter as a two‑column table."""
    width = max((len(str(k)) for k in counter), default=len(head1))
    print(f"{head1:<{width}} {head2:>8}")
    print("-" * (width + 9))
    items = sorted(counter.items()) if sort_keys else counter.most_common()
    for key, cnt in items:
        print(f"{key:<{width}} {cnt:>8}")

# ── TODO Task 1: fill this in ───────────────────────────────────────────────

def analyze_failed_logins(path: str, min_count: int):
    """Parse *failed* SSH login attempts and show a count per source IP.

    You should:
    1. Iterate over each line in ``path``.
    2. Use ``FAILED_LOGIN_PATTERN`` to search the line.
    3. Increment a Counter keyed by IP when a match is found.
    4. After reading the file, *filter out* any IP whose count is
       below ``min_count``.
    5. Print the results using ``_print_counter``.
    """
    # TODO: replace the placeholder implementation below
    #print("[TODO] analyze_failed_logins not yet implemented — write your code here!\n")
    counter = Counter()

    with open(path, encoding="utf-8") as fp:
        for line in fp:
            match = FAILED_LOGIN_PATTERN.search(line)
            if match:
                ip = match.group("ip")
                counter[ip] += 1

    # Apply filtering
    filtered = Counter({ip: count for ip, count in counter.items() if count >= min_count})

    print("Failed Login Attempts Per IP")
    _print_counter(filtered, "IP Address", "Count")

# ── Task 2 (already done) ───────────────────────────────────────────────────

def connections(path: str):
    per_min = Counter()
    with open(path, encoding="utf-8") as fp:
        for line in fp:
            m = NEW_CONN_PATTERN.search(line)
            if m:
                dt = datetime.strptime(m.group("ts")[:19], "%Y-%m-%dT%H:%M:%S")
                per_min[dt.strftime("%Y-%m-%d %H:%M")] += 1
    print("Connections per minute")
    _print_counter(per_min, "Timestamp", "Count", sort_keys=True)

# ── TODO Task 3: fill this in ───────────────────────────────────────────────

def analyze_successful_creds(path: str):
    """Display username/password pairs that *succeeded* and how many unique IPs used each.

    Steps:
    • Iterate lines and apply ``SUCCESS_LOGIN_PATTERN``.
    • Build a ``defaultdict(set)`` mapping ``(user, pw)`` → set of IPs.
    • After reading, sort the mapping by descending IP count and print a
      three‑column table (Username, Password, IP_Count).
    """
    # TODO: replace the placeholder implementation below
    #print("[TODO] analyze_successful_creds not yet implemented — write your code here!\n")
    cred_map = defaultdict(set)

    with open(path, encoding="utf-8") as fp:
        for line in fp:
            match = SUCCESS_LOGIN_PATTERN.search(line)
            if match:
                user = match.group("user").strip("b'")
                pw = match.group("pw").strip("b'")
                ip = match.group("ip")
                cred_map[(user, pw)].add(ip)

    # Convert to list of ((user, pw), count) and sort by count descending
    results = [((user, pw), len(ips)) for (user, pw), ips in cred_map.items()]
    results.sort(key=lambda x: x[1], reverse=True)

    print("Successful Credentials Usage")
    width_user = max(len(user) for (user, pw), _ in results) if results else 8
    width_pw = max(len(pw) for (user, pw), _ in results) if results else 8
    print(f"{'Username':<{width_user}} {'Password':<{width_pw}} {'Unique IPs':>10}")
    print("-" * (width_user + width_pw + 11))
    for (user, pw), count in results:
        print(f"{user:<{width_user}} {pw:<{width_pw}} {count:>10}")

# ── Task 4 (bot fingerprints) already implemented ───────────────────────────

def identify_bots(path: str, min_ips: int):
    fp_map = defaultdict(set)
    with open(path, encoding="utf-8") as fp:
        for line in fp:
            m = FINGERPRINT_PATTERN.search(line)
            if m:
                fp_map[m.group("fp")].add(m.group("ip"))
    bots = {fp: ips for fp, ips in fp_map.items() if len(ips) >= min_ips}
    print(f"Fingerprints seen from ≥ {min_ips} unique IPs")
    print(f"{'Fingerprint':<47} {'IPs':>6}")
    print("-" * 53)
    for fp, ips in sorted(bots.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"{fp:<47} {len(ips):>6}")

# ── Extra Credit Task: Session Times by Qwen AI ───────────────────────────────

def analyze_session_times(path: str):
    """Analyze SSH session durations: min, avg, max. Handles partial sessions."""
    import statistics

    active_sessions = {}  # ip -> start timestamp
    durations = []
    incomplete_count = 0

    with open(path, encoding="utf-8") as fp:
        for line in fp:
            # Look for session start
            start_match = SESSION_START_PATTERN.search(line)
            if start_match:
                ip = start_match.group("ip")
                ts = datetime.fromisoformat(start_match.group("ts"))
                active_sessions[ip] = ts

            # Look for session end
            end_match = SESSION_END_PATTERN.search(line)
            if end_match:
                ip = end_match.group("ip")
                if ip in active_sessions:
                    start_ts = active_sessions.pop(ip)
                    end_ts = datetime.fromisoformat(end_match.group("ts"))
                    duration = (end_ts - start_ts).total_seconds()
                    durations.append(duration)

        # After reading all lines, check for incomplete sessions
        incomplete_count = len(active_sessions)

    if durations:
        min_time = min(durations)
        max_time = max(durations)
        avg_time = statistics.mean(durations)

        print("SSH Session Duration Statistics")
        print(f"{'Min':>8}: {min_time:.2f} sec")
        print(f"{'Avg':>8}: {avg_time:.2f} sec")
        print(f"{'Max':>8}: {max_time:.2f} sec")
        print(f"Completed sessions: {len(durations)}")
        if incomplete_count > 0:
            print(f"⚠️ Incomplete sessions (start only): {incomplete_count}")
    else:
        print("No completed sessions found.")
        if incomplete_count > 0:
            print(f"Found {incomplete_count} incomplete session(s) (connection started but not closed).")

# ── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Cowrie log analyzer — student template")
    parser.add_argument("logfile", help="Path to log file")
    parser.add_argument("--task",
                    required=True,
                    choices=["failed-logins", "connections",
                             "successful-creds", "identify-bots",
                             "geo", "session-times"],
                    help="Which analysis to run")
    parser.add_argument("--min-count", type=int, default=1,
                        help="Min events to report (failed-logins)")
    parser.add_argument("--min-ips", type=int, default=3,
                        help="Min IPs per fingerprint (identify-bots)")
    args = parser.parse_args()

    if args.task == "failed-logins":
        analyze_failed_logins(args.logfile, args.min_count)
    elif args.task == "connections":
        connections(args.logfile)
    elif args.task == "successful-creds":
        analyze_successful_creds(args.logfile)
    elif args.task == "identify-bots":
        identify_bots(args.logfile, args.min_ips)
    elif args.task == "session-times":
        analyze_session_times(args.logfile)

if __name__ == "__main__":
    main()
