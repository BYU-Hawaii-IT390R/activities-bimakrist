"""Windows Admin Toolkit – reference solution
-------------------------------------------------
Requires **pywin32** (``pip install pywin32``) and works on Win10/11.

Implemented tasks (select with ``--task``):

* **win-events**       – failed & successful logons from the Security log
* **win-pkgs**         – list installed software (DisplayName + Version)
* **win-services**     – check service states; auto‑start if ``--fix`` flag supplied

Example runs
------------
```powershell
# Show IPs with ≥ 3 failed logons in last 12 h
python analyze_windows.py --task win-events --hours 12 --min-count 3

# Dump installed packages to a CSV
python analyze_windows.py --task win-pkgs --csv pkgs.csv

# Ensure Spooler & Windows Update are running (start them if stopped)
python analyze_windows.py --task win-services --watch Spooler wuauserv --fix
```
"""

from __future__ import annotations
import argparse
import collections
import csv
import datetime as _dt
import io
import re
import subprocess
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

try:
    import win32evtlog  # type: ignore
    import winreg  # std‑lib but Windows‑only
except ImportError:
    sys.stderr.write("pywin32 required → pip install pywin32\n")
    sys.exit(1)

# ── Constants / regex ──────────────────────────────────────────────────────
SECURITY_CHANNEL = "Security"
EVENT_FAILED = "4625"   # failed logon
EVENT_SUCCESS = "4624"  # successful logon
IP_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
COLOR_WARN = "\033[93m"  # yellow               (Qwen AI-generated constant)

# ── Utility: pretty Counter table ──────────────────────────────────────────

def _print_counter(counter: dict, h1: str, h2: str):
    if not counter:
        print("(no data)\n")
        return
    width = max(len(str(k)) for k in counter)
    print(f"{h1:<{width}} {h2:>8}")
    print("-" * (width + 9))
    for k, v in sorted(counter.items(), key=lambda item: item[1], reverse=True):
        print(f"{k:<{width}} {v:>8}")
    print()

# ══════════════════════════════════════════════════════════════════════════
# Task 1: Event‑Log triage (win-events)
# ══════════════════════════════════════════════════════════════════════════

def _query_security_xml(hours_back: int):
    delta_sec = hours_back * 3600
    q = (
        f"*[(System/TimeCreated[timediff(@SystemTime) <= {delta_sec}] "
        f"and (System/EventID={EVENT_FAILED} or System/EventID={EVENT_SUCCESS}))]"
    )
    try:
        h = win32evtlog.EvtQuery(SECURITY_CHANNEL, win32evtlog.EvtQueryReverseDirection, q)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "winerror", None) == 5:
            sys.exit("❌ Access denied – run as Administrator or add your account to *Event Log Readers* group.")
        raise
    while True:
        try:
            ev = win32evtlog.EvtNext(h, 1)[0]
        except IndexError:
            break
        yield win32evtlog.EvtRender(ev, win32evtlog.EvtRenderEventXml)


def _parse_event(xml_str: str):
    root = ET.fromstring(xml_str)
    eid = root.findtext("./System/EventID")
    data = {n.attrib.get("Name"): n.text for n in root.findall("./EventData/Data")}
    user = data.get("TargetUserName") or data.get("SubjectUserName") or "?"
    ip = data.get("IpAddress") or "?"
    if ip == "?":
        m = IP_RE.search(xml_str)
        if m:
            ip = m.group()
    return eid, user, ip


def win_events(hours_back: int, min_count: int):
    failed = collections.Counter()
    success = collections.defaultdict(set)  # user → {ip,…}
    for xml_str in _query_security_xml(hours_back):
        eid, user, ip = _parse_event(xml_str)
        if eid == EVENT_FAILED and ip != "?":
            failed[ip] += 1
        elif eid == EVENT_SUCCESS and user not in ("-", "?"):
            success[user].add(ip)

    print(f"\n❌ Failed logons ≥{min_count} (last {hours_back}h)")
    _print_counter({ip: c for ip, c in failed.items() if c >= min_count}, "Source IP", "Count")

    print(f"✅ Successful logons ≥{min_count} IPs (last {hours_back}h)")
    succ = {u: ips for u, ips in success.items() if len(ips) >= min_count}
    width = max((len(u) for u in succ), default=8)
    print(f"{'Username':<{width}} {'IPs':>8}")
    print("-" * (width + 9))
    for user, ips in sorted(succ.items(), key=lambda item: len(item[1]), reverse=True):
        print(f"{user:<{width}} {len(ips):>8}")
    print()

# ══════════════════════════════════════════════════════════════════════════
# Task 2: Installed software audit (win-pkgs)
# ══════════════════════════════════════════════════════════════════════════

UNINSTALL_PATHS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
]

def win_pkgs(csv_path: str | None):
    rows: list[tuple[str, str]] = []
    for root, path in UNINSTALL_PATHS:
        try:
            hive = winreg.OpenKey(root, path)
        except FileNotFoundError:
            continue
        for i in range(winreg.QueryInfoKey(hive)[0]):
            try:
                sub = winreg.OpenKey(hive, winreg.EnumKey(hive, i))
                name, _ = winreg.QueryValueEx(sub, "DisplayName")
                ver, _ = winreg.QueryValueEx(sub, "DisplayVersion")
                rows.append((name, ver))
            except FileNotFoundError:
                continue
    print(f"\n🗃 Installed software ({len(rows)} entries)")
    width = max(len(n) for n, _ in rows)
    print(f"{'DisplayName':<{width}} Version")
    print("-" * (width + 8))
    for name, ver in sorted(rows):
        print(f"{name:<{width}} {ver}")
    print()
    if csv_path:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerows(rows)
        print(f"📑 CSV exported → {csv_path}\n")

# ══════════════════════════════════════════════════════════════════════════
# Task 3: Service status checker (win-services)
# ══════════════════════════════════════════════════════════════════════════

COLOR_OK = "\033[92m"  # green
COLOR_BAD = "\033[91m"  # red
COLOR_RESET = "\033[0m"


def _service_state(name: str) -> str:
    out = subprocess.check_output(["sc", "query", name], text=True, stderr=subprocess.STDOUT)
    return "RUNNING" if "RUNNING" in out else "STOPPED"


def win_services(watch: list[str], auto_fix: bool):
    if not watch:
        watch = ["Spooler", "wuauserv"]
    print("\n🩺 Service status")
    for svc in watch:
        state = _service_state(svc)
        ok = state == "RUNNING"
        colour = COLOR_OK if ok else COLOR_BAD
        print(f"{svc:<20} {colour}{state}{COLOR_RESET}")
        if not ok and auto_fix:
            print(f"  ↳ attempting to start {svc} …", end="")
            subprocess.call(["sc", "start", svc], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            state = _service_state(svc)
            print("done" if state == "RUNNING" else "failed")
    print()

# ══════════════════════════════════════════════════════════════════════════
# Task 4: Scheduled Task Auditor (win-tasks)             (Qwen AI-generated)
# ══════════════════════════════════════════════════════════════════════════

def _parse_schtasks():
    try:
        output = subprocess.check_output(
            ["schtasks", "/query", "/fo", "CSV"],
            text=True,
            stderr=subprocess.DEVNULL
        )
    except subprocess.CalledProcessError:
        sys.exit("❌ Failed to query scheduled tasks – run as Administrator.")

    tasks = []
    reader = csv.DictReader(io.StringIO(output))
    for row in reader:
        author = row.get("Author", "")
        name = row.get("TaskName", "").strip()
        if not author.startswith("Microsoft") and name and not name.lower().startswith("taskname"):
            tasks.append((name, row["Next Run Time"], row["Status"]))
    return tasks


def win_tasks(filter_keyword=None, csv_path=None):
    tasks = _parse_schtasks()

    if filter_keyword:
        tasks = [t for t in tasks if filter_keyword.lower() in t[0].lower()]

    print(f"\n⏰ Non-Microsoft scheduled tasks ({len(tasks)} found after filtering)")

    if not tasks:
        print("(no non-Microsoft tasks found)\n")
        return

    if csv_path:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["TaskName", "Next Run Time", "Status"])
            writer.writerows(tasks)
        print(f"📑 CSV exported → {csv_path}\n")

    max_name = max(len(t[0]) for t in tasks)
    print(f"{'Task Name':<{max_name}} {'Next Run':<16} Status")
    print("-" * (max_name + 30))
    for name, nextrun, status in sorted(tasks):
        print(f"{name:<{max_name}} {nextrun:<16} {status}")
    print()

# ══════════════════════════════════════════════════════════════════════════
# Task 5: Shadow Copy Space Checker (win-vss)            (Qwen AI-generated)
# ══════════════════════════════════════════════════════════════════════════

def _get_vss_usage():
    try:
        output = subprocess.check_output(
            ["vssadmin", "list", "shadowstorage"],
            text=True,
            stderr=subprocess.DEVNULL
        )
    except subprocess.CalledProcessError:
        sys.exit("❌ Failed to get VSS data – run as Administrator.")

    usage = []
    pattern = re.compile(r"On device (?P<volume>.+) \(.+?%, (?P<used>\d+) MB allocated out of (?P<max>\d+) MB\)", re.IGNORECASE)
    for line in output.splitlines():
        match = pattern.search(line)
        if match:
            vol = match.group("volume").strip()
            used = int(match.group("used"))
            total = int(match.group("max"))
            percent = round(used / total * 100, 1) if total else 0
            usage.append((vol, used, total, percent))
    return usage


def win_vss():
    usages = _get_vss_usage()
    print(f"\n💾 Volume Shadow Copy Usage")

    if not usages:
        print("(no shadow copy storage configured)\n")
        return

    warn_count = 0
    max_vol = max(len(u[0]) for u in usages)
    print(f"{'Volume':<{max_vol}} {'Used (MB)':>10} {'Max (MB)':>10} {'% Used':>7}")
    print("-" * (max_vol + 35))
    for vol, used, total, percent in usages:
        color = COLOR_WARN if percent > 10 else COLOR_OK
        reset = COLOR_RESET if percent > 10 else ""
        print(f"{vol:<{max_vol}} {used:>10} {total:>10} {color}{percent:>6.1f}%{reset}")
        if percent > 10:
            warn_count += 1

    if warn_count:
        print(f"\n⚠️  Found {warn_count} volumes exceeding 10% VSS usage.")
    print()

# ══════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════

def main():
    p = argparse.ArgumentParser(description="Windows admin toolkit (IT 390R)")
    p.add_argument("--task", required=True,
                   choices=["win-events", "win-pkgs", "win-services", "win-tasks", "win-vss"],
                   help="Which analysis to run")

    # win-events options
    p.add_argument("--hours", type=int, default=24,
                   help="Look‑back window for Security log (win-events)")
    p.add_argument("--min-count", type=int, default=1,
                   help="Min occurrences before reporting (win-events)")

    # win-pkgs options
    p.add_argument("--csv", metavar="FILE", default=None,
                   help="Export installed-software list to CSV (win-pkgs)")

    # win-services options
    p.add_argument("--watch", nargs="*", metavar="SVC", default=[],
                   help="Service names to check (win-services)")
    p.add_argument("--fix", action="store_true",
                   help="Attempt to start stopped services (win-services)")
    
    # win-tasks options                                         (Qwen AI-generated)
    p.add_argument("--filter", metavar="KEYWORD", default=None,
                    help="Filter task names containing KEYWORD (case-insensitive)")

    args = p.parse_args()

    if args.task == "win-events":
        win_events(args.hours, args.min_count)
    elif args.task == "win-pkgs":
        win_pkgs(args.csv)
    elif args.task == "win-services":
        win_services(args.watch, args.fix)
    #Qwen AI-generated parts:
    elif args.task == "win-tasks":
        win_tasks(filter_keyword=args.filter, csv_path=args.csv)  # Pass new args
    elif args.task == "win-vss":
        win_vss()

if __name__ == "__main__":
    main()
