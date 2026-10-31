#!/usr/bin/env python3
"""
Week 7 (MITRE CAR) — generate SYNTHETIC Sysmon-style process-creation telemetry
(EventID 1) for a small org, to run CAR analytics against.

This is lab data, not a real host. It models the phishing ATTACHMENT variant
(T1566.001): most process starts are benign; two hosts show the chain a defender
sees after a user opens a malicious document from a phishing email —
  outlook.exe / winword.exe  ->  cmd.exe  ->  powershell.exe
Ground truth is kept separately for scoring. Nothing is executed; these are just log rows.

Output: data/sysmon_proc.json   (newline JSON; fields match Sysmon EventID 1)
        data/ground_truth.json
Usage:  python3 generate_proc_logs.py [--seed 7]
"""
import argparse
import datetime as dt
import json
import random
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "data"
START = dt.datetime(2026, 10, 26, 9, 0, 0)

BENIGN_PARENTS = ["explorer.exe", "services.exe", "svchost.exe", "cmd.exe"]
BENIGN_PROCS = ["chrome.exe", "msedge.exe", "outlook.exe", "winword.exe", "excel.exe",
                "teams.exe", "code.exe", "python.exe", "cmd.exe", "powershell.exe",
                "notepad.exe", "onedrive.exe", "svchost.exe", "taskhostw.exe"]
# benign cmd/powershell are launched by explorer or an admin tool, not by Office
BENIGN_CMD_PARENTS = ["explorer.exe", "cmd.exe", "code.exe"]

# Planted malicious chains (the phishing attachment follow-on).
MALICIOUS = [
    {"host": "WKS-07", "user": "user07", "parent": "outlook.exe", "day_min": 180},
    {"host": "WKS-19", "user": "user19", "parent": "winword.exe", "day_min": 300},
]


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S+05:00")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=7)
    rnd = random.Random(ap.parse_args().seed)
    hosts = [f"WKS-{i:02d}" for i in range(1, 26)]
    user_of = {h: f"user{int(h[-2:]):02d}" for h in hosts}
    rows = []
    pid = 1000

    for day in range(5):
        for h in hosts:
            for _ in range(rnd.randint(40, 70)):
                pid += 1
                proc = rnd.choices(BENIGN_PROCS, weights=[8, 4, 5, 4, 3, 4, 4, 3, 3, 2, 2, 2, 6, 4])[0]
                if proc in ("cmd.exe", "powershell.exe"):
                    parent = rnd.choice(BENIGN_CMD_PARENTS)
                else:
                    parent = rnd.choice(BENIGN_PARENTS)
                t = START + dt.timedelta(days=day, minutes=rnd.randint(0, 8 * 60), seconds=rnd.randint(0, 59))
                rows.append({"@timestamp": iso(t), "host": h, "user": user_of[h], "event_id": 1,
                             "image": f"C:\\...\\{proc}", "process_name": proc, "pid": pid,
                             "parent_image": f"C:\\...\\{parent}", "parent_process_name": parent,
                             "command_line": f"{proc}"})

    gt = []
    for m in MALICIOUS:
        t0 = START + dt.timedelta(days=2, minutes=m["day_min"])
        chain = [(m["parent"], "cmd.exe", 'cmd.exe /c "set"'),
                 ("cmd.exe", "powershell.exe",
                  "powershell.exe -nop -w hidden -enc <base64>")]  # descriptive only, not run
        for i, (par, proc, cl) in enumerate(chain):
            pid += 1
            rows.append({"@timestamp": iso(t0 + dt.timedelta(seconds=4 + i * 3)), "host": m["host"],
                         "user": m["user"], "event_id": 1, "image": f"C:\\...\\{proc}",
                         "process_name": proc, "pid": pid, "parent_image": f"C:\\...\\{par}",
                         "parent_process_name": par, "command_line": cl})
        gt.append({"host": m["host"], "user": m["user"], "chain": f"{m['parent']} -> cmd.exe -> powershell.exe",
                   "initiating_technique": "T1566.001 (malicious attachment)"})

    OUT.mkdir(exist_ok=True)
    rows.sort(key=lambda r: r["@timestamp"])
    with (OUT / "sysmon_proc.json").open("w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    (OUT / "ground_truth.json").write_text(json.dumps(gt, indent=2))
    print(f"[+] {len(rows):,} process events, {len(hosts)} hosts, 5 days, {len(gt)} planted chains -> {OUT}")


if __name__ == "__main__":
    main()
