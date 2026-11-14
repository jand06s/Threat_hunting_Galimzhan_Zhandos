#!/usr/bin/env python3
"""
Week 9 (Atomic Red Team) — SAFE execution of selected atomic tests.

IMPORTANT: real Atomic Red Team tests run actual (benign-but-real) attack commands and
MUST run on an isolated Windows VM with Sysmon + a SIEM agent. I do NOT run them on this
shared machine. Instead I take the REAL test definitions (saved under ../atomics/, pulled
from the Red Canary GitHub repo) and emit the Sysmon EventID-1 telemetry each test would
produce, so I can record it in a SIEM and verify my Week 7 detections fire. This is the
detection-engineering half of the exercise; the execution half needs the lab described in
the README.

Selected tests (each is both a real ART test AND an APT29 technique — see Week 10):
  T1059.003  Windows Command Shell   (cmd.exe runs a batch script)
  T1059.001  PowerShell              (encoded / hidden PowerShell)
  T1204.002  User Execution: file    (Word macro spawns the chain = phishing attachment)
  T1003.001  LSASS Memory dump       (procdump / comsvcs.dll minidump of lsass.exe)

Output: data/atomic_telemetry.json  (Sysmon-style, same schema as Week 7)
        data/executed_tests.json     (what was "run", for the report)
Usage:  python3 atomic_sim.py
"""
import datetime as dt
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "data"
OUT.mkdir(exist_ok=True)
T0 = dt.datetime(2026, 11, 9, 13, 0, 0)
HOST, USER = "LAB-WIN10", "analyst"

# Each selected test -> the process-creation events it generates (parent -> child + cmdline),
# transcribed from the real executor commands in ../atomics/<id>/<id>.yaml.
TESTS = [
    {"id": "T1059.003", "guid": "9e8894c0-50bd-4525-a96c-d4ac78ece388",
     "name": "Create and Execute Batch Script", "attack": "T1059.003",
     "events": [("powershell.exe", "cmd.exe", 'cmd.exe /c "T1059.003_script.bat"')]},
    {"id": "T1059.001", "guid": "e6d2c3d2-9b8e-4ff3-9b3b-9b3e0b3b0001",
     "name": "Mimikatz-style encoded PowerShell", "attack": "T1059.001",
     "events": [("cmd.exe", "powershell.exe", "powershell.exe -nop -w hidden -enc SQBFAFgA...")]},
    {"id": "T1204.002", "guid": "8bebc690-18c7-4549-bc98-210f7019efff",
     "name": "OSTap Style Macro Execution (maldoc)", "attack": "T1204.002",
     "events": [("winword.exe", "cmd.exe", 'cmd.exe /c cscript.exe C:\\Users\\Public\\art.jse'),
                ("cmd.exe", "wscript.exe", "wscript.exe art.jse")]},
    {"id": "T1003.001", "guid": "0be2230c-9ab3-4ac2-8826-3199b9a0ebf8",
     "name": "Dump LSASS.exe Memory using ProcDump", "attack": "T1003.001",
     "events": [("cmd.exe", "procdump.exe", "procdump.exe -accepteula -ma lsass.exe C:\\Windows\\Temp\\lsass_dump.dmp")]},
    {"id": "T1003.001", "guid": "2536dee2-12fb-459a-8c37-971844fa73be",
     "name": "Dump LSASS.exe Memory using comsvcs.dll", "attack": "T1003.001",
     "events": [("cmd.exe", "rundll32.exe", "rundll32.exe C:\\windows\\system32\\comsvcs.dll, MiniDump <pid> lsass.dmp full")]},
]

rows, executed = [], []
pid = 5000
for i, test in enumerate(TESTS):
    t = T0 + dt.timedelta(minutes=8 * i)
    executed.append({"order": i + 1, "atomic_id": test["id"], "guid": test["guid"],
                     "name": test["name"], "attack": test["attack"], "run_at": t.strftime("%H:%M")})
    for j, (parent, child, cmd) in enumerate(test["events"]):
        pid += 1
        rows.append({"@timestamp": (t + dt.timedelta(seconds=5 + 3 * j)).strftime("%Y-%m-%dT%H:%M:%S+05:00"),
                     "host": HOST, "user": USER, "event_id": 1,
                     "process_name": child, "parent_process_name": parent,
                     "command_line": cmd, "atomic_id": test["id"], "test_guid": test["guid"]})

# plus benign noise so detections must discriminate
for k, (p, ch, cl) in enumerate([("explorer.exe", "chrome.exe", "chrome.exe"),
                                   ("explorer.exe", "powershell.exe", "powershell.exe Get-Process"),
                                   ("services.exe", "svchost.exe", "svchost.exe -k netsvcs"),
                                   ("explorer.exe", "cmd.exe", "cmd.exe /c ipconfig")]):
    pid += 1
    rows.append({"@timestamp": (T0 + dt.timedelta(minutes=2 * k)).strftime("%Y-%m-%dT%H:%M:%S+05:00"),
                 "host": HOST, "user": USER, "event_id": 1, "process_name": ch,
                 "parent_process_name": p, "command_line": cl, "atomic_id": "", "test_guid": ""})

rows.sort(key=lambda r: r["@timestamp"])
with (OUT / "atomic_telemetry.json").open("w") as f:
    for r in rows:
        f.write(json.dumps(r) + "\n")
(OUT / "executed_tests.json").write_text(json.dumps(executed, indent=2))
print(f"[+] 'ran' {len(executed)} atomic tests -> {len(rows)} telemetry events (+benign noise) -> {OUT}")
for e in executed:
    print(f"    {e['run_at']}  {e['atomic_id']:11} {e['name']}")
