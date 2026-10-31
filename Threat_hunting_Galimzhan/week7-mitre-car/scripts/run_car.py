#!/usr/bin/env python3
"""
Week 7: implement two MITRE CAR analytics with DuckDB (the "SIEM") and score them
against the planted chains.

  CAR-2013-02-003  Processes Spawning cmd.exe   -> T1059 / T1059.003 (TA0002 Execution)
     adapted: an Office/mail app (outlook/winword/excel/adobe) spawning cmd.exe = a loaded
     malicious document (CAR's own description names Outlook/Adobe Reader as suspicious parents).
  CAR-2014-04-003  PowerShell Execution         -> T1059.001
     powershell.exe whose parent is not explorer.exe (not launched interactively).

Output: results/car_2013_02_003.csv, results/car_2014_04_003.csv, results/scorecard.csv, summary.md
Usage:  python3 run_car.py
"""
from pathlib import Path

import duckdb
import pandas as pd

BASE = Path(__file__).resolve().parent.parent
DATA, RES = BASE / "data", BASE / "results"
RES.mkdir(exist_ok=True)
con = duckdb.connect()
con.execute(f"CREATE TABLE proc AS SELECT * FROM read_json_auto('{DATA / 'sysmon_proc.json'}')")

OFFICE = ["outlook.exe", "winword.exe", "excel.exe", "powerpnt.exe", "acrord32.exe"]

# CAR-2013-02-003 — Processes Spawning cmd.exe (phishing-attachment-aware variant)
A1 = f"""
SELECT "@timestamp" AS time, host, "user", parent_process_name AS parent, process_name AS child, command_line
FROM proc
WHERE process_name = 'cmd.exe'
  AND parent_process_name IN ({", ".join(f"'{p}'" for p in OFFICE)})
ORDER BY time
"""

# CAR-2014-04-003 — PowerShell Execution (not launched interactively)
# v1 (CAR pseudocode literally: parent != explorer.exe) is too broad in an org where
# admins routinely run cmd -> powershell. v2 adds the real malicious discriminator from
# CAR's own examples: encoded / hidden-window PowerShell. Both are reported to show the tuning.
A2_V1 = """SELECT host FROM proc
WHERE process_name='powershell.exe' AND parent_process_name <> 'explorer.exe'"""
A2 = """
SELECT "@timestamp" AS time, host, "user", parent_process_name AS parent, process_name AS child, command_line
FROM proc
WHERE process_name = 'powershell.exe'
  AND parent_process_name <> 'explorer.exe'
  AND (lower(command_line) LIKE '%-enc%' OR lower(command_line) LIKE '%hidden%')
ORDER BY time
"""


def run(name, q):
    df = con.execute(q).df()
    df.to_csv(RES / f"{name}.csv", index=False)
    print(f"\n== {name}: {len(df)} hits")
    print(df.to_string(index=False, max_colwidth=46))
    return df


a1 = run("car_2013_02_003", A1)
a2 = run("car_2014_04_003", A2)
v1_hosts = set(con.execute(A2_V1).df()["host"])
print(f"\n[note] CAR-2014-04-003 v1 (parent != explorer, no cmdline filter): "
      f"{len(con.execute(A2_V1).df())} hits across {len(v1_hosts)} hosts -> too noisy; v2 used above")

import json
gt = json.loads((DATA / "ground_truth.json").read_text())
gt_hosts = {g["host"] for g in gt}
hits1, hits2 = set(a1["host"]), set(a2["host"])
score = pd.DataFrame([{
    "host": g["host"], "chain": g["chain"],
    "CAR-2013-02-003": "detected" if g["host"] in hits1 else "-",
    "CAR-2014-04-003": "detected" if g["host"] in hits2 else "-"} for g in gt])
# false positives = benign hosts flagged
total_hosts = set(con.execute("SELECT DISTINCT host FROM proc").df()["host"])
metrics = pd.DataFrame([
    {"analytic": "CAR-2013-02-003", "attack": "T1059.003", "hits": len(a1),
     "true_positives": len(hits1 & gt_hosts), "false_positives": len(hits1 - gt_hosts)},
    {"analytic": "CAR-2014-04-003 v1 (raw)", "attack": "T1059.001", "hits": len(con.execute(A2_V1).df()),
     "true_positives": len(v1_hosts & gt_hosts), "false_positives": len(v1_hosts - gt_hosts)},
    {"analytic": "CAR-2014-04-003 v2 (tuned)", "attack": "T1059.001", "hits": len(a2),
     "true_positives": len(hits2 & gt_hosts), "false_positives": len(hits2 - gt_hosts)},
])
score.to_csv(RES / "scorecard.csv", index=False)
metrics.to_csv(RES / "metrics.csv", index=False)
print("\n== scorecard\n", score.to_string(index=False))
print("\n== metrics\n", metrics.to_string(index=False))
(RES / "summary.md").write_text(
    "# CAR analytics results (auto-generated)\n\n## Scorecard\n\n" + score.to_markdown(index=False)
    + "\n\n## Metrics\n\n" + metrics.to_markdown(index=False) + "\n")
