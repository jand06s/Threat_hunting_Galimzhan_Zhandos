#!/usr/bin/env python3
"""
Week 9 — record the atomic-test telemetry in the "SIEM" (DuckDB) and run detections,
then score which test each detection caught. Reuses my Week 7 CAR analytics and adds
one credential-access rule for the LSASS dumps.

Detections:
  D1  CAR-2013-02-003  Office app spawns cmd.exe                 -> T1059.003 / T1204.002
  D2  CAR-2014-04-003  encoded / hidden PowerShell               -> T1059.001
  D3  (new) LSASS access: procdump -ma lsass OR comsvcs MiniDump -> T1003.001

Output: results/detections.csv, results/scorecard.csv, results/summary.md
Usage:  python3 detect.py
"""
from pathlib import Path
import duckdb, pandas as pd, json

BASE = Path(__file__).resolve().parent.parent
DATA, RES = BASE / "data", BASE / "results"
RES.mkdir(exist_ok=True)
con = duckdb.connect()
con.execute(f"CREATE TABLE proc AS SELECT * FROM read_json_auto('{DATA / 'atomic_telemetry.json'}')")
OFFICE = "('outlook.exe','winword.exe','excel.exe','powerpnt.exe','acrord32.exe')"

D = {
 "D1_CAR-2013-02-003": f"""SELECT "@timestamp" t, host, parent_process_name parent, process_name child, command_line, atomic_id
   FROM proc WHERE process_name='cmd.exe' AND parent_process_name IN {OFFICE}""",
 "D2_CAR-2014-04-003": """SELECT "@timestamp" t, host, parent_process_name parent, process_name child, command_line, atomic_id
   FROM proc WHERE process_name='powershell.exe' AND parent_process_name<>'explorer.exe'
     AND (lower(command_line) LIKE '%-enc%' OR lower(command_line) LIKE '%hidden%')""",
 "D3_LSASS-dump": """SELECT "@timestamp" t, host, parent_process_name parent, process_name child, command_line, atomic_id
   FROM proc WHERE lower(command_line) LIKE '%lsass%'
     AND (lower(command_line) LIKE '%-ma %' OR lower(command_line) LIKE '%minidump%')""",
}
caught = {}
for name, q in D.items():
    df = con.execute(q).df()
    df.to_csv(RES / f"{name}.csv", index=False)
    caught[name] = set(df["atomic_id"]) - {""}
    print(f"\n== {name}: {len(df)} hits  -> tests {sorted(caught[name])}")
    print(df.to_string(index=False, max_colwidth=52))

tests = json.loads((DATA / "executed_tests.json").read_text())
seen = set().union(*caught.values()) if caught else set()
rows = []
for t in tests:
    by = [d for d, ids in caught.items() if t["atomic_id"] in ids]
    rows.append({"atomic_id": t["atomic_id"], "name": t["name"], "attack": t["attack"],
                 "detected": "YES" if by else "NO", "by_rule": ";".join(d.split("_")[0] for d in by) or "-"})
sc = pd.DataFrame(rows)
sc.to_csv(RES / "scorecard.csv", index=False)
uniq = {t["atomic_id"] for t in tests}
det = {t["atomic_id"] for t in tests if any(t["atomic_id"] in ids for ids in caught.values())}
print("\n== scorecard\n", sc.to_string(index=False))
print(f"\n[+] techniques detected: {len(det)}/{len(uniq)}  ({', '.join(sorted(det))})")
(RES / "summary.md").write_text(
    "# Atomic test detection results (auto-generated)\n\n" + sc.to_markdown(index=False)
    + f"\n\n**Detected {len(det)} of {len(uniq)} techniques** with my CAR analytics (Week 7) + one new LSASS rule.\n")
