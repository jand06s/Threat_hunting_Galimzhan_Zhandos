#!/usr/bin/env python3
"""
Week 5: run the three hunts on the lab logs with DuckDB (SQL) and score them.

H1  hypothesis-driven  DNS    brand keyword in query, not an official domain (same logic as Sigma v3)
H2  hypothesis-driven  proxy  POST (form submission) to a RARE domain that is not on the allowlist
H3  intel-driven       DNS    IOC sweep: DNS queries matched against my Week 3 normalized IOCs

The same logic is written for Splunk (queries/splunk.spl) and Kibana (queries/elastic.kql),
so the hunt can be repeated in a real SIEM.

Outputs: results/h1.csv, h2.csv, h3.csv, triage.csv, scorecard.csv, results/summary.md
Times are shown in local time (Asia/Almaty, UTC+5).
Usage:   pip install duckdb pandas matplotlib && python3 hunt.py
"""
from pathlib import Path
import json

import duckdb
import pandas as pd

BASE = Path(__file__).resolve().parent.parent
DATA, RES = BASE / "data", BASE / "results"
IOCS = BASE.parent / "week3-data-processing" / "data" / "normalized_iocs.csv"
RES.mkdir(exist_ok=True)

BRANDS = ["kaspi", "halyk", "homebank", "egov", "kazpost", "post-kz", "olxkz", "olx-kz"]
OFFICIAL = ["kaspi.kz", "halykbank.kz", "homebank.kz", "egov.kz", "kazpost.kz", "post.kz", "olx.kz"]
KNOWN_FP = ["kaspian", "turkiyegov"]
ALLOWLIST = OFFICIAL + ["google.com", "mail.google.com", "outlook.office.com", "github.com", "apple.com",
                        "icloud.com", "youtube.com", "instagram.com", "web.telegram.org", "web.whatsapp.com"]

con = duckdb.connect()
con.execute(f"CREATE TABLE dns AS SELECT * FROM read_json_auto('{DATA / 'dns.json'}')")
con.execute(f"CREATE TABLE proxy AS SELECT * FROM read_json_auto('{DATA / 'proxy.json'}')")
con.execute(f"CREATE TABLE iocs AS SELECT * FROM read_csv_auto('{IOCS}')")


def sql_list(xs):
    return ", ".join(f"'{x}'" for x in xs)


official_filter = " AND ".join([f"query <> '{d}' AND NOT ends_with(query, '.{d}')" for d in OFFICIAL])
H1 = f"""
SELECT query, count(*) AS events, count(DISTINCT "user") AS users,
       string_agg(DISTINCT "user", ', ') AS who, min("@timestamp") + INTERVAL 5 HOUR AS first_seen_local
FROM dns
WHERE regexp_matches(query, '{"|".join(BRANDS)}')
  AND {official_filter}
  AND NOT regexp_matches(query, '{"|".join(KNOWN_FP)}')
GROUP BY query ORDER BY first_seen_local
"""

H2 = f"""
WITH rarity AS (
  SELECT host, count(DISTINCT "user") AS users_seen FROM proxy GROUP BY host
)
SELECT p."@timestamp" + INTERVAL 5 HOUR AS time_local, p."user", p.host, p.url_path, p.bytes_out, r.users_seen
FROM proxy p JOIN rarity r USING (host)
WHERE p.method = 'POST'
  AND r.users_seen <= 2
  AND p.host NOT IN ({sql_list(ALLOWLIST)})
ORDER BY p."@timestamp"
"""

H3 = """
SELECT d."@timestamp" + INTERVAL 5 HOUR AS time_local, d."user", d.query, i.confidence, i.cluster, i.impersonated, i.category
FROM dns d JOIN iocs i ON d.query = i.indicator
ORDER BY d."@timestamp"
"""

RARITY = """SELECT host, count(DISTINCT "user") AS users_seen, count(*) AS requests
            FROM proxy GROUP BY host ORDER BY users_seen"""


def run(name, q):
    df = con.execute(q).df()
    df.to_csv(RES / f"{name}.csv", index=False)
    print(f"\n== {name}: {len(df)} rows")
    print(df.to_string(index=False, max_colwidth=40))
    return df


h1, h2, h3 = run("h1", H1), run("h2", H2), run("h3", H3)
run("rarity", RARITY)

# Scorecard: which planted scenario did each hunt find?
truth = json.loads((DATA / "ground_truth.json").read_text())
found = {"H1": set(h1["query"]), "H2": set(h2["host"]), "H3": set(h3["query"])}
rows = []
for s in truth:
    rows.append({"scenario": s["id"], "user": s["user"], "host": s["host"],
                 **{h: ("found" if s["host"] in hs else "-") for h, hs in found.items()}})
score = pd.DataFrame(rows)
score.to_csv(RES / "scorecard.csv", index=False)
truth_hosts = {s["host"] for s in truth}
metrics = []
for h, hs in found.items():
    tp = len(hs & truth_hosts)
    fp = len(hs - truth_hosts)
    metrics.append({"hunt": h, "hits": len(hs), "true_positives": tp, "false_positives": fp,
                    "recall": f"{tp}/{len(truth_hosts)}"})
metrics = pd.DataFrame(metrics)
print("\n== scorecard\n", score.to_string(index=False), "\n\n", metrics.to_string(index=False))

# Triage: one row per affected user, worst observed behaviour first
tri = []
for s in truth:
    in_any = [h for h, hs in found.items() if s["host"] in hs]
    if not in_any:
        continue
    posted = ((h2["host"] == s["host"]) & (h2["user"] == s["user"])).any()
    blocked = s.get("action") == "blocked"
    sev = "HIGH: data submitted" if posted else ("LOW: blocked by proxy" if blocked else "MEDIUM: visited only")
    tri.append({"user": s["user"], "host": s["host"], "found_by": "+".join(in_any), "severity": sev,
                "next_step": {"HIGH": "reset passwords / block card, isolate, interview user",
                              "MEDIUM": "confirm nothing was entered, awareness note",
                              "LOW": "no action, blocklist worked"}[sev.split(":")[0]]})
tri = pd.DataFrame(tri)
tri = tri.iloc[tri["severity"].map(lambda x: ["HIGH", "MEDIUM", "LOW"].index(x.split(":")[0])).argsort()]
tri.to_csv(RES / "triage.csv", index=False)
print("\n== triage\n", tri.to_string(index=False))

(RES / "summary.md").write_text(
    "# Hunt results (auto-generated by hunt.py)\n\n## Scorecard\n\n" + score.to_markdown(index=False)
    + "\n\n## Metrics\n\n" + metrics.to_markdown(index=False)
    + "\n\n## Triage\n\n" + tri.to_markdown(index=False) + "\n")

# Kibana queries generated from the same lists, so Python, Splunk and Kibana use identical logic
brands = " or ".join(f"*{b}*" for b in BRANDS)
off_exact = " or ".join(f'"{d}"' for d in OFFICIAL)
off_sub = " or ".join(f"*.{d}" for d in OFFICIAL)
fps = " or ".join(f"*{w}*" for w in KNOWN_FP)
ioc_list = " or ".join(f'"{x}"' for x in con.execute("SELECT indicator FROM iocs").df()["indicator"])
allow = " or ".join(f'"{d}"' for d in ALLOWLIST)
(BASE / "queries" / "elastic.kql").write_text(f"""// Week 5 hunts for Kibana (Discover). Generated by scripts/hunt.py, do not edit by hand.
// Setup: Kibana > Integrations > Upload a file > data/dns.json (index "dns") and data/proxy.json (index "proxy").
//        Create data views "dns" and "proxy" with time field @timestamp.
