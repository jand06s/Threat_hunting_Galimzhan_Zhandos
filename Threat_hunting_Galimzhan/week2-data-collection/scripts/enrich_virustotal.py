#!/usr/bin/env python3
"""
Week 2: VirusTotal enrichment of collected domains (API v3).

For every domain: detection stats, reputation, registrar, creation date,
categories, and the latest A records. Free API = 4 requests/min, 500/day,
so by default only brand-impersonation rows + a sample of kz-hosted rows are checked.

Usage:
    pip install requests
    export VT_API_KEY=xxxxxxxx
    python3 enrich_virustotal.py ../data/kz_phishing_candidates.csv [--all]
"""
import csv
import datetime as dt
import os
import sys
import time
from pathlib import Path

import requests

API = "https://www.virustotal.com/api/v3/domains/{}"
OUT = Path(__file__).resolve().parent.parent / "data" / "virustotal_enrichment.csv"
SLEEP = 15.5  # free tier: 4 req/min


def lookup(session, domain):
    r = session.get(API.format(domain), timeout=30)
    if r.status_code == 404:
        return {"domain": domain, "vt_status": "not found"}
    r.raise_for_status()
    a = r.json()["data"]["attributes"]
    stats = a.get("last_analysis_stats", {})
    created = a.get("creation_date")
    return {
        "domain": domain,
        "vt_status": "ok",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "reputation": a.get("reputation"),
        "registrar": a.get("registrar", ""),
        "creation_date": dt.datetime.utcfromtimestamp(created).date().isoformat() if created else "",
        "categories": ";".join(sorted(set(a.get("categories", {}).values()))),
        "a_records": ";".join(x["value"] for x in a.get("last_dns_records", []) if x.get("type") == "A"),
    }


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    key = os.environ.get("VT_API_KEY") or sys.exit("set VT_API_KEY")
    with open(sys.argv[1]) as f:
        rows = list(csv.DictReader(f))
    if "--all" not in sys.argv:
        brand = [r for r in rows if r["category"] == "brand-impersonation"]
        other = [r for r in rows if r["category"] != "brand-impersonation"][:30]
        rows = brand + other
    s = requests.Session(); s.headers["x-apikey"] = key
    out = []
    for i, r in enumerate(rows, 1):
        try:
            res = lookup(s, r["indicator"])
        except Exception as e:
            res = {"domain": r["indicator"], "vt_status": f"error: {e}"}
        out.append(res)
        print(f"[{i}/{len(rows)}] {res['domain']:45} malicious={res.get('malicious', '-')}")
        time.sleep(SLEEP)
    keys = list(dict.fromkeys(k for o in out for k in o))
    with OUT.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys); w.writeheader(); w.writerows(out)
    print(f"[+] {len(out)} rows -> {OUT}")


if __name__ == "__main__":
    main()
