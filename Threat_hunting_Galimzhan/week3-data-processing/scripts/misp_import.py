#!/usr/bin/env python3
"""
Week 3: build a MISP event from normalized_iocs.csv and (optionally) push it to MISP.

Offline (default): writes ../data/misp_event.json. You can import it in the MISP UI:
                   Events -> Import from... -> MISP JSON.
Online           : export MISP_URL=https://localhost  MISP_KEY=<auth key>
                   python3 misp_import.py --push

Usage:
    pip install pymisp
    python3 misp_import.py [--push] [--min-confidence low|medium|high]
"""
import argparse
import csv
import datetime as dt
import json
import os
from pathlib import Path

from pymisp import MISPEvent, MISPAttribute

HERE = Path(__file__).resolve().parent
DATA = HERE.parent / "data"
RANK = {"low": 0, "medium": 1, "high": 2}

ATTACK_TAGS = [
    'misp-galaxy:mitre-attack-pattern="Phishing - T1566"',
    'misp-galaxy:mitre-attack-pattern="Spearphishing Link - T1566.002"',
    'misp-galaxy:mitre-attack-pattern="Domains - T1583.001"',
    'misp-galaxy:mitre-attack-pattern="Compromise Infrastructure - T1584"',
]


def build_event(rows):
    ev = MISPEvent()
    ev.info = f"KZ-related phishing infrastructure (Phishing.Database), {dt.date.today().isoformat()}"
    ev.distribution = 0        # your organisation only (lab)
    ev.threat_level_id = 2     # medium
    ev.analysis = 1            # ongoing
    ev.date = dt.date.today()
    for t in ["tlp:clear", 'type:OSINT', 'phishing:techniques="fake-website"',
              'osint:source-type="block-or-filter-list"', "workflow:state=\"incomplete\""] + ATTACK_TAGS:
        ev.add_tag(t)

    for r in rows:
        comment = f"{r['category']}; impersonates={r['impersonated']}; hosting={r['hosting_pattern']}"
        if r["cluster"]:
            comment += f"; cluster={r['cluster']}"
        to_ids = RANK[r["confidence"]] >= 1
        a = ev.add_attribute("domain", r["indicator"], category="Network activity",
                             to_ids=to_ids, comment=comment, first_seen=r["first_seen"])
        a.add_tag(f"confidence:{r['confidence']}")
        if r["brand"]:
            for b in r["brand"].split(";"):
                a.add_tag(f"brand:{b}")
        if r["cluster"]:
            a.add_tag(f"cluster:{r['cluster']}")
        if r["url"]:
            u = ev.add_attribute("url", r["url"], category="Network activity",
                                 to_ids=to_ids, comment=f"example URL for {r['indicator']}")
            u.add_tag(f"confidence:{r['confidence']}")
    return ev


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--push", action="store_true", help="send the event to MISP (needs MISP_URL, MISP_KEY)")
    ap.add_argument("--min-confidence", default="low", choices=RANK)
    a = ap.parse_args()

    with (DATA / "normalized_iocs.csv").open() as f:
        rows = [r for r in csv.DictReader(f) if RANK[r["confidence"]] >= RANK[a.min_confidence]]
    ev = build_event(rows)
    out = DATA / "misp_event.json"
    out.write_text(json.dumps({"Event": json.loads(ev.to_json())}, indent=2, ensure_ascii=False))  # UI import format
    n_ids = sum(1 for x in ev.attributes if x.to_ids)
    print(f"[+] event with {len(ev.attributes)} attributes ({n_ids} to_ids) -> {out}")

    if a.push:
        from pymisp import PyMISP
        misp = PyMISP(os.environ["MISP_URL"], os.environ["MISP_KEY"], ssl=False)
        res = misp.add_event(ev, pythonify=True)
        print(f"[+] pushed: event id={res.id} uuid={res.uuid}")
        # Correlation check: which of our values already exist in other events?
        for attr in ev.attributes[:50]:
            hits = misp.search(controller="attributes", value=attr.value, pythonify=True)
            others = {h.event_id for h in hits if str(h.event_id) != str(res.id)}
            if others:
                print(f"    correlation: {attr.value} also in events {sorted(others)}")


if __name__ == "__main__":
    main()
