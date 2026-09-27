#!/usr/bin/env python3
"""Offline test of dns_kz_brand_lookalike.yml logic against our IOCs + legitimate traffic."""
import csv
from pathlib import Path
import yaml

rule = yaml.safe_load(open(Path(__file__).parent / "dns_kz_brand_lookalike.yml"))
sel = rule["detection"]["selection_brand"]["query|contains"]
exact = rule["detection"]["filter_official_exact"]["query"]
flt = rule["detection"]["filter_official_sub"]["query|endswith"]
fp_words = rule["detection"].get("filter_known_fp", {}).get("query|contains", [])
fires = lambda q: (any(k in q for k in sel) and q not in exact and not any(q.endswith(s) for s in flt)
                   and not any(w in q for w in fp_words))

iocs = [r["indicator"] for r in csv.DictReader(open(Path(__file__).parent.parent / "data" / "normalized_iocs.csv"))
        if r["category"] == "brand-impersonation"]
evasion = ["fakekaspi.kz", "my-egov.kz"]  # must be detected (v3 fix)
legit = ["kaspi.kz", "www.kaspi.kz", "pay.kaspi.kz", "egov.kz", "idp.egov.kz", "homebank.kz",
         "halykbank.kz", "post.kz", "olx.kz", "google.com", "kaspian-sea.org"]
tp = [q for q in iocs if fires(q)]; fn = [q for q in iocs if not fires(q)]
fp = [q for q in legit if fires(q)]
print(f"brand IOCs: {len(iocs)}  detected: {len(tp)}  missed: {fn}")
print(f"legit queries: {len(legit)}  false positives: {fp}")
print(f"evasion test: {[(q, fires(q)) for q in evasion]}")
