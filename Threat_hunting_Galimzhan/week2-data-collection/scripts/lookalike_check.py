#!/usr/bin/env python3
"""
Week 2: generate lookalike (typosquatting) domains for KZ brands with dnstwist
and cross-check them against the phishing feeds.

Two modes:
  offline (default)  - generate permutations, check which appear in the feeds
  --resolve          - also resolve DNS (needs internet) and keep only registered ones.
                       Registered lookalikes are the "watch list" for Shodan / VirusTotal.

Output: ../data/lookalikes_<mode>.csv

Usage:
    pip install dnstwist
    python3 lookalike_check.py --feeds ../data/raw
    python3 lookalike_check.py --feeds ../data/raw --resolve
"""
import argparse
import csv
import re
from collections import Counter
from pathlib import Path

import dnstwist

BRAND_DOMAINS = [
    "kaspi.kz", "egov.kz", "homebank.kz", "halykbank.kz", "jusan.kz",
    "kazpost.kz", "olx.kz", "kolesa.kz", "krisha.kz", "kcell.kz",
]
OUT_DIR = Path(__file__).resolve().parent.parent / "data"


def feed_hosts(feed_dir: Path) -> set[str]:
    hosts = set()
    rx = re.compile(r"https?://([^/:?#]+)", re.I)
    for p in feed_dir.glob("phishing-*.txt"):
        for line in p.open(errors="ignore"):
            line = line.strip().lower()
            m = rx.match(line)
            hosts.add(m.group(1) if m else line)
    hosts.discard("")
    return hosts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--feeds", type=Path, default=OUT_DIR / "raw")
    ap.add_argument("--resolve", action="store_true", help="resolve DNS, keep registered only")
    args = ap.parse_args()

    hosts = feed_hosts(args.feeds)
    # Registered domain of every feed host (last 2 labels, 3 for .com.kz etc.)
    def reg(h):
        p = h.split(".")
        return ".".join(p[-3:]) if len(p) > 2 and p[-2] in {"com", "org", "net", "gov"} else ".".join(p[-2:])
    feed_regs = {reg(h) for h in hosts}
    print(f"[+] {len(hosts):,} feed hosts loaded")

    rows = []
    for brand in BRAND_DOMAINS:
        if args.resolve:
            perms = dnstwist.run(domain=brand, registered=True, format="null")
        else:  # pure permutation generation, no network
            fz = dnstwist.Fuzzer(brand)
            fz.generate()
            perms = fz.permutations()
        for p in perms:
            d = p["domain"]
            if d == brand:
                continue
            rows.append({
                "brand_domain": brand,
                "lookalike": d,
                "fuzzer": p["fuzzer"],
                "dns_a": ";".join(p.get("dns_a", [])),
                "in_phishing_feed": "yes" if d in feed_regs or d in hosts else "no",
            })
        print(f"    {brand:14} {len(perms):5} permutations")

    mode = "resolved" if args.resolve else "offline"
    out = OUT_DIR / f"lookalikes_{mode}.csv"
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    hits = [r for r in rows if r["in_phishing_feed"] == "yes"]
    print(f"[+] {len(rows):,} lookalikes -> {out}")
    print(f"[+] fuzzers: {dict(Counter(r['fuzzer'] for r in rows).most_common())}")
    print(f"[+] found in phishing feeds: {len(hits)}")
    for r in hits:
        print("    ", r["brand_domain"], "->", r["lookalike"], f"({r['fuzzer']})")


if __name__ == "__main__":
    main()
