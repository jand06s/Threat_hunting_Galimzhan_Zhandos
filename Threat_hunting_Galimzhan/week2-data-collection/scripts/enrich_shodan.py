#!/usr/bin/env python3
"""
Week 2: Shodan collection.

1) Hunting queries: search Shodan for pages that LOOK like KZ brands
   but are NOT hosted on the official domains (title / favicon / certificate).
2) Host enrichment: resolve each candidate domain to an IP and pull
   Shodan host data (open ports, org, ASN, country).

Needs a Shodan API key. Search filters (http.title, http.favicon.hash, ssl.*) need a
paid membership or an academic upgrade; check your account plan at account.shodan.io.

Usage:
    pip install shodan mmh3 requests
    export SHODAN_API_KEY=xxxxxxxx
    python3 enrich_shodan.py --queries
    python3 enrich_shodan.py --hosts ../data/kz_phishing_candidates.csv
"""
import argparse
import base64
import csv
import os
import socket
import sys
import time
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent.parent / "data"

# Hunting queries. Exclude the official infrastructure with -hostname.
QUERIES = {
    "kaspi_title":   'http.title:"Kaspi.kz" -hostname:kaspi.kz',
    "kaspi_html":    'http.html:"kaspi" http.html:"password" -hostname:kaspi.kz',
    "egov_title":    'http.title:"eGov.kz" -hostname:egov.kz',
    "homebank":      'http.title:"Homebank" -hostname:homebank.kz -hostname:halykbank.kz',
    "kazpost":       'http.title:"Казпочта" -hostname:post.kz -hostname:kazpost.kz',
    "olx_kz":        'http.html:"olx.kz" http.html:"card" -hostname:olx.kz',
    "cert_kaspi":    'ssl.cert.subject.cn:*kaspi* -ssl.cert.subject.cn:kaspi.kz',
    "cert_egov":     'ssl.cert.subject.cn:*egov* ssl.cert.subject.cn:*kz*',
}
# Official sites whose favicon hash is used to find clones: http.favicon.hash:<hash>
FAVICON_SOURCES = {
    "kaspi": "https://kaspi.kz/favicon.ico",
    "egov": "https://egov.kz/favicon.ico",
}


def favicon_hash(url: str):
    """Shodan favicon hash = mmh3 of base64-encoded favicon bytes."""
    import mmh3, requests
    r = requests.get(url, timeout=15)
    return mmh3.hash(base64.encodebytes(r.content))


def run_queries(api):
    rows = []
    queries = dict(QUERIES)
    for name, url in FAVICON_SOURCES.items():
        try:
            h = favicon_hash(url)
            queries[f"{name}_favicon"] = f"http.favicon.hash:{h} -hostname:{name}.kz"
            print(f"[+] favicon hash {name}: {h}")
        except Exception as e:
            print(f"[!] favicon {name}: {e}")
    for name, q in queries.items():
        try:
            res = api.search(q, limit=100)
        except Exception as e:
            print(f"[!] {name}: {e}")
            continue
        print(f"[+] {name:16} total={res['total']:<6} q={q}")
        for m in res["matches"]:
            rows.append({
                "query": name, "ip": m.get("ip_str"), "port": m.get("port"),
                "hostnames": ";".join(m.get("hostnames", [])), "org": m.get("org"),
                "asn": m.get("asn"), "country": m.get("location", {}).get("country_code"),
                "title": (m.get("http") or {}).get("title", ""), "timestamp": m.get("timestamp"),
            })
        time.sleep(1)
    write(rows, OUT_DIR / "shodan_hunt_results.csv")


def enrich_hosts(api, csv_path: Path):
    rows = []
    with csv_path.open() as f:
        domains = [r["indicator"] for r in csv.DictReader(f)]
    for d in domains:
        try:
            ip = socket.gethostbyname(d)
        except socket.gaierror:
            rows.append({"domain": d, "ip": "", "resolves": "no"})
            continue
        row = {"domain": d, "ip": ip, "resolves": "yes"}
        try:
            h = api.host(ip)
            row.update({
                "org": h.get("org"), "isp": h.get("isp"), "asn": h.get("asn"),
                "country": h.get("country_code"), "ports": ";".join(map(str, h.get("ports", []))),
                "shodan_hostnames": ";".join(h.get("hostnames", [])[:5]),
            })
        except Exception as e:
            row["error"] = str(e)
        rows.append(row)
        print(f"    {d:45} {ip:15} {row.get('org', '')}")
        time.sleep(1)  # API rate limit
    write(rows, OUT_DIR / "shodan_host_enrichment.csv")


def write(rows, out):
    if not rows:
        print("[!] nothing to write"); return
    keys = list(dict.fromkeys(k for r in rows for k in r))  # union of columns, first-seen order
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys); w.writeheader(); w.writerows(rows)
    print(f"[+] {len(rows)} rows -> {out}")


def main():
    import shodan
    ap = argparse.ArgumentParser()
    ap.add_argument("--queries", action="store_true")
    ap.add_argument("--hosts", type=Path)
    a = ap.parse_args()
    key = os.environ.get("SHODAN_API_KEY")
    if not key:
        sys.exit("set SHODAN_API_KEY")
    api = shodan.Shodan(key)
    if a.queries:
        run_queries(api)
    if a.hosts:
        enrich_hosts(api, a.hosts)


if __name__ == "__main__":
    main()
