#!/usr/bin/env python3
"""
Week 5: generate a SYNTHETIC lab dataset of DNS and web-proxy logs for a small
organisation (30 users, 7 days). It is used to practise hypothesis-driven hunting.

The background traffic is random but realistic (banks, eGov, social media, work
sites). Four lab scenarios are planted, using indicators from my Week 2-3 data
plus one domain that is NOT in any feed. The hunter is not supposed to know them
in advance; they are listed in data/ground_truth.json only to score the hunt.

Output (newline-delimited JSON, ready for Splunk "Add Data" or Kibana "Upload file"):
  data/dns.json     fields: @timestamp, src_ip, user, query, qtype, answer
  data/proxy.json   fields: @timestamp, src_ip, user, method, host, url_path, status,
                            bytes_out, action, user_agent
  data/ground_truth.json

Usage: python3 generate_lab_logs.py [--seed 42]
"""
import argparse
import datetime as dt
import json
import random
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "data"
START = dt.datetime(2026, 10, 5, 8, 0, 0)   # Monday 08:00, Almaty time
DAYS = 7

BENIGN = {  # domain: (weight, typical paths)
    "kaspi.kz": (12, ["/", "/shop/", "/pay/"]),
    "pay.kaspi.kz": (4, ["/", "/qr"]),
    "egov.kz": (5, ["/cms/ru", "/cms/ru/services"]),
    "idp.egov.kz": (2, ["/idp/sign-in"]),
    "homebank.kz": (4, ["/", "/login"]),
    "halykbank.kz": (2, ["/"]),
    "olx.kz": (6, ["/", "/d/obyavlenie/", "/myaccount/"]),
    "krisha.kz": (3, ["/", "/prodazha/"]),
    "kolesa.kz": (3, ["/", "/cars/"]),
    "post.kz": (2, ["/", "/tracking"]),
    "google.com": (15, ["/search"]),
    "youtube.com": (10, ["/watch"]),
    "instagram.com": (8, ["/"]),
    "web.telegram.org": (6, ["/"]),
    "web.whatsapp.com": (5, ["/"]),
    "mail.google.com": (8, ["/mail/u/0/"]),
    "outlook.office.com": (6, ["/mail/"]),
    "github.com": (5, ["/"]),
    "apple.com": (2, ["/"]),
    "icloud.com": (2, ["/"]),
    "2gis.kz": (3, ["/astana"]),
    "tengrinews.kz": (4, ["/"]),
    "kaspian-sea.org": (1, ["/"]),            # benign, contains "kaspi" (false-positive trap)
}
USER_AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0",
               "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) Safari/605.1",
               "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0) Mobile Safari/604.1"]

# Lab scenarios (planted). Domains come from my Week 2 feed data, except S4.
SCENARIOS = [
    {"id": "S1", "user": "user07", "day": 2, "time": "14:05", "host": "olxkz.pay-sacure4ds.ru",
     "steps": [("GET", "/", 200, 600), ("GET", "/pay", 200, 700), ("POST", "/pay", 200, 1850)],
     "story": "Seller opened a fake 'OLX delivery' link from a messenger and submitted the payment form"},
    {"id": "S2", "user": "user19", "day": 4, "time": "10:40", "host": "soporteapple.com.kz",
     "steps": [("GET", "/m/sing/k3x9q", 200, 640)],
     "story": "User opened an Apple-ID lure (kit cluster C01) but did not submit anything"},
    {"id": "S3", "user": "user23", "day": 5, "time": "16:20", "host": "post-kz.lol",
     "steps": [("GET", "/", 403, 0)], "action": "blocked",
     "story": "Proxy blocked a Kazpost lure (domain was on the Week 3 blocklist)"},
    {"id": "S4", "user": "user11", "day": 3, "time": "19:55", "host": "kaspi-bonus-kz.top",
     "steps": [("GET", "/", 200, 580), ("POST", "/login", 200, 1320)],
     "story": "NEW domain, not in any feed: fake 'Kaspi bonus' page, credentials submitted"},
]


def ts(day, hhmm=None, rnd=None):
    if hhmm:
        h, m = map(int, hhmm.split(":"))
        return START.replace(hour=h, minute=m) + dt.timedelta(days=day, seconds=rnd.randint(0, 50))
    return START + dt.timedelta(days=day, minutes=rnd.randint(0, 11 * 60), seconds=rnd.randint(0, 59))


def fake_ip(rnd):
    return f"{rnd.randint(2, 223)}.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=42)
    rnd = random.Random(ap.parse_args().seed)
    users = [f"user{i:02d}" for i in range(1, 31)]
    ip_of = {u: f"10.10.1.{10 + i}" for i, u in enumerate(users)}
    ua_of = {u: rnd.choice(USER_AGENTS) for u in users}
    resolved = {}
    domains, weights = zip(*[(d, w) for d, (w, _) in BENIGN.items()])
    dns, proxy = [], []

    def resolve(host):
        return resolved.setdefault(host, fake_ip(rnd))

    for day in range(DAYS):
        busy = 0.35 if day >= 5 else 1.0           # weekend = less traffic
        for u in users:
            for _ in range(int(rnd.randint(25, 45) * busy)):
                t = ts(day, rnd=rnd)
                host = rnd.choices(domains, weights)[0]
                dns.append({"@timestamp": t, "src_ip": ip_of[u], "user": u, "query": host,
                            "qtype": "A", "answer": resolve(host)})
                for i in range(rnd.randint(1, 3)):
                    method = "POST" if (host in {"kaspi.kz", "homebank.kz", "idp.egov.kz"} and rnd.random() < 0.15) else "GET"
                    proxy.append({"@timestamp": t + dt.timedelta(seconds=1 + i), "src_ip": ip_of[u], "user": u,
                                  "method": method, "host": host, "url_path": rnd.choice(BENIGN[host][1]),
                                  "status": 200, "bytes_out": rnd.randint(300, 2500) if method == "POST" else rnd.randint(200, 900),
                                  "action": "allowed", "user_agent": ua_of[u]})

    for s in SCENARIOS:
        t = ts(s["day"], s["time"], rnd)
        u = s["user"]
        dns.append({"@timestamp": t, "src_ip": ip_of[u], "user": u, "query": s["host"], "qtype": "A",
                    "answer": resolve(s["host"])})
        for i, (m, path, status, b) in enumerate(s["steps"]):
            proxy.append({"@timestamp": t + dt.timedelta(seconds=3 + 20 * i), "src_ip": ip_of[u], "user": u,
                          "method": m, "host": s["host"], "url_path": path, "status": status, "bytes_out": b,
                          "action": s.get("action", "allowed"), "user_agent": ua_of[u]})

    OUT.mkdir(exist_ok=True)
    for name, rows in (("dns.json", dns), ("proxy.json", proxy)):
        rows.sort(key=lambda r: r["@timestamp"])
        with (OUT / name).open("w") as f:
            for r in rows:
                f.write(json.dumps({**r, "@timestamp": r["@timestamp"].strftime("%Y-%m-%dT%H:%M:%S+05:00")}) + "\n")
    (OUT / "ground_truth.json").write_text(json.dumps(
        [{k: v for k, v in s.items() if k != "steps"} for s in SCENARIOS], indent=2))
    print(f"[+] {len(dns):,} DNS events, {len(proxy):,} proxy events, {len(users)} users, {DAYS} days -> {OUT}")


if __name__ == "__main__":
    main()
