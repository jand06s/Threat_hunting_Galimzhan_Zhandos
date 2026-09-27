#!/usr/bin/env python3
"""
Week 2: OSINT collection from open phishing feeds.

Downloads active phishing domains/URLs from the Phishing.Database project
(https://github.com/Phishing-Database/Phishing.Database) and extracts every
entry that:
  (a) impersonates a Kazakhstan brand (Kaspi, eGov, Halyk, OLX.kz, ...), or
  (b) is hosted on the .kz ccTLD.

Output: ../data/kz_phishing_candidates.csv

Usage:
    python3 collect_feeds.py                # download fresh feeds
    python3 collect_feeds.py --offline DIR  # use already downloaded files

Feeds used: ACTIVE domains, ACTIVE links, INACTIVE links (historical).
"""
import argparse
import csv
import datetime as dt
import re
import sys
import urllib.request
from collections import Counter
from pathlib import Path

FEED_BASE = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/"
FEEDS = {
    "domains": "phishing-domains-ACTIVE.txt",
    "links": "phishing-links-ACTIVE.txt",
    "links_inactive": "phishing-links-INACTIVE.txt",
}

# Legitimate domains: if the feed lists them, it is a feed false positive.
ALLOWLIST = {
    "kaspi.kz", "egov.kz", "halykbank.kz", "homebank.kz", "jusan.kz", "kazpost.kz",
    "post.kz", "olx.kz", "kolesa.kz", "krisha.kz", "kcell.kz", "beeline.kz", "tele2.kz",
    "altel.kz", "fortebank.com", "bcc.kz", "ffin.kz", "otbasybank.kz", "enpf.kz",
    "kgd.gov.kz", "airastana.com", "gov.kz",
}
OUT_DIR = Path(__file__).resolve().parent.parent / "data"

# Brand rules: (brand, regex over the full hostname, require_kz_context)
# require_kz_context=True means the host must also contain "kz"/"kazakh"
# to avoid collisions (e.g. "egov" is also used by other countries).
BRAND_RULES = [
    ("Kaspi",        r"kaspi(?!an)",                              False),
    ("Halyk",        r"halyk",                              False),
    ("Halyk",        r"homebank",                           True),
    ("eGov",         r"(^|[.-])e-?gov",                     True),
    ("Jusan",        r"(^|[.-])jusan(?!g)",                              False),
    ("Kazpost",      r"kaz-?post|kazpochta|post-?kz",       False),
    ("OLX.kz",       r"olx",                                True),
    ("Kolesa.kz",    r"kolesa",                             True),
    ("Krisha.kz",    r"(^|[.-])krisha([.-]|$)",             True),
    ("ForteBank",    r"forte-?bank",                        False),
    ("BCC",          r"centercredit|(^|[.-])bcc-?kz",       False),
    ("Freedom",      r"freedom-?(bank|finance|broker)|(^|[.-])ffin([.-]|$)", True),
    ("Kcell",        r"(^|[.-])kcell",                              False),
    ("Beeline KZ",   r"beeline",                            True),
    ("Tele2/Altel",  r"tele2|altel",                        True),
    ("Otbasy",       r"otbasy",                             False),
    ("ENPF",         r"(^|[.-])enpf",                       False),
    ("Salyk/KGD",    r"salyk",                              False),
    ("Air Astana",   r"air-?astana",                        False),
    ("Generic KZ",   r"kazakh|qazaq",                       False),  # low confidence
]
KZ_CONTEXT = re.compile(r"kz|kazakh|qazaq")

# Free hosting / platform suffixes. Useful for "where is it hosted" (PIR-2).
PLATFORMS = {
    "web.app": "Firebase", "firebaseapp.com": "Firebase", "netlify.app": "Netlify",
    "vercel.app": "Vercel", "pages.dev": "Cloudflare Pages", "workers.dev": "Cloudflare Workers",
    "github.io": "GitHub Pages", "glitch.me": "Glitch", "repl.co": "Replit",
    "replit.dev": "Replit", "weebly.com": "Weebly", "000webhostapp.com": "000webhost",
    "appspot.com": "Google App Engine", "herokuapp.com": "Heroku", "blogspot.com": "Blogger",
    "duckdns.org": "DuckDNS", "jcloud.kz": "jcloud.kz", "mylp.kz": "mylp.kz",
    "tilda.ws": "Tilda", "wixsite.com": "Wix", "godaddysites.com": "GoDaddy Sites",
    "ipfs.dweb.link": "IPFS gateway", "ipfs.w3s.link": "IPFS gateway",
}


# What the page imitates (for entries without a KZ brand), matched on host + URL.
TARGET_RULES = [
    ("Apple/iCloud",     r"apple|icloud|isupport|miaccount"),
    ("Crypto/NFT",       r"opensea|opersea|opansea|uniswap|metamask|crypt|bitex|coin|wallet"),
    ("Microsoft/Webmail", r"microsoft|office|outlook|owa|webmail|live-?mail|mail\.ru|login\.php\?.*email"),
    ("Brazil banking/retail", r"nubank|banese|hipercard|renner|acessomob|acessodes|contabilidade|ltda|comercio|fatura"),
    ("US/EU banking",    r"chase|tdbank|navy\.?federal|dkb|otbbank|wellsfargo"),
    ("Logistics",        r"dhl|usps|diepost|posta"),
    ("Social/Media",     r"facebook|instag|linkedin|netflix|spotify|roblox|oblox"),
    ("DocuSign",         r"docusign"),
]
EMAIL_RX = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
CMS_RX = re.compile(r"/(wp-admin|wp-content|wp-includes|bitrix|templates|modules|sites/default)/", re.I)


def impersonated(host: str, url: str) -> str:
    text = f"{host} {url}".lower()
    for name, rx in TARGET_RULES:
        if re.search(rx, text):
            return name
    return "unknown"


def hosting_pattern(host: str, url: str, platform: str) -> str:
    if platform != "self-registered / other":
        return "free subdomain platform"
    if CMS_RX.search(url or ""):
        return "compromised CMS site"
    return "registered domain"


def download(name: str, dest: Path) -> Path:
    url = FEED_BASE + name
    print(f"[+] downloading {url}")
    urllib.request.urlretrieve(url, dest / name)
    return dest / name


def platform_of(host: str) -> str:
    for suffix, name in PLATFORMS.items():
        if host == suffix or host.endswith("." + suffix):
            return name
    return "self-registered / other"


def tld_of(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in {"com", "org", "net", "co", "gov", "edu"}:
        return ".".join(parts[-2:])
    return parts[-1]


def match_brands(host: str) -> list[str]:
    hits = []
    for brand, rx, need_kz in BRAND_RULES:
        if re.search(rx, host):
            if need_kz and not KZ_CONTEXT.search(host):
                continue
            if brand not in hits:
                hits.append(brand)
    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", type=Path, help="directory with already downloaded feed files")
    args = ap.parse_args()

    raw_dir = args.offline or (OUT_DIR / "raw")
    raw_dir.mkdir(parents=True, exist_ok=True)
    files = {}
    for key, name in FEEDS.items():
        p = raw_dir / name
        files[key] = p if (args.offline and p.exists()) else download(name, raw_dir)

    host_rx = re.compile(r"https?://([^/:?#]+)", re.I)

    def hosts_from_links(path):
        out = {}
        for line in path.open(errors="ignore"):
            m = host_rx.match(line.strip())
            if m:
                out.setdefault(m.group(1).lower(), line.strip())
        return out

    active_domains = {l.strip().lower() for l in files["domains"].open(errors="ignore") if l.strip()}
    active_links = hosts_from_links(files["links"])
    inactive_links = hosts_from_links(files["links_inactive"])
    print(f"[+] {len(active_domains):,} active domains, {len(active_links):,} active link hosts, "
          f"{len(inactive_links):,} inactive link hosts")

    status = {}
    for h in inactive_links:
        status[h] = "inactive"
    for h in list(active_links) + list(active_domains):
        status[h] = "active"
    examples = {**inactive_links, **active_links}

    rows = []
    for host in sorted(status):
        brands = match_brands(host)
        on_kz = host.endswith(".kz")
        if not brands and not on_kz:
            continue
        bare = host[4:] if host.startswith("www.") else host
        url = EMAIL_RX.sub("[redacted-email]", examples.get(host, ""))
        plat = platform_of(host)
        rows.append({
            "indicator": host,
            "type": "domain",
            "status": status[host],
            "brand": ";".join(brands) if brands else "",
            "category": "brand-impersonation" if brands else "kz-hosted",
            "tld": tld_of(host),
            "platform": plat,
            "impersonated": ";".join(brands) if brands else impersonated(host, url),
            "hosting_pattern": hosting_pattern(host, url, plat),
            "feed_false_positive": "yes" if bare in ALLOWLIST else "no",
            "example_url": url,  # victim emails in URLs are redacted
            "source": "Phishing.Database",
            "collected_at": dt.date.today().isoformat(),
        })

    OUT_DIR.mkdir(exist_ok=True)
    out = OUT_DIR / "kz_phishing_candidates.csv"
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    print(f"[+] {len(rows)} KZ-related entries -> {out}")
    print("    by category:", dict(Counter(r["category"] for r in rows)))
    print("    by status:  ", dict(Counter(r["status"] for r in rows)))
    print("    feed FPs:   ", [r["indicator"] for r in rows if r["feed_false_positive"] == "yes"])
    print("    impersonated:", dict(Counter(r["impersonated"] for r in rows).most_common()))
    print("    hosting:     ", dict(Counter(r["hosting_pattern"] for r in rows).most_common()))
    brands = Counter(b for r in rows for b in r["brand"].split(";") if b)
    print("    by brand:   ", dict(brands.most_common()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
