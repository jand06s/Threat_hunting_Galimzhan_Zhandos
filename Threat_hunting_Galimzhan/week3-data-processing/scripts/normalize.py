#!/usr/bin/env python3
"""
Week 3: filtering + normalization + correlation of the collected indicators.

Input : ../../week2-data-collection/data/kz_phishing_candidates.csv
        (+ optional virustotal_enrichment.csv / shodan_host_enrichment.csv)
Output: ../data/normalized_iocs.csv
        ../data/processing_log.md   (what every step removed/changed)
        ../data/blocklist_domains.txt

Pipeline:
  1. Refang           hxxp -> http, [.] -> .
  2. Normalize        lowercase, strip "www.", trailing dot, IDN -> punycode
  3. Validate         drop values that are not valid hostnames
  4. Deduplicate      same normalized value = one indicator
  5. Filter           allowlist (legit brand domains), known keyword false positives
  6. URL normalize    lowercase host, drop fragment + tracking params, redact emails
  7. Enrich (opt.)    merge VirusTotal / Shodan results if the CSVs exist
  8. Correlate        cluster indicators that share a URL path "kit signature" or parent platform
  9. Score            confidence = low / medium / high
"""
import csv
import re
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

HERE = Path(__file__).resolve().parent
W2 = HERE.parent.parent / "week2-data-collection" / "data"
OUT = HERE.parent / "data"

ALLOWLIST = {
    "kaspi.kz", "egov.kz", "halykbank.kz", "homebank.kz", "jusan.kz", "kazpost.kz",
    "post.kz", "olx.kz", "kolesa.kz", "krisha.kz", "kcell.kz", "beeline.kz", "tele2.kz",
}
# Manually reviewed keyword false positives (analyst decision, documented in the report)
KEYWORD_FP = {"usps.postkz.us": "USPS lure, 'postkz' is coincidental"}
TRACKING = re.compile(r"^(utm_|fbclid|gclid|yclid)", re.I)
EMAIL_RX = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
HOST_RX = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$|^xn--")
PLATFORM_PARENTS = {"jcloud.kz", "mylp.kz", "workers.dev", "web.app", "netlify.app"}


def refang(v: str) -> str:
    v = v.strip()
    v = re.sub(r"^hxxp", "http", v, flags=re.I)
    return v.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")


def norm_host(h: str) -> str:
    h = refang(h).lower().rstrip(".")
    if h.startswith("www."):
        h = h[4:]
    try:
        h = h.encode("idna").decode()
    except UnicodeError:
        pass
    return h


def norm_url(u: str) -> str:
    if not u:
        return ""
    u = EMAIL_RX.sub("[redacted-email]", refang(u))
    p = urlsplit(u)
    q = urlencode([(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if not TRACKING.match(k)])
    return urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path, q, ""))


def kit_signature(url: str) -> str:
    """Path pattern with random tokens removed -> same kit leaves the same signature."""
    if not url:
        return ""
    path = urlsplit(url).path.lower()
    parts = [p for p in path.split("/") if p]
    if len(parts) < 2:
        return ""
    # keep structural words, replace short random tokens / hashes with *
    sig = ["*" if re.fullmatch(r"[a-z0-9]{5,}", p) and not re.search(r"[aeiou]{1}[a-z]{3,}", p) or re.fullmatch(r"[0-9a-f]{16,}", p) else p
           for p in parts]
    return "/" + "/".join(sig[:4])


def parent(h: str) -> str:
    p = h.split(".")
    return ".".join(p[-3:]) if len(p) > 2 and p[-2] in {"com", "org", "net", "gov"} else ".".join(p[-2:])


def load_optional(name, key):
    p = W2 / name
    if not p.exists():
        return {}
    with p.open() as f:
        return {norm_host(r[key]): r for r in csv.DictReader(f)}


def main():
    log = ["# Processing log\n"]
    with (W2 / "kz_phishing_candidates.csv").open() as f:
        raw = list(csv.DictReader(f))
    log.append(f"- Input rows: **{len(raw)}**")

    # 1-3 refang, normalize, validate
    rows, invalid = [], []
    for r in raw:
        h = norm_host(r["indicator"])
        if not HOST_RX.match(h):
            invalid.append(r["indicator"]); continue
        r = dict(r, indicator=h, example_url=norm_url(r.get("example_url", "")))
        rows.append(r)
    log.append(f"- Invalid hostnames dropped: **{len(invalid)}** {invalid[:5]}")

    # 4 dedup (www.x and x collapse into one)
    seen, dedup, dups = {}, [], 0
    for r in rows:
        if r["indicator"] in seen:
            dups += 1
            prev = seen[r["indicator"]]
            if not prev["example_url"] and r["example_url"]:
                prev["example_url"] = r["example_url"]
            continue
        seen[r["indicator"]] = r; dedup.append(r)
    log.append(f"- Duplicates merged after normalization (e.g. www.x = x): **{dups}**")

    # 5 filter
    kept, removed = [], []
    for r in dedup:
        if r["indicator"] in ALLOWLIST:
            removed.append((r["indicator"], "allowlist: legitimate brand domain")); continue
        if r["indicator"] in KEYWORD_FP:
            removed.append((r["indicator"], "keyword false positive: " + KEYWORD_FP[r["indicator"]])); continue
        kept.append(r)
    log.append(f"- Filtered out: **{len(removed)}**")
    log += [f"  - `{i}`: {why}" for i, why in removed]

    # 7 enrichment (optional files from Week 2)
    vt = load_optional("virustotal_enrichment.csv", "domain")
    sh = load_optional("shodan_host_enrichment.csv", "domain")
    log.append(f"- Enrichment available: VirusTotal={len(vt)} rows, Shodan={len(sh)} rows")

    # 8 correlation
    by_sig = defaultdict(list)
    for r in kept:
        r["kit_signature"] = kit_signature(r["example_url"])
        if r["kit_signature"]:
            by_sig[r["kit_signature"]].append(r["indicator"])
    clusters = {s: hs for s, hs in by_sig.items() if len(hs) > 1}
    cid = {}
    for i, (s, hs) in enumerate(sorted(clusters.items(), key=lambda x: -len(x[1])), 1):
        for h in hs:
            cid[h] = f"C{i:02d}-kit"
    for r in kept:
        p = parent(r["indicator"])
        if r["indicator"] not in cid and p in PLATFORM_PARENTS:
            cid[r["indicator"]] = f"P-{p}"
    # brand-name families registered in .com.kz/.org.kz etc. (opensea*, apple*)
    fam_rx = {"F-opensea": r"^op[ea]n?[sr]?ea|^opersea", "F-apple": r"apple|icloud|isupport|miaccount"}
    for r in kept:
        for fam, rx in fam_rx.items():
            if r["indicator"] not in cid and re.search(rx, r["indicator"]):
                cid[r["indicator"]] = fam

    # 9 scoring + final shape
    out = []
    for r in kept:
        h = r["indicator"]
        score = 0
        score += 1 if r["category"] == "brand-impersonation" else 0
        score += 1 if r["status"] == "active" else 0
        score += 1 if cid.get(h, "").startswith(("C", "F")) else 0
        v = vt.get(h, {})
        if v and int(v.get("malicious") or 0) > 0:
            score += 1
        conf = "high" if score >= 3 else "medium" if score == 2 else "low"
        out.append({
            "indicator": h, "misp_type": "domain", "category": r["category"],
            "brand": r["brand"], "impersonated": r["impersonated"],
            "parent_domain": parent(h), "tld": r["tld"], "platform": r["platform"],
            "hosting_pattern": r["hosting_pattern"], "status": r["status"],
            "cluster": cid.get(h, ""), "kit_signature": r["kit_signature"],
            "vt_malicious": v.get("malicious", ""), "shodan_org": sh.get(h, {}).get("org", ""),
            "confidence": conf, "url": r["example_url"], "first_seen": r["collected_at"],
            "source": r["source"],
        })

    OUT.mkdir(exist_ok=True)
    with (OUT / "normalized_iocs.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(out[0])); w.writeheader(); w.writerows(out)
    (OUT / "blocklist_domains.txt").write_text(
        "# KZ phishing blocklist, TLP:CLEAR, source: Phishing.Database, processed by normalize.py\n"
        + "\n".join(sorted(o["indicator"] for o in out if o["confidence"] != "low")) + "\n")

    log.append(f"- Output indicators: **{len(out)}**  (URLs with path: {sum(1 for o in out if o['url'])})")
    log.append(f"- Confidence: {dict(Counter(o['confidence'] for o in out))}")
    log.append("\n## Correlation clusters (same kit signature)\n")
    log.append("| Cluster | Kit signature | Size | Members |\n|---|---|---|---|")
    for i, (s, hs) in enumerate(sorted(clusters.items(), key=lambda x: -len(x[1])), 1):
        log.append(f"| C{i:02d}-kit | `{s}` | {len(hs)} | {', '.join(sorted(hs)[:6])}{' …' if len(hs) > 6 else ''} |")
    fam = Counter(c for c in cid.values() if not c.startswith("C"))
    log.append("\n## Platform / brand-family groups\n")
    log += [f"- `{k}`: {v} indicators" for k, v in fam.most_common()]
    (OUT / "processing_log.md").write_text("\n".join(log) + "\n")
    print("\n".join(log))


if __name__ == "__main__":
    main()
