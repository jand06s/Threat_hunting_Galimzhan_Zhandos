#!/usr/bin/env python3
"""
Week 2: charts + Maltego import file from kz_phishing_candidates.csv.

Outputs:
  ../images/*.png
  ../maltego/maltego_import.csv  (Maltego: Import -> Import Graph from Table)

Usage: python3 make_charts.py
"""
from pathlib import Path

import matplotlib.pyplot as plt
import networkx as nx
import pandas as pd

BASE = Path(__file__).resolve().parent.parent
IMG = BASE / "images"; IMG.mkdir(exist_ok=True)
df = pd.read_csv(BASE / "data" / "kz_phishing_candidates.csv").fillna("")
plt.rcParams.update({"font.size": 10, "axes.spines.top": False, "axes.spines.right": False})
BLUE, ORANGE, GREY = "#2b6cb0", "#c05621", "#a0aec0"


def hbar(series, title, fname, color=BLUE, highlight=None):
    s = series.sort_values()
    fig, ax = plt.subplots(figsize=(8, 0.42 * len(s) + 1.2))
    colors = [ORANGE if highlight and highlight(i) else color for i in s.index]
    bars = ax.barh(s.index, s.values, color=colors)
    ax.bar_label(bars, padding=3)
    ax.set_title(title, loc="left", weight="bold")
    ax.set_xlabel("domains")
    fig.tight_layout(); fig.savefig(IMG / fname, dpi=150); plt.close(fig)


# 1. What is impersonated (KZ brands highlighted)
kz_brands = set(b for x in df.brand for b in x.split(";") if b)
imp = df.impersonated.value_counts()
hbar(imp, "What the collected phishing pages impersonate", "impersonated_targets.png",
     color=GREY, highlight=lambda i: i in kz_brands)

# 2. Hosting pattern
hbar(df.hosting_pattern.value_counts(), "How the phishing infrastructure is hosted", "hosting_pattern.png")

# 3. Platforms (free subdomain providers)
plat = df[df.platform != "self-registered / other"].platform.value_counts()
hbar(plat, "Free subdomain platforms abused (.kz)", "platforms.png")

# 4. Collection funnel
funnel = pd.Series({
    "Feed hosts (domains + link hosts)": 806_622,
    "KZ-related (.kz or KZ brand)": len(df),
    "Impersonating a KZ brand": (df.category == "brand-impersonation").sum(),
    # analyst review: usps.postkz.us is a USPS lure (keyword false positive)
    "…after removing false positives": ((df.category == "brand-impersonation") & (df.feed_false_positive == "no")
                                        & (df.indicator != "usps.postkz.us")).sum(),
})
fig, ax = plt.subplots(figsize=(8, 3.2))
bars = ax.barh(funnel.index[::-1], funnel.values[::-1], color=[ORANGE, ORANGE, BLUE, GREY])
ax.set_xscale("log"); ax.bar_label(bars, labels=[f"{v:,}" for v in funnel.values[::-1]], padding=3)
ax.set_title("Collection funnel (log scale)", loc="left", weight="bold")
fig.tight_layout(); fig.savefig(IMG / "collection_funnel.png", dpi=150); plt.close(fig)

# 5. Link graph (preview of what Maltego shows): domain -> platform/TLD -> target
G = nx.Graph()
sub = df[(df.impersonated != "unknown")]
for _, r in sub.iterrows():
    infra = r.platform if r.platform != "self-registered / other" else "." + r.tld
    G.add_node(r.indicator, kind="domain")
    G.add_node(infra, kind="infra")
    G.add_node(r.impersonated, kind="target")
    G.add_edge(r.indicator, infra); G.add_edge(r.indicator, r.impersonated)
pos = nx.spring_layout(G, k=0.45, seed=7, iterations=200)
fig, ax = plt.subplots(figsize=(14, 10)); ax.axis("off")
col = {"domain": "#90cdf4", "infra": "#f6ad55", "target": "#fc8181"}
size = {"domain": 60, "infra": 900, "target": 1400}
for kind in col:
    nodes = [n for n, d in G.nodes(data=True) if d["kind"] == kind]
    nx.draw_networkx_nodes(G, pos, nodelist=nodes, node_color=col[kind], node_size=size[kind], ax=ax, label=kind)
nx.draw_networkx_edges(G, pos, alpha=0.25, ax=ax)
nx.draw_networkx_labels(G, pos, labels={n: n for n, d in G.nodes(data=True) if d["kind"] != "domain"},
                        font_size=9, font_weight="bold", ax=ax)
ax.legend(loc="lower left", markerscale=0.5, frameon=False)
ax.set_title("Link analysis: phishing domain → infrastructure → impersonated target", weight="bold")
fig.tight_layout(); fig.savefig(IMG / "link_graph.png", dpi=130); plt.close(fig)

# 6. Maltego import table (one row per domain)
mt = df[["indicator", "tld", "platform", "impersonated", "example_url"]].rename(columns={
    "indicator": "Domain", "tld": "TLD", "platform": "Hosting", "impersonated": "Target", "example_url": "URL"})
(BASE / "maltego").mkdir(exist_ok=True)
mt.to_csv(BASE / "maltego" / "maltego_import.csv", index=False)
print("charts ->", IMG, "| maltego ->", BASE / "maltego")
