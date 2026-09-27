#!/usr/bin/env python3
"""Week 3 charts: processing pipeline, clusters, confidence. Usage: python3 make_charts.py"""
import csv
import re
from collections import Counter
from pathlib import Path

import matplotlib.pyplot as plt

BASE = Path(__file__).resolve().parent.parent
IMG = BASE / "images"; IMG.mkdir(exist_ok=True)
rows = list(csv.DictReader(open(BASE / "data" / "normalized_iocs.csv")))
log = (BASE / "data" / "processing_log.md").read_text()
num = lambda label: int(re.search(label + r"[^*]*\*\*(\d+)\*\*", log).group(1))
plt.rcParams.update({"font.size": 10, "axes.spines.top": False, "axes.spines.right": False})

# 1. pipeline
inp, dup, flt = num("Input rows"), num("Duplicates merged"), num("Filtered out")
steps = [("Collected (Week 2)", inp), ("After dedup\n(www.x = x)", inp - dup),
         ("After allowlist +\nFP filter", inp - dup - flt), ("MISP to_ids\n(conf ≥ medium)",
         sum(r["confidence"] != "low" for r in rows))]
fig, ax = plt.subplots(figsize=(8, 3.6))
bars = ax.bar([s for s, _ in steps], [v for _, v in steps], color=["#a0aec0", "#63b3ed", "#2b6cb0", "#c05621"])
ax.bar_label(bars, padding=3); ax.set_ylabel("indicators")
ax.set_title("Processing pipeline: filtering and normalization", loc="left", weight="bold")
fig.tight_layout(); fig.savefig(IMG / "pipeline.png", dpi=150); plt.close(fig)

# 2. clusters
c = Counter(r["cluster"] for r in rows if r["cluster"])
labels, vals = zip(*sorted(c.items(), key=lambda x: x[1]))
fig, ax = plt.subplots(figsize=(8, 0.45 * len(labels) + 1.2))
cols = ["#c05621" if l.startswith("C") else "#6b46c1" if l.startswith("F") else "#2f855a" for l in labels]
bars = ax.barh(labels, vals, color=cols); ax.bar_label(bars, padding=3)
ax.set_title("Correlation groups  (C = same kit path, F = brand family, P = platform)", loc="left", weight="bold")
ax.set_xlabel("indicators")
fig.tight_layout(); fig.savefig(IMG / "clusters.png", dpi=150); plt.close(fig)
print("charts ->", IMG)
