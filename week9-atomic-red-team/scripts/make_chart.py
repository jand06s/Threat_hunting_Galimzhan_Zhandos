#!/usr/bin/env python3
"""Week 9 chart: atomic-test detection coverage matrix. Usage: python3 make_chart.py"""
from pathlib import Path
import matplotlib.pyplot as plt
import pandas as pd

BASE = Path(__file__).resolve().parent.parent
IMG = BASE / "images"; IMG.mkdir(exist_ok=True)
sc = pd.read_csv(BASE / "results" / "scorecard.csv").drop_duplicates("atomic_id")
plt.rcParams.update({"font.size": 10})
fig, ax = plt.subplots(figsize=(8.6, 3.2))
y = range(len(sc))
colors = ["#2f855a" if d == "YES" else "#c53030" for d in sc.detected]
ax.barh(list(y), [1] * len(sc), color=colors)
for i, (_, r) in enumerate(sc.iterrows()):
    ax.text(0.02, i, f"{r.atomic_id}  {r['name'][:34]}", va="center", ha="left", color="white", fontsize=9, weight="bold")
    ax.text(0.98, i, ("✓ " + r.by_rule) if r.detected == "YES" else "✗ gap", va="center", ha="right", color="white", fontsize=9)
ax.set_yticks([]); ax.set_xticks([]); ax.set_xlim(0, 1)
ax.set_title("Atomic Red Team: detection coverage (green = detected, red = gap found)", loc="left", weight="bold")
for s in ax.spines.values(): s.set_visible(False)
fig.tight_layout(); fig.savefig(IMG / "atomic_coverage.png", dpi=150); plt.close(fig)
print("chart -> images/atomic_coverage.png")
