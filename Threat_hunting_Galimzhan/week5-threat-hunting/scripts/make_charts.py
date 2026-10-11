#!/usr/bin/env python3
"""Week 5 charts: hunt funnel, domain rarity (long tail), scenario coverage. Usage: python3 make_charts.py"""
import csv
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

BASE = Path(__file__).resolve().parent.parent
IMG = BASE / "images"; IMG.mkdir(exist_ok=True)
RES = BASE / "results"
plt.rcParams.update({"font.size": 10, "axes.spines.top": False, "axes.spines.right": False})
BLUE, ORANGE, GREEN, GREY = "#2b6cb0", "#c05621", "#2f855a", "#a0aec0"

# 1. Rarity: visits per domain sorted, phishing lives in the long tail (users_seen <= 2)
rar = pd.read_csv(RES / "rarity.csv").sort_values("users_seen")
colors = [ORANGE if u <= 2 else BLUE for u in rar.users_seen]
fig, ax = plt.subplots(figsize=(9, 6))
bars = ax.barh(rar.host, rar.users_seen, color=colors)
ax.axvline(2.5, color=ORANGE, ls="--", lw=1)
ax.text(2.7, 0.5, "hunt H2 looks here\n(≤ 2 users)", color=ORANGE, fontsize=9)
ax.set_xlabel("number of distinct users who visited the domain")
ax.set_title("Domain rarity: phishing hides in the long tail", loc="left", weight="bold")
fig.tight_layout(); fig.savefig(IMG / "rarity.png", dpi=150); plt.close(fig)

# 2. Hunt metrics (true positives / hits per hunt)
m = pd.read_csv(RES / "scorecard.csv")
hunts = ["H1", "H2", "H3"]
tp = [(m[h] == "found").sum() for h in hunts]
fig, ax = plt.subplots(figsize=(7, 3.4))
bars = ax.bar(["H1\nDNS keyword", "H2\nPOST to rare host", "H3\nIOC sweep"], tp, color=[BLUE, GREEN, ORANGE])
ax.bar_label(bars, labels=[f"{t}/4" for t in tp], padding=3)
ax.set_ylim(0, 4.5); ax.set_ylabel("planted scenarios found")
ax.set_title("Each hunt finds a different subset — they complement each other", loc="left", weight="bold")
fig.tight_layout(); fig.savefig(IMG / "hunt_coverage.png", dpi=150); plt.close(fig)

# 3. Coverage matrix scenario x hunt
grid = m.set_index("scenario")[hunts].apply(lambda col: (col == "found").astype(int))
fig, ax = plt.subplots(figsize=(6, 3.2))
ax.imshow(grid.values, cmap="Greens", vmin=0, vmax=1.4, aspect="auto")
ax.set_xticks(range(3)); ax.set_xticklabels(hunts)
ax.set_yticks(range(len(grid))); ax.set_yticklabels([f"{s}  {h}" for s, h in zip(m.scenario, m.host)], fontsize=8)
for i in range(len(grid)):
    for j in range(3):
        ax.text(j, i, "✓" if grid.values[i, j] else "·", ha="center", va="center",
                color="white" if grid.values[i, j] else "#718096", fontsize=14)
ax.set_title("Scenario coverage (rows = planted, cols = hunts)", loc="left", weight="bold", fontsize=11)
fig.tight_layout(); fig.savefig(IMG / "coverage_matrix.png", dpi=150); plt.close(fig)
print("charts ->", IMG)
