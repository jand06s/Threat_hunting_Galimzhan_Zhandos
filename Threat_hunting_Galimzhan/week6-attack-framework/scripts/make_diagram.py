#!/usr/bin/env python3
"""Week 6: timeline diagram of the T1566.002 attack path. Usage: python3 make_diagram.py"""
import json
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

BASE = Path(__file__).resolve().parent.parent
tl = json.loads((BASE / "data" / "attack_timeline.json").read_text())
(BASE / "images").mkdir(exist_ok=True)

TACTIC_COLOR = {"TA0043": "#4a5568", "TA0001": "#2b6cb0", "TA0002": "#3182ce",
                "TA0006": "#c05621", "TA0011": "#6b46c1", "TA0040": "#c53030"}
fig, ax = plt.subplots(figsize=(11, 7.4))
ax.set_xlim(0, 11); ax.set_ylim(0, 7.4); ax.axis("off")
ax.set_title("ATT&CK study: one T1566.002 Spearphishing-Link attack, observed step by step",
             loc="left", weight="bold", fontsize=12)
n = len(tl)
for i, e in enumerate(tl):
    y = 6.5 - i * 0.92
    ta = e["tactic"].split()[0]
    col = TACTIC_COLOR.get(ta, "#718096")
    ax.add_patch(FancyBboxPatch((0.2, y - 0.34), 1.35, 0.68, boxstyle="round,pad=0.02,rounding_size=0.08",
                                fc=col, ec="none"))
    ax.text(0.875, y, e["technique"], ha="center", va="center", color="white", fontsize=9, weight="bold")
    ax.text(1.75, y + 0.1, e["observed"], va="center", fontsize=9, color="#1a202c")
    ax.text(1.75, y - 0.2, f"{e['t']}  ·  {e['tactic']}  ·  {e['name']}  ·  src: {e['data_source']}",
            va="center", fontsize=7.3, color="#718096", style="italic")
    if i < n - 1:
        ax.annotate("", xy=(0.875, y - 0.58), xytext=(0.875, y - 0.34),
                    arrowprops=dict(arrowstyle="-|>", color="#a0aec0", lw=1.3))
ax.text(0.2, 0.2, "Detection owned by me: DNS query (T1566.002) → Sigma rule dns_kz_brand_lookalike (Week 3); "
                  "POST to rare host (T1056.003) → hunt H2 (Week 5)", fontsize=8, color="#2f855a")
fig.tight_layout(); fig.savefig(BASE / "images" / "attack_timeline.png", dpi=150); plt.close(fig)
print("diagram -> images/attack_timeline.png")
