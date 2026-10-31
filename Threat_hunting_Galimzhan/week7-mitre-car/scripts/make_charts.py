#!/usr/bin/env python3
"""Week 7 chart: CAR analytic precision (raw vs tuned). Usage: python3 make_charts.py"""
from pathlib import Path
import matplotlib.pyplot as plt
import pandas as pd

BASE = Path(__file__).resolve().parent.parent
IMG = BASE / "images"; IMG.mkdir(exist_ok=True)
m = pd.read_csv(BASE / "results" / "metrics.csv")
plt.rcParams.update({"font.size": 10, "axes.spines.top": False, "axes.spines.right": False})

fig, ax = plt.subplots(figsize=(8.5, 3.8))
y = range(len(m))
ax.barh([i + 0.2 for i in y], m.true_positives, height=0.38, color="#2f855a", label="true positives")
ax.barh([i - 0.2 for i in y], m.false_positives, height=0.38, color="#c53030", label="false positives")
ax.set_yticks(list(y)); ax.set_yticklabels([f"{a}\n({t})" for a, t in zip(m.analytic, m.attack)], fontsize=8.5)
for i, r in m.iterrows():
    ax.text(r.true_positives + 0.1, i + 0.2, str(r.true_positives), va="center", fontsize=9)
    ax.text(r.false_positives + 0.1, i - 0.2, str(r.false_positives), va="center", fontsize=9)
ax.set_xlabel("hosts flagged"); ax.legend(loc="lower right", frameon=False)
ax.set_title("CAR analytics on the lab telemetry: tuning kills the false positives", loc="left", weight="bold")
fig.tight_layout(); fig.savefig(IMG / "car_precision.png", dpi=150); plt.close(fig)
print("chart -> images/car_precision.png")
