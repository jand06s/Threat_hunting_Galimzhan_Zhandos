#!/usr/bin/env python3
"""
Week 10 — build APT29 analysis artifacts from data/apt29_ttps.json (extracted from the
official MITRE ATT&CK STIX bundle).

  navigator/apt29_layer.json       all APT29 techniques, scored, for ATT&CK Navigator
  navigator/overlap_layer.json     score 2 = APT29 technique that MY detections also cover
  data/comparison.csv              APT29 (espionage) vs Classiscam (my criminal actor)
  images/apt29_phishing_chain.png  APT29's phishing-led intrusion chain
  images/overlap.png               how much of APT29 my phishing detections would catch
Usage: python3 scripts_build.py
"""
import csv, json
from collections import Counter
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

BASE = Path(__file__).resolve().parent.parent
APT = json.loads((BASE / "data" / "apt29_ttps.json").read_text())
for d in ("navigator", "images"):
    (BASE / d).mkdir(exist_ok=True)
techs = APT["techniques"]
tids = [t["id"] for t in techs]

# Techniques my phishing project already detects or maps (Weeks 3/5/7/9).
MINE = {
    "T1566.001": "phishing attachment — CAR-2013-02-003 (W7/W9)",
    "T1566.002": "phishing link — Sigma dns rule (W3), hunt H1 (W5)",
    "T1566.003": "phishing via service — hunt H2 (W5)",
    "T1204.001": "malicious link — hunt H2 (W5)",
    "T1204.002": "malicious file — CAR-2013-02-003 (W7/W9)",
    "T1059.001": "PowerShell — CAR-2014-04-003 (W7/W9)",
    "T1003.002": "cred dumping — LSASS rule (W9, SAM variant)",
    "T1078": "valid accounts — MISP IOC on login host (W8)",
}

def layer(name, scored, desc, maxv):
    return {"name": name, "versions": {"attack": "16", "navigator": "4.9.5", "layer": "4.5"},
            "domain": "enterprise-attack", "description": desc,
            "techniques": [{"techniqueID": t, "score": s, "enabled": True} for t, s in scored.items()],
            "gradient": {"colors": ["#ffe0b2", "#c05621"], "minValue": 1, "maxValue": maxv},
            "showTacticRowBackground": True, "tacticRowBackground": "#2b6cb0", "sorting": 3}

(BASE / "navigator" / "apt29_layer.json").write_text(json.dumps(
    layer("APT29 (G0016) techniques", {t: 1 for t in tids}, "All APT29 techniques from MITRE STIX.", 1), indent=2))
overlap = {t: (2 if t in MINE else 1) for t in tids}
(BASE / "navigator" / "overlap_layer.json").write_text(json.dumps(
    layer("APT29 vs my detections", overlap, "Score 2 = APT29 technique my phishing detections cover.", 2), indent=2))

# comparison table
comp = [
 ["Attribute", "APT29 (Cozy Bear / Midnight Blizzard)", "Classiscam (my actor)"],
 ["Type", "State-sponsored APT (espionage)", "Financially motivated cybercrime (PhaaS)"],
 ["Motivation", "Intelligence collection", "Money (card data, resale)"],
 ["Attribution", "Russian SVR (per US/UK gov)", "Loose criminal affiliate network"],
 ["Initial access", "Spearphishing link+attachment, valid accounts, supply chain (SolarWinds)", "Spearphishing link via OLX/messenger"],
 ["Sophistication", "Very high; custom malware, 0-days, cloud", "Low–medium; rented kits, Telegram bots"],
 ["Targets", "Governments, think-tanks, tech vendors", "Ordinary marketplace users in CIS/KZ"],
 ["Phishing sub-techs", "T1566.001 + .002 + .003 (all three)", "T1566.002 + .003"],
 ["Persistence", "Registry, scheduled tasks, cloud, web shells", "None on victim (uses stolen card/account)"],
 ["Overlap with me", f"{len(MINE)} of {len(tids)} techniques my detections touch", "—"],
]
with (BASE / "data" / "comparison.csv").open("w", newline="") as f:
    csv.writer(f).writerows(comp)

# APT29 phishing chain diagram (the part that overlaps my project)
chain = [
 ("Initial Access", "T1566.002", "Spearphishing link (also .001 attachment, .003 service)", True),
 ("Execution", "T1204", "User opens link / file", True),
 ("Execution", "T1059.001", "PowerShell loader", True),
 ("Persistence", "T1547.001", "Registry Run key", False),
 ("Cred Access", "T1003", "Dump credentials (SAM / LSA)", True),
 ("Collection", "T1114.002", "Remote email collection", False),
 ("C2", "T1573", "Encrypted channel", False),
 ("Exfiltration", "T1567", "Exfil to web service", False),
]
fig, ax = plt.subplots(figsize=(12, 7)); ax.set_xlim(0, 12); ax.set_ylim(0, 7); ax.axis("off")
ax.set_title("APT29 phishing-led intrusion — green = my phishing detections would catch it", loc="left", weight="bold", fontsize=12)
for i, (phase, tid, desc, mine) in enumerate(chain):
    y = 6.2 - i * 0.74
    col = "#2f855a" if mine else "#a0aec0"
    ax.add_patch(FancyBboxPatch((0.2, y - 0.28), 2.4, 0.56, boxstyle="round,pad=0.02,rounding_size=0.08", fc="#2b6cb0", ec="none"))
    ax.text(1.4, y, f"{phase}", ha="center", va="center", color="white", fontsize=9, weight="bold")
    ax.add_patch(FancyBboxPatch((2.8, y - 0.28), 1.5, 0.56, boxstyle="round,pad=0.02,rounding_size=0.08", fc=col, ec="none"))
    ax.text(3.55, y, tid, ha="center", va="center", color="white", fontsize=8.5, family="monospace")
    ax.text(4.5, y, desc, va="center", fontsize=9, color="#1a202c")
    ax.text(11.6, y, "✓ caught" if mine else "✗ blind", va="center", ha="right", fontsize=8,
            color="#2f855a" if mine else "#c53030", weight="bold")
    if i < len(chain) - 1:
        ax.annotate("", xy=(1.4, y - 0.46), xytext=(1.4, y - 0.28), arrowprops=dict(arrowstyle="-|>", color="#a0aec0", lw=1.1))
fig.tight_layout(); fig.savefig(BASE / "images" / "apt29_phishing_chain.png", dpi=150); plt.close(fig)

# overlap bar
fig, ax = plt.subplots(figsize=(7, 2.6))
covered, total = len(MINE), len(tids)
ax.barh([0], [total], color="#e2e8f0"); ax.barh([0], [covered], color="#2f855a")
ax.text(covered + 0.5, 0, f"{covered} of {total} APT29 techniques\ntouched by my phishing detections", va="center", fontsize=10)
ax.set_yticks([]); ax.set_xlim(0, total + 8); ax.set_xlabel("APT29 techniques (MITRE ATT&CK)")
ax.set_title("Coverage of APT29 by a phishing-focused blue team", loc="left", weight="bold")
for s in ["top", "right", "left"]: ax.spines[s].set_visible(False)
fig.tight_layout(); fig.savefig(BASE / "images" / "overlap.png", dpi=150); plt.close(fig)

print(f"[+] APT29: {len(tids)} techniques; my detections touch {len(MINE)}.")
print(f"[+] layers + comparison.csv + 2 images written")
