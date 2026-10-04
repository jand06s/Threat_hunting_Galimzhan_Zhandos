#!/usr/bin/env python3
"""
Week 4: build all Kill Chain artifacts from data/killchain_mapping.json.

Outputs:
  images/killchain_<case>.png     Kill Chain diagram with ATT&CK IDs per stage
  images/attack_heatmap.png       ATT&CK techniques used by each case
  navigator/<case>_layer.json     layers for MITRE ATT&CK Navigator ("Open Existing Layer")
  navigator/combined_layer.json   both cases (score 1 = one case, 2 = both)
  data/killchain_mapping.csv      flat table (case, stage, technique, tactic)
  courses-of-action.md            Lockheed Martin Courses of Action matrix

Usage: python3 scripts/make_killchain.py
"""
import csv
import json
import textwrap
from collections import OrderedDict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Polygon, FancyBboxPatch

BASE = Path(__file__).resolve().parent.parent
DATA = json.loads((BASE / "data" / "killchain_mapping.json").read_text())
(BASE / "images").mkdir(exist_ok=True)
(BASE / "navigator").mkdir(exist_ok=True)

STAGE_COLORS = ["#2c5282", "#2b6cb0", "#3182ce", "#c05621", "#718096", "#6b46c1", "#c53030"]
TACTIC_ORDER = ["reconnaissance", "resource-development", "initial-access", "execution",
                "persistence", "command-and-control", "impact"]


def chevron(ax, x, y, w, h, color, first=False):
    tip = 0.25
    pts = [(x, y), (x + w, y), (x + w + tip, y + h / 2), (x + w, y + h), (x, y + h)]
    if not first:
        pts.append((x + tip, y + h / 2))
    ax.add_patch(Polygon(pts, closed=True, fc=color, ec="white", lw=2))


def killchain_diagram(case):
    stages = case["stages"]
    fig, ax = plt.subplots(figsize=(17, 7.5))
    ax.set_xlim(0, 17); ax.set_ylim(0, 7); ax.axis("off")
    w, h, y = 2.15, 0.9, 5.4
    for i, s in enumerate(stages):
        x = 0.15 + i * 2.4
        absent = "ABSENT" in s["what_happens"]
        color = "#a0aec0" if absent else STAGE_COLORS[i]
        chevron(ax, x, y, w, h, color, first=(i == 0))
        label = s["stage"].replace(" on ", "\non ").replace(" & ", " &\n")
        ax.text(x + w / 2 + 0.12, y + h / 2, f"{i+1}. {label}", ha="center", va="center",
                color="white", fontsize=9.5, fontweight="bold")
        # technique box
        tech = "\n\n".join(f"{t['id']}\n" + textwrap.fill(t['name'], 24)
                           for t in s["techniques"])
        ax.add_patch(FancyBboxPatch((x + 0.05, 1.95), w - 0.1, 3.2, boxstyle="round,pad=0.04",
                                    fc="#f7fafc", ec=color, lw=1.5))
        ax.text(x + w / 2, 5.05, tech, ha="center", va="top", fontsize=7, linespacing=1.15)
        # what happens
        what = textwrap.fill(s["what_happens"], 30)
        ax.text(x + w / 2, 1.8, what, ha="center", va="top", fontsize=6.9, color="#2d3748")
        if absent:
            ax.text(x + w / 2 + 0.12, y + 0.12, "(absent on victim side)", ha="center", fontsize=7,
                    color="white", style="italic")
    ax.text(0.15, 6.75, case["title"], fontsize=13, fontweight="bold")
    ax.text(0.15, 6.45, f"Confidence: {case['confidence']}", fontsize=9, color="#4a5568")
    out = BASE / "images" / f"killchain_{case['id']}.png"
    fig.savefig(out, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    return out


def all_techniques():
    """OrderedDict id -> {name, tactic, cases:set}"""
    techs = OrderedDict()
    for case in DATA["cases"]:
        for s in case["stages"]:
            for t in s["techniques"]:
                e = techs.setdefault(t["id"], {"name": t["name"].split(" (")[0],
                                               "tactic": t["tactic"], "cases": set()})
                e["cases"].add(case["id"])
    return OrderedDict(sorted(techs.items(),
                              key=lambda kv: (TACTIC_ORDER.index(kv[1]["tactic"]), kv[0])))


def heatmap(techs):
    cases = DATA["cases"]
    fig, ax = plt.subplots(figsize=(9, 0.42 * len(techs) + 1.5))
    for r, (tid, t) in enumerate(techs.items()):
        for c, case in enumerate(cases):
            used = case["id"] in t["cases"]
            ax.add_patch(plt.Rectangle((c, r), 1, 1, fc="#c53030" if used else "#edf2f7", ec="white", lw=2))
            if used:
                ax.text(c + 0.5, r + 0.5, "✓", ha="center", va="center", color="white", fontsize=11)
    ax.set_xlim(0, len(cases)); ax.set_ylim(len(techs), 0)
    ax.set_xticks([i + 0.5 for i in range(len(cases))])
    ax.set_xticklabels([c["short"] for c in cases], fontsize=9)
    ax.xaxis.tick_top()
    ax.set_yticks([i + 0.5 for i in range(len(techs))])
    ax.set_yticklabels([f"{tid}  {t['name']}  [{t['tactic']}]" for tid, t in techs.items()], fontsize=8)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.tick_params(length=0)
    shared = sum(1 for t in techs.values() if len(t["cases"]) == 2)
    ax.set_title(f"ATT&CK techniques per case ({len(techs)} unique, {shared} shared)",
                 fontsize=11, pad=28)
    out = BASE / "images" / "attack_heatmap.png"
    fig.savefig(out, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    return out, shared


def nav_layer(name, desc, entries):
    return {
        "name": name, "description": desc, "domain": "enterprise-attack",
        "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
        "techniques": entries,
        "gradient": {"colors": ["#fbd38d", "#c53030"], "minValue": 1, "maxValue": 2},
        "legendItems": [{"label": "used in one case", "color": "#fbd38d"},
                        {"label": "used in both cases", "color": "#c53030"}],
    }


def tech_entry(tid, tactic, score, comment):
    e = {"techniqueID": tid, "tactic": tactic, "score": score, "comment": comment, "enabled": True}
    return e


def navigator(techs):
    for case in DATA["cases"]:
        entries = []
        for s in case["stages"]:
            for t in s["techniques"]:
                entries.append(tech_entry(t["id"], t["tactic"], 1, f"Kill Chain: {s['stage']}"))
        layer = nav_layer(f"W4 {case['short']}", case["title"], entries)
        layer["gradient"] = {"colors": ["#c53030", "#c53030"], "minValue": 0, "maxValue": 1}
        layer.pop("legendItems")
        (BASE / "navigator" / f"{case['id']}_layer.json").write_text(json.dumps(layer, indent=2))
    entries = [tech_entry(tid, t["tactic"], len(t["cases"]), "cases: " + ", ".join(sorted(t["cases"])))
               for tid, t in techs.items()]
    (BASE / "navigator" / "combined_layer.json").write_text(json.dumps(
        nav_layer("W4 KZ phishing: both cases", "Classiscam/OLX.kz + cluster C01 Apple kit", entries), indent=2))


def flat_csv():
    rows = []
    for case in DATA["cases"]:
        for i, s in enumerate(case["stages"], 1):
            for t in s["techniques"]:
                rows.append({"case": case["id"], "stage_no": i, "stage": s["stage"],
                             "technique_id": t["id"], "technique": t["name"], "tactic": t["tactic"]})
    with open(BASE / "data" / "killchain_mapping.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader(); w.writerows(rows)
    return len(rows)


def coa_md():
    cols = ["detect", "deny", "disrupt", "degrade", "deceive", "destroy"]
    lines = ["# Courses of Action matrix (Lockheed Martin)", "",
             "What a defender (OLX.kz, a bank, KZ-CERT, a SOC) can do at each Kill Chain stage.",
             "Empty cell = no realistic action at that stage.", "",
             "| Stage | " + " | ".join(c.capitalize() for c in cols) + " |",
             "|---" * (len(cols) + 1) + "|"]
    for r in DATA["courses_of_action"]:
        lines.append(f"| **{r['stage']}** | " + " | ".join(r[c] or "–" for c in cols) + " |")
    (BASE / "courses-of-action.md").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    for case in DATA["cases"]:
        print("diagram:", killchain_diagram(case).name)
    techs = all_techniques()
    hm, shared = heatmap(techs)
    print("heatmap:", hm.name, f"({len(techs)} techniques, {shared} shared)")
    navigator(techs)
    print("navigator layers: 3")
    print("csv rows:", flat_csv())
    coa_md()
    print("courses-of-action.md written")
