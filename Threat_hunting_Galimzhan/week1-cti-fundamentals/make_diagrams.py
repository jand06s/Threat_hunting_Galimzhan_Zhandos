"""Generate the Week 1 diagrams (threat taxonomy + intelligence lifecycle).

Usage: python3 make_diagrams.py
"""
import math
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

OUT = Path(__file__).parent / "images"
OUT.mkdir(exist_ok=True)

COLORS = ["#2b6cb0", "#c05621", "#2f855a", "#6b46c1"]


def box(ax, x, y, w, h, text, color, fs=9, tc="white"):
    ax.add_patch(FancyBboxPatch((x - w / 2, y - h / 2), w, h,
                                boxstyle="round,pad=0.02,rounding_size=0.08",
                                fc=color, ec="none"))
    ax.text(x, y, text, ha="center", va="center", fontsize=fs, color=tc, wrap=True)


def taxonomy():
    branches = {
        "Delivery vector": ["Email", "SMS (smishing)", "Messengers", "Marketplace scam",
                            "Voice (vishing)", "QR (quishing)", "Malvertising"],
        "Target / goal": ["Banking creds + OTP", "eGov / IIN / ЭЦП", "Card data",
                          "Telecom (SIM swap)", "Crypto wallets"],
        "Threat source": ["PhaaS operators", "Individual scammers", "Call-centre fraud",
                          "APT (spear-phishing)", "Hacktivists", "Insiders"],
        "Intel source": ["Phishing feeds", "Shodan / Censys", "VirusTotal",
                         "Cert. Transparency", "Vendor reports", "KZ-CERT"],
    }
    fig, ax = plt.subplots(figsize=(13, 7))
    ax.set_xlim(0, 13); ax.set_ylim(0, 7.4); ax.axis("off")
    box(ax, 6.5, 6.8, 5.4, 0.6, "Phishing threats against Kazakhstan users", "#1a202c", fs=12)
    xs = [1.7, 4.9, 8.1, 11.3]
    for (name, leaves), x, c in zip(branches.items(), xs, COLORS):
        ax.annotate("", xy=(x, 5.95), xytext=(6.5, 6.5),
                    arrowprops=dict(arrowstyle="-|>", color="#4a5568", lw=1.2))
        box(ax, x, 5.7, 2.8, 0.5, name, c, fs=11)
        for i, leaf in enumerate(leaves):
            y = 4.9 - i * 0.62
            ax.plot([x - 1.25, x - 1.25], [5.45, y], color=c, lw=1)
            ax.plot([x - 1.25, x - 1.05], [y, y], color=c, lw=1)
            box(ax, x + 0.2, y, 2.45, 0.46, leaf, "#edf2f7", fs=9, tc="#1a202c")
    fig.tight_layout()
    fig.savefig(OUT / "threat_taxonomy.png", dpi=160)
    plt.close(fig)


def lifecycle():
    stages = [
        ("1. Direction", "PIR: which KZ brands\nare impersonated?", "Week 1"),
        ("2. Collection", "Feeds, Shodan,\nVirusTotal, Maltego", "Week 2"),
        ("3. Processing", "Normalize, dedup,\nimport into MISP", "Week 3"),
        ("4. Analysis", "Correlation, clusters,\nKill Chain / ATT&CK", "Weeks 4–6"),
        ("5. Dissemination", "MISP event, Sigma,\nblocklists (TLP)", "Weeks 7+"),
        ("6. Feedback", "Did the IOCs help?\nRefine PIR", "continuous"),
    ]
    fig, ax = plt.subplots(figsize=(8, 8))
    ax.set_xlim(-5, 5); ax.set_ylim(-5, 5); ax.axis("off"); ax.set_aspect("equal")
    ax.text(0, 0.2, "CTI\nLifecycle", ha="center", va="center", fontsize=18, weight="bold", color="#1a202c")
    ax.text(0, -0.8, "project: phishing-threat-hunting-kz", ha="center", fontsize=8, color="#4a5568")
    n = len(stages); r = 3.3
    pts = []
    for i, (t, d, wk) in enumerate(stages):
        a = math.pi / 2 - i * 2 * math.pi / n
        x, y = r * math.cos(a), r * math.sin(a)
        pts.append((x, y))
        done = i < 3
        c = "#2b6cb0" if done else "#a0aec0"
        box(ax, x, y, 2.6, 1.35, "", c)
        ax.text(x, y + 0.35, t, ha="center", va="center", fontsize=10.5, color="white", weight="bold")
        ax.text(x, y - 0.15, d, ha="center", va="center", fontsize=8, color="white")
        ax.text(x, y - 0.55, wk, ha="center", va="center", fontsize=7.5, color="#fefcbf" if done else "white", style="italic")
    for i in range(n):
        (x1, y1), (x2, y2) = pts[i], pts[(i + 1) % n]
        ax.add_patch(FancyArrowPatch((x1 * 0.78 + x2 * 0.22, y1 * 0.78 + y2 * 0.22),
                                     (x1 * 0.22 + x2 * 0.78, y1 * 0.22 + y2 * 0.78),
                                     connectionstyle="arc3,rad=-0.25", arrowstyle="-|>",
                                     mutation_scale=16, color="#4a5568", lw=1.4))
    fig.tight_layout()
    fig.savefig(OUT / "intel_lifecycle.png", dpi=160)
    plt.close(fig)


if __name__ == "__main__":
    taxonomy()
    lifecycle()
    print("saved to", OUT)
