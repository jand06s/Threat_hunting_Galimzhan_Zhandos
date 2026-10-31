#!/usr/bin/env python3
"""
Week 8 — build the adversary emulation plan artifacts from the plan defined below.

The plan describes, at a PURPLE-TEAM / detection level, how a Classiscam-style phishing
operator moves initial access -> persistence -> exfiltration, each step tied to ATT&CK and
to a detection I already own (Weeks 3/5/7). It is a PLAN and a DETECTION TEST, not attack code.

The CALDERA abilities emitted are deliberately INERT: each executor only runs `echo` to drop a
marker log line so a defender can test that the detection fires. No step performs a real action.

Outputs:
  emulation-plan.md            the plan as a readable table
  caldera/<id>.yml             one inert CALDERA ability per step
  navigator/emulation_layer.json
  images/emulation_plan.png
Usage: python3 scripts_build.py
"""
import json
import uuid
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

BASE = Path(__file__).resolve().parent.parent
for d in ("caldera", "navigator", "images"):
    (BASE / d).mkdir(exist_ok=True)

# phase, step, technique, procedure (descriptive), detection I own, data source
PLAN = [
    ("Initial Access", "Send KZ-brand lure link via SMS/Telegram", "T1566.002",
     "Operator poses as an OLX buyer, moves the victim to a messenger, sends a link to a lookalike domain",
     "Sigma dns_kz_brand_lookalike (W3) + hunt H1 (W5)", "Network: DNS"),
    ("Initial Access", "Deliver malicious document variant", "T1566.001",
     "Alternative lure: an attachment that, when opened, spawns a shell",
     "CAR-2013-02-003 (W7)", "Process create"),
    ("Execution", "Victim opens link / document", "T1204",
     "User clicks the link or opens the attachment",
     "Hunt H2 POST-to-rare-host (W5); CAR-2013-02-003 (W7)", "Network: Web / Process"),
    ("Credential Access", "Harvest card data / Apple ID on the fake page", "T1056.003",
     "Fake 3-D Secure or Apple-ID form captures the data the victim types",
     "Hunt H2 (W5) on the POST to the phishing host", "Network: Web"),
    ("Persistence", "Reuse stolen valid account", "T1078",
     "Operator logs in to the victim's bank / Apple ID with the stolen credentials",
     "Bank new-device alert (out of my scope); MISP IOC on the login host", "Auth log"),
    ("Command & Control", "Exfil channel via Telegram bot/panel", "T1102",
     "The phishing panel forwards every captured record to the operator in real time",
     "Threat intel on bot names in MISP (W3)", "Threat intel"),
    ("Exfiltration", "Send stolen data out over the web service", "T1567",
     "Captured card/credential records leave over HTTPS to the operator's service",
     "Proxy egress to a rare/new host (hunt H2, W5)", "Network: Web"),
    ("Impact", "Cash out the stolen funds / unlock phone", "T1657",
     "Money withdrawn, or the stolen Apple ID removes the device's Activation Lock",
     "Bank anti-fraud (out of scope); law enforcement (Operation Kaerb)", "Bank log"),
]

# 1. emulation-plan.md
lines = ["# Adversary Emulation Plan — Classiscam-style phishing operator",
         "",
         "**Scope:** a simple plan from initial access to exfiltration for my project's threat.",
         "**Purpose:** purple-team — verify that each step is covered by a detection I built in Weeks 3–7.",
         "**Safety:** this is a plan and a detection test. The CALDERA abilities in `caldera/` are inert",
         "(each only `echo`es a marker line). No real phishing, credential theft or exfiltration is performed.",
         "",
         "| # | Phase | Step | ATT&CK | Procedure (descriptive) | My detection | Data source |",
         "|---|-------|------|--------|-------------------------|--------------|-------------|"]
for i, (phase, step, tech, proc, det, ds) in enumerate(PLAN, 1):
    lines.append(f"| {i} | {phase} | {step} | `{tech}` | {proc} | {det} | {ds} |")
lines += ["", "## Coverage summary", "",
          f"- **{sum(1 for p in PLAN if 'scope' not in p[4].lower())} of {len(PLAN)} steps** have a detection I built myself.",
          "- Gaps (by design, not my layer): the **bank** side — new-device login (T1078) and cash-out (T1657).",
          "- Everything the organisation's network/endpoint can see is covered by my Sigma rule (W3),",
          "  my hunts (W5) and the CAR analytics (W7).",
          "",
          "## How to run the inert emulation (detection test)", "",
          "```bash",
          "# each ability only drops a marker log line; point your SIEM at the host and confirm the",
          "# matching detection fires. Nothing malicious runs.",
          "for a in caldera/*.yml; do echo \"[would import to CALDERA] $a\"; done",
          "```"]
(BASE / "emulation-plan.md").write_text("\n".join(lines) + "\n")

# 2. inert CALDERA abilities
for i, (phase, step, tech, proc, det, ds) in enumerate(PLAN, 1):
    marker = f"[emulation] step {i} {tech} {step}"
    ability = {
        "id": str(uuid.uuid5(uuid.NAMESPACE_DNS, f"phish-emu-{i}")),
        "name": f"{i:02d} {step}",
        "description": f"INERT purple-team marker for {tech} ({phase}). Procedure: {proc}. "
                       f"Detection: {det}. This ability performs no real action; it only logs a marker.",
        "tactic": phase.lower().replace(" ", "-"),
        "technique": {"attack_id": tech, "name": step},
        "platforms": {
            "linux": {"sh": {"command": f"echo '{marker}'"}},
            "windows": {"psh": {"command": f"Write-Output '{marker}'"}},
        },
    }
    (BASE / "caldera" / f"{i:02d}_{tech.replace('.', '_')}.yml").write_text(
        "# INERT emulation ability (echo only) — safe detection test, not attack code.\n"
        + json.dumps([ability], indent=2))

# 3. navigator layer
techs = {}
for _, _, tech, *_ in PLAN:
    techs[tech] = techs.get(tech, 0) + 1
layer = {"name": "Phishing emulation plan (Week 8)", "versions": {"attack": "16", "navigator": "4.9.5", "layer": "4.5"},
         "domain": "enterprise-attack",
         "description": "Techniques in the initial-access -> persistence -> exfiltration emulation plan.",
         "techniques": [{"techniqueID": t, "score": c, "enabled": True} for t, c in techs.items()],
         "gradient": {"colors": ["#ffe0b2", "#c05621"], "minValue": 1, "maxValue": 2},
         "showTacticRowBackground": True, "tacticRowBackground": "#2b6cb0", "sorting": 3}
(BASE / "navigator" / "emulation_layer.json").write_text(json.dumps(layer, indent=2))

# 4. diagram
PHASE_COLOR = {"Initial Access": "#2b6cb0", "Execution": "#3182ce", "Credential Access": "#c05621",
               "Persistence": "#805ad5", "Command & Control": "#6b46c1", "Exfiltration": "#dd6b20",
               "Impact": "#c53030"}
fig, ax = plt.subplots(figsize=(12, 7.6)); ax.set_xlim(0, 12); ax.set_ylim(0, 7.6); ax.axis("off")
ax.set_title("Adversary emulation plan — phishing operator (initial access → exfiltration)",
             loc="left", weight="bold", fontsize=12)
for i, (phase, step, tech, proc, det, ds) in enumerate(PLAN):
    y = 6.8 - i * 0.85
    col = PHASE_COLOR.get(phase, "#718096")
    ax.add_patch(FancyBboxPatch((0.2, y - 0.32), 2.5, 0.64, boxstyle="round,pad=0.02,rounding_size=0.08", fc=col, ec="none"))
    ax.text(1.45, y + 0.08, phase, ha="center", va="center", color="white", fontsize=8.5, weight="bold")
    ax.text(1.45, y - 0.16, tech, ha="center", va="center", color="white", fontsize=8, family="monospace")
    ax.text(2.95, y + 0.08, step, va="center", fontsize=9, color="#1a202c")
    ax.text(2.95, y - 0.18, f"detection: {det}", va="center", fontsize=7.4, color="#2f855a", style="italic")
    if i < len(PLAN) - 1:
        ax.annotate("", xy=(1.45, y - 0.53), xytext=(1.45, y - 0.32), arrowprops=dict(arrowstyle="-|>", color="#a0aec0", lw=1.2))
fig.tight_layout(); fig.savefig(BASE / "images" / "emulation_plan.png", dpi=150); plt.close(fig)

print(f"[+] plan: {len(PLAN)} steps -> emulation-plan.md, {len(PLAN)} inert abilities, navigator layer, diagram")
