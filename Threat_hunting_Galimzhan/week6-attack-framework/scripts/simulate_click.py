#!/usr/bin/env python3
"""
Week 6 (ATT&CK Framework) — SAFE simulation of one T1566.002 (Spearphishing Link) attack.

This does NOT build or send anything real. It only EMITS the telemetry (log lines) that
a SIEM would see when a victim clicks a KZ-brand phishing link, and tags each event with
the ATT&CK technique it evidences. That is the "simulate an attack and map results to
ATT&CK" task done as a purple-team paper exercise — no phishing page, no network traffic.

Output:
  data/attack_timeline.csv   ordered events, each mapped to an ATT&CK technique + data source
  data/attack_timeline.json  same, machine-readable
  navigator/t1566_layer.json ATT&CK Navigator layer of the techniques exercised

Usage: python3 simulate_click.py
"""
import csv
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
(BASE / "data").mkdir(exist_ok=True)
(BASE / "navigator").mkdir(exist_ok=True)

# The modelled scenario: user07 receives an SMS with a link to a fake OLX delivery page
# (the olxkz[.]pay-sacure4ds[.]ru indicator from Week 2) and submits card data.
# Each step is what a defender OBSERVES, not an instruction to do anything.
TIMELINE = [
    {"t": "T+0:00", "observed": "SMS/Telegram message with a shortened link delivered to the user",
     "data_source": "Application Log (messaging)", "technique": "T1566.002",
     "tactic": "TA0001 Initial Access", "name": "Phishing: Spearphishing Link"},
    {"t": "T+0:05", "observed": "DNS query for olxkz.pay-sacure4ds.ru from the user's host",
     "data_source": "Network Traffic: DNS", "technique": "T1566.002",
     "tactic": "TA0001 Initial Access", "name": "Phishing: Spearphishing Link"},
    {"t": "T+0:06", "observed": "User clicks the link; browser issues HTTP GET to the phishing host",
     "data_source": "Network Traffic: Web (proxy)", "technique": "T1204.001",
     "tactic": "TA0002 Execution", "name": "User Execution: Malicious Link"},
    {"t": "T+0:30", "observed": "Fake 3-D Secure form shown; user types card number + CVV + SMS code",
     "data_source": "Network Traffic: Web (proxy)", "technique": "T1598.003",
     "tactic": "TA0043 Reconnaissance", "name": "Phishing for Information: Spearphishing Link"},
    {"t": "T+0:31", "observed": "HTTP POST with form body to the phishing host (credentials leave the org)",
     "data_source": "Network Traffic: Web (proxy)", "technique": "T1056.003",
     "tactic": "TA0006 Credential Access", "name": "Input Capture: Web Portal Capture"},
    {"t": "T+0:32", "observed": "Phishing panel pushes the stolen data to the operator (Telegram bot)",
     "data_source": "Threat Intel (adversary-side)", "technique": "T1102",
     "tactic": "TA0011 Command and Control", "name": "Web Service"},
    {"t": "T+2:00", "observed": "Card charged / money withdrawn using the stolen details",
     "data_source": "Bank anti-fraud log", "technique": "T1657",
     "tactic": "TA0040 Impact", "name": "Financial Theft"},
]


def main():
    with (BASE / "data" / "attack_timeline.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["t", "observed", "data_source", "technique", "tactic", "name"])
        w.writeheader(); w.writerows(TIMELINE)
    (BASE / "data" / "attack_timeline.json").write_text(json.dumps(TIMELINE, indent=2))

    techs = {}
    for e in TIMELINE:
        techs[e["technique"]] = techs.get(e["technique"], 0) + 1
    layer = {
        "name": "T1566.002 spearphishing-link attack path (Week 6)",
        "versions": {"attack": "16", "navigator": "4.9.5", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Techniques observed when one user clicks a KZ-brand phishing link and submits card data.",
        "techniques": [{"techniqueID": t, "score": c, "enabled": True,
                        "comment": "observed in the Week 6 simulation"} for t, c in techs.items()],
        "gradient": {"colors": ["#ffe0b2", "#c05621"], "minValue": 1, "maxValue": 2},
        "showTacticRowBackground": True, "tacticRowBackground": "#2b6cb0", "sorting": 3,
    }
    (BASE / "navigator" / "t1566_layer.json").write_text(json.dumps(layer, indent=2))
    print(f"[+] {len(TIMELINE)} events, {len(techs)} techniques -> data/ and navigator/")
    for e in TIMELINE:
        print(f"    {e['t']:7} {e['technique']:11} {e['name']}")


if __name__ == "__main__":
    main()
