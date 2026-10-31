# Adversary Emulation Plan — Classiscam-style phishing operator

**Scope:** a simple plan from initial access to exfiltration for my project's threat.
**Purpose:** purple-team — verify that each step is covered by a detection I built in Weeks 3–7.
**Safety:** this is a plan and a detection test. The CALDERA abilities in `caldera/` are inert
(each only `echo`es a marker line). No real phishing, credential theft or exfiltration is performed.

| # | Phase | Step | ATT&CK | Procedure (descriptive) | My detection | Data source |
|---|-------|------|--------|-------------------------|--------------|-------------|
| 1 | Initial Access | Send KZ-brand lure link via SMS/Telegram | `T1566.002` | Operator poses as an OLX buyer, moves the victim to a messenger, sends a link to a lookalike domain | Sigma dns_kz_brand_lookalike (W3) + hunt H1 (W5) | Network: DNS |
| 2 | Initial Access | Deliver malicious document variant | `T1566.001` | Alternative lure: an attachment that, when opened, spawns a shell | CAR-2013-02-003 (W7) | Process create |
| 3 | Execution | Victim opens link / document | `T1204` | User clicks the link or opens the attachment | Hunt H2 POST-to-rare-host (W5); CAR-2013-02-003 (W7) | Network: Web / Process |
| 4 | Credential Access | Harvest card data / Apple ID on the fake page | `T1056.003` | Fake 3-D Secure or Apple-ID form captures the data the victim types | Hunt H2 (W5) on the POST to the phishing host | Network: Web |
| 5 | Persistence | Reuse stolen valid account | `T1078` | Operator logs in to the victim's bank / Apple ID with the stolen credentials | Bank new-device alert (out of my scope); MISP IOC on the login host | Auth log |
| 6 | Command & Control | Exfil channel via Telegram bot/panel | `T1102` | The phishing panel forwards every captured record to the operator in real time | Threat intel on bot names in MISP (W3) | Threat intel |
| 7 | Exfiltration | Send stolen data out over the web service | `T1567` | Captured card/credential records leave over HTTPS to the operator's service | Proxy egress to a rare/new host (hunt H2, W5) | Network: Web |
| 8 | Impact | Cash out the stolen funds / unlock phone | `T1657` | Money withdrawn, or the stolen Apple ID removes the device's Activation Lock | Bank anti-fraud (out of scope); law enforcement (Operation Kaerb) | Bank log |

## Coverage summary

- **6 of 8 steps** have a detection I built myself.
- Gaps (by design, not my layer): the **bank** side — new-device login (T1078) and cash-out (T1657).
- Everything the organisation's network/endpoint can see is covered by my Sigma rule (W3),
  my hunts (W5) and the CAR analytics (W7).

## How to run the inert emulation (detection test)

```bash
# each ability only drops a marker log line; point your SIEM at the host and confirm the
# matching detection fires. Nothing malicious runs.
for a in caldera/*.yml; do echo "[would import to CALDERA] $a"; done
```
