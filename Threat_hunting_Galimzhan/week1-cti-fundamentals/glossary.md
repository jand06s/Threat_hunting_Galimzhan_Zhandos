# Week 1: CTI Glossary

These are the key Cyber Threat Intelligence terms we use throughout the project. Each one has a short definition and an example from our topic, **phishing campaigns aimed at Kazakhstan users and brands** (Kaspi, eGov, Halyk, OLX.kz, Kazpost and others).

## 1. Core concepts

| # | Term | Definition | Example in our topic |
|---|------|------------|---------------------|
| 1 | **Cyber Threat Intelligence (CTI)** | Evidence-based knowledge about existing or emerging threats (context, mechanisms, indicators, implications) that helps defenders make decisions. | Knowing that a group mass-registers `kaspi-*` lookalike domains on cheap TLDs and hosts them on free platforms. |
| 2 | **Threat** | Any circumstance or actor with the potential to harm an asset. | A phishing kit that steals Kaspi login + SMS code. |
| 3 | **Vulnerability** | A weakness that a threat can exploit. | Users trusting any page that shows the Kaspi logo. |
| 4 | **Risk** | Threat × vulnerability × impact. | High: stolen banking creds give direct financial loss. |
| 5 | **Threat actor** | Person or group behind malicious activity. | "Classiscam"-style scam teams working through Telegram bots. |
| 6 | **Intent / Capability / Opportunity** | The three conditions that make an actor a real threat. | Intent: money. Capability: ready-made phishing kit. Opportunity: OLX.kz sellers waiting for a buyer. |
| 7 | **Attack surface** | All points where an attacker can interact with the target. | Brand name, public domains, SMS sender IDs, social media pages. |

## 2. Types of intelligence

| # | Term | Definition | Example |
|---|------|------------|---------|
| 8 | **Strategic intelligence** | High-level trends for executives: who, why, and business impact. | "ENISA's Threat Landscape lists phishing among the most common initial access vectors in the EU." |
| 9 | **Operational intelligence** | Information about specific campaigns and how they run. | A campaign sending "your parcel is on hold, pay 350 ₸" SMS on behalf of Kazpost. |
| 10 | **Tactical intelligence** | TTPs: how attackers operate. | Use of URL shorteners + Cloudflare to hide the real phishing host. |
| 11 | **Technical intelligence** | Machine-readable indicators with a short lifetime. | `kaspibank.auth-telegramm.ru` |

## 3. Indicators and TTPs

| # | Term | Definition | Example |
|---|------|------------|---------|
| 12 | **IOC (Indicator of Compromise)** | An observable artifact that indicates malicious activity. | Domain, URL, IP, file hash, email sender. |
| 13 | **IOA (Indicator of Attack)** | An indicator of attacker behaviour, independent of specific artifacts. | A newly registered domain containing a bank brand + "login"/"verify". |
| 14 | **TTP (Tactics, Techniques, Procedures)** | Describes attacker behaviour at three levels of detail. | Tactic: Initial Access → Technique: T1566 Phishing → Procedure: SMS with a link to a fake Kaspi page. |
| 15 | **Pyramid of Pain** | A model (David Bianco) that ranks indicators by how costly they are for the attacker to change: hashes < IPs < domains < artifacts < tools < TTPs. | Blocking one domain costs the attacker ~$1; detecting the kit's HTML structure costs much more. |
| 16 | **Observable** | Any measurable event or property; it becomes an IOC once it's linked to malicious activity. | A DNS query to `egov-kz.site`. |
| 17 | **Typosquatting / lookalike domain** | A domain that imitates a legitimate one through typos, homoglyphs or extra words. | `kaspii.kz`, `egov-kz.online`, `halyk-bank.top` |
| 18 | **Defanging** | Making an IOC unclickable for safe sharing. | `hxxps://kaspi-bonus[.]top` |

## 4. Process and frameworks

| # | Term | Definition | Example |
|---|------|------------|---------|
| 19 | **Intelligence lifecycle** | Direction → Collection → Processing → Analysis → Dissemination → Feedback. | Weeks 1–3 of this project follow the first three stages. |
| 20 | **PIR (Priority Intelligence Requirement)** | A key question that intelligence must answer. | "Which KZ brands are impersonated in active phishing right now, and on what infrastructure?" |
| 21 | **OSINT** | Intelligence from publicly available sources. | Phishing.Database, crt.sh, Shodan, VirusTotal. |
| 22 | **Threat feed** | A continuously updated stream of indicators. | Phishing.Database `phishing-domains-ACTIVE.txt` |
| 23 | **Enrichment** | Adding context to a raw indicator. | Domain → registrar, IP, ASN, country, VT detections. |
| 24 | **Correlation** | Linking indicators that share attributes. | 10 phishing domains on the same IP → one campaign. |
| 25 | **TLP (Traffic Light Protocol)** | Sharing labels: TLP:RED, AMBER(+STRICT), GREEN, CLEAR. | Our public report is TLP:CLEAR, raw victim data would be TLP:RED. |
| 26 | **STIX / TAXII** | STIX is a JSON format for CTI objects. TAXII is the transport protocol used to share them. | Exporting our MISP event as STIX 2.1. |
| 27 | **MISP** | Open-source threat intelligence platform for storing, correlating and sharing IOCs. | Week 3: we import our phishing IOCs into MISP. |
| 28 | **MITRE ATT&CK** | A knowledge base of adversary tactics and techniques. | T1566.002 Spearphishing Link, T1583.001 Acquire Infrastructure: Domains. |
| 29 | **Cyber Kill Chain** | Lockheed Martin's 7-stage attack model. | Recon → Weaponization (kit) → Delivery (SMS) → … |
| 30 | **Diamond Model** | Describes an intrusion as Adversary – Capability – Infrastructure – Victim. | Scam team – phishing kit – `*.top` domains – Kaspi users. |
| 31 | **False positive** | A benign item flagged as malicious. | `kaspi.kz` itself or `krishna-*.github.io` matched by a naive "krisha" filter. |
| 32 | **Confidence level** | How sure the analyst is about an assessment (low / medium / high). | High: domain found in 2+ feeds and has a VT detection. |
| 33 | **Phishing kit** | A packaged set of HTML/PHP files used to deploy phishing pages quickly. | A kit cloning the Kaspi login page with Telegram exfiltration. |
| 34 | **Phishing-as-a-Service (PhaaS)** | Criminal service that rents kits, hosting and panels to operators. | Telegram bots that generate fake "OLX delivery" pages on demand. |
| 35 | **Smishing / Vishing / Quishing** | Phishing via SMS / voice calls / QR codes. | Call from a "Kaspi security officer" asking for the SMS code. |

## References

- Recorded Future, *The Threat Intelligence Handbook*
- ENISA, *Threat Landscape* reports: https://www.enisa.europa.eu/topics/cyber-threats/threat-landscape
- MITRE ATT&CK: https://attack.mitre.org
- D. Bianco, *The Pyramid of Pain*
- FIRST, *TLP 2.0*: https://www.first.org/tlp/
