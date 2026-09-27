# Phishing Threat Hunting: Kazakhstan

**Course:** Introduction to Threat Hunting (ITH), AITU, 2026–2027
**Project topic:** Phishing campaigns targeting Kazakhstan users and brands (Kaspi, eGov, Halyk, OLX.kz, Kazpost…)
**Author:** Galimzhan Zhandos, CS-2427 (individual project)

This repository has my weekly increments. Each week follows section 3.3 of the syllabus and is committed separately.

| Week | Syllabus topic | Deliverables | Status |
|------|----------------|--------------|--------|
| 1 | CTI Fundamentals | [Glossary (35 terms)](week1-cti-fundamentals/glossary.md) · [Threat & source classification](week1-cti-fundamentals/threat-classification.md) · [Report](week1-cti-fundamentals/README.md) | ✅ |
| 2 | Data Collection | [Report](week2-data-collection/README.md) · [Data source mapping](week2-data-collection/data-source-mapping.md) · [scripts](week2-data-collection/scripts) (feeds, dnstwist, Shodan, VirusTotal) · [Maltego](week2-data-collection/maltego) | ✅ (screenshots TODO) |
| 3 | Data Processing & Exploitation | [Report](week3-data-processing/README.md) · [normalize.py](week3-data-processing/scripts/normalize.py) · [MISP event](week3-data-processing/data/misp_event.json) · [MISP deploy](week3-data-processing/misp/DEPLOY.md) · [Sigma](week3-data-processing/sigma) | ✅ (screenshots TODO) |
| 4 | Cyber Kill Chain | | ⏳ |
| 5 | Threat Hunting Concept | | ⏳ |
| 6–10 | ATT&CK, CAR, emulation, Atomic Red Team, APT | | ⏳ |

## Key results so far

- **806,622** phishing hosts from an open feed → **204** KZ-related → **195** after normalization
- Only **6** real KZ-brand impersonations are in global feeds (Kaspi ×2, Halyk, OLX.kz, Kazpost, 1 generic), so local sources are needed
- The `.kz` zone is mostly used as **infrastructure** for foreign campaigns (Apple ID, OpenSea, Brazilian banks), on compromised CMS sites and free platforms (jcloud.kz, mylp.kz)
- Correlation by kit URL path found **one operator behind 5 Apple lookalike domains** in `.com.kz`
- IOCs packaged as a **MISP event** (312 attributes, ATT&CK-tagged) and two **Sigma rules** converted to Elastic queries

## Repository layout

```
week1-cti-fundamentals/   glossary, classification, diagrams
week2-data-collection/    collection scripts, data/, images/, maltego/
week3-data-processing/    normalize + MISP scripts, misp/, sigma/, data/, images/
presentation/             defense notes (7–8 min)
reports/                  Report_Weeks1-3_EN.docx
```

## Quick start

```bash
pip install pandas matplotlib networkx dnstwist pymisp shodan mmh3 requests
python3 week2-data-collection/scripts/collect_feeds.py
python3 week2-data-collection/scripts/lookalike_check.py
python3 week2-data-collection/scripts/make_charts.py
python3 week3-data-processing/scripts/normalize.py
python3 week3-data-processing/scripts/misp_import.py
```

## Ethics

Passive OSINT only. No interaction with phishing pages. Indicators are defanged in the reports, victim emails are redacted. TLP:CLEAR.

## AI use disclosure

Parts of this repository (script drafts, document structure) were prepared with the help of an AI assistant (Claude, Anthropic), in line with the course policy on generative AI. All results were reviewed and run by the author.
