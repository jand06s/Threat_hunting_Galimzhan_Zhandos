# Week 1: Cyber Threat Intelligence Fundamentals

**Project topic:** Phishing campaigns targeting Kazakhstan users and brands
**Syllabus tasks (3.3, Week 1):**
1. Create a glossary of key CTI terms. See [`glossary.md`](glossary.md)
2. Classify different types of threats and their sources. See [`threat-classification.md`](threat-classification.md)

Recommended reading: ENISA Threat Landscape Report.

---

## 1. Why this topic

Phishing is one of the most common initial access vectors in threat landscape reports (ENISA, vendor reports). In Kazakhstan, almost every adult uses a few large digital services: Kaspi.kz, eGov.kz, Halyk Homebank and OLX.kz. That makes their brands an attractive lure: one fake page template reaches millions of potential victims.

## 2. Priority Intelligence Requirement (PIR)

> **PIR-1:** Which Kazakhstan brands are impersonated in *currently active* phishing infrastructure?
> **PIR-2:** Where is that infrastructure hosted (TLDs, hosting platforms, IPs/ASNs)?
> **PIR-3:** Which indicators can we safely share with defenders (MISP, blocklists, detection rules)?

## 3. Results

### 3.1 Glossary
35 terms in 4 groups (core concepts, intelligence types, indicators/TTPs, process/frameworks). Each term has an example from our topic. See [`glossary.md`](glossary.md).

### 3.2 Threat classification
We classified the threats along four dimensions:

![Threat taxonomy](images/threat_taxonomy.png)

- **Delivery vector:** email, SMS, messengers, marketplace scams, voice, QR, malvertising
- **Target / goal:** banking creds + OTP, eGov/IIN/ЭЦП, card data, telecom accounts, crypto
- **Threat source (actor):** PhaaS operators, individual scammers, call-centre groups, APT, hacktivists, insiders
- **Intelligence source:** open feeds, infrastructure search engines, reputation services, CT logs, vendor reports, KZ-CERT

The full tables with ATT&CK technique IDs are in [`threat-classification.md`](threat-classification.md).

### 3.3 Where we are in the intelligence lifecycle

![Lifecycle](images/intel_lifecycle.png)

## 4. Key takeaways

1. The main threat source for our topic is **financially motivated cybercriminals using PhaaS kits**, not APT groups.
2. Phishing domains are at the **low end of the Pyramid of Pain**: cheap to replace, so blocking alone is not enough. We need to track *patterns* (brand keywords, hosting choices).
3. Open sources (feeds, CT logs, Shodan, VirusTotal) are enough to answer our PIR, and Week 2 starts collecting from them.

## 5. How to reproduce the images

```bash
pip install matplotlib
python3 make_diagrams.py
```
