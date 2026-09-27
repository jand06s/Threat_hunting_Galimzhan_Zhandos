# Defense: Weeks 1–3 (7–8 minutes, one speaker)

Show the GitHub repo (or the DOCX report) and go in this order. Timing is cumulative.

| Time | What to show | What to say |
|------|--------------|-------------|
| 0:00–0:40 | Root `README.md`, `git log` | Topic: phishing against KZ users. PIR: *which KZ brands are impersonated, where is it hosted, what can I share?* Each week is a separate commit. |
| 0:40–2:00 | `threat_taxonomy.png`, glossary | 35 terms with examples from the topic. Four classification axes: vector, target, actor, intel source. Main actor = financially motivated PhaaS operators (Classiscam lists Kazakhstan as a target), not APTs. Pyramid of Pain: domains are cheap, so I look for patterns. |
| 2:00–2:20 | `intel_lifecycle.png` | Weeks 1–3 = lifecycle stages 1–3. |
| 2:20–4:30 | Week 2: funnel, impersonated, hosting, link graph | 806k feed hosts → 204 KZ-related → 6 real KZ-brand hits. Examples: `kaspibank.auth-telegramm.ru`, `olxkz.pay-sacure4ds.ru` (fake 3-D Secure). dnstwist: 20k lookalikes, 0 in the feed, so attackers use *keywords on foreign TLDs*, not typos in `.kz`. The `.kz` zone hosts foreign phishing (jcloud.kz, hacked WordPress). Shodan: favicon hash / title queries. VirusTotal: detections + creation date. Data source mapping with the Admiralty code. |
| 4:30–6:50 | Week 3: pipeline, clusters, MISP, Sigma | Refang → normalize → dedup → allowlist → correlate → score. 2 false-positive types. Kit signature: **5 Apple domains = 1 operator**. MISP: 312 attributes, TLP + ATT&CK tags, `to_ids` only for medium+. **Demo:** MISP event (or screenshot). Sigma → Lucene, tested: 5/6 detected, 0 FP, evasion gap fixed in v3. |
| 6:50–7:30 | Conclusions | Global feeds miss local brands. `.kz` = infrastructure for foreign campaigns. Next: Week 4, the Kill Chain. |

the READMEs (📸 TODO) and the DOCX (yellow boxes)
- [ ] Rehearse once with a timer (≤ 7:30)
