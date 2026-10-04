# Courses of Action matrix (Lockheed Martin)

What a defender (OLX.kz, a bank, KZ-CERT, a SOC) can do at each Kill Chain stage.
Empty cell = no realistic action at that stage.

| Stage | Detect | Deny | Disrupt | Degrade | Deceive | Destroy |
|---|---|---|---|---|---|---|
| **Reconnaissance** | Monitor CT logs / feeds for new brand-keyword domains | Hide seller phone numbers on OLX by default | – | – | Honeypot ads to attract scammers and collect their links | – |
| **Weaponization** | Sigma DNS rule dns_kz_brand_lookalike (Week 3); MISP event with kit clusters | Registrar checks for brand names in new domains | Takedown requests to registrar / hosting (KZ-CERT) | – | – | Report Telegram bots for removal |
| **Delivery** | Platform chat filter for 'pay/receive money' links and off-platform moves | Block known phishing domains (blocklist_domains.txt) in DNS / browsers | In-app warning when a link is sent in chat | – | – | – |
| **Exploitation** | Sigma proxy rule proxy_kz_phishing_kit_path (Week 3) | User awareness: to receive money a seller never needs to enter CVV or an SMS code | Safe Browsing / browser warnings | – | – | – |
| **Installation** | Bank / Apple: new device or new login location alert | Strong 2FA not based on SMS (push in bank app) | – | – | – | – |
| **Command & Control** | Threat intel on Telegram bot names (MISP) | – | Bot takedown by Telegram | – | Feed fake card data to the panel (canary cards) | – |
| **Actions on Objectives** | Bank anti-fraud: card-not-present payment right after a 3-DS code request | Card limits for online payments | Instant card block via bank app | Delay of large transfers to new recipients | – | Law-enforcement action (example: Operation Kaerb) |
