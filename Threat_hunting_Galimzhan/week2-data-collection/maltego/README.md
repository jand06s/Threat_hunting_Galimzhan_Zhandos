# Maltego steps

1. Install **Maltego** and log in with a free **Community (CE)** account.
2. New Graph → **Import → Import Graph from Table** → select `maltego_import.csv`.
3. Map the columns:
   - `Domain` → entity **maltego.Domain**
   - `Hosting` → entity **maltego.Phrase** (link Domain → Hosting)
   - `Target` → entity **maltego.Phrase** (link Domain → Target)
4. Select all Domain entities → run transforms:
   - **To DNS Name – A (IP Address)** → **To Netblock / AS** (shared hosting)
   - **To DNS Name – NS** (shared name servers link campaigns)
   - **To WHOIS info** (registrar, creation date)
5. Layout → **Organic**. Save as `kz_phishing.mtgl` and export a screenshot to `../images/maltego_graph.png`.

What to look for: several domains resolving to **one IP/AS or one NS** = one operator (campaign cluster).

The link graph in `../images/link_graph.png` is a Python (networkx) preview of the same data, made before the Maltego transforms.
