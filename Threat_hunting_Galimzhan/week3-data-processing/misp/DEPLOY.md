# Deploying MISP (Docker)

We use the official **MISP/misp-docker** project (images: `misp-core`, `misp-modules`, MariaDB, Redis).

Requirements: Docker + Docker Compose, ~4 GB RAM, ~10 GB disk. Works on Linux, macOS, or Windows with WSL2.

```bash
git clone https://github.com/MISP/misp-docker.git
cd misp-docker
cp template.env .env
```

Edit `.env` (at least these values):

```ini
BASE_URL=https://localhost
ADMIN_EMAIL=admin@admin.test
ADMIN_PASSWORD=<strong password>
ADMIN_ORG=AITU-ThreatHunting
# variable names can change between versions: check template.env
```

Start it:

```bash
docker compose pull
docker compose up -d
docker compose logs -f misp-core     # wait until the logs stop showing setup steps (first start takes 5–10 min)
```

Open **https://localhost** (accept the self-signed certificate) and log in with `ADMIN_EMAIL` / `ADMIN_PASSWORD`.

## Import our IOCs

**Option A: UI (no API key):**
Top menu **Event Actions → Import from…** → choose **MISP JSON** → upload `../data/misp_event.json`.

**Option B: API (PyMISP):**
1. Administration → List Auth Keys → **Add authentication key** → copy it.
2. Run:
```bash
cd ../scripts
export MISP_URL=https://localhost MISP_KEY=<key>
python3 misp_import.py --push
```

**Option C: free-text import (quick demo):**
Event Actions → **Add Event** (create an empty event) → on the event page: **Populate from… → Freetext Import** → paste `../data/blocklist_domains.txt`.

## Screenshots for the report (save to `../images/`)

1. `misp_login.png`: dashboard after login (proves the deployment)
2. `misp_event.png`: the imported event with tags (tlp:clear, ATT&CK)
3. `misp_attributes.png`: attribute list, filtered by `cluster:C01-kit`
4. `misp_correlation.png`: correlation graph (Event → **View correlation graph**)
5. `misp_feeds.png`: Sync Actions → Feeds, with a default feed (CIRCL OSINT) enabled + fetched, so our IOCs correlate with community data

## Useful MISP features to show in the defense

- **Warninglists:** enable them (Input Filters → Warninglists). MISP then flags legitimate domains, the same idea as our allowlist.
- **Taxonomies:** enable `tlp`, `phishing`, `osint`, `workflow` (Event Actions → List Taxonomies).
- **Export:** Event → Download as… → STIX 2.1 / CSV / Suricata rules.
