# Xaxglog — International Deep-Search OSINT Platform (no Docker)

State-grade OSINT intelligence platform. Unified build combining 4 open-source
upstreams + a native deep-search engine + an agency-grade investigation core
(cases, entity graph, chain-of-custody evidence, watchlists, reports).

| Module | Upstream | What we picked |
|---|---|---|
| `threat_intel` | `et842/OSINT_APP` | `collector.py` (URLhaus/AbuseIPDB/OTX/VT), `processor.py` (0-100 scoring), `database.py` schema, live-lookup + breach + AI-brief + Snort/YARA concepts |
| `forensics` | `campwill/osint-dashboard` | `web_tools.py` (URL/DNS/SSL/headers/cookies/ports/whois/links/emails/phones/screenshot), `file_tools.py` (EXIF), `pid_tools.py` (phone validation) |
| `runner` | `aenoshrajora/OSINTel-Dashboard` | Secure generic tool executor (`executor.py`), `default_tools.json` tool definitions, history + streaming model |
| `catalog` | `intelseclab/osintelligence` | 22 curated category markdown files under `catalog/tools/` |
| `deep_search` | Xaxglog-native | International username/email/phone/domain/IP/person/name/social profile/company/geo via free sources (no Docker, no keys required) |
| `recon` | Xaxglog-native | Chained deep-recon pipeline engine (dependency-aware fan-out, evidence capture, graph emission) |
| `trackers` | Xaxglog-native | Subject trackers: fingerprint+diff change watchers over DNS, WHOIS, ports, content, wallets, ALPR, breach/sanctions, LEI, news, Telegram (daemon + typed alerts) |
| `darkweb` | Xaxglog-native | Indexed dark-web search (Ahmia + optional IntelX) + breach-corpus lookups |
| `simswap` | Xaxglog-native | SIM-swap / number-port fraud **risk detection** (0-100 score, evidence trail) |
| `ss7` | Xaxglog-native | **Authorized** carrier SS7 lookup workflow (authority-gated build/submit/ingest, audited) |
| `attribution` | Xaxglog-native | AI-assisted actor tracing across handles/profiles (CERT-style correlation) |
| `cases` | Xaxglog-native | Case management + entity graph + chain-of-custody evidence store + full-text search (FTS5) |
| `watchlist` | Xaxglog-native | Scheduled sweeps + alerts on new findings (breaches / subdomains / handles) |
| `report` | Xaxglog-native | Intelligence report generator (printable HTML/PDF) + STIX 2.1 export |
| `geo` | Xaxglog-native | GEOINT: geocode, case map points, radius queries, GeoJSON/KML export |
| `vehicle` | Xaxglog-native | VIN decode + recalls (NHTSA), plate decode, **authority-gated** reverse-plate/registration, ALPR custody |
| `cctv` | Xaxglog-native | Camera-infrastructure mapper (exposure metadata only) + authorized feed custody |
| `iot` | Xaxglog-native | IoT device register + passive exposure re-scan + change detection + lawful-access hook |
| `corporate` | Xaxglog-native | Corporate ownership graph (Wikidata free / OpenCorporates with key, officer edges) |
| `crypto` | Xaxglog-native | Wallet tracing on public chains (BTC/ETH balance, txs, 1-hop fund-flow graph) |
| `screening` | Xaxglog-native | Sanctions/PEP watchlist screening (OFAC SDN + UN consolidated, fuzzy match) |
| `infra` | Xaxglog-native | Infrastructure attribution: PTR/ASN/hosting pivot + co-hosted domain discovery |

## Layout

```
Xaxglog/
  backend/
    app.py                 # unified Flask API (all modules, JWT auth + RBAC)
    auth.py                # JWT auth, roles (admin/analyst/viewer), decorators
    db.py                  # shared SQLite + FTS5 + chain-of-custody helpers
    config.py
    requirements.txt
    modules/threat_intel/  # collector, processor, database (+legacy_app.py ref)
    modules/forensics/     # web_tools, file_tools, pid_tools (+legacy ref)
    modules/runner/        # executor.py + default_tools.json (+legacy ref)
    modules/catalog/       # baseline json
    modules/deep_search/   # connectors.py — international search engine
                           # social.py — platform matrix, people indexes, profile scraper
    modules/recon/         # pipeline.py — chained recon engine
    modules/darkweb/       # darkweb.py — indexed dark-web + breach search
    modules/simswap/       # simswap.py — SIM-swap risk detection
    modules/ss7/           # ss7.py — authorized carrier SS7 workflow
    modules/attribution/   # profiler.py — AI actor tracing
    modules/cases/         # cases.py — cases, entity graph, watchlists, search
    modules/watchlist/     # sweeper.py — background sweep daemon + alerts
    modules/report/        # report.py — intelligence briefing generator
    modules/export/        # stix.py — STIX 2.1 bundle export
    modules/geo/           # geo.py — GEOINT map points, radius query, GIS export
    modules/vehicle/       # vehicle.py — VIN/recalls/plate/ALPR (authority-gated lookups)
    modules/cctv/          # cctv.py — camera mapper + authorized feed custody
    modules/iot/           # iot.py — device register + exposure re-scan + change alerts
    modules/corporate/     # corporate.py — ownership graph + officer edges
    modules/crypto/        # crypto.py — public-chain wallet tracing
    modules/screening/     # screening.py — OFAC/UN sanctions screening
    modules/infra/         # infra.py — PTR/ASN/hosting pivot
    templates/index.html   # built-in web UI (no build step, served at /)
  frontend/                # React operator console (login + tabbed dashboard)
  catalog/tools/*.md       # curated directory
  data/                    # runtime: xaxglog.db, runner history, outputs, audit.log
  .env.example
```

## Quickstart (no Docker)

```bash
cd Xaxglog/backend
pip install -r requirements.txt
python app.py
# UI (built-in) -> http://127.0.0.1:5000/   API -> http://127.0.0.1:5000/api/health
```

**Authentication.** The API is JWT-protected. On first run an admin user is
bootstrapped (`admin` / `xaxglog-admin`) — set `XAXGLOG_ADMIN_PASSWORD` before
first run to change it. Login at `POST /api/auth/login`, then send
`Authorization: Bearer <token>` on every request. Roles: `admin`, `analyst`,
`viewer`. Every action is written to an append-only audit trail.

React operator console (optional):

```bash
cd Xaxglog/frontend
npm install && npm start
# UI -> http://localhost:3000 (set REACT_APP_API=http://127.0.0.1:5000)
```

The built-in console at `/` includes three workspaces:

- **Search** — auto-detect plus username/email/phone/domain/IP/person/social/profile/company/place modes, with profile cards, lead cards, category filters and JSON export.
- **Intense Recon** — operator login, optional case attachment, live progress, normalized dossier (entities, counts, confidence) and per-axis detail. Calls `POST /api/recon/deep`.
- **Sources** — live catalog from `GET /api/deep/sources` (platforms by category/region, people indexes, social discovery engines).

## Deep search — international coverage

Single entrypoint auto-detects the input type:

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:5000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"xaxglog-admin"}' | jq -r .token)
curl -X POST http://127.0.0.1:5000/api/deep/search \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"query":"example@gmail.com"}'
```

| Endpoint | What it does (free sources) |
|---|---|
| `POST /api/deep/search` | Auto-detect email/IP/phone/domain/username/**person name**/company, run pipeline |
| `POST /api/deep/username` | 90+ global platforms (GitHub, X, IG, TikTok, Telegram, LinkedIn, Bluesky, Mastodon, VK, Weibo, PyPI…) live checks with category/region tags |
| `POST /api/deep/email` | XposedOrNot breaches + MX (Google DoH) + Gravatar + HIBP if key |
| `POST /api/deep/phone` | `phonenumbers` region/carrier/type + apilayer if `NUM_API_KEY` |
| `POST /api/deep/domain` | crt.sh subdomains + DNS (DoH) + RDAP + urlscan |
| `POST /api/deep/ip` | ip-api geo/ASN/hosting + AbuseIPDB/Shodan/ipinfo if keys |
| `POST /api/deep/person` | Handle **or full name**: GitHub profile, platform matrix, Bluesky/Mastodon/Keybase verification, and public people indexes (Wikidata, Wikipedia, GitHub, OpenAlex, Semantic Scholar, ORCID, OpenLibrary, Bluesky, Mastodon, GDELT) + social web discovery |
| `POST /api/deep/social` | Social footprint: categorized profile hits, exact API verification, name-index matches, and constrained social-site search |
| `POST /api/deep/profile` | Scrape one **public** profile URL for OpenGraph/Twitter-card/schema.org metadata, canonical URL and external social links (SSRF-guarded, no login) |
| `GET /api/deep/sources` | Catalog every configured profile platform, category, region, people index and scraper limit |
| `GET /api/deep/company?q=` | OpenCorporates global company search |
| `GET /api/deep/geo?place=` | OSM Nominatim geocode |

People/social search is **public-source only**: profile probes require the handle
to appear in the public HTML (bare HTTP 200 is not treated as a hit), and the
profile scraper blocks private/reserved IPs and login walls. Match scores and
profile existence are leads, not identity proof — verify against primary
sources and respect privacy law, platform ToS and robots/rate limits.

Scope note: public/free OSINT only. There is no lawful "CIA database" API —
anyone claiming one is selling fraud. Verify hits against primary sources and
respect privacy law + source ToS.

## New investigation modules

| Endpoint | What it does |
|---|---|
| `POST /api/recon/run` | Chained recon pipeline (domain/IP) — feeds entity graph |
| `POST /api/recon/deep` · `GET /api/recon/deep/profiles` | Intense target-aware recon: auto-detects class (person/company/domain/vehicle/phone), drives crawl/Wayback/leak/netblock/takeover/ports or identity/ownership axes concurrently, pivots email local-parts into public handles, and returns a normalized `dossier` with entities, counts and confidence |
| `POST /api/attribution/profile` | Trace an actor across handles; AI assessment + confidence |
| `POST /api/darkweb/search` | Indexed dark-web (Ahmia/IntelX) + breach-corpus search |
| `POST /api/simswap/assess` | SIM-swap fraud risk score (detection only) |
| `POST /api/ss7/request` | Authority-gated carrier SS7 lookup (build/submit/ingest) |
| `POST /api/cases` · `GET /api/cases` | Case management with legal basis + members |
| `GET /api/cases/<id>/graph` | Entity graph (nodes + links) |
| `GET /api/search?q=` | Full-text search across all evidence (FTS5) |
| `GET /api/evidence/<id>/verify` | Recompute SHA-256, confirm evidence integrity |
| `POST /api/watchlist` · `POST /api/watchlist/sweep` | Scheduled sweeps + alerts |
| `GET /api/report/<id>/html` · `GET /api/export/stix/<id>` | Intelligence briefing + STIX 2.1 |
| `GET /api/geo/geocode` · `GET /api/geo/case/<id>` · `GET /api/geo/within` | GEOINT: geocode, case map points, radius query |
| `GET /api/geo/export/<id>.geojson` · `.kml` | GIS export for map teams |
| `POST /api/vehicle/vin` · `/vehicle/recalls` · `/vehicle/plate_decode` | NHTSA VIN decode + recalls, structural plate parse |
| `POST /api/vehicle/reverse_plate` · `/vehicle/registration` | **Authority-gated** (warrant ref required; gateway stub until provider) |
| `POST /api/vehicle/alpr` · `GET /api/vehicle/timeline` | Agency plate-read intake into custody + sighting timeline |
| `GET /api/cctv/discover` · `POST /api/cctv/register` · `GET /api/cctv/cameras` | Camera exposure mapping (Shodan with key) |
| `POST /api/iot/register` · `GET /api/iot/devices` · `POST /api/iot/scan/<id>` · `/iot/scan_all` | Device register + exposure re-scan + change alerts |
| `POST /api/iot/lawful_access/<id>` | **Authority-gated** device engagement channel |
| `GET /api/corporate/search` · `/corporate/officers` · `POST /corporate/link` | Company search + officers + graph edges |
| `POST /api/crypto/address` · `/crypto/transactions` · `/crypto/trace` | BTC/ETH wallet overview + 1-hop fund-flow graph |
| `POST /api/screening/name` · `/screening/batch` · `GET /api/screening/case/<id>` | OFAC SDN + UN sanctions screening (fuzzy) |
| `POST /api/infra/ip` · `/api/infra/domain` | PTR/ASN/hosting attribution + shared-infrastructure pivot |
| `GET /api/playbooks` · `POST /api/playbooks/run` | Auto-pivot chains — re-runnable multi-step investigations |
| `GET /api/fusion/timeline/<id>` · `POST /api/fusion/resolve` | Master case timeline + fuzzy entity resolution |
| `GET /api/archive/cdx` · `POST /api/archive/watch` · `/archive/diff` | Wayback CDX history, change-watch daemon, snapshot diffs |
| `POST /api/search/federated` · `/api/search/dork/build` · `/run` | Keyless federated search (DDG/SearX/Mojeek) + dork engine |
| `GET /api/name/variants` · `/name/homographs` · `POST /name/confusables` | International name variants, IDN homographs, confusables |
| `GET /api/regional/telegram` · `POST /api/regional/search` | Telegram public channels + Baidu/Yandex/Weibo relay |
| `POST /api/email/deep` · `/email/header` · `/email/anchor` | Email MX/SPF/DKIM, header hop trace, account-graph anchor |
| `GET /api/courts/search` · `/api/courts/status` | Global court records (CourtListener, BAILII, AustLII, HUDOC) |
| `GET /api/worldcorp/gleif` · `/worldcorp/vat` · `/worldcorp/ch` | GLEIF LEI chains, EU VAT (VIES), UK Companies House |
| `POST /api/sanx/search` · `GET /api/sanx/status` | Multi-list sanctions: OFAC + UN + UK OFSI + EU consolidated |
| `GET /api/risk/gdelt` · `/risk/country` · `/risk/jurisdiction` | GDELT news events, country profiles, jurisdiction legal cards |
| `GET /api/ops/datasets` · `/ops/quota` · `/ops/health` | Bulk dataset mirrors, free-API quota budgets, source health |
| `POST /api/narrative/generate` · `GET /api/narrative/digest/<id>` | SHA-256-cited AI evidence brief (Groq/Gemini + template) |
| `GET /api/geoext/buildings` · `/geoext/pois` · `/geoext/zip` | OSM building/POI footprints, GeoJSON, postal geocode |
| `GET /api/trackers` · `POST /api/trackers` · `POST /trackers/<id>/check` · `GET /trackers/alerts` | 11 change-tracker kinds (DNS, WHOIS, port drift, site content, BTC, ALPR sightings, breach/sanctions, GLEIF, GDELT news, Telegram, sanctions) — fingerprint + diff + typed alerts, background daemon |

## Security & compliance

- **JWT auth + RBAC** (admin/analyst/viewer) on every module endpoint.
- **Chain of custody**: every artifact is SHA-256 hashed at write; `/api/evidence/<id>/verify` recomputes and detects tampering.
- **Append-only audit trail** (`audit.log` + `audit_log` table) records who queried what, when, under which authority.
- **SS7 is authority-gated**: no lawful-authorization reference ⇒ request rejected. No direct-SS7/MAP exploit path — data returns only via the carrier lawful-access channel.
- **SIM-swap is detection-only**: risk scoring from public number-intelligence signals; not an attack tool.
- **Attribution** correlates *public* OSINT for actor tracing (CERT-style); it does not publish private data.
- **Vehicle reverse-plate / registration is authority-gated**: no warrant ref ⇒ 400 rejected; no provider configured ⇒ structured request exported for the lawful channel (same pattern as SS7).
- **IoT re-scan = passive exposure monitoring only**: unauthenticated banner/port checks on public endpoints (Shodan-research model). No credential reuse, no device login, no exploitation. Engagement only via `lawful_access` (authority-gated).
- **CCTV mapper reads exposure metadata only** — never logs into or controls a camera. Frame custody is for feeds the agency is authorized to hold.
- **Sanctions screening** uses public OFAC SDN + UN lists (24h cache), fuzzy match with score thresholds.
- No `shell=True` in runner; shlex-quoted substitution + unresolved-placeholder reject.
- Filename / id sanitization + path-traversal guards on `/api/output`.
- Atomic JSON writes, capped history (500), CORS locked down via env in prod.
- Collector + watchlist sweep run in daemon threads, never block boot.

## Upstream full-parity notes

- OSINT_APP's AI briefs / bulk-protect / encrypted per-session keys live in `modules/threat_intel/legacy_app.py` — ported on demand into `app.py`.
- campwill Jinja templates kept under `modules/forensics/templates_ref` for reference.
- OSINTel streaming SSE + clone-url tools: executor supports streaming; clone-on-install intentionally left out for server hardening (add allowlist if needed).
# Xaxglog
