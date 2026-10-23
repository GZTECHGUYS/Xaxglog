# Xaxglog Upgrade Roadmap — PART 3 (Offensive Search & Pattern Expansion)

Saved: 2026-10-21. Extends ROADMAP_PART1.md / ROADMAP_PART2.md with the offensive
recon + pattern-of-life wave. Filtered against shipped endpoints, PART1/PART2 rows,
and `modules/runner/default_tools.json` — amass, feroxbuster, TruffleHog,
waybackurls, nmap-vuln already wired, so nothing here repeats them.

Access legend: 🔓 keyless free · 🔑 free API key · 💰 paid · ⛔ authority-gated

---

## W1 — Attack-surface modules (OFF waves)

### OFF-1: HTTP surface (GET-only)

| # | Module | What it does | Access |
|---|---|---|---|
| 1 | Exposure checker | Sensitive-path probe: `/.git/HEAD`, `/.env`, `*.bak`, `/server-status`, `/actuator`, `.DS_Store` — detection only | 🔓 |
| 2 | CORS + header posture | Origin-reflection tests, `null` origin, wildcard CORS, HSTS/CSP/cookie flags → 0–100 score (extends `forensics/web_tools`) | 🔓 |
| 3 | API surface discovery | Swagger/OpenAPI, GraphQL introspection-enabled, debug consoles, Actuator → API perimeter map | 🔓 |
| 4 | Third-party script SBOM | External JS inventory: CDN packages + versions, SRI coverage, dep age → feeds CVE/KEV layer | 🔓 |

### OFF-2: Infra pivots

| # | Module | What it does | Access |
|---|---|---|---|
| 5 | Certificate graph | crt.sh pivot: issuer/org/serial, SAN clusters, expiry watch → cert-reuse edges across case domains | 🔓 |
| 6 | Service fingerprint → CVE | Read-only banner grabs on `port_sweep` results → version → NVD + KEV severity | 🔓 |
| 7 | Vhost discovery | Host-header wordlist per resolved IP — vhosts invisible to DNS enum | 🔓 |
| 8 | DNS hygiene | AXFR attempt, DNSSEC validation, CAA, wildcards, dangling CNAMEs → misconfig score | 🔓 |

### OFF-3: Brand & identity abuse surface

| # | Module | What it does | Access |
|---|---|---|---|
| 9 | Lookalike-domain monitor | `namevar` homographs → RDAP/CT new-registration watch → live check + screenshot + alert | 🔓 |
| 10 | SSO/OIDC tenant map | `.well-known` endpoints, Azure tenant-ID, IdP fingerprint (Okta/ADFS/Google) | 🔓 |
| 11 | MX takeover + DMARC drift | Dangling-MX detection (same pattern as `takeover_check`) + DMARC policy strength over time | 🔓 |
| 12 | Public-repo secret sweep | GitHub/GitLab **public** org repos → pattern scan → custody finding + revocation advisory | 🔓 |

---

## W2 — Broad search modules (31)

### Group A — Web, code & content

| # | Module | What it does | Access |
|---|---|---|---|
| 13 | Code-intel string search | grep.app / searchcode / Sourcegraph: target domains, emails, internal hostnames across all public code | 🔓 |
| 14 | Historical JS asset timeline | Wayback `<script src>` versions over time → vulnerable-library era map per target | 🔓 |
| 15 | Rendered-DOM fetcher | Playwright scrape of SPA targets + captured XHR — upgrades every GET-only module | 🔓 |
| 16 | Forum & mailing-list search | Discourse / phpBB / NodeBB / Mailman / public-inbox / Google Groups by handle or email | 🔓 |
| 17 | Wikipedia edit-history intel | Account age, edit network, cross-wiki identity, first-edit reveal patterns | 🔓 |
| 18 | App store & extension intel | Play/App Store/Chrome Web Store/AMO: publisher graph, permission creep, update cadence | 🔓 |
| 19 | Package registry graph | npm/PyPI/crates/Gem typosquat detection + maintainer email/alias graph | 🔓 |
| 20 | Podcast & RSS intel | Feed search, guest rosters, transcripts, hosting infrastructure | 🔓 |

### Group B — People & identity

| # | Module | What it does | Access |
|---|---|---|---|
| 21 | Workforce mapper | Org chart from public profiles, press, filings; headcount timeline | 🔓 |
| 22 | Speaker & attendee intel | Conference sites, Meetup rosters, webinar panels → affiliation confirmation | 🔓 |
| 23 | Fitness activity geolocation | Strava / Komoot / Garmin public segments + routes → pattern-of-life at a coordinate | 🔓 |
| 24 | Gaming platform intel | Steam / PSN / Xbox / Twitch: account age, friends graph, play history | 🔓 |
| 25 | Creative portfolio cluster | Behance / Dribbble / ArtStation / DeviantArt cross-linked to handle graph | 🔓 |
| 26 | Property & land registry router | County assessor/cadastral (US), HM Land Registry (UK), select EU cadastres | 🔓 |

### Group C — Platforms, comms & advertising

| # | Module | What it does | Access |
|---|---|---|---|
| 27 | Discord intel | Public guilds, vanity invites, roles, bot inventory, member counts | 🔓 |
| 28 | IRC & Matrix room search | Public room index by topic/keyword | 🔓 |
| 29 | Ad-library search | Meta Ad Library + Google Political Ads + X transparency: spend brackets, creative archive | 🔓 |
| 30 | Job-posting intel | Hiring boards per org: stack from JDs, new locations, salary bands | 🔓 |
| 31 | Onion location intel | Targets advertising `.onion` via HTTP/DNS + onion title search | 🔓 |

### Group D — Threat & offense (search side)

| # | Module | What it does | Access |
|---|---|---|---|
| 32 | Exploitability overlay | CVE → EPSS + Exploit-DB/PacketStorm/GitHub-PoC availability → priority column | 🔓 |
| 33 | Detection-rule export | Case IOCs → Sigma / Suricata / YARA (only concepts exist in `threat_intel/legacy_app.py`) | 🔓 |
| 34 | ATT&CK Navigator layer | Case coverage as Navigator JSON (complements existing STIX 2.1 export) | 🔓 |
| 35 | Multi-engine device router | Shodan + Censys + ZoomEye + Netlas, one syntax, merged results | 🔑 |
| 36 | Netblock exposure census | Live hosts in tracked netblock: ports/banner/CPE census (extends `netblock_expand`) | 🔓 |

### Group E — Physical world

| # | Module | What it does | Access |
|---|---|---|---|
| 37 | Cell tower geolocation | OpenCelliD: cell ID → coordinates + tower history | 🔑 |
| 38 | Commercial license router | FCC/ITU broadcast, marine, aviation, microwave licenses (beyond P2-3 amateur callsigns) | 🔓 |

### Group F — Records & money

| # | Module | What it does | Access |
|---|---|---|---|
| 39 | UCC / lien / judgment search | Public filing portals → asset, collateral, collection trail | 🔓 |
| 40 | Court docket watcher | Tracker kind `docket_filing`: new dockets matching case entities → alert | 🔓 |
| 41 | Bill-of-lading records | Shipment history: what moved, which ports, counterparties | 💰 |
| 42 | Crowdfunding & donation search | Kickstarter / GoFundMe / electoral donations → funding trail | 🔓 |

### Group G — Actor clustering

| # | Module | What it does | Access |
|---|---|---|---|
| 43 | Domain portfolio clustering | RDAP registrant email/phone + NS reuse → same-actor domain graph (relational, not temporal) | 🔓 |

---

## W3 — Social Pattern Tracker (`modules/pattern/`) — flagship

Links person ↔ organization ↔ handles ↔ frequent contacts ↔ shared sites ↔
associated IPs, with cadence / pattern-of-life output. Unifies PART1 §3
(interaction graph, handle migration), §10 (pattern-of-life, entity resolution).

**Data model (new tables in shared SQLite, FTS5 on interaction text):**

| Table | Holds |
|---|---|
| `pattern_links` | src/dst entity, relation (`member_of`, `contacts`, `shares_url`, `resolves_to`), source, confidence, first_seen/last_seen, evidence_id |
| `pattern_interactions` | actor, target, platform, kind (reply/mention/quote/co-comment/co-author), ts, url, evidence_id |
| `pattern_urls` | entity, url, registrable domain, ts — the "sites they share" timeline |
| `pattern_ips` | entity, ip, first/last seen, source (evidence header / public post / infra), evidence_id |
| `pattern_pins` | case_id, label, lat, lon, radius_m, schedule |

**Endpoints:**

| Endpoint | Does |
|---|---|
| `POST /api/pattern/link` | Create/confirm entity link edges with source + confidence |
| `POST /api/pattern/ingest` | Normalized interaction event in (any connector or manual paste) |
| `GET /api/pattern/frequent_contacts/<entity>` | Time-decayed contact ranking + corroboration count |
| `POST /api/pattern/urls` · `GET /api/pattern/diet/<entity>` | URL-share timeline → top domains, first/last seen |
| `POST /api/pattern/ip_ledger` · `GET /api/pattern/ips/<entity>` | IP association ledger with per-row source |
| `GET /api/pattern/pnl/<entity>` | Pattern-of-life report: active hours, platform cadence, contact core, domain diet, IP set |
| `GET /api/pattern/org/<entity_id>` | Org view: members, roles, contact matrix, shared infrastructure |

**Scoring:**
- `contact_weight = Σ w_kind · e^(−Δt / H)`, H = 90 days default
- Weights: reply 1.0 · co-author 1.2 · quote 0.8 · mention 0.7 · GDELT co-mention 0.6 · co-comment 0.5
- Qualifies as "frequent": ≥3 interactions AND (≥2 sources OR ≥5 on one source)
- Corroboration boost ×1.25 per extra platform, cap ×1.75
- Active-hours: 24-bin histogram over ≥14 days → phase-shift cross-correlation vs UTC offsets → likely timezone, confidence from circular variance

**Connectors (keyless first):** Bluesky / Mastodon public APIs, GitHub commits+issues,
GDELT co-mentions, Telegram `t.me/s/` previews, forum posts, Wayback replay of deleted
feeds, manual evidence paste. X/Twitter = 💰 (API), fallback to profile-card only.

**Data honesty rule:** no public source exposes a person's browsing IPs —
`pattern_ips` covers *disclosed* IPs (evidence headers, public forum posts) and
*infra* IPs (their domains' DNS history, co-hosted). Every row carries its source.

**Wiring:** edges emit into `/api/cases/<id>/graph` (types `person`, `org`, `handle`,
`domain`, `ip`); dedupe via `/api/fusion/resolve`; tracker kinds `new_contact`,
`contact_drop`, `cadence_change`, `geo_pin`; new `PatternPanel.js` tab in
`OperatorPanels.js` (heatmap + top-contacts + timeline).

**Build phases:** 1 schema+links → 2 interaction ingest+connectors → 3 scoring/POL →
4 URL + IP ledgers → 5 graph + UI → 6 tracker alerts.

---

## W4 — VIN lookup expansion (`modules/vehicle/`)

Current: vPIC decode, recalls, plate decode (authority-gated reverse/registration stays as-is).

| # | Endpoint | Source | Access |
|---|---|---|---|
| 44 | `POST /vehicle/vin` (extended) | vPIC B-type decode — all 100+ fields, trim/drive-type/GVWR | 🔓 |
| 45 | `POST /vehicle/complaints` | NHTSA complaints API: crash/fire/speed complaints per VIN, trend over model years | 🔓 |
| 46 | `POST /vehicle/tsb` | NHTSA ODI investigations + technical service bulletin index | 🔓 |
| 47 | `GET /vehicle/risk` | NHTSA theft data by year/make/model → theft-rate score for the VIN's configuration | 🔓 |
| 48 | `POST /vehicle/history` | NMVTIS title-brand / odometer / salvage / loss history | 💰 (approved provider) |
| 49 | `GET /vehicle/economy` | fueleconomy.gov window-sticker data by VIN | 🔓 |
| 50 | `GET /vehicle/status/<vin>` | Recall remedy status tracker: open/reclosed, Takata + EV battery campaigns → tracker kind `recall_open` | 🔓 |

---

## W5 — Location pins & geofence watch (`modules/geo/`)

| # | Endpoint | Does | Access |
|---|---|---|---|
| 51 | `POST /api/geo/pins` | Create labeled pin: lat/lon, radius, case attach, schedule | 🔓 |
| 52 | `GET /api/geo/pins/<id>/bundle` | One call → reverse geocode + buildings + POIs + OT exposure (Shodan key) + 30d news (GDELT) + imagery timeline + cell towers (OpenCelliD) | 🔓/🔑 |
| 53 | `POST /api/geo/pins/<id>/check` | Diff since last check: new buildings/POI, new imagery, new events in radius → alert | 🔓 |
| 54 | `GET /api/geo/pins/<id>/passes` | Sentinel-2/Landsat pass schedule computed locally (sgp4 + Celestrak TLEs) + cloud forecast (Open-Meteo) → "next clear look" alert | 🔓 |

Pin any evidence artifact with EXIF/coordinates to a pin — custody hash already exists,
pins just add the spatial anchor + scheduled diff.

---

## W6 — Bonus offensive modules

| # | Module | What it does | Access |
|---|---|---|---|
| 55 | Tracker-stack fingerprint | What runs on target sites: GA/Meta pixel/fp.js/anti-bot stack → who the target shares data with | 🔓 |
| 56 | Payment-address harvester | Scrape BTC/ETH/XMR addresses from target pages/posts → feeds `crypto/trace` | 🔓 |
| 57 | Data-broker exposure sweep | Which brokers list the person/address (Spokeo-class) → exposure report + removal workflow | 🔓 |
| 58 | Canary/pixel detector | Flag phone-home URLs & tracking pixels in received evidence — investigator OPSEC | 🔓 |
| 59 | Route-change tracker | Tracker kind `route_change`: BGP origin/ASN change on tracked IPs (RIPE RIS, keyless) | 🔓 |
| 60 | Email relationship graph | Header `In-Reply-To` chains → conversation map + auto-responder (OOO) pattern leak | 🔓 |
| 61 | Shortener/campaign intel | Expand shorteners, decode campaign/UTM IDs, resolve preview cards | 🔓 |
| 62 | Imagery revisit scheduler | Per-pin upcoming pass alerts (pairs with #54) — subscribe a case to a coordinate | 🔓 |

---

## Recommended build order (Wave 3C)

1. **W3 Pattern tracker** — schema + link store + one connector (GitHub), then scoring
2. **W4 VIN quick wins** — complaints + extended decode + recall status (all keyless)
3. **W5 Pins** — store + bundle + geofence diff (reuses geoext/GDELT already shipped)
4. **W1 OFF-1** (exposure + posture) and **W2-A/D** (code intel, exploitability overlay)
5. **W6** quick bonuses: 58, 59, 61 (small, pure keyless)
6. Remaining groups by investigation volume demand
