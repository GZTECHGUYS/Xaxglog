# Xaxglog — International Deep-Search OSINT Platform (no Docker)

State-grade OSINT intelligence platform. Unified build combining 4 open-source
upstreams + a native deep-search engine + an agency-grade investigation core
(cases, entity graph, chain-of-custody evidence, watchlists, reports), plus a
multi-part expansion across Parts 1-8 spanning live CT/host monitoring,
transport & imagery, media/document forensics, identity/finance,
marketplace/community intelligence, social-pattern and broker-exposure
analysis, public records, country-scoped search, broad public social search
and reverse-image lookup.

| Module | Upstream | What we picked |
|---|---|---|
| `threat_intel` | `et842/OSINT_APP` | `collector.py` (URLhaus/AbuseIPDB/OTX/VT), `processor.py` (0-100 scoring), `database.py` schema, live-lookup + breach + AI-brief + Snort/YARA concepts |
| `forensics` | `campwill/osint-dashboard` | `web_tools.py` (URL/DNS/SSL/headers/cookies/ports/whois/links/emails/phones/screenshot), `file_tools.py` (EXIF), `pid_tools.py` (phone validation) |
| `runner` | `aenoshrajora/OSINTel-Dashboard` | Secure generic tool executor (`executor.py`), `default_tools.json` tool definitions, history + streaming model |
| `catalog` | `intelseclab/osintelligence` | 22 curated category markdown files under `catalog/tools/` |
| `deep_search` | Xaxglog-native | International username/email/phone/domain/IP/person/name/social profile/company/geo via free sources (no Docker, no keys required) |
| `identity` | Xaxglog-native | Name/identity orchestrator: comma/suffix/initial normalization, always-on variants, keyless people/academic/archive/code/records adapters, a general web pass, dedupe, confidence and per-source coverage |
| `source_registry` | Xaxglog-native | Unified 402-source public catalog: verified/adapter/optional-key/link-out/blocked/error status, per-category plans, public link-out builder and live verification |
| `module_registry` | Xaxglog-native | Declarative 405-module control plane: generic JSON/profile/search/oEmbed/adapter/link-out probes, live verification overlay, dedupe/ranking, coverage diagnostics and honest automatic-evidence counts |
| `operator_compat` | Xaxglog-native | Legacy dashboard compatibility: owner-only operator key store, `/api/lookup` deep-search view, breach lookup, deterministic briefing and Snort/YARA rule helpers |
| `platform_ops` | Xaxglog-native | Phase 1–12 services: evidence graph/timeline/provenance, source health, social coverage, runtime/self-test, signed module packs, offline cache, security posture, team workspaces, performance, plugin SDK, compliance and observability |
| `recon` | Xaxglog-native | Chained deep-recon pipeline engine (dependency-aware fan-out, evidence capture, graph emission) |
| `trackers` | Xaxglog-native | Subject trackers: fingerprint+diff change watchers over DNS, WHOIS, ports, content, wallets, ALPR, breach/sanctions, LEI, news, Telegram, plus pattern new-contact/contact-drop/cadence shifts (daemon + typed alerts) |
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
| `pattern` | Xaxglog-native | Social pattern tracker: public interaction ingest, entity links, time-decayed frequent contacts, active-hours/timezone inference, URL/IP ledgers, email thread graph |
| `broker` | Xaxglog-native | Public data-broker exposure sweep: people-search catalog checks with honest `possible_hit` / `no_signal` / `blocked` statuses and an exposure score |
| `procurement` | Xaxglog-native | Public procurement: USAspending federal awards + EU TED notices, normalized buyer/awardee/amount/date |
| `lobbying` | Xaxglog-native | US LDA (lda.gov) lobbying disclosures: client/registrant search, lobbyists, issues, income/expenses |
| `nonprofit` | Xaxglog-native | ProPublica Nonprofit Explorer: IRS-registered nonprofits, EIN lookup, Form 990 financial summaries |
| `countryscope` | Xaxglog-native | Country-scoped search: selected-country registry/procurement/court/charity links plus GLEIF, USAspending/TED, nonprofit/lobbying and domain/IP country checks |
| `socialscrape` | Xaxglog-native | Broad international public social-media search/scrape: 168-platform catalog, federated + regional engines, keyless Reddit/Bluesky/Lemmy APIs, public-page metadata/media, platform search links, case evidence |
| `imgreverse` | Xaxglog-native | Public reverse-image lookup: 14 public engines (11 link-out: Google Lens, Bing, Yandex, TinEye, SauceNAO, IQDB, ascii2d, Baidu, Sogou, Karma Decay, Trace.moe) + keyless Trace.moe and optional-key APIs; face-search engines excluded |

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
    modules/socialscrape/  # socialscrape.py — 168-platform public social search/scrape
    modules/imgreverse/    # imgreverse.py — public reverse-image links + keyless/optional APIs
    modules/identity/      # identity.py + adapters.py — normalization, variants, orchestration
    modules/source_registry/ # source_registry.py — unified public-source catalog + plans
    modules/module_registry/ # declarative ModuleSpec registry, generic probes, engine, verification store
    modules/operator_compat/ # legacy dashboard compatibility helpers
    modules/platform/      # Phase 1-12 graph, packs, offline, collab, plugins, compliance, ops
    routes/p7.py           # identity + source-registry API group
    routes/p8.py           # module registry + legacy dashboard compatibility
    routes/p9.py           # Phase 1-12 platform API group
  packaging/               # PyInstaller spec, Windows/Linux/deb/AppImage build scripts
  sdk/                     # declarative plugin SDK + pack signing helper
  packs/                   # example signed module pack manifest
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
    modules/<45 more>/     # Part 1-6 expansion modules (see below)
    routes/                # extra-module route groups (p1a..p8)
    templates/index.html   # built-in web UI (no build step, served at /)
  frontend/                # React operator console (login + tabbed dashboard)
  catalog/tools/*.md       # curated directory
  data/                    # runtime: xaxglog.db, runner history, outputs, audit.log
  .env.example
```

## Quickstart (no Docker)

The launcher repairs the common fresh-clone failure
`sh: 1: react-scripts: not found` by installing frontend dependencies when
`frontend/node_modules` is absent:

```bash
./start.sh                 # backend + React dev server
./start.sh --backend-only  # built-in console only: http://127.0.0.1:5000/
./start.sh --frontend-only # React only
./start.sh --build         # production React build
```

Manual backend start:

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
./start.sh                 # installs node_modules on first run, then starts
# UI -> http://localhost:3000 (set REACT_APP_API=http://127.0.0.1:5000)
```

The built-in console at `/` includes thirteen workspaces:

- **Search** — auto-detect plus username/email/phone/domain/IP/person/social/location/profile/company/place modes, with depth/public-records/code-index controls, profile cards, lead cards, category filters and JSON export.
- **Identity** — comma/suffix/initial normalization, always-on name and handle variants, keyless people/academic/archive/code/records adapters, a general web pass, dedupe/confidence ranking, per-source coverage diagnostics and public link-outs.
- **Social Media** — search a name, handle, hashtag, keyword or public post URL across 168 international platforms; federated/regional engines, keyless public APIs, public-page metadata and platform-native search links.
- **Image Reverse** — use 14 public reverse-image engines (11 link-out) and run keyless Trace.moe plus optional keyed APIs; face-search/biometric engines are excluded.
- **Country Scope** — enter a name, company, domain, IP, phone or email, choose a country, and get a country-specific source plan plus live jurisdiction/infrastructure checks.
- **Intense Recon** — operator login, optional case attachment, live progress, normalized dossier (entities, counts, confidence) and per-axis detail. Calls `POST /api/recon/deep`.
- **TrackPin** — consent-link and authority-request workflow for lawful location.
- **Pattern** — collect public interactions, run pattern-of-life/frequent-contact views, inspect URL/IP ledgers and analyze email headers.
- **Broker** — public people-search exposure sweep with hit/blocked/clean statuses.
- **Records** — procurement awards, lobbying disclosures, and nonprofit/Form 990 lookups.
- **Sources** — unified source registry from `GET /api/sources/registry` with category/access/status filters, public link-out builder and live keyless-adapter verification. The older platform catalog remains at `GET /api/deep/sources`.
- **Modules** — declarative module registry from `GET /api/module-registry/summary`: generic probe types, honest verified/fragile/adapter/candidate/blocked counts, filterable module table, verified search, two-check live verification and browser link-outs.
- **Platform** — Phase 1–12 control plane: evidence graph/timeline/provenance, source health, social coverage (direct APIs vs public search link-outs vs handle-only), runtime/self-test, signed module packs, offline mode, security posture, team workspaces, performance benchmark, plugin SDK, compliance and diagnostics.

## Compiled distributions (Windows `.exe`, Linux `.deb`)

The engine is a plain Python process plus SQLite/FTS5; the built-in console
needs no Node runtime. Build one-folder artifacts (faster start, fewer AV false
positives) with:

```bash
python -m pip install pyinstaller
python packaging/build.py --target deb        # dist/Xaxglog + dist/*.deb
python packaging/build.py --target appimage   # optional, needs linuxdeploy
```

On Windows:

```powershell
./packaging/build_windows.ps1                 # dist/Xaxglog/Xaxglog.exe
./packaging/build_windows.ps1 -CertThumbprint <THUMBPRINT>  # signed
```

CI (`.github/workflows/release.yml`) builds and tests Linux and Windows
artifacts. See `docs/DISTRIBUTION.md` for signing, packaging and reproducibility,
and `docs/PHASES.md` for the Phase 1–12 endpoint/acceptance map. Runtime
diagnostics are at `/api/platform/runtime`, `/api/platform/health` and
`/api/platform/metrics`.

## Identity intelligence & unified source registry

The identity layer is deliberately stricter than a plain name search: it
normalizes `Doe, Jane A. Jr.` into a base name plus suffix/initial metadata,
runs the exact name **and** prioritized variants (always-on, not only when the
exact name returns zero), and then merges public people, academic, archive,
code, records and web results. Every source is reported as `verified`,
`adapter`, `optional_key`, `link_out`, `blocked`, `error` or `cataloged`.
A blocked/captcha/optional-key/link-out source is never counted as “no results”.

| Endpoint | What it does |
|---|---|
| `POST /api/identity/search` | Full identity run; accepts `query`, `kind`, `depth` (`quick`/`standard`/`deep`), `country`, `include_social`, `include_web`, `include_records`, `include_code`, `include_link_out`, `case_id` |
| `GET /api/identity/plan?q=` | Preview normalization, variants, source groups and planned source count before spending time |
| `GET /api/identity/variants?q=` | Name variants + handle spellings |
| `GET /api/sources/registry?include_sources=true&limit=1000` | Unified catalog with per-source access, status, adapter, region, key and public URL |
| `GET /api/sources/summary` | Counts only (small response) |
| `GET /api/sources/links?q=&categories=&limit=` | Public search/profile link-outs; never automatic hits |
| `POST /api/sources/verify` | Live-check selected keyless adapters/engines (`ids`, `query`, `timeout`) |

`POST /api/deep/person` now routes through the identity orchestrator and
attaches `identity`, `coverage`, `variants`, `normalized` and
`identity_results`, with a legacy person-search fallback.

### Catalog snapshot (live-verified from this host)

| Status | Count | Meaning |
|---|---:|---|
| Total catalog | **402** | Public/free sources only; no login walls or paywalled law-enforcement databases |
| Queryable | **264** | Sources with an adapter/engine, including 169 public social/profile catalog entries |
| Live-verified | **84** | Returned valid, usable rows during the verification pass |
| Adapter-ready | **10** | Code exists; a later live probe is still recommended |
| Optional key | **20** | Free API with an operator-supplied key |
| Link-out | **101** | Reliable public search/profile page, never counted as an automatic result |
| Blocked from this host | **15** | 401/403/429/captcha/bot challenge; not “no results” |
| Hard endpoint error | **3** | Dead/404/400 endpoint from this host |
| Cataloged | **169** | Public social/profile page templates; no automatic hit claim |

The registry covers global/regional web search, people and academic indexes,
public records/company/court sources, code/package indexes, social/fediverse
platforms, image/media sources, geospatial/infrastructure sources and
monitoring feeds. Direct Google/Bing result-page scraping is intentionally not
used; those engines stay as official APIs (optional key) or clearly marked
link-outs.

The React operator console exposes the same features as **Search**,
**Modules**, **Identity** and **Source Registry** tabs. The old `/lookup` path
is kept as a compatibility view over `POST /api/deep/search`.

## Declarative module registry

The registry replaces "one Python file per website" with a small declarative
contract and generic probe types: `json_api_probe`, `http_profile_probe`,
`html_search_probe`, `oembed_probe`, `adapter_probe` and `link_out`. A module is
only automatic evidence when it is `verified` (API/adapter) or `fragile`
(live-checked public scrape). Adapter, candidate, optional-key, link-out,
blocked and error sources stay catalog-only.

| Endpoint | What it does |
|---|---|
| `GET /api/module-registry/summary` | Honest counts by status, probe, category and access |
| `GET /api/module-registry/modules?status=verified&category=people&limit=100` | Filtered module list |
| `GET /api/module-registry/modules/<id>` | One module including its probe payload |
| `POST /api/module-registry/search` | Run verified/fragile modules; dedupe, rank, per-source coverage and "why empty" diagnostics |
| `POST /api/module-registry/verify` | Live-check selected ids (analyst+); two checks by default; persists an owner-only overlay |
| `GET/POST /api/module-registry/links` | Build browser link-outs (never API URLs) |

Current honest snapshot from this host:

| Metric | Count |
|---|---:|
| Declared modules | **405** |
| Live-verified APIs/adapters | **70** |
| Live-verified fragile scrapes | **14** |
| Automatic evidence modules | **84** |
| Adapter-ready (not rechecked) | **9** |
| Candidate probes | **156** |
| Optional-key | **20** |
| Link-out | **118** |
| Blocked from this host | **15** |
| Hard endpoint error | **3** |

This is deliberately not a padded Osintly-style count. Osintly's 1,835 public
entries are useful as a candidate list, but its execution is CAPTCHA/credit
gated and its backend is closed. Xaxglog's realistic target is 300–600
genuinely verified/queryable modules plus 1,000+ link-outs. See
`docs/MODULE_REGISTRY.md` for the probe contract, status semantics, verification
rules and how to add a source.

### Legacy dashboard compatibility

The unified app now registers the routes the React dashboard already called but
which were missing: `GET/POST/DELETE /api/keys`, `POST /api/validate-key`,
`GET /api/lookup`, `GET /api/breach-lookup`, `POST /api/ai-summary`,
`POST /api/template-rules`, `POST /api/generate-rules` and
`POST /api/bulk-protect`. The key store is owner-only and uses Fernet when
`cryptography` is installed; the briefing/rules fallbacks are deterministic and
do not require a paid model key. `/api/stats` and `/api/threats` return valid
empty/zero shapes when the optional threat-intel stack is unavailable.

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
| `POST /api/deep/person` | Handle **or full name**: platform matrix + **display-name search** (GitHub, Bluesky, Mastodon, Lemmy, Stack Overflow, Codeberg) + 15 public people indexes (Wikidata, Wikipedia, GitHub, OpenAlex, Semantic Scholar, ORCID, OpenLibrary, Bluesky, Mastodon, GDELT, Crossref, arXiv, Lemmy, Stack Exchange, Codeberg) + social web discovery |
| `POST /api/deep/social` | Social footprint: categorized profile hits, exact API verification, name-index matches, and constrained social-site search |
| `POST /api/deep/location` | Precision-labelled **public location signals** for phone/email/name/handle/domain: number-plan region/carrier/timezone, Gravatar/profile self-declared location, JSON-LD address, server/IP geo. Never live GPS; no silent tracking |
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

## TrackPin — lawful location workflow

TrackPin is **not** a covert tracker. It does not intercept calls/SMS, exploit
SS7/MAP, install spyware or silently track a device. It provides two lawful
paths:

1. **Consent check-in** — issue a one-time expiring link; the subject opens it
   in their own browser and explicitly presses “share my location”. The point
   is stored with a consent flag, accuracy, timestamp, audit trail and SHA-256
   evidence hash.
2. **Authority request** — generate a formal carrier/emergency-location request
   packet referencing a warrant/legal basis. The operator submits it through
   the agency's lawful channel; Xaxglog has no automated carrier access.

| Endpoint | What it does |
|---|---|
| `POST /api/trackpin/operations` | Create a case-linked operation (`consent_checkin`, `authority_request`, `manual_ingest`) |
| `GET /api/trackpin/operations` · `GET /api/trackpin/operations/<id>` | List/detail with points and consent status |
| `POST /api/trackpin/operations/<id>/consent-link` | Issue/rotate a one-time consent link |
| `POST /api/trackpin/operations/<id>/points` | Ingest a provenance-labelled manual/authority/open-source point |
| `POST /api/trackpin/operations/<id>/authority` | Generate the authority-request packet |
| `GET /api/trackpin/operations/<id>/geojson` | GeoJSON export |
| `GET /trackpin/consent/<token>` · `GET/POST /api/trackpin/consent/<token>` | Public consent page and one-time submission |

Precise/real-time location is only collected with explicit consent or through a
valid legal process handled by the provider/authority.

## Pattern Tracker + Broker Exposure

**Pattern Tracker** builds an evidence-linked interaction graph from public
signals only: public posts, mentions, follows, shared URLs, GitHub org links,
GDELT co-mentions, public Telegram channels, and email headers supplied by the
operator. It does **not** claim browsing history or private message access.
Every row carries its source and can be attached to a case entity graph.

| Endpoint | What it does |
|---|---|
| `GET /api/pattern/sources` | List public connectors and target hints |
| `POST /api/pattern/collect` | Harvest GitHub/Bluesky/Mastodon/GDELT/Telegram for an entity |
| `POST /api/pattern/ingest` | Ingest normalized public interaction events |
| `POST /api/pattern/link` · `GET /api/pattern/links` | Add/list entity links (member_of, handle_of, contacts, shares_url, resolves_to) |
| `GET /api/pattern/frequent_contacts/<entity>` | Time-decayed contact ranking with corroboration boost |
| `GET /api/pattern/pnl/<entity>` | Pattern-of-life: cadence, active hours, inferred UTC offset, contact core, URL/IP summary |
| `GET /api/pattern/diet/<entity>` · `GET /api/pattern/ips/<entity>` | Shared-URL domain diet + public/disclosed IP ledger |
| `POST /api/pattern/urls` · `POST /api/pattern/ips` · `POST /api/pattern/header_ips` | Record public URLs, disclosed IPs, or Received-header hops |
| `GET /api/pattern/org/<entity>` | Org members, handles, domains, and member contacts |
| `POST /api/pattern/email_graph` | Reconstruct email threads from headers, rank participants, flag auto-responders |

`new_contact`, `contact_drop`, and `cadence_change` are also registered tracker
kinds, so pattern-of-life changes can raise typed alerts.

**Broker Exposure** walks a curated public people-search catalog for a name or
address and records how each site responded. `blocked` is explicitly treated as
unknown, not as a clean result. Rate-limited sequential checks only.

| Endpoint | What it does |
|---|---|
| `GET /api/broker/catalog` | List configured public broker sites |
| `POST /api/broker/sweep` | Sweep by name/address, return hit/clean/blocked counts and exposure score |

## Public Records — Procurement, Lobbying, Nonprofit

Three official-transparency modules for company/person due diligence. All are
keyless public APIs and report per-source status; no private databases.

| Endpoint | What it does |
|---|---|
| `GET /api/procurement/sources` · `POST /api/procurement/search` | USAspending federal awards + EU TED notices; filter by `country` (`all`/`us`/`eu`) |
| `GET /api/lobbying/sources` · `POST /api/lobbying/search` | US LDA (lda.gov) filings by client or registrant; optional `year` |
| `GET /api/nonprofit/sources` · `POST /api/nonprofit/search` | ProPublica/IRS nonprofit search by name and optional state |
| `GET /api/nonprofit/org/<ein>` | One nonprofit + recent Form 990 financial summaries |

Search endpoints accept an optional `case_id`; when supplied, the normalized
result is SHA-256 hashed into the case evidence store. `lda.gov` may apply
network-level access controls, so an HTTP 403 is reported as `blocked` rather
than as “no results.”

## Country Scope — country-specific search

One input accepts a name, company, domain, IP, phone or email. Pick a
country (or use `auto` for domains/IPs/phones) and the module returns:

- a country source catalog — official company registry, procurement portal,
  court search, charity register and country-scoped search-engine links;
- live free checks where available — GLEIF legal/headquarters jurisdiction
  (all countries), USAspending federal awards and US nonprofit/lobbying
  records, TED notices for EU member states, and server/IP country for sites
  and IPs;
- a precision-labelled `scope` block with a `high`/`medium`/`low`/`unknown`
  match and explicit caveats.

```bash
curl -X POST http://127.0.0.1:5000/api/countryscope/search \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"query":"example.de","country":"DE"}'
```

| Endpoint | What it does |
|---|---|
| `GET /api/countryscope/countries` | Country catalog (68 jurisdictions) with ccTLD, region and live capabilities |
| `GET /api/countryscope/profile/<cc>` | One country's source templates and capabilities |
| `POST /api/countryscope/search` | Scope `query` to `country` (`auto` for infrastructure inputs); optional `case_id` hashes the response into evidence |

Country attribution is an analytical lead. A ccTLD is a registration choice,
server/IP geolocation is infrastructure, and a registry jurisdiction is not
proof that a person or company is the same target. Confirm with a unique
identifier (LEI, EIN, company number) before drawing conclusions. No login
walls, captcha solving, private databases or device access are used.

## Social Media Search + Image Reverse

**Social Media Search** is a broad, public-source discovery layer. It does not
log in, join private groups, solve captchas or evade anti-bot controls. Input
can be a name, handle, hashtag, keyword or public profile/post URL. The module
combines:

- a **168-platform international catalog** with region/category tags and
  platform-native search links (CN, RU, JP, KR, IN, SEA, VN, TH, ID, LATAM,
  MENA, Africa, Europe, North America and global platforms);
- federated keyless search through DuckDuckGo, SearXNG and Mojeek;
- regional public engines — Baidu, Yandex, Weibo and Telegram public preview;
- keyless public APIs — Reddit search, Bluesky search and Lemmy search;
- a public-page scraper for title, author, timestamp, hashtags, mentions,
  outbound/social links, image/video URLs and OpenGraph/Twitter/JSON-LD;
- optional public oEmbed for TikTok, X/Twitter, YouTube, Vimeo, SoundCloud,
  Spotify and Reddit;
- optional exact-handle probing across the existing public profile matrix;
- optional case attachment with SHA-256 evidence hashing.

A login wall, captcha, rate limit or private channel is reported as `blocked`,
never bypassed. Profile/post matches are leads, not identity proof.

| Endpoint | What it does |
|---|---|
| `GET /api/socialscrape/catalog` | Platform/region/category coverage, engine list and limits |
| `GET /api/socialscrape/links?q=` | Platform-native public search links only |
| `POST /api/socialscrape/search` | Broad search (`query`, optional `platforms`, `region`, `category`, `scrape`, `probe`, `case_id`) |
| `POST /api/socialscrape/page` | Scrape one public profile/post URL (SSRF-guarded, no login) |
| `POST /api/socialscrape/oembed` | Public oEmbed metadata for supported platforms |

**Image Reverse Lookup** builds ready-to-open links for Google Lens, Bing
Visual Search, Yandex Images, TinEye, SauceNAO, IQDB, ascii2d, Baidu, Sogou,
Karma Decay and Trace.moe. It runs keyless **Trace.moe** and, when configured,
optional SauceNAO/TinEye/Google Vision APIs. It deliberately excludes
face-search/biometric engines such as PimEyes and FaceCheck.ID. Local images
are hashed with `imgverify` and are never uploaded automatically.

| Endpoint | What it does |
|---|---|
| `GET /api/imgreverse/catalog` | Engines, link/API modes, optional key env names, excluded face-search engines |
| `GET /api/imgreverse/links?url=` | Link-out URLs for one public image URL |
| `POST /api/imgreverse/search` | Links + keyless/optional API lookup (`image_url` or local `image_path`, optional `case_id`) |

Optional keys: `XAXGLOG_SAUCENAO_KEY` / `SAUCENAO_API_KEY`,
`XAXGLOG_TINEYE_KEY` / `TINEYE_API_KEY`, and
`XAXGLOG_GOOGLE_VISION_KEY` / `GOOGLE_VISION_API_KEY`. Reverse-image hits are
provenance leads, not proof of ownership, identity or location. Respect each
provider's ToS and rate limits.

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
| `POST /api/socialscrape/search` · `GET /api/socialscrape/catalog` | Broad international public social search + 168-platform catalog |
| `POST /api/imgreverse/search` · `GET /api/imgreverse/catalog` | Public reverse-image links + keyless/optional API lookup |
| `POST /api/email/deep` · `/email/header` · `/email/anchor` | Email MX/SPF/DKIM, header hop trace, account-graph anchor |
| `GET /api/courts/search` · `/api/courts/status` | Global court records (CourtListener, BAILII, AustLII, HUDOC) |
| `GET /api/worldcorp/gleif` · `/worldcorp/vat` · `/worldcorp/ch` | GLEIF LEI chains, EU VAT (VIES), UK Companies House |
| `POST /api/sanx/search` · `GET /api/sanx/status` | Multi-list sanctions: OFAC + UN + UK OFSI + EU consolidated |
| `GET /api/risk/gdelt` · `/risk/country` · `/risk/jurisdiction` | GDELT news events, country profiles, jurisdiction legal cards |
| `GET /api/ops/datasets` · `/ops/quota` · `/ops/health` | Bulk dataset mirrors, free-API quota budgets, source health |
| `POST /api/narrative/generate` · `GET /api/narrative/digest/<id>` | SHA-256-cited AI evidence brief (Groq/Gemini + template) |
| `GET /api/geoext/buildings` · `/geoext/pois` · `/geoext/zip` | OSM building/POI footprints, GeoJSON, postal geocode |
| `GET /api/trackers` · `POST /api/trackers` · `POST /trackers/<id>/check` · `GET /trackers/alerts` | 14 change-tracker kinds (DNS, WHOIS, port drift, site content, BTC, ALPR sightings, breach/sanctions, GLEIF, GDELT news, Telegram, sanctions, new-contact, contact-drop, cadence) — fingerprint + diff + typed alerts, background daemon |

## Expansion modules (Part 1 + Part 2)

35 additional investigation modules. Same house rules everywhere: JWT + RBAC,
`{"status": ...}` responses, lazy imports, optional deps degrade honestly
(`/api/modules` shows live `caps`), public-source/passive collection only,
authority-gating where noted. Keyless-first — every module works without any
API key (paid keys only deepen coverage where marked).

### Network & infrastructure

| Module | What it does | Free sources (key status) |
|---|---|---|
| `certstream` | Certificate-transparency watch: new TLS certs for watched domains → typed alerts (daemon) | crt.sh (keyless) |
| `hostwatch` | Host exposure drift: Shodan InternetDB ports/CPE fingerprint + diff alerts (daemon) | Shodan InternetDB (keyless) |
| `wireless` | Wi-Fi/cell geolocation from public radio maps (BSSID/SSID/tower) | mylnikov WiFi/cell (keyless), Wigle (key) |
| `darknet` | Anonymizer exposure: Tor exit/VPN/proxy + threat blocklists, watch + alerts (daemon) | Tor bulk exit list, dan.me.uk, blocklist.de, ipsum, FeodoTracker (keyless) |
| `exposure` | Public exposure monitoring: breach mentions + web posture, watch + alerts (daemon) | XposedOrNot (keyless), Mozilla Observatory (keyless) |
| `brandguard` | Typosquat/lookalike domain generator + DNS/RDAP sweep for a brand | Google/Cloudflare DoH + RDAP (keyless) |
| `opsecaudit` | Passive web posture audit (headers/HSTS/TLS/robots/security.txt), **authorization-gated** (explicit authorization field required) | crt.sh, Observatory, direct GETs (keyless) |
| `supplychain` | Typosquat package probing across registries + snapshot watch (daemon) | PyPI / npm / crates.io / Go proxy (keyless) |
| `malintel` | IOC enrichment + file-hash reputation + optional local YARA scan | AlienVault OTX, MalwareBazaar, URLhaus (keyless), YARA (local optional) |

### Transport & imagery

| Module | What it does | Free sources (key status) |
|---|---|---|
| `flight` | Civil aircraft tracking: state by ICAO24, area snapshot, airport departures/arrivals, case attach | OpenSky Network (keyless, anonymous quota) |
| `maritime` | MMSI decode (flag/station/ship class), AIS vessel search, maritime news | local MID tables (keyless), MarineTraffic (key), GDELT (keyless) |
| `satellite` | Scene discovery (Sentinel-2 etc.) + daily imagery tile previews | Microsoft Planetary Computer STAC (keyless), NASA GIBS WMTS (keyless) |
| `hazards` | Natural-hazard monitoring: earthquakes, GDACS alerts, NWS alerts + brief | USGS, GDACS, US NWS (keyless) |

### Media & documents

| Module | What it does | Free sources (key status) |
|---|---|---|
| `imgverify` | Image provenance: perceptual hashes, near-dup detection, case attach, reverse-search links | local hashing (keyless) + Google/Bing/Yandex/TinEye link builders |
| `synthetic` | Media authenticity triage: EXIF/software signals + prior-art hash check | local EXIF parsing (keyless) |
| `docintel` | Document metadata: PDF/OOXML authorship, revision timeline, red flags, embedded links | local parsing (keyless) |
| `browserrender` | JS-rendered page capture (screenshot/text) when selenium installed | local optional dep (honest `caps:false` otherwise) |
| `feedstream` | Watched RSS/Atom feed ingestion + keyword alerts (daemon) | any public feed (keyless) |

### Identity & finance

| Module | What it does | Free sources (key status) |
|---|---|---|
| `identitytimeline` | URL/identity first-appearance timeline + multi-URL batch | Wayback CDX (keyless) |
| `kinship` | Family/associate graph from public records (+ obituary dorks), case edges | Wikidata SPARQL (keyless) |
| `property` | Land-registry directory (30 jurisdictions, official portals) + UK price-paid transactions | HM Land Registry price-paid API (keyless) |
| `donortrail` | Political donations: candidate/committee filings, donor flows, bulk mirrors | FEC open API (key), official registers directory (keyless) |
| `langintel` | Script/language detect, snippet translation, transliteration, name normalize + search-term expand | MyMemory (keyless), local Unicode tables |
| `filings` | Company filings: SEC EDGAR submissions, full-text search, insider trades | SEC EDGAR (keyless) |
| `onchain` | ETH/BTC address intel: resolve, balance/tx overview, NFTs, case anchor | Cloudflare & Llama RPC, Blockstream Esplora (keyless) |
| `trade` | Country trade partners + bilateral flows + concentration | UN Comtrade public preview (keyless) |

### Platform & community

| Module | What it does | Free sources (key status) |
|---|---|---|
| `adwatch` | Ad-library tracking: transparency links, ad-archive API, history + news context, bundle (daemon-capable) | Google Ads Transparency (keyless), Meta Ads Library (token), GDELT (keyless) |
| `coordcheck` | Coordination signals: near-dup text clusters, burst posting, cadence outliers (case or inline) | local analysis (keyless) |
| `broadcast` | Radio station directory + stream status + feed mentions + transmitter finder | Radio Browser API (keyless), local lookup |
| `community` | Community platform intel: Discord guild/widget/invite, Matrix public rooms, watch + snapshot diff (daemon) | Discord & Matrix public APIs (keyless) |
| `marketplace` | Marketplace/NFT account intel + listing watch + snapshot diff (daemon) | OpenSea (key), federated search (keyless) |
| `phishkit` | Phishing page tracking + campaign view + takedown letter workflow (daemon) | URLhaus, OpenPhish, PhishTank (keyless) |
| `foia` | FOIA request drafting + jurisdiction deadline calendar + submit/status ledger (daemon) | official portals directory (keyless) |
| `dsar` | Data-subject access request regimes (GDPR/CCPA/…) + letter drafts + deadline checks | local regime cards (keyless) |
| `graphstudio` | Interactive case-graph viewer (`/graph/<case_id>`, self-contained HTML) + server-side layout API | local (no build step) |

### Watch daemons

`certstream` (30 min), `hostwatch` (15 min), `darknet` (1 h), `exposure` (6 h),
`feedstream` (10 min), `supplychain` (3 h), `community` (30 min), `marketplace`
(12 h), `phishkit` (2 h), `foia` (12 h), `dsar` (6 h). All start with the app,
run in daemon threads, write typed alerts, and are controllable via their
module watch/unwatch/check endpoints.

### Key expansion endpoints

```bash
# CT + host monitoring
GET  /api/certstream/search?domain=      POST /api/certstream/watch|unwatch|check
POST /api/hostwatch/scan|watch|check     GET  /api/hostwatch/rdap?ip=
POST /api/wireless/wifi|ssid|cell        GET  /api/darknet/tor|ipsum|blocklist
POST /api/darknet/check|watch|check_all  POST /api/exposure/assess|watch|check_all

# transport & imagery
POST /api/flight/aircraft|area|airport|attach
POST /api/maritime/mmsi|search|news      POST /api/satellite/preview|scenes
GET  /api/satellite/layers               GET  /api/hazards/gdacs|nws|sources
POST /api/hazards/quakes|brief

# media & documents
POST /api/imgverify/hashes|attach|similar   GET  /api/imgverify/reverse_links
POST /api/synthetic/assess                  POST /api/docintel/analyze
POST /api/browserrender/render|text         GET  /api/browserrender/caps
POST /api/filings/company|filings|fulltext|insider

# identity & finance
POST /api/identitytimeline/timeline|age|multi
POST /api/kinship/resolve|relatives|graph|obituaries
POST /api/property/uk                       GET  /api/property/directory|where
POST /api/donortrail/candidate|receipts|flows   GET /api/donortrail/directory|bulk
POST /api/langintel/detect|translate|transliterate|normalize|expand
POST /api/malintel/file|hash|ioc|yara|attach
POST /api/onchain/resolve|account|nfts|anchor
POST /api/trade/flows|comtrade|concentration
POST /api/phishkit/check|campaign|takedown|check_all

# platform & community
POST /api/adwatch/links|api|history|news|bundle
POST /api/coordcheck/analyze        POST /api/coordcheck/case/<id>
POST /api/broadcast/stations|stream_status|feed_mentions|find
POST /api/community/guild|invite|matrix|watch|check_all
POST /api/marketplace/search|inspect|watch|check_all
POST /api/opsecaudit/run|quick      (authorization field required)
POST /api/supplychain/check|watch|check_all
GET  /api/feedstream/status         POST /api/feedstream/run
GET  /api/foia/jurisdictions|requests   POST /api/foia/draft|<id>/submit|<id>/status|check_deadlines
GET  /api/dsar/regimes|requests     POST /api/dsar/draft|<id>/status|check_deadlines
GET  /api/graph/<case_id>/layout    GET  /graph/<case_id>   (interactive viewer)
```

## Free APIs & public sources (entire project)

Every external source the platform touches. **Keyless** = works out of the box,
no registration. **Key** = free tier exists, set the env var to enable (module
still runs keyless without it). Polite pacing + identifiable User-Agent on all
calls; robots/ToS of each source still applies.

**DNS, certificates & domains**
- Google DoH — `https://dns.google/resolve` — keyless
- Cloudflare DoH — `https://cloudflare-dns.com/dns-query` — keyless
- crt.sh certificate-transparency search — `https://crt.sh/` — keyless
- RDAP (domain + IP) — `https://rdap.org/domain/`, `https://rdap.org/ip/` — keyless
- IANA TLD list — `https://data.iana.org/TLD/tlds-alpha-by-domain.txt` — keyless
- urlscan.io — public search — keyless
- DNSDumpster — `https://dnsdumpster.com/` — keyless
- Netcraft DNS search — `http://searchdns.netcraft.com` — keyless
- HackerTarget hostsearch — `https://api.hackertarget.com/hostsearch/` — keyless (rate-limited tier)
- SecurityTrails — `https://api.securitytrails.com/v1/` — key (`SECURITYTRAILS_API_KEY`)

**Infra, hosting & exposure**
- Shodan InternetDB — `https://internetdb.shodan.io/` — keyless
- Shodan host/host-search — `https://api.shodan.io/` — key (`SHODAN_API_KEY`)
- ip-api.com — geo/ASN/hosting — keyless
- ipinfo.io — `https://ipinfo.io/` — key (`IPINFO_TOKEN`)
- ThreatCrowd — domain report — keyless
- Mozilla Observatory scan — `https://observatory-api.mdn.mozilla.net/api/v2/scan` — keyless
- AbuseIPDB check/blacklist — `https://api.abuseipdb.com/api/v2/` — key (`ABUSEIPDB_API_KEY`)
- XposedOrNot — domain/email/IOC breach exposure — `https://api.xposedornot.com/v1/` — keyless

**Breaches, leaks, malware & dark web**
- XposedOrNot breach corpora — keyless
- HIBP breached-account / paste-account — `https://haveibeenpwned.com/api/v3/` — key (`HIBP_API_KEY`)
- Ahmia dark-web search — `https://ahmia.fi/search/` — keyless
- IntelX free tier — `https://free.intelx.io/` — key (`INTELX_API_KEY`)
- AlienVault OTX indicator pulses — `https://otx.alienvault.com/api/v1/indicators/` — keyless
- MalwareBazaar — `https://mb-api.abuse.ch/api/v1/` — keyless
- URLhaus — `https://urlhaus-api.abuse.ch/v1/` — keyless
- VirusTotal — `https://www.virustotal.com/api/v3/` — key (`VIRUSTOTAL_API_KEY`)
- FeodoTracker botnet C2 blocklist — `https://feodotracker.abuse.ch/downloads/ipblocklist.txt` — keyless
- OpenPhish phishing feed — `https://openphish.com/feed.txt` — keyless
- PhishTank verified feed — `https://data.phishtank.com/` — keyless (`PHTANK_API_KEY` deepens quota)

**Anonymizer & threat lists**
- Tor bulk exit list — `https://check.torproject.org/torbulkexitlist` — keyless
- dan.me.uk Tor relay list — `https://www.dan.me.uk/torlist/` — keyless (strictly rate-limited)
- blocklist.de attacker IPs — `https://www.blocklist.de/downloads/iplist.txt` — keyless
- ipsum aggregated blocklists — `raw.githubusercontent.com/stamparm/ipsum` — keyless

**Search, dorking & news**
- DuckDuckGo HTML — `https://html.duckduckgo.com/html/` — keyless
- SearXNG public instances — `https://searx.be` etc. — keyless
- Mojeek — `https://www.mojeek.com/search` — keyless
- Bing / Google / Yandex web search — keyless (ToS-constrained relay)
- GDELT Doc API (news/events) — `https://api.gdeltproject.org/api/v2/doc/doc` — keyless
- Wikipedia / Wikimedia API — `https://en.wikipedia.org/w/api.php` — keyless
- Wikidata API + SPARQL — `https://www.wikidata.org/`, `https://query.wikidata.org/sparql` — keyless

**People, identity & research**
- Wikidata SPARQL (people/relations) — keyless
- OpenAlex authors/works — `https://api.openalex.org/` — keyless
- Semantic Scholar author search — `https://api.semanticscholar.org/graph/v1/` — keyless
- ORCID expanded search — `https://pub.orcid.org/v3.0/expanded-search/` — keyless
- OpenLibrary author search — `https://openlibrary.org/search/authors.json` — keyless
- Keybase profile lookup — `https://keybase.io/_/api/1.0/user/lookup.json` — keyless
- Gravatar profile — `https://en.gravatar.com/` — keyless
- Mastodon account lookup/search — `https://mastodon.social/api/v1/accounts/lookup` — keyless
- Bluesky public API — `https://public.api.bsky.app/xrpc/app.bsky.actor.searchActors` — keyless
- MyMemory translation — `https://api.mymemory.translated.net/get` — keyless
- emailrep.io — `https://emailrep.io/` — key (`EMAILREP_API_KEY`)
- Numverify/apilayer — phone validation — key (`NUM_API_KEY`)

**Social platform matrix (90+ public profile probes, keyless)**
- GitHub, GitLab, Codeberg, Gitea, Bitbucket-style hosts, HuggingFace, Docker Hub, Replit
- X/Twitter, Instagram, Threads, Facebook, TikTok, Snapchat, Reddit, Bluesky, Mastodon, Gab, Truth Social, Gettr, VK, OK.ru, Weibo, Zhihu, Douban, Bilibili, Douyin
- LinkedIn, About.me, Keybase, Linktree, DeviantArt, Dribbble, Behance, Figma-style portfolios
- YouTube, Twitch, Spotify, SoundCloud, Bandcamp, Last.fm, Flickr, 500px, Unsplash, Letterboxd
- Medium, Dev.to, Substack-style, Wattpad, AO3, Goodreads, ResearchGate, Academia.edu
- Kaggle, LeetCode, HackerNews, Exercism, TryHackMe, Steam, Roblox, Xbox, Duolingo
- Patreon, BuyMeACoffee, Ko-fi, Etsy, eBay, Fiverr, Freelancer, Trello, Quora
- Telegram public previews (`t.me/s/…`), Discord public profiles, Twitch, Rumble, Odysee, Archive of Our Own

**Corporate, finance & filings**
- OpenCorporates company search — key (`OC_API_KEY`)
- GLEIF LEI records — `https://api.gleif.org/api/v1/lei-records` — keyless
- EU VIES VAT check — `https://ec.europa.eu/taxation_customs/vies/` — keyless
- UK Companies House — `https://api.company-information.service.gov.uk` — key (`CH_API_KEY`)
- SEC EDGAR submissions + full-text search — `https://data.sec.gov/`, `https://efts.sec.gov/LATEST/search-index` — keyless
- FEC open API — `https://api.open.fec.gov/v1/` — key (`FEC_API_KEY`)
- EU Transparency Register — keyless
- National party-donation registers (DE Bundestag, AT HATVP, CH, IE, IN ECI/DILRMP, BR TSE, AE Dubai, ZA deeds, IL, PL EKW, KR iROS, FI kiintokeskus, GR geoyst, DK ejendomsinfo, PT registropublico…) — keyless official portals (see `property`/`donortrail`/`foia` directories)

**Sanctions, screening & courts**
- OFAC SDN (CSV/XML + sanctions-list service API) — `https://sanctionslistservice.ofac.treas.gov/api/` — keyless
- UN consolidated sanctions — `https://scsanctions.un.org/resources/xml/en/consolidated.xml` — keyless
- UK OFSI consolidated list — `https://ofsistorage.blob.core.windows.net/publishlive/` — keyless
- EU consolidated list — keyless
- OpenSanctions dataset mirror — `https://data.opensanctions.org/datasets/latest/` — keyless
- CourtListener — `https://www.courtlistener.com/api/rest/v4/search/` — keyless
- BAILII (UK) — `https://www.bailii.org` — keyless
- AustLII (AU) — keyless
- HUDOC (ECHR) — `https://hudoc.echr.coe.int/app/query/results` — keyless
- Indian Kanoon — `https://indiankanoon.org/search/` — keyless

**Property & land**
- HM Land Registry price-paid API — `https://prodapi.landregistry.gov.uk/price-paid/` — keyless
- Official land-registry portals directory (30 jurisdictions: NL Kadaster, SE Lantmäteriet, DE Katasteramt, NO Kartverket, NZ LINZ, BC Land Title, SG SLA, ES Sedecatastro, IE PRA, UA map.land.gov.ua, GR geoyst, DK ejendomsinfo, FI kiintokeskus, PT Justica, ZA deeds, AT Grundbuch, CH zh.ch, PL EKW, JP MLIT, IN DilRMP…) — keyless (see `/api/property/directory`)

**Transport & radio**
- OpenSky Network — `https://opensky-network.org/api` — keyless (anonymous quota)
- MarineTraffic AIS — `https://www.marinetraffic.com/api/v2/` — key (`MARINETRAFFIC_API_KEY`)
- mylnikov WiFi/cell geolocation — `https://api.mylnikov.org/geolocation/` — keyless
- Wigle WiFi/cell search — `https://api.wigle.net/api/v2/` — key (`WIGLE_BASIC_AUTH`)
- Radio Browser API — `https://at1.api.radio-browser.info` (auto-balanced mirrors) — keyless

**Satellite, geo & imagery**
- Microsoft Planetary Computer STAC — `https://planetarycomputer.microsoft.com/api/stac/v1/search` — keyless
- NASA GIBS WMTS — `https://gibs.earthdata.nasa.gov/wmts/epsg3857/best` — keyless
- OpenAerialMap — `https://api.openaerialmap.org/meta` — keyless
- OSM Nominatim geocode — `https://nominatim.openstreetmap.org` — keyless (polite)
- OSM Overpass — `https://overpass-api.de/api/interpreter` (+ kumi mirror) — keyless
- Mapillary street imagery — `https://graph.mapillary.com/images` — key (`MAPILLARY_CLIENT_TOKEN`)
- Zippopotam postal geocode — `http://api.zippopotam.us/` — keyless
- US Census place files — `https://www.census.gov/…/complete-place-files.html` — keyless

**Trade & economy**
- UN Comtrade public preview — `https://comtradeapi.un.org/public/v1/preview/` — keyless
- World Bank API — `https://api.worldbank.org/v2/country/` — keyless

**Supply chain (package registries)**
- PyPI JSON API — `https://pypi.org/pypi/` — keyless
- npm registry — `https://registry.npmjs.org/` — keyless
- crates.io — `https://crates.io/api/v1/crates/` — keyless
- Go module proxy — `https://proxy.golang.org/` — keyless

**Ads, community & messaging**
- Google Ads Transparency Center — `https://adstransparency.google.com/` — keyless
- Meta Ads Library archive API — `https://graph.facebook.com/v19.0/ads_archive` — key (`META_ACCESS_TOKEN`)
- Discord widget/invite/guild API — `https://discord.com/api/v10` — keyless
- Matrix public rooms — `https://matrix.org/_matrix/client/v3/publicRooms` — keyless
- Telegram public channels — `https://t.me/s/` — keyless

**Crypto (public chains)**
- Cloudflare ETH JSON-RPC — `https://cloudflare-eth.com` — keyless
- LlamaRPC ETH — `https://eth.llamarpc.com` — keyless
- Blockstream Esplora (BTC) — `https://blockstream.info/api` — keyless (+ testnet)
- OpenSea API — `https://api.opensea.io/api/v2/` — key (`OPENSEA_API_KEY`)
- Etherscan — link-outs — keyless

**Hazards & weather**
- USGS earthquakes (feeds + FDSN) — `https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/` — keyless
- GDACS event list — `https://www.gdacs.org/gdacsapi/api/events/geteventlist/MAP` — keyless
- US NWS alerts — `https://api.weather.gov/alerts/active` — keyless

**Email & phone**
- MX/SPF/DKIM via DoH (Google/Cloudflare) — keyless
- Gravatar + social cross-check — keyless
- Numverify — key (`NUM_API_KEY`) — keyless fallback via `phonenumbers` lib

**Reverse image & icons**
- Google Lens / Bing Visual Search / Yandex Images / TinEye — URL builders (keyless)
- icon.horse favicon aggregation — `https://icon.horse/icon/` — keyless

**AI narrative assist (optional)**
- Groq — `https://api.groq.com/openai/v1/chat/completions` — key (`GROQ_API_KEY`)
- Google Gemini — `https://generativelanguage.googleapis.com/v1beta/models/` — key (`GEMINI_API_KEY`)

**Local, no network**
- Perceptual hashing / EXIF / OOXML-PDF parsing / YARA (optional rules dir) / MMSI MID decode / name normalization tables / FOIA+DSAR deadline calendars / coordination-signal analysis / graph layout — all local, keyless.

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
- **opsecaudit is authorization-gated**: every run requires an explicit `authorization` field (engagement/ticket reference); it performs passive GET/header observation only — no scanning, fuzzing or exploitation.
- **All new monitors are passive**: CT logs, blocklists, package registries, ad libraries, community APIs and marketplaces are read via public endpoints; watch daemons diff public snapshots and alert — they never log in, post, or interact with targets.
- **flight/maritime/wireless/satellite** read public state (OpenSky, MID tables, radio maps, open STAC/WMTS catalogs) — no transponder interrogation, no AIS position forging, no wardriving.
- No `shell=True` in runner; shlex-quoted substitution + unresolved-placeholder reject.
- Filename / id sanitization + path-traversal guards on `/api/output`.
- Atomic JSON writes, capped history (500), CORS locked down via env in prod.
- Collector + watchlist sweep run in daemon threads, never block boot.

## Upstream full-parity notes

- OSINT_APP's AI briefs / bulk-protect / encrypted per-session keys live in `modules/threat_intel/legacy_app.py` — ported on demand into `app.py`.
- campwill Jinja templates kept under `modules/forensics/templates_ref` for reference.
- OSINTel streaming SSE + clone-url tools: executor supports streaming; clone-on-install intentionally left out for server hardening (add allowlist if needed).
