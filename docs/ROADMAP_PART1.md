# Xaxglog Upgrade Roadmap — PART 1 (11 Phases)

Saved: 2026-10-16. These phases define the first major expansion wave beyond the
21 shipped modules. Access legend:

- 🔓 = works keyless (free, no account)
- 🔑 = free API key
- 💰 = paid provider
- ⛔ = authority-gated (SS7 lawful-access pattern)

## 1. Deep-search core (make the search engine itself heavier)

| Module | What it does | Access |
|---|---|---|
| Federated search | SearxNG/self-hosted meta-search: fan one query across DDG/Yandex/Brave/Wikipedia + dedupe + rank | 🔓 |
| Dork engine | Automated Google/Bing/Yandex dork templates per entity type (site:, filetype:, intitle:, inurl:) with result custody | 🔓 |
| Common Crawl index | Query petabyte historical web corpus — find pages that existed years ago | 🔓 |
| GreyNoise context | Is this IP scanning everyone or targeting you? | 🔑 free |
| Shodan InternetDB | Ports/vulns/CPE per IP without a key | 🔓 |
| Search receipt custody | Every query result hashed + stored as evidence with source receipt | 🔓 |

## 2. Web time machine (deleted/changed content)

| Module | What it does | Access |
|---|---|---|
| Wayback CDX | Full site history: every archived snapshot, diff two versions | 🔓 |
| Archive.today | Other archivers' snapshots | 🔓 |
| Domain timeline | DNS/WHOIS/subdomain history stitched over time (Wayback + crt.sh + CT) | 🔓 |
| Change watch daemon | Watch a URL: content-hash diff → alert when page changes (defacement, takedown, edit) | 🔓 |
| Historical favicon/TLS fingerprint | Match "same infrastructure" across time via favicon hash (Murmur3) + cert SHA-256 | 🔓 |

## 3. People & communications intel

| Module | What it does | Access |
|---|---|---|
| Email deep-dive | Full header analysis, SPF/DKIM/DMARC chain, disposable-domain flag, breach timeline, MX provider fingerprint | 🔓 |
| Email↔account graph | Email is the hub: link every username/module hit back to one email node | 🔓 |
| Phone deep-dive | Reputation, carrier port-out risk, numbering-plan timeline (extends simswap) | 🔓 |
| Social interaction graph | Crawl public profiles → who replies/mentions/retweets whom → community clusters | 🔓 |
| Bot/inauthentic-behavior score | Posting cadence, account age, handle churn, network shape → sockpuppet detection | 🔓 |
| Username timeline | First-seen/last-seen per platform (Wayback on profile URLs) → activity pattern of life | 🔓 |
| Handle migration tracker | Same handle reused across platforms → unified actor identity graph | 🔓 |

## 4. Technical attribution (deeper pivots)

| Module | What it does | Access |
|---|---|---|
| Passive-DNS pivot | Historical IP↔domain bindings (hackertarget/BufferOver/Rapid7 Open Data) | 🔓/🔑 |
| BGP/routing intel | RIPE RIS/BGPStream: who announces this netblock, origin-change history | 🔓 |
| Rapid7 Sonar datasets | Internet-wide scan data — free bulk (HTTP banners, DNS, FTP) | 🔓 |
| Wappalyzer-style tech fingerprint | CMS/framework/server detection from headers/HTML + CVE mapping | 🔓 |
| Subdomain enumeration 2.0 | amass-style: wayback + DNSDumpster + bufferover + brute module, all into graph | 🔓 |
| WHOIS-change watch | Registrar/name-server change → alert (infrastructure rotation detection) | 🔓 |
| APT infrastructure clustering | Group all observed infra by cert reuse + favicon + JA3 → campaign tracks | 🔓+keys |

## 5. Financial & crypto (deeper)

| Module | What it does | Access |
|---|---|---|
| ETH/ERC-20 + multi-chain | Token transfers, ENS, TRX/LTC/DOGE addresses | 🔓 |
| Address clustering | Common-input-ownership + change-address heuristics → wallet clusters | 🔓 |
| Exchange/mixer labels | Public label datasets (Dune/Glassnode free tiers, known-service corpus) | 🔑 |
| Cross-chain bridge tracer | Follow funds BTC→bridge→ETH (public bridge event logs) | 🔓 |
| Sanctions address screen | OFAC crypto address list screening | 🔓 |
| Fiat on-ramp trail | KYC'd-exchange endpoints noted as "where chain exits to KYC" (gated request if subpoena needed) | ⛔ |

## 6. Corporate, legal & government records

| Module | What it does | Access |
|---|---|---|
| Court records | CourtListener/RECAP full-text US federal+state opinions & dockets | 🔓 |
| SEC/EDGAR full-text | Filings search, insider/officer links, 13D/G ownership changes | 🔓 |
| SAM.gov exclusions | Debarred/sanctioned contractors (official US list) | 🔑 free |
| USAspending | Contract/award money trails to entities | 🔓 |
| EU TED tenders | Public procurement notices across EU | 🔓 |
| FEC political donations | Donor→candidate flows | 🔓 |
| Patent/trademark | USPTO + EPO OPS: inventor→company→assignment history | 🔓/🔑 |
| UBO/beneficial-owner register | EU public UBO registries (access rules vary by country — legal review per jurisdiction) | ⛔/💰 |
| Litigation/entity map | All lawsuits involving an entity → plaintiffs, defendants, counsel, outcomes | 🔓 |

## 7. Geospatial & physical world (heavier GEOINT)

| Module | What it does | Access |
|---|---|---|
| Wayback-imagery timeline | Historic satellite/street imagery dates per coordinate (ESRI/Google static history + OSM changeset history) | 🔓 |
| OSM changeset diff | What changed on the ground at a coordinate over time | 🔓 |
| ADS-B flight tracker | OpenSky: aircraft position history → aircraft registration → owner | 🔓 |
| AIS ship tracker | Vessel tracks, MMSI→IMO→flag owner (gated for paid feeds) | 🔑/⛔ |
| NASA FIRMS | Fires/industrial-heat anomalies globally (12h latency) | 🔑 free |
| Sentinel-2 imagery | Free satellite revisit every ~5 days, cloud cover aware | 🔓 |
| WiGLE Wi-Fi geolocation | BSSID→location & network history (device geolocate) | 🔑 free |
| Weather/alibi verification | NOAA archive: was it actually raining that day? | 🔓 |

## 8. Media, documents & forensics (deep forensics)

| Module | What it does | Access |
|---|---|---|
| Reverse image search | Yandex (best on faces)/Google/TinEye fan-out → where did this image come from | 🔓/💰 |
| Image provenance | EXIF + C2PA/Content-Credential check + perceptual hash + deepfake/AI-artifact indicators | 🔓 |
| Document forensics | PDF/Office metadata, author, revision history, template origin | 🔓 |
| OCR pipeline | Scanned docs/photos → text → straight into FTS + NER | 🔓 tesseract |
| Audio/video transcription | Evidence audio → text (whisper local or API) → searchable | 🔓/🔑 |
| Video platform search | YouTube Data API + Rumble crawl → upload timelines | 🔑 free |
| LLM evidence narrative | Read all case evidence → auto-draft findings with citations to artifact hashes (Groq/Gemini keys already in .env) | 🔑 |

## 9. Dark web & leak monitoring

| Module | What it does | Access |
|---|---|---|
| Forum indexer | Torch + Ahmia + forum RSS scrapers, periodic re-crawl, diff | 🔓 |
| Credential-exposure monitor | Watch watchlisted emails/domains in breach corpora → new-exposure alerts | 🔓 |
| Market/vendor tracker | Public marketplace/vendor reputation snapshots (custody-stored) | 🔓 |
| Paste-site monitor | Ghostbin/pastebin-family new-paste watch for watchlisted strings | 🔓 |
| Tor egress OPSEC | Route dark-web queries through Tor SOCKS + separate custody log | 🔓 torsocks |

## 10. Fusion & automation — the glue that makes it "intensive"

| Module | What it does | Access |
|---|---|---|
| Entity resolution engine | Cross-module dedupe: "John Smith" = "jsmith" = "j.smith@mail" → one canonical node with aliases | 🔓 |
| Master timeline | Every artifact/scan/sighting/registration merged into one scrollable event stream | 🔓 |
| Auto-pivot chains | Configurable playbooks: domain → IPs → ASN → crypto → corporate → screen in one click, results all enter graph | 🔓 |
| Corroboration scoring | Claim confidence = # of independent sources agreeing; flag single-source facts | 🔓 |
| Pattern-of-life engine | Regularity analysis over timelines (active hours, travel loops, posting rhythm) | 🔓 |
| Graph engine upgrade | Replace SVG with force-directed clustered layout (Cytoscape/sigma.js), communities + betweenness centrality | 🔓 |
| Watchlist fan-out | One watchlisted entity sweeps all 21+ modules on schedule, not just 3 | 🔓 |
| NLP entity extraction | NER over all evidence text → auto-create person/org/place/date entities | 🔓/🔑 |
| Translation layer | Multilingual OSINT → case language (MyMemory/Google free endpoint) | 🔓 |
| PLAYBOOK runner | Saved multi-step investigations re-runnable on new targets, diffed against last run | 🔓 |

## 11. Sharing & operations

| Module | What it does | Access |
|---|---|---|
| MISP bidirectional sync | Push/pull threat intel communities | 🔓 self-host |
| TAXII live export | STIX bundles on a schedule to your TAXII server (STIX already exists) | 🔓 |
| PDF/DOCX report pipeline | HTML brief → PDF (weasyprint) + DOCX for prosecutors | 🔓 |
| Redaction engine | Auto-redact PII in exports per policy (SSN-pattern, minors, addresses) | 🔓 |
| Collection plans | Case checklist: required sources per case type, completion % | 🔓 |

## Recommended build order (Wave 3A)

1. PLAYBOOK / auto-pivot chains
2. Master timeline + entity resolution
3. Wayback CDX + change watch
4. Email deep-dive + email↔account graph
5. Federated search + dork engine
6. Watchlist fan-out
7. Graph engine upgrade (force layout + communities)
8. LLM evidence narrative
