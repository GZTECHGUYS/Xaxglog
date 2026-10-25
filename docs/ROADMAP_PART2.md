# Xaxglog Upgrade Roadmap — PART 2 (International Deep OSINT Additions)

Saved: 2026-10-16. Part 2 extends Part 1 (see ROADMAP_PART1.md) with
**international / multilingual / free-only** capabilities so the platform
performs deep OSINT on any country without paid providers.

Access legend: 🔓 keyless free · 🔑 free API key · 💰 paid · ⛔ authority-gated

## P2-1. Multilingual & name intelligence (the international multiplier)

| Module | What it does | Access |
|---|---|---|
| Name variant engine | Generate every plausible form: Cyrillic↔Latin transliteration, Arabic romanization, Pinyin/Wade-Giles, Kana, Devanagari, diacritic stripping, leet/handle variants, culturally typical nicknames | 🔓 |
| Cross-script query fan-out | Run each variant natively (Russian in Cyrillic, Chinese in Hanzi, Arabic RTL) across search engines | 🔓 |
| IDN homograph detector | Punycode confusable domains, lookalike ccTLDs, typosquat detection | 🔓 |
| Language ID + region inference | Detect language/dialect of evidence, route to right regional sources | 🔓 |
| Stylometric geolocation | Idioms, spelling, punctuation habits → likely country/region of author | 🔓 |
| Transliteration-aware matcher | "Медведев" ≈ "Medvedev" in screening, entity resolution and FTS | 🔓 |

## P2-2. Global corporate & ownership intelligence

| Module | What it does | Access |
|---|---|---|
| GLEIF LEI explorer | Global Legal Entity Identifier: cross-border parent-child ownership chains, status flags | 🔓 |
| UK Companies House API | Officers, PSCs, filings, charges for every UK company | 🔑 free |
| EU VAT validation (VIES) | VAT number → verified legal name + address, all EU states | 🔓 |
| Registry router matrix | Per-country connector map: FR SIRENE (free), DE/IT/NL/SE/NO/PL sources, with format validators | 🔑/🔓 |
| ICIJ Offshore Leaks DB | Panama/Pandora/Cybahaven offshore entities + officers + relationships (free CSV) | 🔓 |
| OpenOwnership register | Published UBO statements | 🔓 |
| Company-number validator | ISO country format checks + which jurisdiction has a free registry | 🔓 |

## P2-3. Global courts, law & regulatory registers

| Module | What it does | Access |
|---|---|---|
| Court network connector | BAILII (UK), CanLII (CA), AustLII/NZLII (Oceania), SAFLII (ZA), HKLII + Indian Kanoon (Asia), CURIA + HUDOC (EU) | 🔓 |
| Regulatory register router | FCA (UK), FINRA BrokerCheck, NMLS, ASIC (AU), MAS (SG), BaFin, AMF, GMC (UK doctors) | 🔓/🔑 |
| Charity/NGO registers | UK Charity Commission API + EU equivalents | 🔑 |
| Provider registry | NPI (US healthcare) + EU professional registers | 🔓 |
| Radio callsign DB | Amateur/GMRS license → public licensee name/location | 🔓 |
| Debarment watch | World Bank debarred firms + national debarment lists | 🔓 |

## P2-4. Global sanctions / PEP upgrade

| Module | What it does | Access |
|---|---|---|
| OpenSanctions aggregator | One local index over 1000+ lists (sanctions, PEP, RCA, aliases, native-script names) — the strongest free screening base | 🔓 |
| Regional list merger | EU consolidated, UK OFSI, Canada SEFA, Australia DFAT, Japan MOF, Switzerland SECO, India MEA, Singapore MAS | 🔓 |
| FATF grey/black list monitor | Country list changes → alert | 🔓 |
| Relatives & associates graph | RCA edges (family/associates) into the case graph | 🔓 |
| Native-script alias matching | Screen "Владимир Путин" and "Vladimir Putin" as the same hit | 🔓 |

## P2-5. International trade, money & influence

| Module | What it does | Access |
|---|---|---|
| UN Comtrade | Import/export partner flows, HS codes, trade-money trails (free API) | 🔓 |
| Procurement international | World Bank procurement (free) + UK Contracts Finder (free key) | 🔑 |
| Influence registers | EU Transparency Register (lobbyists, free CSV) + US LD-2 lobbying bulk | 🔓 |
| IBAN/SWIFT intelligence | Format validation + country bank-ID registry, BIC lookups | 🔓 |
| OpenFIGI | Securities identifier mapping (ISIN/CUSIP/ticker → instrument → issuer) | 🔓 |
| International donations | UK Electoral Commission donations + EU political funding | 🔓 |

## P2-6. Country risk & conflict context

| Module | What it does | Access |
|---|---|---|
| Country risk profile | TI Corruption Index, RSF Press Freedom, WJP Rule of Law, Fragile States, World Bank/IMF indicators (all free bulk) | 🔓 |
| GDELT event stream | Global news-event database: who is mentioned with whom, 15-min cadence | 🔓 |
| ACLED conflict events | Political violence/protest events by country (free research key) | 🔑 |
| Jurisdiction legal card | Per-country data-protection / scraping / PI-licensing notes shown *before* querying | 🔓 local |
| Travel/sanctions overlay | Case travel plan vs sanctions/export-control country overlays | 🔓 |

## P2-7. Regional platforms & search engines

| Module | What it does | Access |
|---|---|---|
| Regional engine router | Baidu (CN), Yandex (CIS), Naver (KR), Seznam (CZ), Qwant/Brave, Sogou, Mojeek — country-appropriate results + dorks | 🔓 |
| Telegram public monitor | Public channel/post timelines keyless via t.me/s/ previews | 🔓 |
| China coverage | Weibo (m.weibo.cn), Zhihu, Tieba, Baidu ecosystems | 🔓 |
| Korea/Japan coverage | Naver blog/kin, Yahoo!Japan, 5ch archives | 🔓 |
| Russia/CIS coverage | VK public pages, OK.ru, Habr, RuTube | 🔓/🔑 |
| Platform coverage matrix | Dashboard: which connectors are live per region/country | 🔓 |

## P2-8. Global geospatial (includes the "buildings" ask)

| Module | What it does | Access |
|---|---|---|
| Mapillary street-level | International Street View alternative (free key), image timeline per road | 🔑 |
| OSM Overpass query | POIs, buildings, landuse, amenities at a coordinate | 🔓 |
| Building footprints | Microsoft Open Buildings + OSM footprints — global building shapes → map coverage | 🔓 |
| GeoNames gazetteer | All-country populated places/admin divisions (free bulk dump) | 🔓 |
| Aerial history | OpenAerialMap + USGS EarthExplorer historical imagery | 🔓 |
| National addressing | Free addressing/postal-code systems where available | 🔓 |

## P2-9. Global technical free intel

| Module | What it does | Access |
|---|---|---|
| RIR allocation history | RIPE/ARIN/APNIC/LACNIC/AFRINIC: netblock owner over time (free whois/API) | 🔓 |
| IPv6 + RDAP coverage | Full IPv6/RDAP lookups via IANA bootstrap | 🔓 |
| Origin-IP discovery | Behind-CDN host: CT + mail records + DNS history + SMTP banner | 🔓 |
| Phishing feeds | PhishTank + OpenPhish community + APWG; kit-hash reuse clustering | 🔓 |
| Malware intel | MalBazaar samples + SSDEEP fuzzy-hash cross-case duplicate detection | 🔓/🔑 |
| Exposure severity | Observed tech → NVD CVE + CISA KEV prioritization | 🔓 |

## P2-10. Engine glue (free + international at scale)

| Module | What it does | Access |
|---|---|---|
| Bulk dataset manager | Auto-download + local FTS indexes: OpenSanctions, GLEIF, GeoNames, ICIJ, OFAC/EU lists → instant keyless search | 🔓 |
| Free-API quota manager | Per-source rate budgets, daily caps, backoff, latency/cost dashboard | 🔓 |
| Source health + fallback | Live up/down checks; auto-failover Baidu → Yandex → Brave | 🔓 |
| Cross-case entity dedupe | Same person/entity across all investigations → canonical node | 🔓 |
| Country collection plan | "Best free sources for jurisdiction X" auto-runs on case open | 🔓 |

## Recommended build order (Wave 3B)

1. P2-1 Name variant engine + cross-script fan-out (unlocks every other module internationally)
2. P2-4 OpenSanctions aggregator (free, replaces hand-merged lists)
3. P2-2 GLEIF + Companies House + VIES (corporate ownership without paying)
4. P2-3 Court network connector
5. P2-7 Regional engine router + Telegram/China coverage
6. P2-8 Mapillary + building footprints (finishes original CCTV/buildings ask)
7. P2-10 Bulk dataset manager + quota manager (powers everything keyless)
8. P2-6 GDELT + country risk profile
