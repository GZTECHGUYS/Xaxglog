# Declarative module registry

Xaxglog now has a **data-first module registry**. One module is a declaration
plus a probe recipe, not a new Python file. This is the scalable path for source
coverage: adding a public JSON API, a public profile page, a public search page
or an oEmbed endpoint is a small declaration and a live verification run.

The registry is intentionally honest. It does **not** claim Osintly's 1,835
entries are implemented. Osintly's public registry is useful as a candidate
list, but its execution is CAPTCHA/credit-gated and its backend is closed.
Xaxglog keeps its own public/free probes and reports only what actually works
from this host.

## Status vocabulary

| Status | Automatic evidence? | Meaning |
|---|---|---|
| `verified` | yes | Live-checked JSON/API/adapter returned usable rows, twice consistently |
| `fragile` | yes | Live-checked public HTML/profile/search scrape returned usable rows; can break at any time |
| `adapter` | no | Code exists but this registry has not live-checked it |
| `candidate` | no | Declarative probe exists; run verification before trusting it |
| `optional_key` | no | Free API with an operator-supplied key; no key means no automatic result |
| `link_out` | no | Public search/profile link for the analyst; never a result |
| `blocked` | no | Anti-bot/login/captcha/rate wall; never reported as "no results" |
| `error` | no | Endpoint/connection error from this host |
| `unstable` | no | Passed once but failed the stability check |

Only `verified` and `fragile` modules are executed by default. A blocked or
optional-key source is never silently treated as empty. Scraped sources are
always marked `fragile`.

## Probe types

The registry has six generic types. Adding a source usually means filling one
of these objects.

### `json_api_probe`

```python
{
  "type": "json_api_probe",
  "url": "https://api.example.org/search?q={q}&limit=8",
  "items_path": "data.items",
  "fields": {"name": "title", "url": "link", "snippet": "summary",
             "author": "author.name", "date": "published", "id": "id"},
  "result_url": "https://example.org/item/{id}",
  "limit": 8
}
```

`items_path` is a dotted path. `fields` values are dotted paths or lists of
candidate paths. `result_url` is optional and can use fields from the item.
The probe requires HTTP 200, valid JSON, a list, and at least one row with a
name/title or URL.

### `http_profile_probe`

```python
{
  "type": "http_profile_probe",
  "url": "https://example.org/@{u}",
  "limit": 1
}
```

`{u}` is the handle variant, `{q}` is the raw query. The probe parses
OpenGraph/Twitter/title/canonical metadata, rejects not-found/login-wall
markers, and marks successful rows `fragile: true`.

### `html_search_probe`

```python
{
  "type": "html_search_probe",
  "url": "https://example.org/search?q={q}",
  "limit": 10
}
```

Extracts external anchors from a public search page. It is always fragile and
always refused for Google/Bing result pages; use their official API or a
clearly marked link-out instead.

### `oembed_probe`

```python
{
  "type": "oembed_probe",
  "url": "https://www.youtube.com/oembed?url={q}&format=json"
}
```

Requires JSON with a title/author and returns the public metadata row.

### `adapter_probe`

```python
{"type": "adapter_probe", "adapter": "people.openalex"}
```

Delegates to an existing keyless adapter in `modules.identity.adapters`,
`modules.deep_search.social.PEOPLE_SOURCES` or `modules.searchx.ENGINE_FNS`.
This is how the existing verified inventory stays usable without duplicating
code.

### `link_out`

```python
{"type": "link_out", "url": "https://example.org/search?q={q}"}
```

Never executed automatically. The engine returns it in `link_outs` only.

## Adding a module

1. Prefer a real public/free source with a documented API or public HTML page.
2. Add a declaration to the source registry or a `PROBE_OVERRIDES` entry for a
   source that needs a declarative API shape.
3. Run verification with a positive query and `checks=2`.
4. Only a stable `verified`/`fragile` result becomes automatic. Persist it with
   `persist=true`; the overlay lives in `data/module_registry_status.json`
   (git-ignored, owner-only).
5. Add a test with a mocked `fetch`/adapter. Never make the unit suite depend on
   a live third-party site.

## Installed module packs

Module packs are versioned JSON bundles of declarative modules. Installed packs
live in `data/module_packs/` and are loaded by the registry on startup or after
`reload()`. A pack cannot self-certify `verified`/`fragile`: probe modules enter
as `candidate` and link-outs as `link_out` until a live verification pass from
this host changes the overlay. Disabling or rolling back a pack rewrites the
pack file's `enabled` flag and reloads the registry, so disabled modules do not
linger after a restart.

Install/validate/rollback endpoints are under `/api/platform/packs*`; see
`docs/PHASES.md` and `sdk/sign_pack.py` for HMAC signing.

## API

| Endpoint | What it does |
|---|---|
| `GET /api/module-registry/summary` | Honest counts by status, probe, category and access |
| `GET /api/module-registry/types` | Probe/status vocabulary |
| `GET /api/module-registry/modules?status=verified&category=people&limit=100` | Filtered module list |
| `GET /api/module-registry/modules/<id>` | One module including its probe payload |
| `POST /api/module-registry/search` | Run verified/fragile modules; dedupe, rank, coverage and "why empty" diagnostics |
| `POST /api/module-registry/verify` | Live-check selected ids; requires analyst+; `checks`, `timeout`, `persist` |
| `GET/POST /api/module-registry/links` | Build public browser link-outs (never API URLs) |

Search body:

```json
{
  "query": "Jane Doe",
  "types": ["name", "social"],
  "categories": ["people", "social"],
  "limit": 60,
  "timeout": 8,
  "max_workers": 8,
  "include_link_out": true
}
```

Verification body:

```json
{
  "ids": ["wikipedia", "github_users", "crossref"],
  "query": "Albert Einstein",
  "checks": 2,
  "timeout": 8,
  "persist": true
}
```

## Current honest snapshot

Run these commands for the live values:

```bash
curl -s http://127.0.0.1:5000/api/sources/summary
curl -s http://127.0.0.1:5000/api/module-registry/summary
```

At the time of this implementation:

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

The realistic target is **300–600 genuinely verified/queryable modules plus
1,000+ link-outs**, not a padded 1,835 count. The registry is designed so that
verification, not marketing, decides the number.

## Legal and operational boundaries

- Public/free OSINT only. No login-wall bypass, captcha solving, private
  databases, paywalled law-enforcement data or unauthorized device access.
- Access order: free API → public HTML scrape → link-out fallback.
- Do not scrape Google/Bing result pages. Use official APIs or link-outs.
- Respect robots/rate limits and each source's terms.
- Name/profile matches are leads, not identity proof. Verify against primary
  sources and applicable law.
