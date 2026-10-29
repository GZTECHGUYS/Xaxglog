# Xaxglog Phase 1–12 implementation

This document maps the upgrade roadmap to working code, endpoints and
acceptance checks. The implementation is deliberately honest: a capability is
only marked `implemented` when an endpoint or build path exists and is covered
by the test suite. Source counts are never inflated by counting link-outs,
blocked sites or unverified candidates as automatic evidence.

## Status

| Phase | Capability | Code | API |
|---|---|---|---|
| 1 | Intelligence core & evidence graph | `modules/platform/store.py`, `core.py` | `/api/platform/graph*`, `/api/platform/timeline`, `/api/platform/provenance` |
| 2 | Verified coverage & regional expansion | `module_registry`, `source_registry`, `core.source_health` | `/api/platform/sources/health`, `/api/module-registry/*` |
| 3 | Social/human recon & analytics | `deep_search/social.py`, `core.social_recon`, `core.analytics` | `/api/platform/social/*`, `/api/platform/analytics` |
| 4 | Packaging & lightweight runtime | `packaging/`, `ops.runtime_info`, `ops.self_test` | `/api/platform/runtime*` |
| 5 | Module packs & signed updates | `ops.install_pack`, `store.module_packs` | `/api/platform/packs*` |
| 6 | Offline / air-gapped mode | `ops.offline_status`, cache | `/api/platform/offline`, `/api/platform/cache/warm` |
| 7 | Security & trust hardening | `ops.security_posture`, `ops.ssrf_check`, `auth` | `/api/platform/security/*`, `/api/platform/audit` |
| 8 | Team / collaboration server | `collab.py`, workspace tables | `/api/platform/workspaces*`, `/api/platform/comments*`, `/api/platform/assignments*` |
| 9 | Performance & release engineering | `ops.performance`, `ops.benchmark`, CI | `/api/platform/performance*`, `.github/workflows/release.yml` |
| 10 | Plugin SDK & ecosystem | `ecosystem.py`, `sdk/` | `/api/platform/plugins*` |
| 11 | Compliance & governance | `ecosystem.policy`, retention, DSAR | `/api/platform/compliance/*` |
| 12 | Observability & support | `ecosystem.health`, metrics, bundle | `/api/platform/health`, `/api/platform/metrics`, `/api/platform/support/*` |

## Phase 1 — intelligence core

- Reuses the existing `entities`, `edges` and `artifacts` tables.
- Adds `timeline_events` and `provenance` tables.
- Every artifact gets a SHA-256 hash; provenance stores source, URL, access
  mode, status and retrieval time.
- Entity resolution uses stdlib `difflib` (no extra dependency) and is
  explicitly a lead, not identity proof.

Acceptance: `backend/tests/test_platform_phases.py` creates entities, an edge,
a timeline event and provenance, then reads them back.

## Phase 2 — verified coverage

- `verified` and `fragile` remain the only automatic evidence statuses.
- `adapter`, `candidate`, `optional_key`, `link_out`, `blocked`, `error` and
  `unstable` remain catalog/diagnostic only.
- `source_health` returns module and source summaries side by side.

Acceptance: `GET /api/platform/sources/health` reports the same automatic count
as the module registry, not a hand-written number.

## Phase 3 — social/human recon

The old coverage message said “89 platforms need a handle/profile URL.” That
was misleading: many of those platforms have public search pages. The coverage
report now separates:

- `direct_name_apis` — name-search API rows are automatic evidence.
- `public_search_link_out` — analyst-opened public search pages; never
  auto-scraped, may show login/consent walls.
- `handle_only` — genuinely requires a known handle/profile URL.

The current matrix is 4 direct APIs + 85 public search link-outs + 4
handle-only = 93 platforms. `name_search_links(name)` returns the URLs and
marks every row `automatic_evidence: false`.

`POST /api/platform/social/recon` with `probe=false` performs no network call.
With `probe=true` it runs the direct public name APIs and records provenance
for each source that returned rows.

## Phase 4 — runtime & packaging

`packaging/build.py` creates a PyInstaller one-folder build, then a `.deb` when
`dpkg-deb` is available. `packaging/build_windows.ps1` creates the Windows
portable build and optionally signs it with `signtool`. One-folder is preferred
over one-file for cold start and AV false-positive reasons.

`GET /api/platform/runtime` reports version, frozen state, Python, SQLite/FTS5,
data paths and latency budgets. `POST /api/platform/runtime/self-test` checks
SQLite, FTS5, registries, auth, pack directory and optional crypto.

## Phase 5 — module packs

Pack manifests are JSON with `name`, `version`, `min_app`, `modules` and
optional `sources`. Install is versioned and reversible. When
`XAXGLOG_PACK_SECRET` is set, installs require an HMAC-SHA256 signature over the
canonical manifest. Set `XAXGLOG_REQUIRE_PACK_SIGNATURE=1` to reject unsigned
packs entirely.

```bash
XAXGLOG_PACK_SECRET=change-me python sdk/sign_pack.py packs/example-pack.json
```

## Phase 6 — offline

Offline mode is an admin setting (`POST /api/platform/offline`) or
`XAXGLOG_OFFLINE=1`. `POST /api/platform/cache/warm` caches registry summaries,
social coverage and phase metadata. Offline mode is reported by runtime and
security posture so operators can tell cached from live data.

## Phase 7 — security

- Shared SSRF guard rejects loopback/private/reserved targets.
- Posture report flags default Flask secret, default bootstrap password,
  missing pack signing, missing PyJWT and optional crypto.
- Audit tail is admin-only.
- The report is a posture check, not a penetration test.

## Phase 8 — collaboration

Workspaces, members, comments and assignments live in SQLite. Evidence remains
in the existing case graph; workspaces only add shared context and task
ownership.

## Phase 9 — performance/release

`GET /api/platform/performance` reports DB size, FTS5, stats latency and
budgets. `POST /api/platform/performance/benchmark` runs a bounded read
benchmark. CI builds Linux `.deb` and Windows portable `.zip` artifacts.

## Phase 10 — plugin SDK

Plugins are declarative JSON only. The server validates manifests and never
imports or executes plugin code. This keeps the compiled runtime small and
removes an arbitrary-code-execution path.

## Phase 11 — compliance

Policy, retention preview/run, hashed case export and a DSAR checklist are
implemented. Retention is dry-run first and requires admin for deletion.
Deleting artifacts also updates the FTS index through the existing triggers.

## Phase 12 — observability

`GET /api/platform/health` returns checks and disk state.
`GET /api/platform/metrics` returns Prometheus text.
`GET /api/platform/support/diagnostics` and `.../support/bundle` return
redacted diagnostics; the bundle excludes secrets, keys and raw evidence.

## Test commands

```bash
cd backend && python -m unittest discover -s tests
cd frontend && npm run build
python packaging/build.py --target deb
```
