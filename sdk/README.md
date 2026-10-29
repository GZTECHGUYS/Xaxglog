# Xaxglog Plugin SDK (declarative)

Plugins are JSON manifests, not Python packages. The server validates a
manifest and records it in the plugin registry; it never imports or executes
plugin code. This keeps the compiled distribution small and prevents a plugin
from becoming an arbitrary-code-execution path.

## Manifest

```json
{
  "name": "example-linkout",
  "version": "1.0.0",
  "kind": "link_out",
  "label": "Example public search",
  "description": "Public search link-out",
  "author": "you",
  "min_app": "1.1.0",
  "probe_type": "link_out",
  "url": "https://example.org/search?q={query}",
  "permissions": ["link_out"]
}
```

Allowed `kind` values: `source`, `probe`, `link_out`, `ui_panel`, `report`.
Allowed `probe_type` values: `json_api_probe`, `http_profile_probe`,
`html_search_probe`, `oembed_probe`, `link_out`.
Allowed permissions: `network`, `case_read`, `case_write`, `link_out`.

## Validate and install

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:5000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"xaxglog-admin"}' | jq -r .token)

curl -s -X POST http://127.0.0.1:5000/api/platform/plugins/validate \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"manifest": '"$(cat examples/sample_plugin.json)"'}'

curl -s -X POST http://127.0.0.1:5000/api/platform/plugins/install \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"manifest": '"$(cat examples/sample_plugin.json)"'}'
```

## Module packs

A module pack is a versioned bundle of declarative source specs. It supports
SHA-256 integrity and HMAC-SHA256 signatures. Set `XAXGLOG_PACK_SECRET` on the
server and sign the canonical manifest; set `XAXGLOG_REQUIRE_PACK_SIGNATURE=1`
to reject unsigned packs.

See `packs/example-pack.json` and `POST /api/platform/packs/install`.
