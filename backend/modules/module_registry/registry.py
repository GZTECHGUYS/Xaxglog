"""Declarative module registry.

One module = one public source + one probe recipe.  The registry is intentionally
data-first so adding a source is a small declaration, not a new Python file.

Status vocabulary
-----------------
``verified``    live-checked API/JSON adapter, usable automatically
``fragile``     live-checked public HTML scrape, usable automatically but can break
``adapter``     code exists but has not been live-checked in this registry
``candidate``   declarative public probe; not yet verified
``optional_key``free API that needs an operator key
``link_out``    public search/profile link only; never an automatic result
``blocked``     anti-bot/login/captcha wall; never "no results"
``error``       dead/endpoint error from this host
``unstable``    verification passed once but not consistently
"""
from __future__ import annotations

import copy
import re
from collections import Counter

from modules.source_registry import source_registry as SR
from . import store

STATUSES = (
    "verified", "fragile", "adapter", "candidate", "optional_key",
    "link_out", "blocked", "error", "unstable",
)
AUTOMATIC_STATUSES = ("verified", "fragile")

CATEGORY_LABELS = dict(SR.CATEGORY_LABELS)
PROBE_LABELS = {
    "json_api_probe": "JSON API",
    "http_profile_probe": "Public profile page",
    "html_search_probe": "Public search page (fragile)",
    "oembed_probe": "oEmbed API",
    "adapter_probe": "Existing keyless adapter",
    "link_out": "Analyst link-out",
}

# Explicit declarative upgrades for sources whose public API is simple enough
# to describe without a bespoke adapter.  These are examples of the generic
# types, not a second hand-maintained adapter list.
PROBE_OVERRIDES = {
    "wikipedia": {
        "type": "json_api_probe",
        "url": "https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch={q}&format=json&srlimit=8",
        "items_path": "query.search",
        "fields": {"name": "title", "snippet": "snippet", "id": "pageid"},
        "result_url": "https://en.wikipedia.org/wiki/{title}",
        "limit": 8,
    },
    "github_users": {
        "type": "json_api_probe",
        "url": "https://api.github.com/search/users?q={q}&per_page=8",
        "items_path": "items",
        "fields": {"name": "login", "url": "html_url", "id": "id"},
        "limit": 8,
    },
    "crossref": {
        "type": "json_api_probe",
        "url": "https://api.crossref.org/works?query={q}&rows=8",
        "items_path": "message.items",
        "fields": {"name": "title", "url": "URL", "snippet": "container-title",
                   "date": "published-print.date-parts", "id": "DOI",
                   "author": "author.0.family"},
        "limit": 8,
    },
    "openalex_authors": {
        "type": "json_api_probe",
        "url": "https://api.openalex.org/authors?search={q}&per-page=8",
        "items_path": "results",
        "fields": {"name": "display_name", "url": "id", "snippet": "works_count",
                   "id": "id"},
        "limit": 8,
    },
    "openlibrary": {
        "type": "json_api_probe",
        "url": "https://openlibrary.org/search/authors.json?q={q}&limit=8",
        "items_path": "docs",
        "fields": {"name": "name", "url": "key", "snippet": "top_work",
                   "id": "key"},
        "limit": 8,
    },
}

# Generic oEmbed modules are candidates until an operator verifies them.
GENERIC_MODULES = [
    {
        "id": "youtube_oembed",
        "label": "YouTube oEmbed",
        "category": "image",
        "types": ["url", "video"],
        "region": "global",
        "language": "en",
        "access": "api",
        "status": "candidate",
        "homepage": "https://www.youtube.com/",
        "note": "Public oEmbed metadata for a YouTube video URL. No API key.",
        "probe": {
            "type": "oembed_probe",
            "url": "https://www.youtube.com/oembed?url={q}&format=json",
        },
    },
    {
        "id": "vimeo_oembed",
        "label": "Vimeo oEmbed",
        "category": "image",
        "types": ["url", "video"],
        "region": "global",
        "language": "en",
        "access": "api",
        "status": "candidate",
        "homepage": "https://vimeo.com/",
        "note": "Public oEmbed metadata for a Vimeo video URL. No API key.",
        "probe": {
            "type": "oembed_probe",
            "url": "https://vimeo.com/api/oembed.json?url={q}",
        },
    },
    {
        "id": "tiktok_oembed",
        "label": "TikTok oEmbed",
        "category": "image",
        "types": ["url", "video"],
        "region": "global",
        "language": "en",
        "access": "api",
        "status": "candidate",
        "homepage": "https://www.tiktok.com/",
        "note": "Public oEmbed metadata for a TikTok video URL. No API key.",
        "probe": {
            "type": "oembed_probe",
            "url": "https://www.tiktok.com/oembed?url={q}",
        },
    },
]

_MODULES = {}
_STATUS = {}
_BY_CATEGORY = Counter()
_BY_STATUS = Counter()
_BY_PROBE = Counter()
_BY_ACCESS = Counter()


def _slug(value):
    return re.sub(r"[^a-z0-9]+", "_", (value or "").lower()).strip("_")


def _source_probe(src):
    access = src.get("access") or ""
    status = src.get("status") or ""
    adapter = src.get("adapter") or ""
    search = src.get("search") or ""
    profile = src.get("profile_url") or ""
    homepage = src.get("homepage") or src.get("url") or ""
    if status in ("blocked", "optional_key", "link_out") or access in (
            "blocked", "optional_key", "link_out"):
        return {"type": "link_out", "url": search or profile or homepage}
    if adapter == "monitoring.rss":
        return {"type": "link_out", "url": homepage}
    if adapter == "socialscrape.page":
        if profile:
            return {"type": "http_profile_probe", "url": profile,
                    "limit": 1}
        if search:
            return {"type": "html_search_probe", "url": search, "limit": 10}
        return {"type": "link_out", "url": homepage}
    if adapter:
        return {"type": "adapter_probe", "adapter": adapter}
    if profile:
        return {"type": "http_profile_probe", "url": profile, "limit": 1}
    if search:
        return {"type": "html_search_probe", "url": search, "limit": 10}
    return {"type": "link_out", "url": homepage}


def _status_for(src, probe):
    st = src.get("status") or "cataloged"
    ptype = probe.get("type")
    if st == "blocked":
        return "blocked"
    if st == "optional_key":
        return "optional_key"
    if st == "link_out":
        return "link_out"
    if st == "error":
        return "error"
    if st == "verified":
        if ptype == "link_out":
            return "link_out"
        if ptype in ("http_profile_probe", "html_search_probe") or src.get("access") == "public_html":
            return "fragile"
        return "verified"
    if st == "adapter":
        return "adapter" if ptype != "link_out" else "link_out"
    if st == "cataloged":
        return "candidate" if ptype != "link_out" else "link_out"
    if ptype == "link_out":
        return "link_out"
    return "candidate"


def _module_from_source(src):
    probe = _source_probe(src)
    override = PROBE_OVERRIDES.get(src["id"])
    if override:
        probe = dict(override)
    probe.update({
        "source": src["id"],
        "label": src["label"],
        "category": src["category"],
        "module_id": src["id"],
    })
    status = _status_for(src, probe)
    ptype = probe.get("type")
    fragile = status == "fragile" or ptype in ("http_profile_probe", "html_search_probe") and status in AUTOMATIC_STATUSES
    return {
        "id": src["id"],
        "source_id": src["id"],
        "label": src["label"],
        "category": src["category"],
        "category_label": CATEGORY_LABELS.get(src["category"], src["category"]),
        "region": src.get("region") or "global",
        "language": src.get("language") or "en",
        "types": list(src.get("types") or ["name"]),
        "access": src.get("access") or "link_out",
        "status": status,
        "verified": status in AUTOMATIC_STATUSES,
        "fragile": bool(fragile),
        "automatic": status in AUTOMATIC_STATUSES and ptype != "link_out",
        "probe_type": ptype,
        "probe_label": PROBE_LABELS.get(ptype, ptype),
        "probe": probe,
        "search_url": src.get("search") or "",
        "profile_url": src.get("profile_url") or "",
        "homepage": src.get("homepage") or src.get("url") or "",
        "adapter": src.get("adapter") or "",
        "requires_key": bool(src.get("requires_key")),
        "key_env": src.get("key_env") or "",
        "domains": list(src.get("domains") or []),
        "tags": list(src.get("tags") or []),
        "note": src.get("note") or "",
        "last_checked": "",
        "last_error": "",
    }


def _generic_module(spec):
    probe = dict(spec.get("probe") or {})
    probe.update({
        "source": spec["id"],
        "label": spec["label"],
        "category": spec.get("category", "web"),
        "module_id": spec["id"],
    })
    ptype = probe.get("type")
    status = spec.get("status") or "candidate"
    return {
        "id": spec["id"],
        "source_id": spec["id"],
        "label": spec["label"],
        "category": spec.get("category", "web"),
        "category_label": CATEGORY_LABELS.get(spec.get("category", "web"),
                                              spec.get("category", "web")),
        "region": spec.get("region", "global"),
        "language": spec.get("language", "en"),
        "types": list(spec.get("types") or ["url"]),
        "access": spec.get("access", "api"),
        "status": status,
        "verified": status in AUTOMATIC_STATUSES,
        "fragile": False,
        "automatic": status in AUTOMATIC_STATUSES and ptype != "link_out",
        "probe_type": ptype,
        "probe_label": PROBE_LABELS.get(ptype, ptype),
        "probe": probe,
        "search_url": spec.get("search_url", ""),
        "profile_url": spec.get("profile_url", ""),
        "homepage": spec.get("homepage", ""),
        "adapter": "",
        "requires_key": False,
        "key_env": "",
        "domains": list(spec.get("domains") or []),
        "tags": list(spec.get("tags") or []),
        "note": spec.get("note", ""),
        "last_checked": "",
        "last_error": "",
    }


def _apply_overlay(module, overlay):
    item = overlay.get(module["id"]) or {}
    if not item:
        return module
    status = item.get("status")
    if status in STATUSES:
        module["status"] = status
        module["verified"] = status in AUTOMATIC_STATUSES
        module["fragile"] = bool(item.get("fragile")) or status == "fragile"
        module["automatic"] = status in AUTOMATIC_STATUSES and module["probe_type"] != "link_out"
    module["last_checked"] = item.get("checked_at") or ""
    module["last_error"] = item.get("detail") or ""
    return module


def _build():
    global _MODULES, _STATUS
    _MODULES = {}
    _STATUS = store.load_status()
    for src in SR.sources():
        mod = _module_from_source(src)
        _MODULES[mod["id"]] = _apply_overlay(mod, _STATUS)
    for spec in GENERIC_MODULES:
        mod = _generic_module(spec)
        _MODULES[mod["id"]] = _apply_overlay(mod, _STATUS)
    _recount()


def _recount():
    _BY_CATEGORY.clear()
    _BY_STATUS.clear()
    _BY_PROBE.clear()
    _BY_ACCESS.clear()
    for mod in _MODULES.values():
        _BY_CATEGORY[mod["category"]] += 1
        _BY_STATUS[mod["status"]] += 1
        _BY_PROBE[mod["probe_type"]] += 1
        _BY_ACCESS[mod["access"]] += 1


def reload():
    _build()


def modules():
    return list(_MODULES.values())


def get(module_id):
    return _MODULES.get(_slug(module_id)) or _MODULES.get(module_id)


def set_status(module_id, status, *, query="", checks=0, fragile=False,
               detail="", sample=None, persist=True):
    global _STATUS
    mod = get(module_id)
    if not mod:
        return False
    _STATUS = store.set_status(_STATUS, mod["id"], status, query=query,
                               checks=checks, fragile=fragile, detail=detail,
                               sample=sample)
    if persist:
        store.save_status(_STATUS)
    _apply_overlay(mod, {mod["id"]: _STATUS[mod["id"]]})
    _recount()
    return True


def select(*, q=None, types=None, categories=None, statuses=None, access=None,
           probe_types=None, region=None, automatic=None, limit=None,
           offset=0):
    wanted_types = _lower_set(types)
    wanted_categories = _lower_set(categories)
    wanted_status = _lower_set(statuses)
    wanted_access = _lower_set(access)
    wanted_probe = _lower_set(probe_types)
    needle = (q or "").strip().lower()
    out = []
    for mod in _MODULES.values():
        if wanted_types and not (set(t.lower() for t in mod["types"]) & wanted_types):
            continue
        if wanted_categories and mod["category"].lower() not in wanted_categories:
            continue
        if wanted_status and mod["status"].lower() not in wanted_status:
            continue
        if wanted_access and mod["access"].lower() not in wanted_access:
            continue
        if wanted_probe and mod["probe_type"].lower() not in wanted_probe:
            continue
        if region and region not in ("all", "*") and mod["region"] not in (region, "global"):
            continue
        if automatic is True and not mod["automatic"]:
            continue
        if automatic is False and mod["automatic"]:
            continue
        if needle and needle not in " ".join([
                mod["id"], mod["label"], mod["category"], mod["probe_type"],
                mod["adapter"], mod["note"]]).lower():
            continue
        out.append(mod)
    out.sort(key=lambda m: (
        0 if m["status"] == "verified" else 1 if m["status"] == "fragile" else 2,
        m["category"], m["label"].lower()))
    offset = max(0, int(offset or 0))
    if limit:
        return out[offset:offset + int(limit)]
    return out[offset:]


def _lower_set(value):
    if value is None:
        return set()
    if isinstance(value, str):
        value = [x.strip() for x in value.split(",") if x.strip()]
    return {str(x).strip().lower() for x in value if str(x).strip()}


def summary():
    total = len(_MODULES)
    by_status = dict(sorted(_BY_STATUS.items()))
    by_probe = dict(sorted(_BY_PROBE.items()))
    by_category = dict(sorted(_BY_CATEGORY.items()))
    by_access = dict(sorted(_BY_ACCESS.items()))
    verified = _BY_STATUS.get("verified", 0)
    fragile = _BY_STATUS.get("fragile", 0)
    adapter = _BY_STATUS.get("adapter", 0)
    candidate = _BY_STATUS.get("candidate", 0)
    optional_key = _BY_STATUS.get("optional_key", 0)
    link_out = _BY_STATUS.get("link_out", 0)
    blocked = _BY_STATUS.get("blocked", 0)
    error = _BY_STATUS.get("error", 0)
    unstable = _BY_STATUS.get("unstable", 0)
    automatic = sum(1 for m in _MODULES.values() if m["automatic"])
    queryable = sum(1 for m in _MODULES.values()
                    if m["probe_type"] != "link_out"
                    and m["status"] in ("verified", "fragile", "adapter", "candidate"))
    return {
        "total": total,
        "verified": verified,
        "fragile": fragile,
        "live_verified": verified + fragile,
        "automatic": automatic,
        "adapter": adapter,
        "candidate": candidate,
        "optional_key": optional_key,
        "link_out": link_out,
        "blocked": blocked,
        "error": error,
        "unstable": unstable,
        "queryable": queryable,
        "by_status": by_status,
        "by_probe": by_probe,
        "by_category": by_category,
        "by_access": by_access,
        "probe_types": PROBE_LABELS,
        "statuses": list(STATUSES),
        "automatic_statuses": list(AUTOMATIC_STATUSES),
        "note": ("Only verified and fragile modules are automatic evidence. "
                 "Fragile means a public HTML scrape passed a live check; it can "
                 "break at any time. Adapter/candidate/link-out/optional-key/"
                 "blocked sources are never counted as automatic hits."),
    }


def catalog(include_modules=False, **filters):
    out = summary()
    if include_modules:
        out["modules"] = [public_module(m) for m in select(**filters)]
    return out


def public_module(module, include_probe=False):
    out = copy.deepcopy(module)
    if not include_probe:
        out.pop("probe", None)
    return out


_build()
