"""Xaxglog OPS module — bulk reference datasets, free-API quota accounting, source health.

Purpose
-------
  - fetch_dataset()  : mirror well-known PUBLIC bulk datasets (OFAC SDN CSV,
                       UN consolidated sanctions XML, IANA TLD list) into the
                       local data/cache area with a size cap and a SHA-256
                       (chain of custody) recorded in ops_datasets.
  - datasets_status(): inventory of every registered dataset with staleness
                       flags (stale when last successful fetch is > 7 days old).
  - quota_allow()/quota_record()/quota_status(): hour-bucketed local counters
                       so the platform stays inside free-tier limits of the
                       keyless APIs it depends on.
  - health_check()   : read-only HEAD/GET probes of the default source list
                       (OFAC, Wayback CDX, GDELT, GLEIF, Blockstream, Nominatim,
                       t.me, Google DNS) with latency + status upserted to
                       ops_health.

Sources (all public, keyless):
  https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.CSV
  https://scsanctions.un.org/resources/xml/en/consolidated.xml
  https://data.iana.org/TLD/tlds-alpha-by-domain.txt
  http://web.archive.org/cdx/search/cdx  |  https://api.gdeltproject.org/api/v2/doc/doc
  https://api.gleif.org/api/v1/lei-records  |  https://blockstream.info/api
  https://nominatim.openstreetmap.org/status  |  https://t.me/s/telegram
  https://dns.google/resolve

Lawful use: mirrors of government/public reference lists for lawful OSINT,
sanctions compliance and research; probes are single read-only requests at a
6 s timeout. Every row written is recorded in the immutable audit log. No
scraping behind auth, no circumvention of rate limits — quotas are enforced
locally and each provider's terms of use still apply.
"""
import datetime
import os
import time

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 20            # standard outbound timeout (shared convention)
PROBE_TIMEOUT = 6  # health probes: short, one request each

# ---------------------------------------------------------------- registry
DATASETS = {
    "ofac_sdn_csv": {
        "url": ("https://sanctionslistservice.ofac.treas.gov/api/"
                "PublicationPreview/exports/SDN.CSV"),
        "schedule_hint": "daily",
    },
    "un_consolidated_xml": {
        "url": "https://scsanctions.un.org/resources/xml/en/consolidated.xml",
        "schedule_hint": "weekly",
    },
    "iana_tlds": {
        "url": "https://data.iana.org/TLD/tlds-alpha-by-domain.txt",
        "schedule_hint": "daily",
    },
}

DEFAULT_SOURCES = [
    {"name": "ofac", "url": DATASETS["ofac_sdn_csv"]["url"]},
    {"name": "wayback_cdx",
     "url": "http://web.archive.org/cdx/search/cdx?url=example.com&limit=1"},
    {"name": "gdelt",
     "url": ("https://api.gdeltproject.org/api/v2/doc/doc?query=test"
             "&mode=artlist&format=json&maxrecords=1")},
    {"name": "gleif", "url": "https://api.gleif.org/api/v1/lei-records?page[size]=1"},
    {"name": "blockstream", "url": "https://blockstream.info/api/blocks/tip/height"},
    {"name": "nominatim", "url": "https://nominatim.openstreetmap.org/status?format=json"},
    {"name": "tme", "url": "https://t.me/s/telegram"},
    {"name": "dns_google", "url": "https://dns.google/resolve?name=example.com&type=A"},
]


class _TooLarge(Exception):
    """Internal: dataset exceeded the caller's size cap."""


_tables_ready = False


def _ensure_tables():
    """Create this module's own scratch tables (idempotent, never db.py)."""
    global _tables_ready
    if _tables_ready:
        return
    c = db.get_db()
    c.execute("CREATE TABLE IF NOT EXISTS ops_datasets ("
              " name TEXT PRIMARY KEY,"
              " url TEXT DEFAULT '',"
              " last_fetch TEXT,"
              " bytes INTEGER DEFAULT 0,"
              " sha256 TEXT DEFAULT '',"
              " status TEXT DEFAULT '',"
              " note TEXT DEFAULT '')")
    c.execute("CREATE TABLE IF NOT EXISTS ops_quota ("
              " source TEXT NOT NULL,"
              " window_start TEXT NOT NULL,"
              " count INTEGER NOT NULL DEFAULT 0,"
              " PRIMARY KEY(source, window_start))")
    c.execute("CREATE TABLE IF NOT EXISTS ops_health ("
              " name TEXT PRIMARY KEY,"
              " url TEXT DEFAULT '',"
              " last_check TEXT,"
              " status TEXT DEFAULT '',"
              " latency_ms INTEGER DEFAULT 0,"
              " note TEXT DEFAULT '')")
    c.commit()
    _tables_ready = True


_ensure_tables()


def _cache_dir():
    import config as C
    d = os.path.join(C.DATA_DIR, "cache")
    try:
        os.makedirs(d, exist_ok=True)
    except Exception:
        pass
    return d


# ---------------------------------------------------------------- datasets
def fetch_dataset(name, max_mb=100, user="system"):
    """Stream a registered bulk dataset to data/cache/<name> with a size cap.

    Returns {name, bytes, sha256, status, note}. status is one of
    ok | too_large | error | unknown_dataset. Never raises.
    """
    _ensure_tables()
    meta = DATASETS.get(name)
    if not meta:
        return {"name": name, "bytes": 0, "sha256": "", "status": "unknown_dataset",
                "note": f"dataset '{str(name)[:60]}' is not registered"}
    url = meta["url"]
    cap = int(float(max_mb) * 1024 * 1024)
    total, sha, status, note = 0, "", "error", ""

    try:
        import requests
        chunks = []
        with requests.get(url, headers=UA, stream=True, timeout=T) as r:
            if r.status_code >= 400:
                raise RuntimeError(f"HTTP {r.status_code}")
            for chunk in r.iter_content(65536):
                if not chunk:
                    continue
                total += len(chunk)
                if total > cap:
                    status, note = "too_large", f"exceeded {max_mb} MB cap"
                    raise _TooLarge()
                chunks.append(chunk)
        data = b"".join(chunks)
        text = data.decode("utf-8", "replace")
        sha = db.hash_content(text)          # SHA-256 of decoded payload
        path = os.path.join(_cache_dir(), name)
        with open(path, "wb") as f:
            f.write(data)
        status, note = "ok", f"{meta.get('schedule_hint', '')} mirror"
    except _TooLarge:
        pass
    except Exception as e:
        status, note = "error", str(e)[:150]

    try:
        c = db.get_db()
        c.execute(
            "INSERT INTO ops_datasets (name,url,last_fetch,bytes,sha256,status,note)"
            " VALUES (?,?,?,?,?,?,?)"
            " ON CONFLICT(name) DO UPDATE SET url=excluded.url,"
            " last_fetch=excluded.last_fetch, bytes=excluded.bytes,"
            " sha256=excluded.sha256, status=excluded.status, note=excluded.note",
            (name, url, db.utcnow(), total, sha, status, note))
        c.commit()
        db.audit(user, "ops.dataset.fetch", name,
                 f"status={status} bytes={total} sha256={sha[:16]} {note}"[:500])
    except Exception:
        pass
    out = {"name": name, "bytes": total, "sha256": sha, "status": status, "note": note}
    if status == "error":
        out["error"] = note
    return out


def datasets_status():
    """Rows for every registered dataset (+ staleness flag, threshold: 7 days)."""
    _ensure_tables()
    now = datetime.datetime.utcnow()
    rows, seen = [], set()
    try:
        c = db.get_db()
        for r in c.execute("SELECT name,url,last_fetch,bytes,sha256,status,note"
                           " FROM ops_datasets ORDER BY name").fetchall():
            row = dict(r)
            seen.add(row["name"])
            rows.append(_stale_flag(row, now))
        for n, meta in DATASETS.items():
            if n not in seen:
                rows.append(_stale_flag(
                    {"name": n, "url": meta["url"], "last_fetch": None, "bytes": 0,
                     "sha256": "", "status": "never_fetched",
                     "note": meta.get("schedule_hint", "")}, now))
    except Exception as e:
        return {"error": str(e)[:150]}
    return rows


def _stale_flag(row, now):
    last, age = row.get("last_fetch"), None
    if last:
        try:
            dt = datetime.datetime.strptime(str(last).replace("Z", "")[:19],
                                            "%Y-%m-%dT%H:%M:%S")
            age = (now - dt).total_seconds() / 86400.0
        except Exception:
            age = None
    row["age_days"] = round(age, 2) if age is not None else None
    row["stale"] = (age is None) or (age > 7.0)
    return row


# ---------------------------------------------------------------- quotas
def _hour_bucket():
    return datetime.datetime.utcnow().replace(minute=0, second=0,
                                              microsecond=0).isoformat() + "Z"


def _bucket_end(bucket):
    dt = datetime.datetime.strptime(bucket.replace("Z", ""), "%Y-%m-%dT%H:%M:%S")
    return dt + datetime.timedelta(hours=1)


def quota_allow(source, limit_per_hour=60):
    """Hour-bucketed allow/deny check for a free API source (read-only)."""
    _ensure_tables()
    bucket = _hour_bucket()
    limit = int(limit_per_hour)
    try:
        c = db.get_db()
        row = c.execute("SELECT count FROM ops_quota WHERE source=? AND window_start=?",
                        (source, bucket)).fetchone()
        count = int(row["count"]) if row else 0
    except Exception as e:
        return {"error": str(e)[:150]}
    allowed = count < limit
    reset_dt = _bucket_end(bucket)
    retry = 0 if allowed else max(1, int((reset_dt - datetime.datetime.utcnow()).total_seconds()))
    return {"allowed": allowed, "remaining": max(0, limit - count),
            "reset_at": reset_dt.isoformat() + "Z", "retry_after_sec": retry,
            "source": source, "count": count, "limit": limit}


def quota_record(source, user="system"):
    """Increment this hour's counter for a source (audited)."""
    _ensure_tables()
    bucket = _hour_bucket()
    try:
        c = db.get_db()
        c.execute("INSERT INTO ops_quota (source,window_start,count) VALUES (?,?,1)"
                  " ON CONFLICT(source,window_start) DO UPDATE SET count=count+1",
                  (source, bucket))
        c.commit()
        db.audit(user, "ops.quota.record", source, f"window_start={bucket}")
        row = c.execute("SELECT count FROM ops_quota WHERE source=? AND window_start=?",
                        (source, bucket)).fetchone()
        return {"source": source, "window_start": bucket,
                "count": int(row["count"]) if row else 1}
    except Exception as e:
        return {"error": str(e)[:150]}


def quota_status():
    """All sources with counts for the current hour bucket."""
    _ensure_tables()
    bucket = _hour_bucket()
    try:
        c = db.get_db()
        rows = [dict(r) for r in c.execute(
            "SELECT source,window_start,count FROM ops_quota WHERE window_start=?"
            " ORDER BY count DESC", (bucket,)).fetchall()]
    except Exception as e:
        return {"error": str(e)[:150]}
    return {"window_start": bucket, "reset_at": _bucket_end(bucket).isoformat() + "Z",
            "sources": rows}


# ---------------------------------------------------------------- health
def health_check(sources=None, user="system"):
    """Probe each source with a 6 s HEAD (GET fallback); upsert ops_health.

    Returns [{name, status, latency_ms, note}, ...]; status is ok | http_<code>
    | error. Read-only requests, one per source. Never raises.
    """
    _ensure_tables()
    probes = sources if sources else list(DEFAULT_SOURCES)
    import requests
    out = []
    for p in probes:
        name, url = str(p.get("name", ""))[:60], str(p.get("url", ""))[:500]
        t0 = time.time()
        status, note = "error", ""
        code = None
        try:
            try:
                code = requests.head(url, headers=UA, timeout=PROBE_TIMEOUT,
                                     allow_redirects=True).status_code
            except Exception:
                code = None
            if code is None or code >= 400:
                r = requests.get(url, headers=UA, timeout=PROBE_TIMEOUT,
                                 stream=True, allow_redirects=True)
                code = r.status_code
                try:
                    r.close()
                except Exception:
                    pass
            status = "ok" if code is not None and code < 400 else f"http_{code}"
        except Exception as e:
            note = str(e)[:150]
        latency = int((time.time() - t0) * 1000)
        try:
            c = db.get_db()
            c.execute(
                "INSERT INTO ops_health (name,url,last_check,status,latency_ms,note)"
                " VALUES (?,?,?,?,?,?)"
                " ON CONFLICT(name) DO UPDATE SET url=excluded.url,"
                " last_check=excluded.last_check, status=excluded.status,"
                " latency_ms=excluded.latency_ms, note=excluded.note",
                (name, url, db.utcnow(), status, latency, note))
            c.commit()
            db.audit(user, "ops.health_check", name,
                     f"status={status} latency_ms={latency} {note}"[:500])
        except Exception:
            pass
        out.append({"name": name, "status": status, "latency_ms": latency, "note": note})
    return out
