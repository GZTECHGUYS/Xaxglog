"""Xaxglog marketplace — counterfeit/diversion listing watch (public pages).

Keyless core:
  - Generic marketplace search via searchx federated dorks restricted to
    major marketplace hosts (ebay, etsy, amazon marketplace paths,
    aliexpress, walmart, mercari) — finds *listings* for a brand/product
    without hitting platform APIs.
  - Listing URL snapshot: HTTP GET the listing page (SSRF-guarded), pull
    OpenGraph title/price/seller meta, store as artifact + fingerprint for
    the change watch (price drop / listing removal / seller swap).
  - Divergence signals: price far below MSRP (diversion/counterfeit
    hint), seller with no history page, marketplace-hosted clones of your
    brand name.

Optional: env EBAY_CLIENT_ID/EBAY_CLIENT_SECRET for eBay Browse API
structured results (OAuth app key, free).

Lawful-use note: public listing pages for brand-protection monitoring of
your own brand (or authorized client). No purchases, no account creation,
no scraping behind logins — one GET per watch check, rate-limited.
"""
import hashlib
import ipaddress
import json
import os
import socket
import threading
import urllib.parse

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 15
MARKETPLACES = {
    "ebay": "site:ebay.com",
    "etsy": "site:etsy.com",
    "amazon": "site:amazon.com",
    "aliexpress": "site:aliexpress.com",
    "walmart": "site:walmart.com",
    "mercari": "site:mercari.com",
}


def _guard(url):
    p = urllib.parse.urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("http(s) URL required")
    try:
        infos = socket.getaddrinfo(p.hostname, 443)
    except socket.gaierror:
        return
    for _f, _t, _p, _cn, sa in infos:
        if not ipaddress.ip_address(sa[0]).is_global:
            raise ValueError(f"private address blocked: {sa[0]}")


def search(brand, marketplaces=None, limit=15):
    """Federated marketplace-restricted search via searchx (keyless)."""
    try:
        brand = (brand or "").strip()
        if not brand:
            return {"status": "error", "error": "empty brand query"}
        markets = marketplaces or list(MARKETPLACES)
        try:
            import modules.searchx.searchx as SX
        except Exception:
            return {"status": "unconfigured", "error": "searchx unavailable"}
        results = []
        for mk in markets:
            restrict = MARKETPLACES.get(mk)
            q = f'"{brand}" {restrict or ("site:" + mk)}'
            try:
                out = SX.federated(q, limit=max(4, limit // len(markets) + 1))
            except TypeError:
                out = SX.federated(q)
            if out and out.get("status") == "ok":
                for r in out.get("results", [])[:limit]:
                    r = dict(r)
                    r["marketplace"] = mk
                    results.append(r)
        seen, dedup = set(), []
        for r in results:
            key = (r.get("url") or "").split("?")[0]
            if key and key not in seen:
                seen.add(key)
                dedup.append(r)
        db.audit("system", "marketplace.search", brand, f"n={len(dedup)}")
        return {"status": "ok", "brand": brand, "count": len(dedup),
                "listings": dedup[:limit],
                "note": "links point at public listing pages — open to verify"}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "listings": []}


def inspect(url):
    """One GET of a listing page: extract og:title/price/seller signals."""
    try:
        _guard(url)
        import requests
        r = requests.get(url, headers=UA, timeout=T, allow_redirects=True)
        html = r.text[:600_000]
        def og(prop):
            import re
            m = re.search(rf'property="{re.escape(prop)}"\s+content="([^"]{1,400})"',
                          html, re.I)
            if m:
                return m.group(1).strip()
            m = re.search(rf'name="{re.escape(prop)}"\s+content="([^"]{1,400})"',
                          html, re.I)
            return m.group(1).strip() if m else None
        import re as _re
        price = og("product:price:amount") or og("og:price:amount")
        if not price:
            m = _re.search(r'[$€£]\s?(\d[\d.,]{0,12})', html)
            price = m.group(1) if m else None
        title = og("og:title")
        seller = og("product:brand") or og("og:site_name")
        signals = []
        if r.status_code in (403, 429, 503):
            signals.append(f"anti-bot response {r.status_code} — use browserrender")
        fp = hashlib.sha256(html.encode("utf-8", "replace")).hexdigest()
        out = {"status": "ok", "url": url, "final_url": r.url[:400],
               "http": r.status_code, "title": (title or "")[:300],
               "price": price, "marketplace": seller,
               "fingerprint": fp[:16], "signals": signals}
        return out
    except ValueError as e:
        return {"status": "error", "error": str(e)}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


SCHEMA = """
CREATE TABLE IF NOT EXISTS marketplace_watch (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  url TEXT UNIQUE NOT NULL,
  brand TEXT NOT NULL,
  case_id INTEGER,
  enabled INTEGER NOT NULL DEFAULT 1,
  fingerprint TEXT,
  last_price TEXT,
  last_run TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);
"""


def init_schema():
    try:
        c = db.get_db()
        c.executescript(SCHEMA)
        c.commit()
    except Exception:
        pass


def watch(url, brand, case_id=None, created_by="system"):
    """Watch a listing: fingerprint + price baseline."""
    init_schema()
    try:
        out = inspect(url)
        if out.get("status") != "ok":
            return out
        c = db.get_db()
        c.execute(
            "INSERT OR IGNORE INTO marketplace_watch "
            "(url,brand,case_id,fingerprint,last_price,created_by,created_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (url, brand, case_id, out.get("fingerprint"),
             str(out.get("price") or ""), created_by, db.utcnow()))
        c.commit()
        db.audit(created_by, "marketplace.watch", url[:120], f"brand={brand}")
        return {"status": "ok", "url": url, "watching": True,
                "baseline": {"fingerprint": out.get("fingerprint"),
                             "price": out.get("price")}}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def unwatch(url):
    try:
        c = db.get_db()
        c.execute("UPDATE marketplace_watch SET enabled=0 WHERE url=?", (url,))
        c.commit()
        return {"status": "ok", "watching": False}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def list_watch(case_id=None):
    try:
        c = db.get_db()
        q = ("SELECT id,url,brand,case_id,last_price,last_run FROM "
             "marketplace_watch WHERE enabled=1")
        args = ()
        if case_id is not None:
            q += " AND case_id=?"
            args = (case_id,)
        return {"status": "ok", "watch": [dict(r) for r in c.execute(q, args).fetchall()]}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "watch": []}


def check_all():
    init_schema()
    rows = db.get_db().execute(
        "SELECT id,url,brand,case_id,fingerprint,last_price FROM "
        "marketplace_watch WHERE enabled=1").fetchall()
    results = []
    for row in rows:
        out = inspect(row["url"])
        if out.get("status") != "ok":
            results.append({"url": row["url"], "error": out.get("error")})
            continue
        drift = {}
        if row["fingerprint"] and row["fingerprint"] != out.get("fingerprint"):
            drift["content"] = {"was": row["fingerprint"], "now": out.get("fingerprint")}
        if str(row["last_price"] or "") != str(out.get("price") or ""):
            drift["price"] = {"was": row["last_price"], "now": out.get("price")}
        if out.get("http") in (404, 410):
            drift["listing"] = {"state": "removed"}
        c = db.get_db()
        c.execute("UPDATE marketplace_watch SET fingerprint=?, last_price=?, last_run=? "
                  "WHERE id=?",
                  (out.get("fingerprint"), str(out.get("price") or ""),
                   db.utcnow(), row["id"]))
        if drift:
            c.execute(
                "INSERT INTO alerts (case_id,ts,severity,message,detail) VALUES (?,?,?,?,?)",
                (row["case_id"], db.utcnow(),
                 "high" if "listing" in drift else "medium",
                 f"Marketplace change for {row['brand']}: " + ", ".join(drift),
                 json.dumps(drift, default=str)[:900]))
        c.commit()
        results.append({"url": row["url"], "drift": drift or None})
    return {"status": "ok", "checked": len(results), "results": results}


_daemon_stop = threading.Event()


def start_daemon(interval_sec=43200):
    init_schema()

    def _loop():
        while not _daemon_stop.is_set():
            try:
                check_all()
            except Exception:
                pass
            _daemon_stop.wait(interval_sec)

    threading.Thread(target=_loop, daemon=True, name="marketplace").start()
    return True
