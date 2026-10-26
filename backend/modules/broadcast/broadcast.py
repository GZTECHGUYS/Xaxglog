"""Xaxglog broadcast — radio/podcast/stream mention capture.

Keyless core:
  - Radio Browser API (radio-browser.info, community-mirrored, no key):
    search public radio stations by name/country/tag/bitrate with stream
    URLs; the `clickcount` and `lastcheckok` fields separate live stations
    from dead entries.
  - Podcast/Atom feed ingestion (stdlib xml): fetch an RSS feed, find
    episode show-notes + <podcast:transcript> tags when publishers provide
    them, then grep for target terms -> mention records.
  - ICY metadata probe: connect to a stream URL briefly and read the
    current "Now Playing" title (station name/song) — a 5-second passive
    read, no recording.

Output: station/episode mention records with source URLs, stored as case
artifacts. Complements regional (Telegram/Weibo) and risk (GDELT news)
with the audio/RTVGPT broadcast axis.

Lawful-use note: public streams and public feeds. The metadata probe reads
the stream header only — no recording of content, no redistribution.
"""
import re
import socket
import urllib.parse
import xml.etree.ElementTree as ET

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 20
MIRRORS = ["https://de1.api.radio-browser.info",
           "https://fi1.api.radio-browser.info",
           "https://at1.api.radio-browser.info"]


def _radio_get(path, params=None):
    import requests
    last_err = None
    for base in MIRRORS:
        try:
            r = requests.get(base + path, headers=UA, params=params, timeout=T)
            if r.status_code == 200:
                return r.json()
        except Exception as e:
            last_err = e
            continue
    raise RuntimeError(f"all mirrors failed: {last_err}")


def stations(query=None, country=None, tag=None, limit=25, hidebroken=True):
    """Search public radio stations (keyless, community mirrors)."""
    try:
        params = {"limit": min(int(limit), 200), "order": "clickcount",
                  "reverse": "true"}
        if query:
            params["name"] = query
        if country:
            params["countrycode"] = country.upper()
        if tag:
            params["tag"] = tag
        if hidebroken:
            params["hidebroken"] = "true"
        rows = _radio_get("/json/stations/search", params)
        out = [{
            "name": s.get("name"), "url": s.get("url"),
            "homepage": s.get("homepage"), "country": s.get("country"),
            "countrycode": s.get("countrycode"), "tags": (s.get("tags") or "")[:120],
            "codec": s.get("codec"), "bitrate": s.get("bitrate"),
            "clickcount": s.get("clickcount"),
        } for s in rows]
        db.audit("system", "broadcast.stations",
                 query or country or tag or "-", f"n={len(out)}")
        return {"status": "ok", "count": len(out), "stations": out}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "stations": []}


def stream_status(url, timeout=5):
    """Read ICY metadata (stream title) from a public stream — no recording."""
    try:
        p = urllib.parse.urlparse(url)
        if p.scheme not in ("http", "https"):
            return {"status": "error", "error": "http(s) stream only"}
        host, port = p.hostname, p.port or (443 if p.scheme == "https" else 80)
        path = p.path + ("?" + p.query if p.query else "")
        s = socket.create_connection((host, port), timeout=timeout)
        try:
            if p.scheme == "https":
                import ssl
                ctx = ssl.create_default_context()
                s = ctx.wrap_socket(s, server_hostname=host)
            req = (f"GET {path} HTTP/1.0\r\nHost: {host}\r\n"
                   f"Icy-MetaData: 1\r\nUser-Agent: {UA['User-Agent']}\r\n\r\n")
            s.sendall(req.encode())
            data = s.recv(2048)
        finally:
            s.close()
        head = data.decode("latin-1", "replace")
        status_ok = head.startswith("HTTP/1.") and " 200" in head.split("\r\n")[0]
        title = None
        m = re.search(r"ice-name:\s*(.+)", head, re.I) or \
            re.search(r"icy-name:\s*(.+)", head, re.I) or \
            re.search(r"Server:\s*(.+)", head, re.I)
        if m:
            title = m.group(1).strip()[:160]
        mt = re.search(r"StreamTitle '(.*?)';", head)
        if mt:
            title = mt.group(1).strip()[:160]
        return {"status": "ok" if status_ok else "error", "url": url,
                "stream_title": title,
                "icy_br": (re.search(r"icy-br:(\S+)", head, re.I).group(1)
                           if re.search(r"icy-br:(\S+)", head, re.I) else None)}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def _localname(tag):
    return tag.rsplit("}", 1)[-1]


def feed_mentions(feed_url, terms, limit=100):
    """Scan a podcast/RSS feed's episodes for target terms (keyless)."""
    try:
        import requests
        terms = [t.lower() for t in (terms or []) if t]
        if not terms:
            return {"status": "error", "error": "provide at least one term"}
        r = requests.get(feed_url, headers=UA, timeout=T)
        if r.status_code != 200:
            return {"status": "error", "error": f"HTTP {r.status_code}"}
        root = ET.fromstring(r.content)
        items = [e for e in root.iter() if _localname(e.tag) in ("item", "entry")]
        mentions = []
        checked = 0
        for it in items[:limit]:
            checked += 1
            title = next((c.text or "" for c in it if _localname(c.tag) == "title"), "")
            desc = next((c.text or "" for c in it
                         if _localname(c.tag) in ("description", "summary",
                                                  "content")), "")
            link = next((c.text for c in it if _localname(c.tag) == "link"), None)
            if link is None:
                link = next((c.get("href") for c in it
                             if _localname(c.tag) == "link"), None)
            transcript = next((c.get("href") for c in it
                               if _localname(c.tag) == "transcript"), None)
            blob = f"{title}\n{desc}".lower()
            hits = [t for t in terms if t in blob]
            if hits:
                mentions.append({"title": title[:200], "url": link,
                                 "terms": hits,
                                 "transcript_url": transcript,
                                 "published": next(
                                     (c.text for c in it
                                      if _localname(c.tag) in ("pubDate", "published",
                                                               "updated")), None)})
        db.audit("system", "broadcast.feed_mentions", feed_url[:100],
                 f"terms={terms} hits={len(mentions)}")
        return {"status": "ok", "feed": feed_url, "items_checked": checked,
                "mentions": mentions,
                "note": "transcript_url set when the publisher offers one "
                        "(fetch it for full-text verification)"}
    except ET.ParseError:
        return {"status": "error", "error": "feed is not valid XML/RSS"}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def find_and_scan(term, country=None, limit=10, terms=None):
    """Convenience: find popular stations for a market — analyst queues the
    stream probes; full audio monitoring is out of scope (metadata only)."""
    out = stations(query=term, country=country, limit=limit)
    if out.get("status") != "ok":
        return out
    probes = [stream_status(s["url"]) for s in out["stations"][:5] if s.get("url")]
    return {"status": "ok", "stations": out["stations"],
            "live_probes": probes,
            "next": "queue stream_status() pings or feed_mentions() for "
                    "podcast coverage"}
