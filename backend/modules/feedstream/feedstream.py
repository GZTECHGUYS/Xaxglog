"""Xaxglog feedstream — streaming public threat-feed ingest.

Unlike the 12-hour batch collector in threat_intel, this pulls continuously
-updated public feeds on a short timer and lands new indicators as custody
artifacts + typed alerts (dedup against the seen-store).

Keyless feeds:
  - URLhaus recent URLs (urlhaus-api.abuse.ch) — fresh malware distribution
    URLs (JSON).
  - OpenPhish community feed (openphish.com) — active phishing URLs (text).
  - blocklist.de (blocklist.de) — attacking IPs per category (text).
  - Abuse.ch Feodo Tracker (feodotracker.abuse.ch) — C2 IP:port list.
  - AlienVault OTX plain text (otx.alienvault.com) — accelerated+pulses IP
    list (keyless anonymous GET).

Alerting: when an indicator matches a watched domain/IP/exposure target
(via LIKE against watch tables), a medium/high alert fires so the operator
sees "C2 feed lists a host next to our target".

Lawful-use note: consumption of published threat intel. Detection only —
no interaction with listed infrastructure.
"""
import json
import os
import threading
import time

import db
import config as C

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 30
FEEDS = {
    "urlhaus_recent": "https://urlhaus-api.abuse.ch/v1/urls/recent/",
    "openphish": "https://openphish.com/feed.txt",
    "blocklist_de": "https://www.blocklist.de/downloads/iplist.txt",
    "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "otx_pulses": "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50",
}
SEEN = os.path.join(C.DATA_DIR, "feedstream_seen.json")
SEEN_CAP = 50000


def _load_seen():
    try:
        with open(SEEN, encoding="utf-8") as f:
            return set(json.load(f))
    except (OSError, ValueError):
        return set()


def _save_seen(seen):
    try:
        blob = json.dumps(sorted(seen)[-SEEN_CAP:])
        with open(SEEN + ".tmp", "w", encoding="utf-8") as f:
            f.write(blob)
        os.replace(SEEN + ".tmp", SEEN)
    except OSError:
        pass


def _fetch_lines(url):
    import requests
    r = requests.get(url, headers=UA, timeout=T)
    if r.status_code != 200:
        raise RuntimeError(f"{url.split('/')[2]} HTTP {r.status_code}")
    return [ln.strip() for ln in r.text.splitlines() if ln.strip()]


def pull(name):
    """Pull one feed -> list of indicator strings (dedup happens in run_once)."""
    if name == "urlhaus_recent":
        import requests
        r = requests.get(FEEDS[name], headers=UA, timeout=T)
        if r.status_code != 200:
            raise RuntimeError(f"urlhaus HTTP {r.status_code}")
        rows = r.json().get("urls") or []
        return [f"url|{row.get('url')}|{row.get('threat') or 'malware'}"
                for row in rows[:500]]
    if name == "openphish":
        return [f"url|{ln}" for ln in _fetch_lines(FEEDS[name])]
    if name in ("blocklist_de", "feodo"):
        return [f"ip|{ln.split()[0]}" for ln in _fetch_lines(FEEDS[name])
                if not ln.startswith("#")]
    if name == "otx_pulses":
        import requests
        r = requests.get(FEEDS[name], headers=UA, timeout=T)
        if r.status_code != 200:
            raise RuntimeError(f"otx HTTP {r.status_code}")
        out = []
        for pulse in (r.json().get("results") or []):
            for ind in (pulse.get("indicators") or [])[:20]:
                if ind.get("type") in ("IPv4", "domain", "hostname", "URL"):
                    out.append(f"{ind['type'].lower()}|{ind.get('indicator')}"
                               f"|{pulse.get('name', '')[:80]}")
        return out[:400]
    raise ValueError(f"unknown feed {name}")


def _watch_hits(indicator):
    """Does this indicator touch anything on our watch tables?"""
    hits = []
    try:
        parts = indicator.split("|")
        val = parts[1] if len(parts) > 1 else ""
        c = db.get_db()
        for table, col in (("certstream_watch", "domain"),
                           ("hostwatch", "ip"),
                           ("darknet_watch", "ip"),
                           ("exposure_watch", "target")):
            try:
                rows = c.execute(
                    f"SELECT case_id,{col} FROM {table} WHERE enabled=1 AND {col} LIKE ?",
                    (f"%{val}%",)).fetchall()
                for r in rows:
                    hits.append({"table": table, "case_id": r["case_id"],
                                 "value": r[col]})
            except Exception:
                continue
    except Exception:
        pass
    return hits


def run_once(feeds=None):
    """Pull selected feeds, land new indicators as artifacts + alerts."""
    feeds = feeds or list(FEEDS)
    seen = _load_seen()
    results = {}
    c = db.get_db()
    for name in feeds:
        try:
            indicators = pull(name)
        except Exception as e:
            results[name] = {"status": "error", "error": str(e)[:150]}
            continue
        new = [i for i in indicators if i not in seen]
        seen.update(new)
        matched = []
        for ind in new[:200]:
            hits = _watch_hits(ind)
            if hits:
                matched.append({"indicator": ind, "watch": hits})
        if new:
            db.store_artifact(None, None, "feed", f"feedstream:{name}",
                              {"count": len(new), "indicators": new[:100]},
                              "feedstream-daemon")
        for m in matched[:20]:
            for w in m["watch"][:3]:
                c.execute(
                    "INSERT INTO alerts (case_id,ts,severity,message,detail) VALUES (?,?,?,?,?)",
                    (w.get("case_id"), db.utcnow(), "high",
                     f"Threat feed hit on watched {w['value']}: "
                     f"{m['indicator'][:140]}",
                     json.dumps({"feed": name, "indicator": m["indicator"]})[:900]),
                )
        c.commit()
        results[name] = {"status": "ok", "pulled": len(indicators),
                         "new": len(new), "watch_matches": len(matched)}
        time.sleep(1)
    _save_seen(seen)
    db.audit("system", "feedstream.run_once", ",".join(feeds),
             "new=" + str(sum(r.get("new", 0) for r in results.values())))
    return {"status": "ok", "feeds": results}


def status():
    seen = _load_seen()
    return {"status": "ok", "feeds": list(FEEDS),
            "seen_count": len(seen), "seen_store": SEEN}


_daemon_stop = threading.Event()


def start_daemon(interval_sec=600):
    """Background feed puller — never blocks boot."""
    def _loop():
        while not _daemon_stop.is_set():
            try:
                run_once()
            except Exception:
                pass
            _daemon_stop.wait(interval_sec)

    threading.Thread(target=_loop, daemon=True, name="feedstream").start()
    return True
