"""Xaxglog pattern connectors — public-source interaction harvest.

Keyless connectors feeding the normalized event schema in pattern.py:
  github    — events API: pushes, PRs, issues, comments + profile company links
  bluesky   — public repo records: posts (mentions), follows, shared links
  mastodon  — lookup + statuses (mentions) + public following
  gdelt     — news co-mentions: article titles matched against case entities
  telegram  — public channel posts via the shipped regional module

Every connector degrades cleanly: no key, blocked, rate-limited -> status only.
"""
import re
from datetime import datetime, timezone

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0", "Accept": "application/json"}
T = 15

PLATFORMS = {
    "github":   {"label": "GitHub events + org links", "hint": "username"},
    "bluesky":  {"label": "Bluesky posts, mentions, follows", "hint": "handle.bsky.social"},
    "mastodon": {"label": "Mastodon statuses + following", "hint": "user@instance.social"},
    "gdelt":    {"label": "GDELT news co-mentions", "hint": "person / org / phrase"},
    "telegram": {"label": "Public Telegram channel posts", "hint": "channel name (t.me/s/<c>)"},
}

_MENTION_RE = re.compile(r"@([a-z0-9][a-z0-9.\-]{1,60}\.[a-z]{2,24}|[a-z0-9_]{4,32})", re.I)
_URL_RE = re.compile(r"https?://[^\s\"'<>\)]+", re.I)


def _get(url, **kw):
    import requests
    kw.setdefault("timeout", T)
    headers = dict(UA)
    headers.update(kw.pop("headers", {}))
    try:
        return requests.get(url, headers=headers, **kw)
    except Exception as e:
        return e


def _ok(r):
    return (not isinstance(r, Exception)) and r is not None and r.status_code == 200


def _iso(ts):
    """Normalize connector timestamps to UTC ISO-Z."""
    if not ts:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    try:
        s = str(ts).strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        pass
    for fmt in ("%Y%m%dT%H%M%SZ", "%Y-%m-%d %H:%M:%S", "%Y%m%d%H%M%S"):
        try:
            return datetime.strptime(str(ts), fmt).replace(
                tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
        except Exception:
            continue
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _case_values(case_id, exclude, limit=150):
    """Other entity values in the case — co-mention match targets."""
    if case_id is None:
        return []
    c = db.get_db()
    rows = c.execute(
        "SELECT value FROM entities WHERE case_id=? AND value<>? AND LENGTH(value)>3"
        " ORDER BY id LIMIT ?", (case_id, exclude, limit)).fetchall()
    return [r["value"] for r in rows]


def _match_case_entities(text, values):
    hits = []
    low = (text or "").lower()
    for v in values:
        token = v.lower().strip()
        if len(token) < 4:
            continue
        if re.search(r"(?<![a-z0-9])" + re.escape(token) + r"(?![a-z0-9])", low):
            hits.append(v)
    return hits


def _ev(actor, target, platform, kind, ts, url="", text="", case_id=None, atype=None, ttype=None):
    return {"actor": {"type": atype, "value": actor}, "target": {"type": ttype, "value": target},
            "platform": platform, "kind": kind, "ts": _iso(ts), "url": url,
            "text": (text or "")[:400], "case_id": case_id}


# ---------------------------------------------------------------- github
def github_actor(username, case_id=None):
    u = (username or "").strip().lstrip("@")
    if not u:
        return {"status": "error", "error": "username required"}
    events, links, urls = [], [], []
    prof = _get(f"https://api.github.com/users/{u}")
    if not _ok(prof):
        return {"status": "blocked" if not isinstance(prof, Exception) and prof.status_code == 403 else "error",
                "error": "profile fetch failed", "http": getattr(prof, "status_code", None)}
    try:
        p = prof.json()
    except Exception as e:
        return {"status": "error", "error": str(e)[:120]}
    company = (p.get("company") or "").strip().lstrip("@")
    if company and len(company) > 2:
        links.append({"src": {"type": "handle", "value": u},
                      "dst": {"type": "org", "value": company},
                      "relation": "member_of", "confidence": 0.7, "source": "github_profile"})
    if p.get("blog"):
        blog = p["blog"] if str(p["blog"]).startswith("http") else f"https://{p['blog']}"
        urls.append(blog)

    ev = _get(f"https://api.github.com/users/{u}/events/public?per_page=100")
    if _ok(ev):
        try:
            for e in ev.json():
                et, created, repo = e.get("type"), e.get("created_at"), (e.get("repo") or {}).get("name") or ""
                owner = repo.split("/")[0] if "/" in repo else repo
                if not owner or owner.lower() == u.lower():
                    continue
                base = f"https://github.com/{repo}"
                payload = e.get("payload") or {}
                if et == "PushEvent":
                    msg = ""
                    commits = payload.get("commits") or []
                    if commits:
                        msg = str(commits[0].get("message") or "")[:300]
                    events.append(_ev(u, owner, "github", "co_author", created,
                                      url=base, text=msg, case_id=case_id,
                                      atype="username", ttype="org"))
                elif et in ("PullRequestEvent", "IssuesEvent"):
                    events.append(_ev(u, owner, "github", "co_author", created,
                                      url=base, text=str(payload.get("action") or ""),
                                      case_id=case_id, atype="username", ttype="org"))
                elif et in ("IssueCommentEvent", "PullRequestReviewEvent", "PullRequestReviewCommentEvent"):
                    events.append(_ev(u, owner, "github", "reply", created,
                                      url=base, case_id=case_id,
                                      atype="username", ttype="org"))
                elif et in ("WatchEvent", "ForkEvent", "ReleaseEvent", "CreateEvent"):
                    events.append(_ev(u, owner, "github", "mention", created,
                                      url=base, case_id=case_id,
                                      atype="username", ttype="org"))
        except Exception as e:
            return {"status": "error", "error": f"events parse: {e}"[:150]}
    else:
        return {"status": "limited", "events": 0, "error": "events endpoint unavailable (rate limit?)"}

    return {"status": "ok", "profile": {"login": p.get("login"), "name": p.get("name"),
                                        "company": p.get("company"), "created": p.get("created_at")},
            "events": events, "links": links, "urls": urls}


# ---------------------------------------------------------------- bluesky
def bluesky_actor(handle, case_id=None):
    h = (handle or "").strip().lstrip("@")
    if not h:
        return {"status": "error", "error": "handle required"}
    events, links, urls = [], [], []
    prof = _get(f"https://bsky.social/xrpc/com.atproto.actor.getProfile?actor={h}")
    if not _ok(prof):
        return {"status": "error", "error": "profile fetch failed",
                "http": getattr(prof, "status_code", None)}
    try:
        p = prof.json()
    except Exception as e:
        return {"status": "error", "error": str(e)[:120]}
    desc = p.get("description") or ""
    for m in _URL_RE.findall(desc)[:5]:
        urls.append(m)

    rec = _get(f"https://bsky.social/xrpc/com.atproto.repo.listRecords?repo={h}"
               f"&collection=app.bsky.feed.post&limit=100")
    n_posts = 0
    if _ok(rec):
        try:
            for r in rec.json().get("records") or []:
                val = r.get("value") or {}
                text = str(val.get("text") or "")
                created = val.get("createdAt")
                uri = str(r.get("uri") or "")
                rkey = uri.split("/")[-1] if uri else ""
                post_url = f"https://bsky.app/profile/{h}/post/{rkey}" if rkey else ""
                n_posts += 1
                for m in set(_MENTION_RE.findall(text)):
                    if m.lower() == h.lower():
                        continue
                    events.append(_ev(h, m, "bluesky", "mention", created,
                                      url=post_url, text=text[:300], case_id=case_id,
                                      atype="handle", ttype="handle"))
                for u2 in _URL_RE.findall(text)[:4]:
                    urls.append(u2)
                embed = val.get("embed") or {}
                ext = (embed.get("external") or {}).get("uri")
                if ext:
                    urls.append(ext)
        except Exception as e:
            return {"status": "error", "error": f"posts parse: {e}"[:150]}
    else:
        return {"status": "limited", "error": "listRecords unavailable", "posts": 0}

    fol = _get(f"https://bsky.social/xrpc/com.atproto.repo.listRecords?repo={h}"
               f"&collection=app.bsky.graph.follow&limit=100")
    n_follows = 0
    if _ok(fol):
        try:
            for r in fol.json().get("records") or []:
                did = ((r.get("value") or {}).get("subject") or "")
                if did:
                    n_follows += 1
                    events.append(_ev(h, did, "bluesky", "follow",
                                      r.get("createdAt") or _iso(None),
                                      case_id=case_id, atype="handle", ttype="handle"))
        except Exception:
            pass

    return {"status": "ok", "profile": {"handle": p.get("handle"), "name": p.get("displayName"),
                                        "followers": p.get("followersCount"),
                                        "created": p.get("createdAt")},
            "posts": n_posts, "follows": n_follows,
            "events": events, "links": links, "urls": sorted(set(urls))[:30]}


# ---------------------------------------------------------------- mastodon
def mastodon_actor(acct, case_id=None):
    a = (acct or "").strip().lstrip("@")
    if "@" not in a:
        return {"status": "error", "error": "use user@instance.social"}
    user, instance = a.rsplit("@", 1)
    events, urls = [], []
    lk = _get(f"https://{instance}/api/v1/accounts/lookup?acct={user}")
    if not _ok(lk):
        return {"status": "error", "error": "instance lookup failed",
                "http": getattr(lk, "status_code", None)}
    try:
        p = lk.json()
    except Exception as e:
        return {"status": "error", "error": str(e)[:120]}
    acc_id = p.get("id")
    for m in _URL_RE.findall(p.get("note") or "")[:5]:
        urls.append(m)

    st = _get(f"https://{instance}/api/v1/accounts/{acc_id}/statuses?limit=40&exclude_reblogs=true")
    n_posts = 0
    if _ok(st):
        try:
            for s in st.json():
                n_posts += 1
                content = re.sub(r"<[^>]+>", " ", s.get("content") or "")
                created = s.get("created_at")
                surl = s.get("url") or ""
                for ment in s.get("mentions") or []:
                    m_acct = ment.get("acct") or ""
                    if m_acct and m_acct.split("@")[0].lower() != user.lower():
                        events.append(_ev(a, m_acct, "mastodon", "mention", created,
                                          url=surl, text=content[:300], case_id=case_id,
                                          atype="handle", ttype="handle"))
                for u2 in _URL_RE.findall(content)[:4]:
                    urls.append(u2)
        except Exception as e:
            return {"status": "error", "error": f"statuses parse: {e}"[:150]}
    else:
        return {"status": "limited", "error": "statuses unavailable"}

    fg = _get(f"https://{instance}/api/v1/accounts/{acc_id}/following?limit=40")
    n_follow = 0
    if _ok(fg):
        try:
            for f in fg.json():
                fq = f.get("acct") or ""
                if fq:
                    n_follow += 1
                    events.append(_ev(a, fq, "mastodon", "follow", f.get("created_at") or _iso(None),
                                      case_id=case_id, atype="handle", ttype="handle"))
        except Exception:
            pass

    return {"status": "ok", "profile": {"acct": a, "followers": p.get("followers_count"),
                                        "created": p.get("created_at")},
            "posts": n_posts, "follows": n_follow,
            "events": events, "urls": sorted(set(urls))[:30]}


# ---------------------------------------------------------------- gdelt co-mentions
def gdelt_comentions(entity, case_id=None, timespan="1week", maxrecords=30):
    """Fetch articles about `entity`, then match titles against every other
    case entity — a co-mention is two entities sharing a headline."""
    import urllib.parse
    q = urllib.parse.quote(f'"{entity}"')
    url = ("https://api.gdeltproject.org/api/v2/doc/doc"
           f"?query={q}&mode=artlist&format=json&maxrecords={maxrecords}"
           f"&timespan={timespan}&sort=datedesc")
    r = _get(url)
    if not _ok(r):
        return {"status": "error", "error": "gdelt unavailable",
                "http": getattr(r, "status_code", None)}
    try:
        arts = (r.json() or {}).get("articles") or []
    except Exception as e:
        return {"status": "error", "error": str(e)[:120]}
    others = _case_values(case_id, entity)
    events, urls = [], []
    for a in arts:
        title = a.get("title") or ""
        aurl = a.get("url") or ""
        seen = _iso(a.get("seendate"))
        if aurl:
            urls.append(aurl)
        for hit in _match_case_entities(title, others):
            events.append(_ev(entity, hit, "gdelt", "co_mention", seen,
                              url=aurl, text=title[:300], case_id=case_id))
    return {"status": "ok", "articles": len(arts), "case_entities_matched": len(others),
            "events": events, "urls": urls}


# ---------------------------------------------------------------- telegram
def telegram_actor(channel, case_id=None):
    ch = (channel or "").strip().lstrip("@").replace("https://t.me/s/", "").replace("t.me/", "")
    try:
        import modules.regional.regional as REG
        r = REG.telegram_channel(ch)
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}
    posts = r.get("posts") or []
    if not posts and (r.get("error") or r.get("status") == "error"):
        return {"status": "error", "error": str(r.get("error") or "channel fetch failed")[:150]}
    others = _case_values(case_id, ch)
    events, urls = [], []
    for p in posts:
        text = str(p.get("text") or "")
        pid = p.get("id")
        ts = p.get("date") or p.get("timestamp") or p.get("time")
        purl = f"https://t.me/s/{ch}/{pid}" if pid is not None else ""
        if purl:
            urls.append(purl)
        for u2 in _URL_RE.findall(text)[:5]:
            urls.append(u2)
        for m in set(_MENTION_RE.findall(text)):
            if m.lower() != ch.lower():
                events.append(_ev(ch, m, "telegram", "mention", ts, url=purl,
                                  text=text[:300], case_id=case_id,
                                  atype="channel", ttype="handle"))
        for hit in _match_case_entities(text, others):
            events.append(_ev(ch, hit, "telegram", "co_mention", ts, url=purl,
                              text=text[:300], case_id=case_id,
                              atype="channel", ttype="person"))
    return {"status": r.get("status") or "ok", "posts": len(posts),
            "events": events, "urls": sorted(set(urls))[:40]}


# ---------------------------------------------------------------- orchestrator
_HANDLERS = {
    "github":   lambda e, cid: github_actor(e, cid),
    "bluesky":  lambda e, cid: bluesky_actor(e, cid),
    "mastodon": lambda e, cid: mastodon_actor(e, cid),
    "gdelt":    lambda e, cid: gdelt_comentions(e, cid),
    "telegram": lambda e, cid: telegram_actor(e, cid),
}


def run(entity, platforms=None, case_id=None, user="system"):
    """Harvest every requested platform for `entity`, ingest normalized
    events into the pattern store, return per-platform summaries."""
    from modules.pattern import pattern as PAT
    PAT.ensure()
    want = [p.strip().lower() for p in (platforms or list(_HANDLERS))] if platforms else list(_HANDLERS)
    out, all_events = {}, []
    links, urls = 0, 0
    for p in want:
        fn = _HANDLERS.get(p)
        if not fn:
            out[p] = {"status": "error", "error": "unknown platform"}
            continue
        try:
            res = fn(entity, case_id)
        except Exception as e:
            out[p] = {"status": "error", "error": str(e)[:150]}
            continue
        evs = res.pop("events", []) or []
        for lk in res.pop("links", []) or []:
            try:
                PAT.add_link(lk["src"].get("type"), lk["src"].get("value"),
                             lk["dst"].get("type"), lk["dst"].get("value"),
                             lk.get("relation", "contacts"), lk.get("source", "pattern"),
                             lk.get("confidence", 0.5), case_id, user)
                links += 1
            except Exception:
                pass
        u2 = res.pop("urls", []) or []
        if u2:
            urls += PAT.record_urls(entity, u2, case_id, source=p, user=user)["inserted"]
        out[p] = {**res, "events_found": len(evs)}
        all_events.extend(evs)
    ingested = PAT.ingest_events(all_events, case_id=case_id, user=user) if all_events else \
        {"received": 0, "inserted": 0, "skipped": 0}
    db.audit(user, "pattern.collect", entity, f"platforms={','.join(want)} events={ingested['inserted']}")
    return {"entity": entity, "platforms": out,
            "events": ingested, "links_created": links, "urls_recorded": urls,
            "case_id": case_id}


def source_catalog():
    return [{"platform": k, "label": v["label"], "target_hint": v["hint"]}
            for k, v in PLATFORMS.items()]
