"""Xaxglog regional — international/regional search platforms & relays.

Purpose
-------
Extend OSINT coverage beyond Western engines: Telegram public channels,
Baidu (CN), Yandex (RU), Weibo (CN), plus a relay into the federated
searchx stack. Every engine reports per-source availability with latency.

Sources (public, keyless)
-------------------------
  - Telegram public preview pages   https://t.me/s/<channel>
  - Baidu SERP                      https://www.baidu.com/s?wd=
  - Yandex SERP                     https://yandex.com/search/?text=
  - Weibo search                    https://s.weibo.com/weibo?q=
  - SearXNG/DDG/Mojeek/Wikipedia    via modules.searchx.searchx.federated

Lawful use
----------
Public pages only — no logins, no scraping behind auth walls, no captcha
solving. Respect each platform's ToS and robots.txt, keep request volume low.
Anti-bot / captcha / login walls degrade to ``{"status": "blocked", "mode": ...}``
(or "not_found") and never crash the caller. No credential attacks.
"""
import re
import html as _html
import time

import requests

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 15
ZHCN_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

_BLOCK_MARKERS = (
    "captcha", "wappass", "showcaptcha", "unusual traffic", "verifying",
    "are you a robot", "just a moment", "cf-chl", "access denied",
    "request blocked", "异常", "验证", "安全验证",
)
_SAFE_CH = re.compile(r"^[A-Za-z0-9_]{4,32}$")


def _get(url, **kw):
    kw.setdefault("timeout", T)
    headers = dict(UA)
    headers.update(kw.pop("headers", {}))
    try:
        return requests.get(url, headers=headers, **kw)
    except Exception as e:
        return e


def _clean(s):
    s = re.sub(r"<[^>]+>", " ", s or "")
    s = _html.unescape(s)
    return re.sub(r"\s+", " ", s).strip()


def _classify(r):
    try:
        if isinstance(r, Exception):
            return "error"
        if r.status_code in (403, 429, 451, 503):
            return "blocked"
        if r.status_code == 404:
            return "not_found"
        if r.status_code >= 500:
            return "error"
        head = (r.text or "")[:8000].lower()
        if any(m in head for m in _BLOCK_MARKERS):
            return "blocked"
        return "ok"
    except Exception:
        return "error"


def _blocked(engine, mode):
    return {"engine": engine, "status": "blocked", "mode": mode, "results": []}


# ------------------------------------------------------------------ telegram
def telegram_channel(channel):
    """Public Telegram channel preview posts via https://t.me/s/<channel>.

    Returns {channel, count, posts:[{id,url,ts,text,views}], status}.
    status: ok | not_found | blocked | error.
    """
    out = {"channel": channel, "count": 0, "posts": [], "status": "ok"}
    try:
        ch = (channel or "").strip().lstrip("@").strip("/")
        if not _SAFE_CH.match(ch):
            out["status"] = "error"
            out["error"] = "invalid channel name (4-32 chars, A-Z a-z 0-9 _)"
            return out
        r = _get(f"https://t.me/s/{ch}")
        st = _classify(r)
        if st == "not_found":
            out["status"] = "not_found"
            return out
        final = getattr(r, "url", "") or ""
        if st == "ok" and f"/s/{ch}" not in final:
            # t.me/s/<ch> 302s to t.me/<ch> when the channel doesn't exist
            out["status"] = "not_found"
            out["note"] = "redirected off preview: " + final[:120]
            return out
        if st != "ok":
            out["status"] = st if st != "error" else "error"
            out["mode"] = "anti_bot" if st == "blocked" else "http_error"
            return out
        page = r.text or ""
        if "tgme_widget_message_wrap" not in page:
            # empty channel vs. soft block: 200 with no messages widget
            if any(m in page.lower() for m in ("captcha", "just a moment")):
                out["status"] = "blocked"
                out["mode"] = "anti_bot"
            else:
                out["status"] = "ok"
                out["note"] = "no public posts (or channel is empty/private)"
            return out
        blocks = []
        starts = [m.start() for m in
                  re.finditer(r'<div class="tgme_widget_message_wrap', page)]
        starts.append(len(page))
        for i in range(len(starts) - 1):
            blocks.append(page[starts[i]:starts[i + 1]])
        posts = []
        for b in blocks:
            pm = re.search(r'data-post="([^"]+)"', b)
            if not pm:
                continue
            post_ref = pm.group(1)                 # "<channel>/<msgid>"
            msg_id = post_ref.split("/")[-1]
            dtm = re.search(r'datetime="([^"]+)"', b)
            tm = re.search(r'class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>',
                           b, re.S)
            text = _clean(tm.group(1)) if tm else ""
            vm = re.search(r'class="tgme_widget_message_views[^"]*"[^>]*>([^<]+)<', b)
            if not vm:
                vm = re.search(r'data-views="([^"]+)"', b)
            posts.append({
                "id": msg_id,
                "url": f"https://t.me/{ch}/{msg_id}",
                "ts": dtm.group(1) if dtm else "",
                "text": text[:2000],
                "views": _clean(vm.group(1)) if vm else "",
            })
        out["posts"] = posts
        out["count"] = len(posts)
        out["status"] = "ok"
        return out
    except Exception as e:
        return {"channel": channel, "count": 0, "posts": [],
                "status": "error", "error": str(e)[:150]}


# ------------------------------------------------------------------ baidu
def baidu_search(q):
    """Baidu SERP (zh-CN). Captcha/WAF -> status blocked, never raises."""
    out = {"engine": "baidu", "status": "ok", "results": []}
    try:
        q = (q or "").strip()
        if not q:
            out["status"] = "error"
            out["error"] = "empty query"
            return out
        r = _get("https://www.baidu.com/s", params={"wd": q},
                 headers={"User-Agent": ZHCN_UA,
                          "Accept-Language": "zh-CN,zh;q=0.9",
                          "Accept": "text/html,application/xhtml+xml",
                          "Referer": "https://www.baidu.com/"})
        st = _classify(r)
        if st != "ok":
            out["status"] = st
            out["mode"] = "waf_captcha" if st == "blocked" else "http_error"
            return out
        page = r.text or ""
        final = getattr(r, "url", "") or ""
        if ("wappass" in final or "captcha" in final
                or "wappass.baidu.com" in page or "captcha" in page.lower()):
            out["status"] = "blocked"
            out["mode"] = "waf_captcha"
            return out
        rows = []
        # <h3 class="t"><a href="...">title</a></h3>  (also class="t c-title-en")
        for m in re.finditer(
                r'<h3[^>]*class="t[^"]*"[^>]*>\s*<a([^>]*)>(.*?)</a>',
                page, re.S | re.I):
            attrs, inner = m.group(1), m.group(2)
            hm = re.search(r'href\s*=\s*"([^"]+)"', attrs)
            title = _clean(inner)
            if hm and title:
                rows.append({"title": title, "url": _html.unescape(hm.group(1)),
                             "snippet": ""})
        # abstracts follow the h3: <div class="c-abstract ...">text</div>
        abstracts = [_clean(x) for x in re.findall(
            r'class="c-abstract[^"]*"[^>]*>(.*?)</div>', page, re.S)]
        for i, row in enumerate(rows[:20]):
            if i < len(abstracts):
                row["snippet"] = abstracts[i][:500]
        out["results"] = rows[:20]
        if not rows:
            out["status"] = "ok"
            out["note"] = "no parsable results (layout change or soft block)"
        return out
    except Exception as e:
        return {"engine": "baidu", "status": "error", "results": [],
                "error": str(e)[:150]}


# ------------------------------------------------------------------ yandex
def yandex_search(q):
    """Yandex SERP — usually captcha from datacenter IPs -> graceful blocked."""
    out = {"engine": "yandex", "status": "ok", "results": []}
    try:
        q = (q or "").strip()
        if not q:
            out["status"] = "error"
            out["error"] = "empty query"
            return out
        r = _get("https://yandex.com/search/", params={"text": q},
                 headers={"Accept-Language": "en-US,en;q=0.9"})
        final_url = getattr(r, "url", "") or ""
        st = _classify(r)
        if "showcaptcha" in final_url or st == "blocked":
            out["status"] = "blocked"
            out["mode"] = "captcha"
            return out
        if st != "ok":
            out["status"] = st
            out["mode"] = "http_error"
            return out
        page = r.text or ""
        if "showcaptcha" in page or "smartcaptcha" in page:
            out["status"] = "blocked"
            out["mode"] = "captcha"
            return out
        urls = [ _html.unescape(m.group(1)) for m in re.finditer(
            r'<a[^>]*class="[^"]*organic__url[^"]*"[^>]*href="([^"]+)"', page) ]
        if not urls:
            urls = [ _html.unescape(m.group(1)) for m in re.finditer(
                r'<span[^>]*class="[^"]*organic__url[^"]*"[^>]*href="([^"]+)"', page) ]
        titles = [_clean(x) for x in re.findall(
            r'class="organic__title[^"]*"[^>]*>(.*?)</', page, re.S)]
        # organic__url may itself be the link text
        link_texts = [_clean(x) for x in re.findall(
            r'class="organic__url[^"]*"[^>]*>(.*?)</a>', page, re.S)]
        for i, u in enumerate(urls[:20]):
            title = titles[i] if i < len(titles) else (
                link_texts[i] if i < len(link_texts) else u)
            out["results"].append({"title": title, "url": u, "snippet": ""})
        if not out["results"]:
            out["note"] = "no organic results parsed"
        return out
    except Exception as e:
        return {"engine": "yandex", "status": "error", "results": [],
                "error": str(e)[:150]}


# ------------------------------------------------------------------ weibo
def weibo_search(q):
    """Sina Weibo public search — login wall -> status blocked, never raises."""
    out = {"engine": "weibo", "status": "ok", "results": []}
    try:
        q = (q or "").strip()
        if not q:
            out["status"] = "error"
            out["error"] = "empty query"
            return out
        r = _get("https://s.weibo.com/weibo", params={"q": q},
                 headers={"Accept-Language": "zh-CN,zh;q=0.9",
                          "Referer": "https://s.weibo.com/"})
        final_url = getattr(r, "url", "") or ""
        if "passport.weibo" in final_url or "/login" in final_url:
            out["status"] = "blocked"
            out["mode"] = "login_wall"
            return out
        st = _classify(r)
        if st != "ok":
            out["status"] = st
            out["mode"] = "login_wall" if st == "blocked" else "http_error"
            return out
        page = r.text or ""
        if "passport.weibo" in page or "S.weibo.com 需要登录" in page:
            out["status"] = "blocked"
            out["mode"] = "login_wall"
            return out
        nicks = [_clean(x) for x in re.findall(
            r'<a[^>]*class="(?:nick|name)"[^>]*>(.*?)</a>', page, re.S)]
        authors = [_clean(x) for x in re.findall(
            r'<a[^>]*class="au_name[^"]*"[^>]*>(.*?)</a>', page, re.S)]
        txts = re.findall(r'<p[^>]*class="txt[^"]*"[^>]*>(.*?)</p>', page, re.S)
        for i, raw in enumerate(txts[:20]):
            # strip the trailing "from" / action chrome inside <p class="txt">
            body = re.split(r'<span[^>]*class="from"', raw)[0]
            text = _clean(body)
            if not text:
                continue
            out["results"].append({
                "nickname": nicks[i] if i < len(nicks) else "",
                "author": authors[i] if i < len(authors) else
                          (nicks[i] if i < len(nicks) else ""),
                "text": text[:1000],
                "position": i,
            })
        if not out["results"]:
            out["note"] = "no parsable posts (layout change or soft wall)"
        return out
    except Exception as e:
        return {"engine": "weibo", "status": "error", "results": [],
                "error": str(e)[:150]}


# ------------------------------------------------------------------ relay
def searx_relay(query):
    """Thin relay into the same agent's federated search stack (searchx)."""
    try:
        from modules.searchx import searchx as SEARCHX
        fed = SEARCHX.federated(query)
        fed["relay"] = "searx_relay"
        eng = fed.get("engines") or {}
        if fed.get("error"):
            fed["status"] = "error"
        elif fed.get("total", 0) > 0:
            fed["status"] = "ok"
        elif eng and any(v == "ok" for v in eng.values()):
            fed["status"] = "ok"
        elif eng and all(v == "blocked" for v in eng.values()):
            fed["status"] = "blocked"
        else:
            fed["status"] = "error"
        return fed
    except Exception as e:
        return {"query": query, "relay": "searx_relay", "engines": {},
                "total": 0, "results": [], "status": "error",
                "error": str(e)[:150]}


# ------------------------------------------------------------------ probe
def availability(query="test"):
    """Probe each regional engine with a tiny query -> status + latency."""
    probes = [
        ("telegram", lambda: telegram_channel("telegram")),
        ("baidu", lambda: baidu_search(query)),
        ("yandex", lambda: yandex_search(query)),
        ("weibo", lambda: weibo_search(query)),
        ("searx_relay", lambda: searx_relay(query)),
    ]
    out = []
    for name, fn in probes:
        t0 = time.time()
        try:
            res = fn()
        except Exception as e:                    # defensive: never raise
            res = {"status": "error", "error": str(e)[:150]}
        lat = int((time.time() - t0) * 1000)
        status = res.get("status", "error")
        note = res.get("mode") or res.get("error") or res.get("note") or ""
        if name == "searx_relay" and not note:
            eng = res.get("engines") or {}
            note = "engines=" + ",".join(f"{k}:{v}" for k, v in eng.items())
        out.append({"engine": name, "status": status,
                    "latency_ms": lat, "note": str(note)[:200]})
    return {"checked_at_probe": True, "count": len(out), "engines": out}
