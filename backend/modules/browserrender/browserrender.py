"""Xaxglog browserrender — fetch JS-rendered public pages (Selenium, opt-in).

Why: some public pages (search result pages, anti-bot walls, SPA profiles)
return an empty shell or a challenge to plain HTTP clients. This renders the
page in a headless browser and returns the post-JS DOM — same constraints
as the deep_search profile scraper:

  - public pages only; no logins, no cookies, no form submissions
  - SSRF-guarded: private/reserved/loopback targets are refused
  - response capped (bytes), single page load, bounded time budget

CAPS: requires `selenium` + a local Chrome/Chromium + chromedriver
(both commented as optional in requirements.txt). When unavailable the
module reports `unconfigured` instead of failing the route.

Used by searchx/deep_search integrations when their plain-HTTP fetch
returns `blocked`.

Lawful-use note: renders what any browser would show anonymously. Respect
robots.txt and each site's ToS; rate-limited by the operator's own pacing.
"""
import ipaddress
import os
import re
import urllib.parse

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
MAX_BYTES = 900_000
CAPS = False
try:
    from selenium import webdriver  # noqa: F401
    CAPS = True
except Exception:
    CAPS = False


def caps():
    return {"status": "ok", "selenium": CAPS,
            "note": "pip install selenium + chromium + chromedriver to enable"
            if not CAPS else "ready"}


def _host_guard(url):
    """Reject private/reserved/loopback targets, non-http schemes."""
    p = urllib.parse.urlparse(url)
    if p.scheme not in ("http", "https"):
        raise ValueError("only http/https allowed")
    host = p.hostname or ""
    if not host:
        raise ValueError("no host")
    if host in ("localhost",):
        raise ValueError("localhost blocked")
    try:
        infos = socket_getaddrinfo(host)
    except Exception:
        infos = []
    for ip in infos:
        addr = ipaddress.ip_address(ip)
        if not addr.is_global:
            raise ValueError(f"private/reserved address blocked: {ip}")
    return True


def socket_getaddrinfo(host):
    import socket
    out = set()
    try:
        for fam, _t, _p, _cn, sa in socket.getaddrinfo(host, 443):
            out.add(sa[0])
    except socket.gaierror:
        pass  # unresolved host -> let the browser fail it
    return sorted(out)


_driver = None


def _driver_singleton():
    """One headless driver reused across calls (fast, low memory)."""
    global _driver
    if _driver is not None:
        return _driver
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-gpu")
    opts.add_argument(f"--user-agent={UA['User-Agent']}")
    opts.add_argument("--disable-dev-shm-usage")
    opts.page_load_strategy = "eager"
    _driver = webdriver.Chrome(options=opts)
    _driver.set_page_load_timeout(int(os.getenv("BROWSERRENDER_TIMEOUT", "20")))
    return _driver


def render(url, wait_ms=1500, screenshot_path=None):
    """Render one public URL; return post-JS DOM + title (+ optional PNG)."""
    if not CAPS:
        return {"status": "unconfigured",
                "error": "selenium/chromium not installed (optional dep)"}
    try:
        _host_guard(url)
        drv = _driver_singleton()
        drv.get(url)
        if wait_ms:
            import time
            time.sleep(min(int(wait_ms), 5000) / 1000.0)
        title = drv.title
        page = drv.page_source or ""
        page = page[:MAX_BYTES]
        final_url = drv.current_url
        shot = None
        if screenshot_path:
            os.makedirs(os.path.dirname(screenshot_path) or ".", exist_ok=True)
            drv.save_screenshot(screenshot_path)
            shot = screenshot_path
        db.audit("system", "browserrender.render", url, f"title={title[:60]}")
        return {"status": "ok", "url": url, "final_url": final_url,
                "title": title[:300], "bytes": len(page), "screenshot": shot,
                "html": page}
    except ValueError as e:
        return {"status": "error", "error": str(e)}
    except Exception as e:
        # driver crash -> drop singleton so the next call restarts it
        global _driver
        try:
            if _driver:
                _driver.quit()
        except Exception:
            pass
        _driver = None
        return {"status": "error", "error": str(e)[:150]}


def text(url, wait_ms=1500):
    """Render + strip tags: visible text only (smaller payload for search)."""
    out = render(url, wait_ms=wait_ms)
    if out.get("status") != "ok":
        return out
    html = out["html"]
    html = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", html)
    text = re.sub(r"(?s)<[^>]+>", " ", html)
    text = re.sub(r"\s+", " ", text).strip()
    return {"status": "ok", "url": url, "final_url": out["final_url"],
            "title": out["title"], "text": text[:400_000]}


def shutdown():
    global _driver
    try:
        if _driver:
            _driver.quit()
    except Exception:
        pass
    _driver = None
    return {"status": "ok"}
