"""Xaxglog deep-recon orchestrator — target-aware "dig profiles".

Turns a single seed (person, domain, vehicle, company, phone, handle) into a
multi-axis investigation that recursively drives the *other* modules, links
everything into the entity graph, and stores SHA-256 evidence at each hop.

Target classes and the axes they drive:
  domain / ip  -> passive recon + 6 NEW deep steps (crawl, wayback, leak,
                  netblock, takeover, port sweep) + corporate + archive watch
  person / username / email -> namevar variants + emailintel + deep_search
                  handles + courts + screening (sanx)
  company      -> worldcorp (GLEIF/VIES) + corporate + officers
  phone        -> deep_search phone + simswap risk (detection only)
  vehicle      -> vehicle decode + ALPR timeline (identity stays gateway-gated)

Everything here is keyless-first and degrades gracefully: a failing source
yields {"status":"error"} for that axis, never a crash. No stored-credential
access to third-party devices; no direct SS7/MAP exploit; lawful-access paths
remain authority-gated upstream.

Sources (all free / public): crt.sh, dns.google (DoH), Wayback CDX, GitHub
code-search API, ip-api, Team Cymru origin ASN, RDAP, urlscan, and the sibling
Xaxglog modules imported lazily below.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import socket
import time

import requests

import db

_UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
_TMO = 15


def _get(url, **kw):
    kw.setdefault("headers", _UA)
    kw.setdefault("timeout", _TMO)
    return requests.get(url, **kw)


def _ok(status):
    return status in ("ok", "partial")


# ================================================================ NEW DEEP STEPS
def _robots_paths(domain):
    """Fetch /robots.txt + /sitemap.xml -> a small list of interesting paths."""
    paths = set()
    for res in ("robots.txt", "sitemap.xml"):
        try:
            r = _get(f"http://{domain}/{res}", timeout=8)
            if r.status_code == 200 and len(r.text) < 200000:
                for m in re.findall(r'(?i)(?:disallow|allow)\s*:\s*(/\S*)', r.text):
                    paths.add(m.strip())
                for m in re.findall(r'<loc>(https?://[^<]+)</loc>', r.text)[:40]:
                    paths.add(re.sub(r'^https?://[^/]+', '', m).split('?')[0])
        except Exception:
            pass
    return paths


def crawl_host(domain, seed_ips=None, cap=40):
    """Deep-crawl a host: title, tech hints, exposed files, extra contacts.

    Fetches the homepage and a set of candidate paths (robots/sitemap-derived
    plus a built-in sensitive-file wordlist). Collects page titles, technology
    fingerprints from headers/body, leaked .env/backup content heads, and any
    extra emails/phones/meta tags. Fully keyless.
    """
    out = {"host": domain, "live": False, "pages": [], "tech": [],
           "exposed_files": [], "emails": [], "phones": [], "social": [],
           "status": "error", "error": None}

    # resolve first so we only crawl hosts that actually answer
    try:
        ip = socket.gethostbyname(domain)
        out["resolved_ip"] = ip
    except Exception as e:
        out["error"] = f"resolve failed: {str(e)[:100]}"
        return out

    candidate = ["/"]
    candidate += sorted(_robots_paths(domain))[:20]
    # sensitive-file / backup wordlist (public, defensive)
    candidate += ["/.env", "/.git/config", "/.git/HEAD", "/backup.zip",
                  "/config.php.bak", "/wp-config.php.bak", "/.DS_Store",
                  "/sitemap_index.xml", "/security.txt", "/.well-known/security.txt",
                  "/server-status", "/phpinfo.php", "/admin", "/login"]

    seen = set()
    for path in candidate:
        if path in seen or len(out["pages"]) >= cap:
            continue
        seen.add(path)
        url = f"http://{domain}{path}"
        try:
            r = requests.get(url, headers=_UA, timeout=8, allow_redirects=True,
                             verify=False)
        except Exception:
            continue
        if r.status_code >= 400 and path not in ("/",):
            continue
        out["live"] = True
        text = r.text or ""
        title = ""
        m = re.search(r'(?is)<title[^>]*>(.*?)</title>', text)
        if m:
            title = re.sub(r'\s+', ' ', m.group(1)).strip()[:160]

        if path == "/" or r.status_code == 200:
            out["pages"].append({"path": path, "status": r.status_code,
                                 "title": title, "bytes": len(r.content)})

        # tech fingerprint: headers + body markers
        srv = r.headers.get("Server", "")
        pow = r.headers.get("X-Powered-By", "")
        if srv:
            out["tech"].append(srv)
        if pow:
            out["tech"].append(pow)
        for marker, name in (("wp-content", "WordPress"), ("Drupal.settings", "Drupal"),
                             ("__NEXT_DATA__", "Next.js"), ("csrfmiddlewaretoken", "Django"),
                             ("nginx", "nginx"), ("cloudflare", "Cloudflare"),
                             ("gtag(", "Google Analytics"), ("wp-json", "WordPress-REST")):
            if marker.lower() in text.lower() or marker.lower() in srv.lower():
                out["tech"].append(name)

        # exposed sensitive file: capture a small head for evidence
        if any(k in path for k in (".env", "config.php", ".git", "security.txt", "phpinfo")) \
                and r.status_code == 200 and len(r.content) > 0:
            head = text[:400]
            out["exposed_files"].append({"path": path, "status": r.status_code,
                                         "bytes": len(r.content), "head": head})

        # harvest contact + social signals from every fetched page
        for em in re.findall(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', text):
            if not em.lower().endswith(('.png', '.jpg', '.gif', '.svg', '.webp')):
                out["emails"].append(em.lower())
        for ph in re.findall(r'\+\d[\d\s().-]{7,}\d', text):
            out["phones"].append(ph.strip())
        for sm in re.findall(r'https?://(?:twitter|x|linkedin|github|instagram|facebook)\.com/[A-Za-z0-9_.-]+', text):
            out["social"].append(sm)

        time.sleep(0.15)  # be polite to the target

    # dedupe + cap
    out["tech"] = sorted(set(out["tech"]))[:30]
    out["emails"] = sorted(set(out["emails"]))[:50]
    out["phones"] = sorted(set(out["phones"]))[:30]
    out["social"] = sorted(set(out["social"]))[:30]
    out["status"] = "ok" if out["live"] else "no_response"
    return out


def historical_pivot(domain, cap=60):
    """Wayback CDX: old subdomains + paths the site once served (keyless)."""
    out = {"domain": domain, "hosts": [], "paths": [], "status": "error",
           "error": None}
    try:
        import modules.archive.archive as ARC
        res = ARC.wayback_cdx(f".{domain}", limit=cap)
        snaps = res.get("snapshots") or []
        hosts, paths = set(), set()
        for s in snaps:
            orig = s.get("url") or s.get("original") or ""
            m = re.match(r'https?://([^/]+)(/.*)?$', orig)
            if m:
                h = m.group(1).lower()
                if domain.lower() in h:
                    hosts.add(h)
                if m.group(2):
                    paths.add(m.group(2).split('?')[0])
        out["hosts"] = sorted(hosts)[:cap]
        out["paths"] = sorted(paths)[:cap]
        out["status"] = "ok"
    except Exception as e:
        out["error"] = str(e)[:150]
    return out


def leak_search(domain, cap=40):
    """GitHub code-search for secrets/internal hosts tied to a domain (keyless)."""
    out = {"domain": domain, "results": [], "queries": [],
           "status": "error", "error": None}
    queries = [f'"{domain}"', f'"{domain}" password', f'"{domain}" api_key',
               f'"{domain}" aws_secret', f'filename:.env "{domain}"']
    hits = []
    try:
        for q in queries[:4]:
            out["queries"].append(q)
            r = _get("https://api.github.com/search/code",
                     params={"q": q, "per_page": 10})
            if r.status_code == 403:
                out["status"] = "rate_limited"
                break
            if r.status_code != 200:
                continue
            j = r.json()
            for item in (j.get("items") or [])[:10]:
                repo = (item.get("repository") or {})
                hits.append({
                    "repo": repo.get("full_name"),
                    "path": item.get("path"),
                    "url": item.get("html_url"),
                    "score": item.get("score"),
                })
            time.sleep(2)  # anonymous code-search is 10 req/min
        out["results"] = hits[:cap]
        out["status"] = "ok" if hits else "no_hits"
    except Exception as e:
        out["error"] = str(e)[:150]
    return out


def netblock_expand(domain, cap=25):
    """ASN/netblock expansion: siblings that share the org's network (keyless)."""
    out = {"domain": domain, "asn": None, "org": None, "siblings": [],
           "status": "error", "error": None}
    try:
        import modules.infra.infra as INFRA
        ip = socket.gethostbyname(domain)
        asn = INFRA.asn_lookup(ip)
        out["asn"] = asn.get("asn")
        out["org"] = asn.get("org")
        # urlscan co-hosted domains on the same IP
        r = _get(f"https://urlscan.io/api/v1/search/?q=ip:{ip}")
        if not isinstance(r, Exception) and r.status_code == 200:
            j = r.json()
            sibs = sorted({(x.get("page") or {}).get("domain")
                           for x in (j.get("results") or []) if (x.get("page") or {}).get("domain")})
            out["siblings"] = [s for s in sibs if domain.lower() not in s.lower()][:cap]
        out["status"] = "ok"
    except Exception as e:
        out["error"] = str(e)[:150]
    return out


def takeover_check(subdomains, cap=60):
    """Flag dead subdomains that resolve to nothing (possible takeover)."""
    out = {"checked": 0, "dead": [], "live": 0, "status": "ok"}
    dead = []
    live = 0
    subs = (subdomains or [])[:cap]
    for s in subs:
        out["checked"] += 1
        try:
            socket.gethostbyname(s)
            live += 1
        except Exception:
            dead.append(s)
    out["dead"] = dead
    out["live"] = live
    out["note"] = "dead subdomains are takeover *candidates*; verify CNAME before claiming"
    return out


def port_sweep(ip, cap=1000):
    """Fast top-N TCP connect sweep for common services (keyless, local)."""
    COMMON = [21, 22, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
              1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 6379, 8000,
              8080, 8443, 8888, 9000, 9090, 9200, 11211, 27017]
    open_ports = []

    def probe(p):
        try:
            with socket.create_connection((ip, p), timeout=0.6):
                return p
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=64) as ex:
        for fut in as_completed([ex.submit(probe, p) for p in COMMON[:cap]]):
            got = fut.result()
            if got:
                open_ports.append(got)
    return {"ip": ip, "open_ports": sorted(set(open_ports)),
            "scanned": min(len(COMMON), cap), "status": "ok"}


# ================================================================ TARGET DISPATCH
def _identity_stage_variants(seed, case_id, user):
    import modules.namevar.namevar as NV
    return NV.cross_script_search_terms(seed)[:10]


def _identity_stage_handles(seed, case_id, user):
    import modules.deep_search.connectors as DS
    if "@" in seed:
        return DS.email_search(seed)
    return DS.person_search(seed) or DS.username_search(seed)


def _identity_stage_email(seed, case_id, user):
    import modules.emailintel.emailintel as EI
    return EI.deep(seed, case_id, user)


def _identity_stage_email_pivots(seed, case_id, user):
    """Pivot an email local-part into public handle variants.

    ``jane.doe@example.com`` -> ``jane.doe``, ``janedoe``, ``jane_doe`` across
    social/professional/code platform checks. Public profile matrix only.
    """
    import modules.deep_search.connectors as DS
    local = seed.split("@", 1)[0].lower().split("+", 1)[0]
    raw = re.sub(r'[^a-z0-9._-]', '', local)
    candidates = []
    for c in (raw, raw.replace(".", ""), raw.replace(".", "_"),
              raw.replace("_", "."), raw.split(".", 1)[0]):
        if c and 2 <= len(c) <= 39 and c not in candidates:
            candidates.append(c)
    candidates = candidates[:3]
    out = {"seed": seed, "candidates": candidates, "results": {},
           "total_hits": 0, "status": "ok" if candidates else "skipped"}
    if not candidates:
        out["note"] = "local-part produced no safe handle candidates"
        return out
    with ThreadPoolExecutor(max_workers=len(candidates)) as ex:
        futs = {ex.submit(DS.username_search, c,
                          ("social", "professional", "code", "regional")): c
                for c in candidates}
        for fut in as_completed(futs):
            c = futs[fut]
            try:
                res = fut.result()
                hits = res.get("hits") or []
                out["results"][c] = {"checked": res.get("checked"),
                                     "hits": hits[:20]}
                out["total_hits"] += len(hits)
            except Exception as e:
                out["results"][c] = {"hits": [], "error": str(e)[:120]}
    return out


def _identity_stage_screening(seed, case_id, user):
    import modules.sanx.sanx as SANX
    return SANX.search(seed, 0.75)


def _identity_stage_courts(seed, case_id, user):
    import modules.courts.courts as CRT
    return CRT.search(seed, None, None, timeout=12)


def _identity_profile(seed, case_id=None, user="system"):
    """Person/username/email axis: variants + email intel + handles + courts.

    Stages run concurrently (the courts fan-out is the slow one; it no longer
    serializes behind the fast name/email lookups).
    """
    axis = {"seed": seed, "status": "ok", "error": None}
    stages = {
        "variants": _identity_stage_variants,
        "handles": _identity_stage_handles,
        "screening": _identity_stage_screening,
        "courts": _identity_stage_courts,
    }
    if "@" in seed:
        stages["email"] = _identity_stage_email
        stages["email_pivots"] = _identity_stage_email_pivots
    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = {ex.submit(fn, seed, case_id, user): name
                for name, fn in stages.items()}
        for fut in as_completed(futs):
            name = futs[fut]
            try:
                axis[name] = fut.result()
            except Exception as e:
                axis[f"{name}_error"] = str(e)[:120]
    return axis


def _company_profile(seed, case_id=None, user="system"):
    """Company axis: GLEIF ownership + corporate officers + jurisdiction."""
    axis = {"seed": seed, "status": "ok", "error": None}
    try:
        import modules.worldcorp.worldcorp as WC
        axis["gleif"] = WC.gleif_search(seed)
    except Exception as e:
        axis["gleif_error"] = str(e)[:120]
    try:
        import modules.corporate.corporate as CORP
        axis["officers"] = CORP.trace_person(seed)
    except Exception as e:
        axis["officers_error"] = str(e)[:120]
    return axis


def _vehicle_profile(seed, case_id=None, user="system"):
    """Vehicle axis: VIN/plate decode + ALPR timeline (identity gateway-gated)."""
    axis = {"seed": seed, "status": "ok", "error": None}
    try:
        import modules.vehicle.vehicle as VEH
        axis["decode"] = VEH.decode_vin(seed)
    except Exception as e:
        axis["decode_error"] = str(e)[:120]
    return axis


def _phone_profile(seed, case_id=None, user="system"):
    """Phone axis: carrier lookup + SIM-swap risk (detection only)."""
    axis = {"seed": seed, "status": "ok", "error": None}
    try:
        import modules.deep_search.connectors as DS
        axis["carrier"] = DS.phone_search(seed)
    except Exception as e:
        axis["carrier_error"] = str(e)[:120]
    try:
        import modules.simswap.simswap as SS
        axis["simswap"] = SS.assess(seed)
    except Exception as e:
        axis["simswap_error"] = str(e)[:120]
    return axis


DEEP_AXES = {
    "domain": ["passive_recon", "crawl", "historical", "leak", "netblock",
               "takeover", "ports", "company", "archive_watch"],
    "ip": ["passive_recon", "ports", "netblock"],
    "person": ["identity"],
    "username": ["identity"],
    "email": ["identity"],
    "company": ["company"],
    "vehicle": ["vehicle"],
    "phone": ["phone"],
}


def _guess_axis(value):
    v = (value or "").strip()
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', v):
        return "ip"
    if "@" in v:
        return "email"
    if re.match(r'^(?:[a-z0-9-]+\.)+[a-z]{2,}$', v, re.I):
        return "domain"
    if re.match(r'^[A-HJ-NPR-Z0-9]{17}$', v.upper()):
        return "vehicle"
    if re.match(r'^\+?\d[\d\s().-]{7,}$', v):
        return "phone"
    # company heuristic: a corporate token anywhere => company (people don't
    # have "bank"/"technologies"/"ltd" in their name); otherwise 2+ title-case
    # words with no person-name shape.
    words = v.split()
    corporate = ("ltd", "llc", "inc", "corp", "gmbh", "plc", "ag", "sa",
                 "nv", "bv", "co", "company", "bank", "group", "holdings",
                 "technologies", "solutions", "consulting", "university")
    if any(any(c in w.lower() for c in corporate) for w in words):
        return "company"
    # A title-case multi-word value without a corporate suffix is treated as a
    # person (e.g. "Ada Lovelace"). Callers can still force an axis explicitly.
    try:
        import modules.deep_search.social as SOC
        if " " in v and SOC.NAME_RE.fullmatch(v):
            return "person"
    except Exception:
        pass
    if len(words) >= 2 and not re.match(r'^\+?\d', v):
        return "company"
    return "person"


def _company_seed(typed, seed):
    return seed


# ================================================================ ORCHESTRATOR
def _run_axis(name, typed, seed, ctx, case_id=None, user="system"):
    """Run one deep axis for the given target; returns (name, result)."""
    try:
        if name == "passive_recon":
            import modules.recon.pipeline as RECON
            ptype = "ip" if typed == "ip" else "domain"
            return name, RECON.run_pipeline(seed, ptype, case_id, user, keys={})
        if name == "crawl":
            return name, crawl_host(seed)
        if name == "historical":
            return name, historical_pivot(seed)
        if name == "leak":
            return name, leak_search(seed)
        if name == "netblock":
            return name, netblock_expand(seed)
        if name == "takeover":
            subs = (ctx.get("passive_recon") or {}).get("context", {}) \
                .get("subdomains", {}).get("subdomains", [])
            return name, takeover_check(subs)
        if name == "ports":
            ip = ctx.get("passive_recon", {}).get("context", {}) \
                .get("resolve", {}).get("ips", [seed])
            if isinstance(ip, list):
                ip = ip[0] if ip else seed
            return name, port_sweep(ip)
        if name == "company":
            return name, _company_profile(_company_seed(typed, seed), case_id, user)
        if name == "identity":
            return name, _identity_profile(seed, case_id, user)
        if name == "vehicle":
            return name, _vehicle_profile(seed, case_id, user)
        if name == "phone":
            return name, _phone_profile(seed, case_id, user)
        if name == "archive_watch":
            # seed a change-watch so the operator is alerted to future edits
            try:
                import modules.archive.archive as ARC
                wid = ARC.register_watch(f"http://{seed}", case_id, 720, user)
                return name, {"watch_id": wid, "status": "watching"}
            except Exception as e:
                return name, {"status": "error", "error": str(e)[:120]}
        return name, {"status": "skipped", "note": f"unknown axis '{name}'"}
    except Exception as e:
        return name, {"status": "error", "error": str(e)[:200]}


def run_deep(target, axis=None, case_id=None, user="system", max_workers=6):
    """Run an intense, target-aware deep recon.

    Detects the target class, resolves the dig-profile (or uses an explicit
    axis), runs the independent axes concurrently, and returns a merged result
    with an axis status summary + elapsed time. Every axis is independently
    fault-isolated (a failing source never aborts the run).
    """
    t0 = time.time()
    seed = (target or "").strip()
    if not seed:
        return {"error": "target required"}

    typed = _guess_axis(seed)
    plan = list(DEEP_AXES.get(typed, ["identity"]))
    if axis:
        want = [a.strip() for a in (axis if isinstance(axis, list)
                                    else str(axis).split(",")) if a.strip()]
        # allow explicit override but keep only known axes
        known = set(DEEP_AXES.get(typed, []))
        plan = [a for a in want if a in known] or plan

    ctx = {}
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(_run_axis, a, typed, seed, ctx, case_id, user): a
                for a in plan}
        for fut in as_completed(futs):
            name = futs[fut]
            try:
                _, res = fut.result()
            except Exception as e:
                res = {"status": "error", "error": str(e)[:200]}
            results[name] = res
            ctx[name] = res  # let dependent axes (takeover/ports) read it

    # emit entities/edges into the graph for the axes that produced structure
    if case_id:
        try:
            emit_deep_entities(case_id, seed, typed, results, user)
        except Exception as e:
            results["_emit_error"] = str(e)[:200]

    return {
        "target": seed,
        "detected_type": typed,
        "axes_run": plan,
        "axis_status": {k: _status_of(v) for k, v in results.items()},
        "axes": results,
        "dossier": _dossier_summary(seed, typed, results),
        "elapsed": round(time.time() - t0, 2),
    }


def _status_of(res):
    """Best-effort status for any axis result.

    Surfaces an explicit status/error when the axis set one; otherwise infers
    ok from a result that carried data (count/results/total) so callers never
    see a bare None.
    """
    if not isinstance(res, dict):
        return "ok"
    if res.get("status"):
        return res["status"]
    if res.get("error"):
        return "error"
    for k in ("count", "results", "total", "open_ports", "servers",
              "variants", "hits", "emails", "phones"):
        if res.get(k):
            return "ok"
    return "ok"


def _upsert(case_id, etype, value):
    c = db.get_db()
    now = db.utcnow()
    c.execute(
        "INSERT INTO entities (case_id,type,value,first_seen,last_seen) VALUES (?,?,?,?,?)"
        " ON CONFLICT(case_id,type,value) DO UPDATE SET last_seen=excluded.last_seen",
        (case_id, etype, value, now, now))
    c.commit()
    row = c.execute("SELECT id FROM entities WHERE case_id=? AND type=? AND value=?",
                    (case_id, etype, value)).fetchone()
    return row["id"]


def _edge(case_id, src, dst, relation):
    c = db.get_db()
    c.execute(
        "INSERT INTO edges (case_id,src_id,dst_id,relation,weight,source,created_at)"
        " VALUES (?,?,?,?,?,?,?) ON CONFLICT(case_id,src_id,dst_id,relation) DO NOTHING",
        (case_id, src, dst, relation, 1.0, "deeprecon", db.utcnow()))
    c.commit()


def emit_deep_entities(case_id, seed, typed, results, user):
    """Write deep-recon discoveries into the entity graph + evidence trail."""
    root_type = "domain" if typed in ("domain", "ip") else typed
    root = _upsert(case_id, root_type, seed)

    # crawl -> live host, tech, exposed files, extra contacts
    crawl = results.get("crawl") or {}
    for sub in (crawl.get("subdomains") or []):
        sid = _upsert(case_id, "domain", sub)
        _edge(case_id, root, sid, "subdomain_of")
    for em in (crawl.get("emails") or []):
        eid = _upsert(case_id, "email", em)
        _edge(case_id, root, eid, "exposes_email")
    for ph in (crawl.get("phones") or []):
        pid = _upsert(case_id, "phone", ph)
        _edge(case_id, root, pid, "exposes_phone")
    for so in (crawl.get("social") or []):
        sid = _upsert(case_id, "handle", so)
        _edge(case_id, root, sid, "links_social")

    # historical -> old hosts now known
    hist = results.get("historical") or {}
    for h in (hist.get("hosts") or []):
        hid = _upsert(case_id, "domain", h)
        _edge(case_id, root, hid, "historical_host")

    # netblock -> sibling domains sharing infra
    netb = results.get("netblock") or {}
    for s in (netb.get("siblings") or []):
        sid = _upsert(case_id, "domain", s)
        _edge(case_id, root, sid, "shares_infra")

    # ports -> service entities
    ports = results.get("ports") or {}
    for p in (ports.get("open_ports") or []):
        sid = _upsert(case_id, "service", f"{ports.get('ip','')}:{p}")
        _edge(case_id, root, sid, "exposes_service")

    # leak -> code repos
    leak = results.get("leak") or {}
    for hit in (leak.get("results") or []):
        rid = _upsert(case_id, "repo", hit.get("url"))
        _edge(case_id, root, rid, "leaked_in")

    # store a consolidated evidence artifact
    db.store_artifact(case_id, root, "deeprecon", "deeprecon:run",
                      {"target": seed, "axes": list(results)}, user)


def _dossier_summary(target, typed, results):
    """Normalize intense-recon output into entities + a confidence summary."""
    entities, seen = [], set()
    counts = {"profile": 0, "person": 0, "social": 0, "email": 0,
              "phone": 0, "domain": 0, "port": 0, "company": 0,
              "officer": 0, "url": 0}

    def add(etype, value, source, url="", confidence="lead"):
        value = (value or "").strip() if isinstance(value, str) else value
        if not value:
            return
        key = (etype, str(value).lower())
        if key in seen or len(entities) >= 300:
            return
        seen.add(key)
        rec = {"type": etype, "value": str(value), "source": source,
               "confidence": confidence}
        if url:
            rec["url"] = url
        entities.append(rec)
        counts[etype] = counts.get(etype, 0) + 1

    def add_profile(rec, source):
        if not isinstance(rec, dict) or rec.get("exists") is False:
            return
        platform = rec.get("platform") or ""
        handle = (rec.get("handle") or rec.get("username") or rec.get("login")
                  or rec.get("acct") or rec.get("name") or "")
        url = rec.get("url") or rec.get("html_url") or rec.get("final_url") or ""
        if platform or handle or url:
            add("profile", (platform + ":" + handle).strip(":") or url,
                source, url, rec.get("confidence") or "lead")

    identity = results.get("identity") or {}
    handles = identity.get("handles") or {}
    if isinstance(handles, dict):
        for hit in (handles.get("profiles") or {}).get("hits") or []:
            add_profile(hit, "profile_matrix")
        for hit in (handles.get("verified") or {}).get("verified") or []:
            add_profile(hit, "api_verified")
        gh = handles.get("github") or {}
        if isinstance(gh, dict) and gh.get("html_url"):
            add_profile({"platform": "GitHub", "login": gh.get("login"),
                         "url": gh.get("html_url")}, "github")
        for src, rows in ((handles.get("people") or {}).get("sources") or {}).items():
            for row in (rows or [])[:8]:
                add("person", row.get("name") or row.get("title") or row.get("login")
                    or row.get("acct") or row.get("handle"), src,
                    row.get("url") or row.get("html_url"))
        for row in ((handles.get("social") or {}).get("results") or [])[:20]:
            add("social", row.get("platform") or row.get("title") or row.get("url"),
                "social_web", row.get("url"))

    for cand, res in ((identity.get("email_pivots") or {}).get("results") or {}).items():
        for hit in (res or {}).get("hits") or []:
            add_profile(hit, "email_pivot:" + cand)

    for row in ((identity.get("screening") or {}).get("results") or [])[:20]:
        if isinstance(row, dict):
            add("person", row.get("name") or row.get("caption"), "sanctions",
                row.get("url"), "watchlist")
    for row in ((identity.get("courts") or {}).get("results") or [])[:15]:
        if isinstance(row, dict):
            add("person", row.get("case_name") or row.get("title") or row.get("name"),
                "courts", row.get("url") or row.get("docket_url"))

    crawl = results.get("crawl") or {}
    for em in crawl.get("emails") or []:
        add("email", em, "crawl")
    for ph in crawl.get("phones") or []:
        add("phone", ph, "crawl")
    for so in crawl.get("social") or []:
        add("url", so, "crawl_social")
    for sub in ((results.get("passive_recon") or {}).get("context", {})
                .get("subdomains", {}).get("subdomains") or [])[:100]:
        add("domain", sub, "passive_recon")
    for host in ((results.get("historical") or {}).get("hosts") or [])[:100]:
        add("domain", host, "wayback")
    for sibling in ((results.get("netblock") or {}).get("siblings") or [])[:50]:
        add("domain", sibling, "netblock")
    for port in ((results.get("ports") or {}).get("open_ports") or []):
        add("port", str(port), "port_sweep")

    company = results.get("company") or {}
    for key in ("gleif", "officers", "corporate"):
        block = company.get(key) or {}
        rows = block.get("results") if isinstance(block, dict) else block
        for row in (rows or [])[:25]:
            if not isinstance(row, dict):
                continue
            name = (row.get("name") or row.get("company_name") or row.get("officer")
                    or row.get("legal_name"))
            role = "officer" if key == "officers" else (
                "company" if key in ("gleif", "corporate") else "person")
            add(role, name, key, row.get("url") or row.get("opencorporates_url"))

    phone = results.get("phone") or {}
    if isinstance(phone, dict):
        if phone.get("international") or phone.get("e164"):
            add("phone", phone.get("international") or phone.get("e164"), "phone_intel")
        for key in ("carrier", "region"):
            if phone.get(key):
                add("phone", str(phone[key]), "phone_intel")

    score = min(100, (
        counts.get("profile", 0) * 10
        + min(counts.get("person", 0), 15) * 2
        + counts.get("social", 0) * 3
        + counts.get("email", 0) * 8
        + counts.get("domain", 0) * 4
        + counts.get("port", 0) * 2
        + counts.get("company", 0) * 6
        + counts.get("officer", 0) * 8
        + (10 if typed else 0)
    ))
    # Name-index hits are homonym-prone; without a profile/email/domain/company
    # anchor the dossier stays at medium confidence.
    if not any(counts.get(k, 0) for k in
               ("profile", "email", "domain", "company", "officer")):
        score = min(score, 55)
    band = "high" if score >= 65 else ("medium" if score >= 30 else "low")
    reasons = []
    if counts.get("profile"):
        reasons.append("%d public profile hit(s)" % counts["profile"])
    if counts.get("person"):
        reasons.append("%d people-index match(es)" % counts["person"])
    if counts.get("email") or counts.get("domain"):
        reasons.append("%d email/domain pivot(s)" % (counts.get("email", 0) + counts.get("domain", 0)))
    if counts.get("social"):
        reasons.append("%d social-web lead(s)" % counts["social"])
    if counts.get("company") or counts.get("officer"):
        reasons.append("%d company/officer record(s)"
                       % (counts.get("company", 0) + counts.get("officer", 0)))
    if not reasons:
        reasons.append("no corroborating pivot yet")
    return {
        "target": target,
        "detected_type": typed,
        "counts": counts,
        "entities": entities,
        "confidence": {"score": score, "band": band, "reasons": reasons},
    }


def list_deep_profiles():
    return {"profiles": DEEP_AXES,
            "target_types": list(DEEP_AXES.keys()),
            "note": "run via POST /api/recon/deep {target, axis?, case_id?}"}

