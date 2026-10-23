"""Xaxglog deep-recon pipeline engine.

Chained, dependency-aware reconnaissance. Unlike single deep_search calls, a
pipeline walks a graph of steps: a domain fans out to subdomains -> DNS -> IPs
-> ASN/hosting -> threat score -> breach check, and every discovered entity is
fed into the next stage and into the entity graph.

Steps are pure functions registered by name. The engine handles fan-out,
dedup, timeouts, evidence capture (chain of custody), and graph emission.
"""
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

import db

# ---------------------------------------------------------------- step registry
STEPS = {}


def step(name, needs=()):
    """Register a recon step. `needs` lists upstream step outputs it consumes."""
    def deco(fn):
        STEPS[name] = {"fn": fn, "needs": list(needs), "name": name}
        return fn
    return deco


# ---------------------------------------------------------------- helpers
def _resolve(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


# ---------------------------------------------------------------- built-in steps
@step("subdomains")
def s_subdomains(domain):
    import requests
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json",
                         timeout=20, headers={"User-Agent": "Xaxglog-OSINT/2.0"})
        names = {e.get("name_value", "") for e in r.json()}
        flat = set()
        for n in names:
            for part in n.splitlines():
                part = part.strip().lower()
                if part.endswith(domain) and "*" not in part:
                    flat.add(part)
        return {"subdomains": sorted(flat)[:200]}
    except Exception as e:
        return {"error": str(e)[:150]}


@step("dns")
def s_dns(domain):
    import requests
    out = {}
    for qt in ("A", "AAAA", "MX", "TXT", "NS"):
        try:
            r = requests.get(f"https://dns.google/resolve?name={domain}&type={qt}",
                             timeout=10).json()
            out[qt] = [a.get("data") for a in r.get("Answer", [])]
        except Exception:
            out[qt] = []
    return {"dns": out}


@step("resolve")
def s_resolve(domain):
    ips = []
    for h in [domain]:
        ip = _resolve(h)
        if ip:
            ips.append(ip)
    return {"ips": ips}


@step("resolve_subs", needs=["subdomains"])
def s_resolve_subs(ctx):
    subs = (ctx.get("subdomains") or {}).get("subdomains", [])
    ips = set()
    with ThreadPoolExecutor(max_workers=16) as ex:
        futs = {ex.submit(_resolve, s): s for s in subs}
        for f in as_completed(futs):
            ip = f.result()
            if ip:
                ips.add(ip)
    return {"subdomain_ips": sorted(ips)}


@step("ip_intel", needs=["resolve"])
def s_ip_intel(ctx, keys=None):
    import requests
    ips = (ctx.get("resolve") or {}).get("ips", [])
    intel = {}
    for ip in ips[:20]:
        try:
            r = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,lat,lon,isp,org,as,query,proxy,hosting",
                timeout=10).json()
            intel[ip] = r
        except Exception as e:
            intel[ip] = {"error": str(e)[:100]}
    return {"ip_intel": intel}


@step("whois_rdap")
def s_rdap(domain):
    import requests
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=12)
        j = r.json()
        return {"rdap": {
            "events": j.get("events", [])[:5],
            "nameservers": [n.get("ldhName") for n in j.get("nameservers", [])],
        }}
    except Exception as e:
        return {"rdap": {"error": str(e)[:150]}}


@step("ssl_cert")
def s_ssl(domain):
    """Pull the TLS certificate subject/SANs — a rich source of related hosts."""
    import ssl
    import json as _json
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        san = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
        subject = dict(x[0] for x in cert.get("subject", []))
        return {"ssl": {"subject": subject, "sans": sorted(set(san))[:100],
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "notAfter": cert.get("notAfter")}}
    except Exception as e:
        return {"ssl": {"error": str(e)[:150]}}


@step("email_harvest")
def s_email_harvest(domain):
    """Extract publicly exposed emails/phones from the site source."""
    import requests
    import re as _re
    try:
        r = requests.get(f"http://{domain}", timeout=15,
                         headers={"User-Agent": "Xaxglog-OSINT/2.0"})
        emails = sorted(set(_re.findall(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', r.text)))
        phones = sorted(set(_re.findall(r'\+?\d[\d\s().-]{7,}\d', r.text)))
        return {"emails": emails[:50], "phones": phones[:30]}
    except Exception as e:
        return {"error": str(e)[:150]}


PIPELINES = {
    "domain": ["dns", "resolve", "subdomains", "resolve_subs", "ssl_cert",
               "whois_rdap", "ip_intel", "email_harvest"],
    "ip": ["ip_intel"],
}


# ---------------------------------------------------------------- engine
def run_pipeline(target, ptype="domain", case_id=None, user="system", keys=None, max_workers=8):
    """Execute a recon pipeline. Returns a merged context + emitted entities/edges.

    Every step's raw output is stored as an evidence artifact (chain of custody)
    and its discovered entities/edges are written to the graph when case_id is set.
    """
    plan = PIPELINES.get(ptype)
    if not plan:
        return {"error": f"no pipeline for type '{ptype}'", "available": list(PIPELINES)}
    keys = keys or {}
    ctx = {"_target": target, "_type": ptype}
    executed = []

    # seed context so single-target steps can read ctx["resolve"] etc.
    seed = {"resolve": {"ips": [target]}} if ptype == "ip" else {}
    ctx.update(seed)

    for name in plan:
        reg = STEPS.get(name)
        if not reg:
            continue
        try:
            if name == "ip_intel":
                out = reg["fn"](ctx, keys=keys)
            elif reg["needs"]:
                out = reg["fn"](ctx)
            else:
                # pass target for the base steps
                out = reg["fn"](target)
            ctx[name] = out
            executed.append(name)
            if case_id is not None:
                _emit_entities(case_id, name, target, out, user)
        except Exception as e:
            ctx[name] = {"error": str(e)[:200]}
            executed.append(f"{name}(error)")

    return {
        "target": target,
        "type": ptype,
        "pipeline": plan,
        "executed": executed,
        "context": {k: v for k, v in ctx.items() if not k.startswith("_")},
    }


ENTITY_RE = {
    "email": re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$'),
    "ip": re.compile(r'^\d{1,3}(\.\d{1,3}){3}$'),
    "domain": re.compile(r'^(?:[a-z0-9-]+\.)+[a-z]{2,}$', re.I),
}


def _emit_entities(case_id, step_name, target, out, user):
    """Write discovered entities + relations into the graph and store evidence."""
    import json
    if not isinstance(out, dict):
        return
    root_id = _upsert_entity(case_id, _guess_type(target), target)
    db.store_artifact(case_id, root_id, "recon", f"recon:{step_name}", out, user)

    for sub in (out.get("subdomains") or []):
        sid = _upsert_entity(case_id, "domain", sub)
        _upsert_edge(case_id, root_id, sid, "subdomain_of")
    for ip in (out.get("ips") or []) + (out.get("subdomain_ips") or []):
        iid = _upsert_entity(case_id, "ip", ip)
        _upsert_edge(case_id, root_id, iid, "resolves_to")
    for em in (out.get("emails") or []):
        eid = _upsert_entity(case_id, "email", em)
        _upsert_edge(case_id, root_id, eid, "exposes_email")
    for ph in (out.get("phones") or []):
        pid = _upsert_entity(case_id, "phone", ph)
        _upsert_edge(case_id, root_id, pid, "exposes_phone")
    for sansub in ((out.get("ssl") or {}).get("sans") or []):
        if ENTITY_RE["domain"].match(sansub):
            sid = _upsert_entity(case_id, "domain", sansub)
            _upsert_edge(case_id, root_id, sid, "cert_san")


def _guess_type(value):
    for t, rx in ENTITY_RE.items():
        if rx.match(value):
            return t
    return "handle"


def _upsert_entity(case_id, etype, value):
    c = db.get_db()
    now = db.utcnow()
    c.execute(
        "INSERT INTO entities (case_id,type,value,first_seen,last_seen) VALUES (?,?,?,?,?)"
        " ON CONFLICT(case_id,type,value) DO UPDATE SET last_seen=excluded.last_seen",
        (case_id, etype, value, now, now),
    )
    c.commit()
    row = c.execute("SELECT id FROM entities WHERE case_id=? AND type=? AND value=?",
                    (case_id, etype, value)).fetchone()
    return row["id"]


def _upsert_edge(case_id, src, dst, relation, weight=1.0, source=""):
    c = db.get_db()
    c.execute(
        "INSERT INTO edges (case_id,src_id,dst_id,relation,weight,source,created_at)"
        " VALUES (?,?,?,?,?,?,?) ON CONFLICT(case_id,src_id,dst_id,relation) DO NOTHING",
        (case_id, src, dst, relation, weight, source, db.utcnow()),
    )
    c.commit()


def list_pipelines():
    return {k: {"steps": v, "step_details": [
        {"name": s, "needs": STEPS[s]["needs"]} for s in v if s in STEPS]}
        for k, v in PIPELINES.items()}
