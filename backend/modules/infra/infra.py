"""Xaxglog infrastructure attribution — network pivot.

Maps an IP/domain to its operator and pivots across shared infrastructure:
  - reverse DNS / PTR
  - ASN + org + hosting provider (Team Cymru DNS + ip-api)
  - passive-DNS style pivots: other domains on the same ASN/IP (crt.sh, RDAP)
  - reverse-PTR: domains resolving to this IP
Emits ip/asn/domain relationships into the entity graph.
"""
import socket

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 12


def _get(url, **kw):
    import requests
    kw.setdefault("timeout", T)
    headers = dict(UA)
    headers.update(kw.pop("headers", {}))
    try:
        return requests.get(url, headers=headers, **kw)
    except Exception as e:
        return e


def ptr_lookup(ip):
    """Reverse DNS / PTR for an IP."""
    try:
        host, aliases, _ = socket.gethostbyaddr(ip)
        return {"ip": ip, "ptr": host, "aliases": aliases}
    except Exception as e:
        return {"ip": ip, "error": str(e)[:120]}


def asn_lookup(ip):
    """ASN + org + hosting via ip-api + Team Cymru origin DNS."""
    out = {"ip": ip}
    r = _get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,query,proxy,hosting,reverse")
    if not isinstance(r, Exception):
        try:
            j = r.json()
            out.update({"asn": j.get("as"), "org": j.get("org"), "isp": j.get("isp"),
                        "hosting": j.get("hosting"), "proxy": j.get("proxy"),
                        "country": j.get("country"), "city": j.get("city"),
                        "reverse": j.get("reverse")})
        except Exception:
            pass
    # Team Cymru origin ASN (DNS, free)
    try:
        parts = ip.split(".")[::-1]
        q = ".".join(parts) + ".origin.asn.cymru.com"
        import subprocess
        txt = socket.gethostbyname(q)
        out["cymru"] = txt
    except Exception:
        pass
    return out


def resolve_domains(domains):
    """Resolve a list of domains to IPs (for co-hosting pivot)."""
    resolved = {}
    for d in domains:
        try:
            resolved[d] = socket.gethostbyname(d)
        except Exception:
            resolved[d] = None
    return resolved


def pivot_ip(ip, case_id=None, user="system"):
    """Full attribution pivot for an IP: PTR + ASN + reverse-DNS domains."""
    out = {"ip": ip}
    out["ptr"] = ptr_lookup(ip)
    out["asn"] = asn_lookup(ip)
    # who else resolves here? (reverse via RDAP/hosting DNS not directly possible;
    # use passive sources: urlscan by IP)
    r = _get(f"https://urlscan.io/api/v1/search/?q=ip:{ip}")
    if not isinstance(r, Exception) and r.status_code == 200:
        try:
            j = r.json()
            domains = sorted({(x.get("page") or {}).get("domain")
                              for x in (j.get("results") or []) if x.get("page")})
            out["co_hosted_domains"] = [d for d in domains if d][:50]
            out["urlscan_total"] = j.get("total")
        except Exception:
            pass
    if case_id:
        _emit(ip, out, case_id, user)
    return out


def pivot_domain(domain, case_id=None, user="system"):
    """Domain -> IP(s) -> ASN/operator + shared-hosting domains."""
    domain = (domain or "").strip().lower().split("/")[0]
    out = {"domain": domain}
    try:
        ip = socket.gethostbyname(domain)
        out["ip"] = ip
        out["asn"] = asn_lookup(ip)
        out["ptr"] = ptr_lookup(ip)
        # other domains on same IP
        r = _get(f"https://urlscan.io/api/v1/search/?q=ip:{ip}")
        if not isinstance(r, Exception) and r.status_code == 200:
            j = r.json()
            siblings = sorted({(x.get("page") or {}).get("domain")
                               for x in (j.get("results") or []) if x.get("page")})
            out["shared_ip_domains"] = [d for d in siblings if d][:50]
    except Exception as e:
        out["error"] = str(e)[:150]
    if case_id:
        _emit_domain(domain, out, case_id, user)
    return out


def _emit(ip, out, case_id, user):
    c = db.get_db()
    now = db.utcnow()
    c.execute(
        "INSERT INTO entities (case_id,type,value,first_seen,last_seen) VALUES (?,?,?,?,?)"
        " ON CONFLICT(case_id,type,value) DO UPDATE SET last_seen=excluded.last_seen",
        (case_id, "ip", ip, now, now))
    c.commit()
    root = c.execute("SELECT id FROM entities WHERE case_id=? AND type='ip' AND value=?",
                     (case_id, ip)).fetchone()["id"]
    db.store_artifact(case_id, root, "infra", "infra:pivot_ip", out, user)
    for d in (out.get("co_hosted_domains") or [])[:30]:
        did = c.execute(
            "INSERT INTO entities (case_id,type,value,first_seen,last_seen) VALUES (?,?,?,?,?)"
            " ON CONFLICT(case_id,type,value) DO UPDATE SET last_seen=excluded.last_seen",
            (case_id, "domain", d, now, now)).lastrowid or \
            c.execute("SELECT id FROM entities WHERE case_id=? AND type='domain' AND value=?",
                      (case_id, d)).fetchone()["id"]
        _edge(case_id, root, did, "co_hosted", 0.6, "urlscan")
    db.audit(user, "infra.pivot_ip", ip, f"domains={len(out.get('co_hosted_domains') or [])}")


def _emit_domain(domain, out, case_id, user):
    c = db.get_db()
    now = db.utcnow()
    c.execute(
        "INSERT INTO entities (case_id,type,value,first_seen,last_seen) VALUES (?,?,?,?,?)"
        " ON CONFLICT(case_id,type,value) DO UPDATE SET last_seen=excluded.last_seen",
        (case_id, "domain", domain, now, now))
    c.commit()
    root = c.execute("SELECT id FROM entities WHERE case_id=? AND type='domain' AND value=?",
                     (case_id, domain)).fetchone()["id"]
    db.store_artifact(case_id, root, "infra", "infra:pivot_domain", out, user)
    ip = out.get("ip")
    if ip:
        iid = c.execute(
            "INSERT INTO entities (case_id,type,value,first_seen,last_seen) VALUES (?,?,?,?,?)"
            " ON CONFLICT(case_id,type,value) DO UPDATE SET last_seen=excluded.last_seen",
            (case_id, "ip", ip, now, now)).lastrowid or \
            c.execute("SELECT id FROM entities WHERE case_id=? AND type='ip' AND value=?",
                      (case_id, ip)).fetchone()["id"]
        _edge(case_id, root, iid, "resolves_to", 1.0, "dns")
    for d in (out.get("shared_ip_domains") or [])[:30]:
        did = c.execute(
            "INSERT INTO entities (case_id,type,value,first_seen,last_seen) VALUES (?,?,?,?,?)"
            " ON CONFLICT(case_id,type,value) DO UPDATE SET last_seen=excluded.last_seen",
            (case_id, "domain", d, now, now)).lastrowid or \
            c.execute("SELECT id FROM entities WHERE case_id=? AND type='domain' AND value=?",
                      (case_id, d)).fetchone()["id"]
        _edge(case_id, iid if ip else root, did, "shared_hosting", 0.6, "urlscan")
    db.audit(user, "infra.pivot_domain", domain)


def _edge(case_id, src, dst, relation, weight=1.0, source=""):
    c = db.get_db()
    c.execute(
        "INSERT INTO edges (case_id,src_id,dst_id,relation,weight,source,created_at)"
        " VALUES (?,?,?,?,?,?,?) ON CONFLICT(case_id,src_id,dst_id,relation) DO NOTHING",
        (case_id, src, dst, relation, weight, source, db.utcnow()))
    c.commit()
