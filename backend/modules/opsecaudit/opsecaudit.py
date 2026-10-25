"""Xaxglog opsecaudit — authorized external exposure audit (self-targeting).

Orchestrates existing Xaxglog modules against ONE authorized target domain
and returns a scored posture report with prioritized remediation items.

Guardrails (the whole point of this module):
  - explicit authorization required: caller passes `authorization` (a
    reference: engagement letter / internal ticket / asset-ownership
    statement) — it is audited and written into the artifact.
  - only public, passive sources are queried (no exploitation, no
    brute-force, no logins): DNS/CT, HTTP headers/TLS posture, email
    authentication records, breach exposure, search-engine footprint.
  - refuses targets that are not domains and refuses private IPs.

Score composition (0-100, higher = better posture):
  security headers (20) + email auth SPF/DKIM/DMARC (20) + HTTPS/HSTS (15)
  + CT/watch hygiene (10) + breach exposure inverse (20) + web footprint
  discipline (15).

Lawful-use note: run only against estates you own or are authorized to
test. This is a passive review, not a pentest.
"""
import ipaddress
import json
import re
import socket

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 15

SECURITY_HEADERS = ["strict-transport-security", "content-security-policy",
                    "x-frame-options", "x-content-type-options",
                    "referrer-policy", "permissions-policy"]


def _valid_domain(t):
    return bool(re.match(r"^(?!-)[a-z0-9-]{1,63}(?<!-)"
                         r"(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$", (t or "").lower()))


def _guard(domain):
    if not _valid_domain(domain):
        raise ValueError("not a domain")
    try:
        infos = socket.getaddrinfo(domain, 443)
    except socket.gaierror:
        return []  # unresolvable — posture checks will simply fail soft
    for fam, _t, _p, _cn, sa in infos:
        addr = ipaddress.ip_address(sa[0])
        if not addr.is_global:
            raise ValueError(f"resolves to non-public address {sa[0]}")
    return sorted({sa[0] for _f, _t, _p, _cn, sa in infos})


def run(target, authorization, case_id=None, actor="system"):
    """Full posture audit. `authorization` is mandatory and audited."""
    try:
        if not authorization or len(str(authorization).strip()) < 6:
            return {"status": "error", "http": 400,
                    "error": "authorization reference required "
                             "(engagement letter / ticket / ownership statement)"}
        domain = (target or "").strip().lower().strip(".")
        _guard(domain)
        report = {"target": domain, "authorization": str(authorization)[:200],
                  "audited_at": db.utcnow(), "checks": [], "score": 0,
                  "max_score": 100}
        score = 0
        import requests

        # 1. HTTPS + security headers (20)
        try:
            r = requests.get(f"https://{domain}/", headers=UA, timeout=T,
                             allow_redirects=True)
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            present = [h for h in SECURITY_HEADERS if h in hdrs]
            missing = [h for h in SECURITY_HEADERS if h not in hdrs]
            subscore = int(20 * len(present) / len(SECURITY_HEADERS))
            score += subscore
            report["checks"].append({
                "name": "https_headers", "subscore": subscore, "max": 20,
                "present": present, "missing": missing,
                "final_url": r.url[:200], "status": r.status_code,
                "server": hdrs.get("server"),
                "hint": "add missing headers at the edge/WAF"})
            hsts = 15 if "strict-transport-security" in hdrs else 0
        except Exception as e:
            report["checks"].append({"name": "https_headers", "subscore": 0,
                                     "max": 20, "error": str(e)[:120],
                                     "hint": "site unreachable over HTTPS"})
            hsts = 0
        score += hsts  # bonus tracked separately

        # 2. Email auth records via DoH (20)
        def doh(name, rtype):
            try:
                rr = requests.get("https://cloudflare-dns.com/dns-query",
                                  headers={**UA, "Accept": "application/dns-json"},
                                  params={"name": name, "type": rtype}, timeout=T)
                return [a.get("data") for a in (rr.json().get("Answer") or [])]
            except Exception:
                return []
        spf = any("v=spf1" in str(d) for d in doh(domain, "TXT"))
        dmarc = any("v=DMARC1" in str(d) for d in doh("_dmarc." + domain, "TXT"))
        dkim_common = any(
            any("v=DKIM1" in str(d) for d in doh(f"{sel}._domainkey." + domain, "TXT"))
            for sel in ("default", "google", "selector1", "selector2", "k1", "mail"))
        esub = sum([spf, dmarc, dkim_common])
        escore = int(20 * esub / 3)
        score += escore
        report["checks"].append({
            "name": "email_auth", "subscore": escore, "max": 20,
            "spf": spf, "dkim_detected": dkim_common, "dmarc": dmarc,
            "hint": "publish SPF + DKIM + a DMARC policy (p=none at minimum)"})

        # 3. CT footprint (10)
        try:
            import modules.certstream.certstream as CS
            ct = CS.search(domain, limit=100)
            ncerts = ct.get("count", 0) if ct.get("status") == "ok" else None
            ctscore = 10 if (ncerts is not None and ncerts <= 25) else 5 \
                if ncerts is not None else 0
            score += ctscore
            report["checks"].append({"name": "ct_footprint", "subscore": ctscore,
                                     "max": 10, "certs_total": ncerts,
                                     "hint": "very high cert counts can indicate "
                                             "mis-issuance or scan noise"})
        except Exception as e:
            report["checks"].append({"name": "ct_footprint", "subscore": 0,
                                     "max": 10, "error": str(e)[:100]})

        # 4. Breach exposure inverse (20)
        try:
            import modules.exposure.exposure as EX
            exp = EX.assess(domain)
            if exp.get("status") == "ok":
                exp_score = max(0, 20 - int(exp.get("score", 0) * 0.2))
                score += exp_score
                report["checks"].append({
                    "name": "breach_exposure", "subscore": exp_score, "max": 20,
                    "exposure_score": exp.get("score"),
                    "breaches": len((exp.get("breaches") or {}).get("breaches") or []),
                    "web_grade": (exp.get("web_posture") or {}).get("grade"),
                    "hint": "rotate affected credentials; check staff reuse"})
        except Exception as e:
            report["checks"].append({"name": "breach_exposure", "subscore": 0,
                                     "max": 20, "error": str(e)[:100]})

        # 5. Web footprint discipline (15): robots, sitemap, .well-known, dir-list
        fp = {"robots_txt": None, "security_txt": None, "sitemap": None}
        for path, key in (("/robots.txt", "robots_txt"),
                          ("/.well-known/security.txt", "security_txt"),
                          ("/sitemap.xml", "sitemap")):
            try:
                rr = requests.get(f"https://{domain}{path}", headers=UA,
                                  timeout=10, allow_redirects=True)
                fp[key] = rr.status_code == 200 and len(rr.text.strip()) < 20000
            except Exception:
                fp[key] = None
        fpscore = int(15 * sum(1 for v in fp.values() if v) / 3)
        score += fpscore
        report["checks"].append({"name": "web_footprint", "subscore": fpscore,
                                 "max": 15, **{k: bool(v) for k, v in fp.items()},
                                 "hint": "security.txt + honest robots.txt reduce "
                                         "accidental exposure discovery"})

        report["score"] = min(100, score)
        report["grade"] = ("A" if score >= 85 else "B" if score >= 70 else
                           "C" if score >= 50 else "D" if score >= 30 else "F")
        report["priorities"] = [
            c["hint"] for c in report["checks"]
            if c.get("subscore", c.get("max", 0)) < c.get("max", 0) * 0.5
            and c.get("hint")][:6]
        db.audit(actor, "opsecaudit.run", domain,
                 f"auth={report['authorization'][:60]} score={report['score']}")
        if case_id is not None:
            art = db.store_artifact(case_id, None, "opsecaudit", "passive",
                                    report, actor)
            report["artifact"] = art
        return {"status": "ok", "report": report}
    except ValueError as e:
        return {"status": "error", "http": 400, "error": str(e)}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def quick(target, authorization):
    """Compact variant: score + grade + top 3 priorities only."""
    out = run(target, authorization)
    if out.get("status") != "ok":
        return out
    r = out["report"]
    return {"status": "ok", "target": r["target"],
            "score": r["score"], "grade": r["grade"],
            "priorities": r["priorities"][:3]}
