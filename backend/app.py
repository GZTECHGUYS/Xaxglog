"""Xaxglog — unified national-grade OSINT platform.

Unifies:
  1. et842/OSINT_APP            -> threat-intel engine (collector/processor/database,
                                     live lookups, breach check, AI briefs, Snort/YARA gen)
  2. campwill/osint-dashboard   -> web forensics (URL analysis, EXIF, phone lookup)
  3. aenoshrajora/OSINTel-Dash  -> generic secure tool-runner + history + streaming
  4. intelseclab/osintelligence -> curated tool catalog (markdown in /catalog/tools)

Run:
  cd backend && pip install -r requirements.txt && python app.py
  API on http://127.0.0.1:5000 ; frontend in ../frontend (npm start)
"""
import datetime
import json
import logging
import os
import re
import sys
import threading

from flask import Flask, jsonify, request, send_from_directory, Response, stream_with_context, render_template
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config as C

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("xaxglog")

# Recon probes intentionally use verify=False against self-signed hosts;
# suppress only that warning class to keep stdout free of stack noise.
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

app = Flask(__name__, template_folder="templates")
app.secret_key = C.FLASK_SECRET_KEY
CORS(app)

# ---------------------------------------------------------------- core platform: db + auth
import auth as AUTH
import db as DB

DB.init_db()

# bootstrap the first admin user if none exists (change via .env on first run)
_admin = DB.get_db().execute("SELECT COUNT(*) c FROM users WHERE role='admin'").fetchone()["c"]
if _admin == 0:
    import os as _os
    _pw = _os.getenv("XAXGLOG_ADMIN_PASSWORD", "xaxglog-admin")
    AUTH.create_user("admin", _pw, "admin")
    if "XAXGLOG_ADMIN_PASSWORD" in _os.environ:
        log.warning("Bootstrap admin user created -> username=admin "
                    "(password sourced from XAXGLOG_ADMIN_PASSWORD, not logged)")
    else:
        log.warning("Bootstrap admin user created -> username=admin with the "
                    "default dev password (set XAXGLOG_ADMIN_PASSWORD before "
                    "first run, then rotate this credential)")

def _keys():
    return {"HIBP_API_KEY": C.HIBP_API_KEY, "ABUSEIPDB_API_KEY": C.ABUSEIPDB_API_KEY,
            "SHODAN_API_KEY": C.SHODAN_API_KEY, "IPINFO_TOKEN": C.IPINFO_TOKEN,
            "NUM_API_KEY": C.NUM_API_KEY, "INTELX_API_KEY": C.INTELX_API_KEY,
            "GEMINI_API_KEY": C.GEMINI_API_KEY, "GROQ_API_KEY": C.GROQ_API_KEY}

def _user():
    return getattr(request, "xuser", {"username": "system", "role": "admin"})


def _as_bool(value, default=False):
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip().lower() not in ("0", "false", "no", "off", "")
    return bool(value)

AUDIT_LOG = os.path.join(C.DATA_DIR, "audit.log")

def audit(action, detail=""):
    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(f"{datetime.datetime.utcnow().isoformat()} {request.remote_addr} {action} {detail}\n")
    except OSError:
        pass

# ---------------------------------------------------------------- capability map
CAPS = {"threat_intel": False, "forensics": False, "runner": True, "catalog": False,
        "deep_search": True, "trackpin": True}
TI = FORENSICS = None
try:
    from modules.deep_search import connectors as DEEP
    log.info("deep_search module loaded")
except Exception as e:
    CAPS["deep_search"] = False
    DEEP = None
    log.warning("deep_search unavailable: %s", e)
TI = FORENSICS = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "modules", "threat_intel"))
    import database as ti_db
    import collector as ti_collector
    import processor as ti_processor
    # point DB into shared data dir
    ti_db.DB_PATH = C.DB_PATH
    ti_db.init_db()
    CAPS["threat_intel"] = True
    TI = (ti_db, ti_collector, ti_processor)
    log.info("threat_intel module loaded")
except Exception as e:
    log.warning("threat_intel unavailable: %s", e)

try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "modules", "forensics"))
    import web_tools as wt
    import file_tools as ft
    import pid_tools as pt
    CAPS["forensics"] = True
    FORENSICS = (wt, ft, pt)
    log.info("forensics module loaded")
except Exception as e:
    log.warning("forensics unavailable: %s", e)

from modules.runner import executor as EX

import modules.cases.cases as CASES

RUNNER_STORE = os.path.join(C.DATA_DIR, "runner_tools.json")
HISTORY_FILE = C.RUNNER_DB
if not os.path.exists(RUNNER_STORE):
    # seed from upstream default_tools.json
    try:
        import shutil
        src = os.path.join(os.path.dirname(__file__), "modules", "runner", "default_tools.json")
        if os.path.exists(src):
            shutil.copy(src, RUNNER_STORE)
        else:
            with open(RUNNER_STORE, "w") as f:
                json.dump([], f)
    except Exception:
        pass

try:
    catalog_files = []
    for root, _, files in os.walk(os.path.join(os.path.dirname(__file__), "..", "catalog")):
        for fn in files:
            if fn.endswith(".md"):
                catalog_files.append(os.path.join(root, fn))
    CAPS["catalog"] = len(catalog_files) > 0
    log.info("catalog: %d markdown files", len(catalog_files))
except Exception as e:
    log.warning("catalog scan failed: %s", e)

# ---------------------------------------------------------------- core routes
@app.get("/")
def ui():
    return render_template("index.html")

@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "app": "Xaxglog", "modules": CAPS,
                    "time": datetime.datetime.utcnow().isoformat()})

@app.get("/api/modules")
def modules():
    out = {
        "threat_intel": {"enabled": CAPS["threat_intel"],
                         "desc": "IOC aggregation (URLhaus/AbuseIPDB/OTX/VT), scoring, lookups, breach, AI briefs, Snort/YARA",
                         "from": "et842/OSINT_APP"},
        "forensics": {"enabled": CAPS["forensics"],
                      "desc": "URL analysis (DNS/SSL/headers/cookies/ports/whois/links/emails/phones/screenshot), EXIF, phone validation",
                      "from": "campwill/osint-dashboard"},
        "runner": {"enabled": True,
                   "desc": "Secure generic tool executor with streaming + history",
                   "from": "aenoshrajora/OSINTel-Dashboard"},
        "catalog": {"enabled": CAPS["catalog"],
                    "desc": "Curated OSINT tool/resource directory",
                    "from": "intelseclab/osintelligence"},
        "deep_search": {"enabled": CAPS["deep_search"],
                        "desc": "International deep search: username/email/phone/domain/IP/person/name/social profile/company/geo (free-tier, no docker)",
                        "from": "Xaxglog-native"},
        "location": {"enabled": True,
                     "desc": "Public location signals: phone region/carrier, Gravatar/profile locations, server/IP geo; precision-labelled with no silent tracking",
                     "from": "Xaxglog-native"},
        "trackpin": {"enabled": True,
                     "desc": "Lawful location workflow: one-time consent check-in link + authority-gated carrier request packet (no covert call/SMS interception)",
                     "from": "Xaxglog-native"},
        "recon": {"enabled": True, "desc": "Chained deep-recon pipeline engine (domain/IP fan-out, evidence capture, graph emission)", "from": "Xaxglog-native"},
        "deeprecon": {"enabled": True, "desc": "Intense target-aware deep recon: drives crawl/wayback/leak/netblock/takeover/ports + identity/company/vehicle/phone axes recursively", "from": "Xaxglog-native"},
        "trackers": {"enabled": True, "desc": "Change trackers over any subject: DNS, whois, ports, site content, crypto, ALPR, breach/sanctions, GLEIF, news, Telegram — fingerprint + diff + typed alerts", "from": "Xaxglog-native"},
        "darkweb": {"enabled": True, "desc": "Indexed dark-web search (Ahmia + optional IntelX) + breach-corpus lookups", "from": "Xaxglog-native"},
        "simswap": {"enabled": True, "desc": "SIM-swap / number-port fraud risk detection (0-100 score, evidence trail)", "from": "Xaxglog-native"},
        "ss7": {"enabled": True, "desc": "Authorized carrier SS7 lookup workflow (build/submit/ingest, authority-gated, audited)", "from": "Xaxglog-native"},
        "attribution": {"enabled": True, "desc": "AI-assisted actor tracing across handles/profiles (CERT-style correlation)", "from": "Xaxglog-native"},
        "cases": {"enabled": True, "desc": "Case management + entity graph + chain-of-custody evidence store", "from": "Xaxglog-native"},
        "watchlist": {"enabled": True, "desc": "Scheduled sweeps + alerts on new findings", "from": "Xaxglog-native"},
        "report": {"enabled": True, "desc": "Intelligence report generator (HTML/PDF) + STIX 2.1 export", "from": "Xaxglog-native"},
        "geo": {"enabled": True, "desc": "GEOINT: geocode, case map points, radius query, GeoJSON/KML export", "from": "Xaxglog-native"},
        "vehicle": {"enabled": True, "desc": "Vehicle intel: VIN decode, recalls, plate decode, authority-gated reverse-plate + registration, ALPR custody", "from": "Xaxglog-native"},
        "cctv": {"enabled": True, "desc": "Camera infrastructure mapper (exposure mapping) + authorized feed custody", "from": "Xaxglog-native"},
        "iot": {"enabled": True, "desc": "IoT device register + passive exposure re-scan + change detection + lawful-access hook", "from": "Xaxglog-native"},
        "corporate": {"enabled": True, "desc": "Corporate ownership graph: company search, officers, person->officer links", "from": "Xaxglog-native"},
        "crypto": {"enabled": True, "desc": "Wallet tracing: BTC/ETH overview, tx history, 1-hop fund-flow graph", "from": "Xaxglog-native"},
        "screening": {"enabled": True, "desc": "Sanctions/PEP/watchlist screening (OFAC SDN + UN, fuzzy match)", "from": "Xaxglog-native"},
        "infra": {"enabled": True, "desc": "Infrastructure attribution: PTR/ASN/hosting pivot + co-hosted domain discovery", "from": "Xaxglog-native"},
        "playbook": {"enabled": True, "desc": "Auto-pivot playbooks: re-runnable multi-step investigations (domain/person/crypto chains)", "from": "Xaxglog-native"},
        "fusion": {"enabled": True, "desc": "Master case timeline + fuzzy entity resolution + cross-case dedupe", "from": "Xaxglog-native"},
        "archive": {"enabled": True, "desc": "Wayback CDX history, snapshot diffs, URL change-watch daemon with alerts", "from": "Xaxglog-native"},
        "searchx": {"enabled": True, "desc": "Federated keyless search (DDG/SearXNG/Mojeek/Wikipedia) + dork builder/runner", "from": "Xaxglog-native"},
        "namevar": {"enabled": True, "desc": "International name variants: transliteration, nicknames, IDN homographs, confusables", "from": "Xaxglog-native"},
        "regional": {"enabled": True, "desc": "Regional platforms: Telegram public channels, Baidu/Yandex/Weibo, engine availability", "from": "Xaxglog-native"},
        "emailintel": {"enabled": True, "desc": "Email deep-dive: MX/SPF/DKIM/DMARC, breaches, header hop tracing, account graph anchor", "from": "Xaxglog-native"},
        "courts": {"enabled": True, "desc": "Global court records: CourtListener, BAILII, AustLII, HUDOC, Indian Kanoon", "from": "Xaxglog-native"},
        "worldcorp": {"enabled": True, "desc": "Global corporate: GLEIF LEI chains, EU VAT (VIES), UK Companies House", "from": "Xaxglog-native"},
        "sanx": {"enabled": True, "desc": "Multi-list sanctions: OFAC + UN + UK OFSI + EU consolidated (+ optional OpenSanctions bulk)", "from": "Xaxglog-native"},
        "risk": {"enabled": True, "desc": "World risk: GDELT news events, country profiles, jurisdiction legal cards, sanctions overlay", "from": "Xaxglog-native"},
        "ops": {"enabled": True, "desc": "Operations: bulk dataset mirrors, free-API quota budgets, source health probes", "from": "Xaxglog-native"},
        "narrative": {"enabled": True, "desc": "AI evidence briefing: Groq/Gemini with deterministic SHA-256-cited template fallback", "from": "Xaxglog-native"},
        "geoext": {"enabled": True, "desc": "Global geospatial: OSM building/POI footprints, street-level imagery, postal/ZIP geocode", "from": "Xaxglog-native"},
    }
    # Part 1 + Part 2 modules (routes package; CAPS flipped on registration)
    for _n, _d in EXTRA_META.items():
        out[_n] = {"enabled": CAPS.get(_n, False), "desc": _d,
                   "from": "Xaxglog-native"}
    return jsonify(out)

# ---------------------------------------------------------------- 1. threat intel passthrough
# Re-uses upstream logic directly so scoring/collector behaviour is identical.
# For full endpoint parity (ai-summary, bulk-protect, keys…) run the upstream
# legacy app or import its Flask routes; here we expose the high-value core.

@app.get("/api/threats")
def threats():
    if not CAPS["threat_intel"]:
        # The dashboard must still boot when the optional threat-intel stack
        # (cryptography/feed keys) is absent.  Return an empty, valid list and
        # let /api/modules explain which capability is unavailable.
        return jsonify([])
    ti_db, _, _ = TI
    conn = ti_db.get_connection()
    cur = conn.cursor()
    itype = request.args.get("type")
    source = request.args.get("source")
    limit = min(int(request.args.get("limit", 100)), 1000)
    q = "SELECT * FROM threat_indicators WHERE 1=1"
    args = []
    if itype:
        q += " AND indicator_type=?"; args.append(itype)
    if source:
        q += " AND source=?"; args.append(source)
    q += " ORDER BY threat_score DESC LIMIT ?"; args.append(limit)
    rows = [dict(r) for r in cur.execute(q, args).fetchall()]
    conn.close()
    audit("threats.list", f"n={len(rows)}")
    return jsonify(rows)

@app.get("/api/stats")
def stats():
    if not CAPS["threat_intel"]:
        return jsonify({
            "total": 0, "active": 0, "by_source": [], "by_type": [],
            "warning": "threat_intel module unavailable; live deep search and the module registry still work",
        })
    ti_db, _, _ = TI
    conn = ti_db.get_connection()
    cur = conn.cursor()
    total = cur.execute("SELECT COUNT(*) c FROM threat_indicators").fetchone()["c"]
    active = cur.execute("SELECT COUNT(*) c FROM threat_indicators WHERE is_active=1").fetchone()["c"]
    by_source = [dict(r) for r in cur.execute("SELECT source,COUNT(*) c FROM threat_indicators GROUP BY source").fetchall()]
    by_type = [dict(r) for r in cur.execute("SELECT indicator_type,COUNT(*) c FROM threat_indicators GROUP BY indicator_type").fetchall()]
    conn.close()
    return jsonify({"total": total, "active": active, "by_source": by_source, "by_type": by_type})

@app.post("/api/collect")
def collect_now():
    if not CAPS["threat_intel"]:
        return jsonify({"error": "threat_intel module unavailable"}), 503
    _, ti_collector, ti_processor = TI
    def _run():
        try:
            for fn in ("fetch_urlhaus", "fetch_abuseipdb", "fetch_otx", "fetch_virustotal"):
                if hasattr(ti_collector, fn):
                    try:
                        getattr(ti_collector, fn)()
                    except Exception as e:
                        log.warning("collector %s: %s", fn, e)
            ti_processor.process_indicators()
        except Exception as e:
            log.error("collect failed: %s", e)
    threading.Thread(target=_run, daemon=True).start()
    audit("collect.trigger")
    return jsonify({"status": "collection started"})

@app.post("/api/rescore")
def rescore():
    if not CAPS["threat_intel"]:
        return jsonify({"error": "threat_intel module unavailable"}), 503
    _, _, ti_processor = TI
    threading.Thread(target=ti_processor.rescore_all, daemon=True).start()
    return jsonify({"status": "rescore started"})

# ---------------------------------------------------------------- 2. forensics (campwill)
@app.post("/api/forensics/url")
def forensics_url():
    if not CAPS["forensics"]:
        return jsonify({"error": "forensics module unavailable"}), 503
    wt, _, _ = FORENSICS
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    if not url or not wt.is_valid_url(url):
        return jsonify({"error": "valid http(s) URL required"}), 400
    import concurrent.futures
    domain, ip_str, title, favicon = wt.website_information(url)
    out = {}
    with concurrent.futures.ThreadPoolExecutor() as ex:
        futs = {
            ex.submit(wt.get_redirects, url): "redirects",
            ex.submit(wt.get_cookies, url): "cookies",
            ex.submit(wt.get_headers, url): "headers",
            ex.submit(wt.get_ip_info, ip_str): "ip_info",
            ex.submit(wt.get_records, domain): "dns",
            ex.submit(wt.get_ssl, domain): "ssl",
            ex.submit(wt.site_maps, url): "sitemap",
            ex.submit(wt.check_ports, domain): "ports",
            ex.submit(wt.whois_info, domain): "whois",
            ex.submit(wt.get_internal_external_links, url): "links",
            ex.submit(wt.get_emails, url): "emails",
            ex.submit(wt.get_phone_numbers, url): "phones",
        }
        try:
            futs[ex.submit(wt.get_screenshot, url)] = "screenshot"
        except Exception:
            pass
        for f in concurrent.futures.as_completed(futs):
            try:
                out[futs[f]] = f.result()
            except Exception as e:
                out[futs[f]] = {"error": str(e)}
    out.update({"domain": domain, "ip": ip_str, "title": title})
    audit("forensics.url", url)
    return jsonify(out)

@app.post("/api/forensics/exif")
def forensics_exif():
    if not CAPS["forensics"]:
        return jsonify({"error": "forensics module unavailable"}), 503
    _, ft, _ = FORENSICS
    if "file" not in request.files:
        return jsonify({"error": "multipart 'file' required"}), 400
    f = request.files["file"]
    try:
        res = ft.get_exif(f)
        audit("forensics.exif", f.filename)
        return jsonify({"result": str(res)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.get("/api/forensics/phone")
def forensics_phone():
    if not CAPS["forensics"]:
        return jsonify({"error": "forensics module unavailable"}), 503
    _, _, pt = FORENSICS
    num = request.args.get("number", "")
    if not num:
        return jsonify({"error": "?number= required"}), 400
    try:
        return jsonify(pt.get_phone_info(num))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------------------------------------------------------- 3. runner (OSINTel)
def _history():
    try:
        with open(HISTORY_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def _save_history(h):
    h = h[:C.MAX_HISTORY]
    tmp = HISTORY_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(h, f, indent=2)
    os.replace(tmp, HISTORY_FILE)

@app.get("/api/tools")
def list_tools():
    return jsonify(EX.load_tools(RUNNER_STORE))

@app.post("/api/tools")
def add_tool():
    data = request.get_json(silent=True) or {}
    if not data.get("name") or not data.get("command_template"):
        return jsonify({"error": "name + command_template required"}), 400
    import uuid as _u
    tools = EX.load_tools(RUNNER_STORE)
    tool = {"id": str(_u.uuid4()), "name": data["name"],
            "description": data.get("description", ""),
            "command_template": data["command_template"],
            "input_fields": data.get("input_fields", []),
            "timeout": int(data.get("timeout", C.DEFAULT_TIMEOUT)),
            "output_filename_pattern": data.get("output_filename_pattern",
                                                "{{TOOL_NAME_SANITIZED}}_{{TIMESTAMP}}.txt")}
    tools.append(tool)
    EX.save_tools(RUNNER_STORE, tools)
    audit("runner.add", tool["name"])
    return jsonify(tool), 201

@app.post("/api/run/<tool_id>")
def run_tool(tool_id):
    if not EX.is_safe_id(tool_id):
        return jsonify({"error": "bad id"}), 400
    inputs = request.get_json(silent=True) or {}
    tools = EX.load_tools(RUNNER_STORE)
    tool = next((t for t in tools if t["id"] == tool_id), None)
    if not tool:
        return jsonify({"error": "not found"}), 404
    try:
        rep = {f["id"]: inputs.get(f["id"], f.get("default_value", "")) for f in tool.get("input_fields", [])}
        cmd = EX.substitute(tool["command_template"], rep)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    out, err, ok = EX.run_command(cmd, timeout=int(tool.get("timeout", C.DEFAULT_TIMEOUT)))
    full = out + (f"\n--- stderr ---\n{err}" if err else "")
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = EX.resolve_output(tool.get("output_filename_pattern"), tool, inputs, ts)
    with open(os.path.join(C.OUTPUT_DIR, fname), "w", encoding="utf-8", errors="replace") as f:
        f.write(full)
    h = _history()
    h.insert(0, {"tool_id": tool_id, "tool_name": tool["name"],
                 "timestamp": datetime.datetime.now().isoformat(),
                 "inputs": inputs, "output_file": fname,
                 "status": "success" if ok else "error",
                 "preview": full.splitlines()[0][:120] if full.splitlines() else ""})
    _save_history(h)
    audit("runner.run", tool["name"])
    return jsonify({"output": full, "output_file": fname, "status": "success" if ok else "error"})

@app.get("/api/history")
def history():
    return jsonify(_history()[:min(int(request.args.get("limit", 100)), C.MAX_HISTORY)])

@app.get("/api/output/<path:fname>")
def output(fname):
    safe = os.path.basename(fname)
    return send_from_directory(C.OUTPUT_DIR, safe, as_attachment=True)

# ---------------------------------------------------------------- 4. catalog (osintelligence)
@app.get("/api/catalog")
def catalog():
    base = os.path.join(os.path.dirname(__file__), "..", "catalog", "tools")
    cats = []
    if os.path.isdir(base):
        for fn in sorted(os.listdir(base)):
            if not fn.endswith(".md"):
                continue
            path = os.path.join(base, fn)
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read()
            tools = re.findall(r'^#{2,3}\s+(.+)$', text, re.M)
            cats.append({"category": fn[:-3].replace("-", " "), "file": fn,
                         "count": len(tools), "sample": tools[:10]})
    return jsonify({"categories": cats, "total_categories": len(cats)})

@app.get("/api/catalog/<name>")
def catalog_one(name):
    safe = re.sub(r'[^\w.\-]', '_', name)
    base = os.path.join(os.path.dirname(__file__), "..", "catalog", "tools")
    for ext in ("", ".md"):
        p = os.path.join(base, safe + ext)
        if os.path.isfile(p) and os.path.abspath(p).startswith(os.path.abspath(base)):
            with open(p, encoding="utf-8", errors="replace") as f:
                return jsonify({"file": safe, "markdown": f.read()})
    return jsonify({"error": "not found"}), 404

# ---------------------------------------------------------------- 5. deep search (Xaxglog-native, international)
def _need_deep():
    if not CAPS["deep_search"]:
        return jsonify({"error": "deep_search unavailable"}), 503
    return None

@app.post("/api/deep/search")
def deep_auto():
    err = _need_deep()
    if err:
        return err
    q = (request.get_json(silent=True) or {}).get("query", "")
    out = DEEP.deep_search(q, _keys())
    audit("deep.search", q[:120])
    return jsonify(out)

@app.post("/api/deep/username")
def deep_username():
    err = _need_deep()
    if err:
        return err
    q = (request.get_json(silent=True) or {}).get("query", "")
    out = DEEP.username_search(q)
    audit("deep.username", q[:80])
    return jsonify(out)

@app.post("/api/deep/email")
def deep_email():
    err = _need_deep()
    if err:
        return err
    q = (request.get_json(silent=True) or {}).get("query", "")
    out = DEEP.email_search(q, C.HIBP_API_KEY)
    audit("deep.email", q[:80])
    return jsonify(out)

@app.post("/api/deep/phone")
def deep_phone():
    err = _need_deep()
    if err:
        return err
    q = (request.get_json(silent=True) or {}).get("query", "")
    out = DEEP.phone_search(q, C.NUM_API_KEY)
    audit("deep.phone", q[:40])
    return jsonify(out)

@app.post("/api/deep/domain")
def deep_domain():
    err = _need_deep()
    if err:
        return err
    q = (request.get_json(silent=True) or {}).get("query", "")
    out = DEEP.domain_search(q)
    audit("deep.domain", q[:80])
    return jsonify(out)

@app.post("/api/deep/ip")
def deep_ip():
    err = _need_deep()
    if err:
        return err
    q = (request.get_json(silent=True) or {}).get("query", "")
    k = _keys()
    out = DEEP.ip_search(q, k["ABUSEIPDB_API_KEY"], k["SHODAN_API_KEY"], k["IPINFO_TOKEN"])
    audit("deep.ip", q[:40])
    return jsonify(out)

@app.post("/api/deep/person")
def deep_person():
    err = _need_deep()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    q = data.get("query", "")
    include_social = _as_bool(data.get("include_social"), True)
    include_code = data.get("include_code")
    if isinstance(include_code, str):
        include_code = _as_bool(include_code, False)
    elif include_code is not None:
        include_code = bool(include_code)
    # Phase 1: route person searches through identity intelligence when it is
    # available. Keep the legacy person_search shape for existing UI consumers
    # and attach the richer identity payload alongside it.
    try:
        from modules.identity import identity as ID
        ident = ID.search(
            q,
            kind="person",
            depth=data.get("depth", "standard"),
            country=data.get("country") or None,
            include_social=include_social,
            include_web=_as_bool(data.get("include_web"), True),
            include_records=_as_bool(data.get("include_records"), True),
            include_code=include_code,
            include_link_out=_as_bool(data.get("include_link_out"), True),
            case_id=data.get("case_id"),
            user=_user()["username"],
        )
        person = (ident.get("sources") or {}).get("people")
        if isinstance(person, dict):
            out = dict(person)
            # ``ident["sources"]["people"]`` is the legacy payload we just
            # copied; drop it from the attached view to avoid a circular graph.
            ident_view = {k: v for k, v in ident.items() if k != "sources"}
            out["identity"] = ident_view
            out["coverage"] = ident.get("coverage")
            out["variants"] = ident.get("variants")
            out["normalized"] = ident.get("normalized")
            out["identity_results"] = ident.get("results")
        else:
            out = ident
    except Exception as e:
        out = DEEP.person_search(q, include_social=include_social)
        out["identity_error"] = str(e)[:180]
    audit("deep.person", q[:80])
    return jsonify(out)

@app.post("/api/deep/social")
def deep_social():
    err = _need_deep()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    q = data.get("query", "")
    out = DEEP.social_search(q, include_web=bool(data.get("include_web", True)))
    audit("deep.social", q[:80])
    return jsonify(out)

@app.post("/api/deep/profile")
def deep_profile():
    err = _need_deep()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    out = DEEP.profile_lookup(url)
    audit("deep.profile", url[:160])
    status = 200 if out.get("status") == "ok" else 400
    return jsonify(out), status

@app.post("/api/deep/location")
def deep_location():
    err = _need_deep()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    q = (data.get("query") or data.get("target") or "").strip()
    include_profiles = bool(data.get("include_profiles", True))
    out = DEEP.location_search(q, include_profiles=include_profiles)
    audit("deep.location", "%s profiles=%s" % (q[:80], include_profiles))
    return jsonify(out)


@app.get("/api/deep/sources")
def deep_sources():
    err = _need_deep()
    if err:
        return err
    return jsonify(DEEP.source_catalog())


# ---------------------------------------------------------------- 5b. TrackPin (lawful location)
@app.post("/api/trackpin/operations")
@AUTH.require("analyst")
def trackpin_create():
    import modules.trackpin.trackpin as TP
    data = request.get_json(silent=True) or {}
    out = TP.create_operation(
        data.get("label"), data.get("target"), data.get("mode", "consent_checkin"),
        data.get("case_id"), data.get("legal_basis", ""), data.get("notes", ""),
        _user()["username"], data.get("ttl_hours", 24), _user()["role"])
    if out.get("error"):
        return jsonify(out), 400
    token = out.get("consent_token")
    if token:
        out["consent_path"] = "/trackpin/consent/" + token
        out["consent_url"] = request.host_url.rstrip("/") + out["consent_path"]
    return jsonify(out), 201


@app.get("/api/trackpin/operations")
@AUTH.require("viewer")
def trackpin_list():
    import modules.trackpin.trackpin as TP
    u = _user()
    return jsonify(TP.list_operations(u["username"], u["role"],
                                      request.args.get("case_id", type=int)))


@app.get("/api/trackpin/operations/<int:op_id>")
@AUTH.require("viewer")
def trackpin_get(op_id):
    import modules.trackpin.trackpin as TP
    u = _user()
    out = TP.get_operation(op_id, u["username"], u["role"])
    if out.get("error"):
        return jsonify(out), 404 if "not found" in out["error"] else 403
    return jsonify(out)


@app.post("/api/trackpin/operations/<int:op_id>/points")
@AUTH.require("analyst")
def trackpin_point(op_id):
    import modules.trackpin.trackpin as TP
    data = request.get_json(silent=True) or {}
    u = _user()
    out = TP.add_point(
        op_id, data.get("lat"), data.get("lon"), data.get("accuracy_m"),
        data.get("source", "manual"), bool(data.get("consent", False)),
        data.get("note", ""), u["username"], u["role"],
        request.remote_addr or "", request.headers.get("User-Agent", ""),
        data.get("captured_at"), data.get("meta"))
    if out.get("error"):
        return jsonify(out), 400
    return jsonify(out)


@app.post("/api/trackpin/operations/<int:op_id>/consent-link")
@AUTH.require("analyst")
def trackpin_consent_link(op_id):
    import modules.trackpin.trackpin as TP
    data = request.get_json(silent=True) or {}
    u = _user()
    out = TP.create_consent_link(op_id, u["username"], u["role"],
                                 data.get("ttl_hours", 24))
    if out.get("error"):
        return jsonify(out), 400
    out["consent_url"] = request.host_url.rstrip("/") + out["path"]
    return jsonify(out)


@app.post("/api/trackpin/operations/<int:op_id>/authority")
@AUTH.require("analyst")
def trackpin_authority(op_id):
    import modules.trackpin.trackpin as TP
    data = request.get_json(silent=True) or {}
    u = _user()
    out = TP.request_authority(
        op_id, data.get("agency"), data.get("reference"),
        data.get("legal_basis", ""), u["username"], u["role"],
        data.get("notes", ""))
    if out.get("error"):
        return jsonify(out), 400
    return jsonify(out)


@app.get("/api/trackpin/operations/<int:op_id>/geojson")
@AUTH.require("viewer")
def trackpin_geojson(op_id):
    import modules.trackpin.trackpin as TP
    u = _user()
    out = TP.geojson(op_id, u["username"], u["role"])
    if out.get("error"):
        return jsonify(out), 404 if "not found" in out["error"] else 403
    return Response(json.dumps(out), mimetype="application/geo+json")


@app.get("/trackpin/consent/<token>")
def trackpin_consent_page(token):
    return render_template("trackpin_consent.html", token=token)


@app.get("/api/trackpin/consent/<token>")
def trackpin_consent_info(token):
    import modules.trackpin.trackpin as TP
    return jsonify(TP.consent_info(token))


@app.post("/api/trackpin/consent/<token>")
def trackpin_consent_submit(token):
    import modules.trackpin.trackpin as TP
    data = request.get_json(silent=True) or {}
    out = TP.submit_consent(
        token, data.get("lat"), data.get("lon"), data.get("accuracy_m"),
        bool(data.get("consent", False)), request.remote_addr or "",
        request.headers.get("User-Agent", ""), data.get("note", ""))
    if out.get("error"):
        return jsonify(out), 400
    return jsonify(out)

@app.get("/api/deep/company")
def deep_company():
    err = _need_deep()
    if err:
        return err
    q = request.args.get("q", "")
    out = DEEP.company_search(q)
    audit("deep.company", q[:80])
    return jsonify(out)

@app.get("/api/deep/geo")
def deep_geo():
    err = _need_deep()
    if err:
        return err
    q = request.args.get("place", "")
    out = DEEP.geo_search(q)
    audit("deep.geo", q[:80])
    return jsonify(out)

# ---------------------------------------------------------------- 6. auth
@app.post("/api/auth/login")
def auth_login():
    data = request.get_json(silent=True) or {}
    user = AUTH.authenticate(data.get("username", ""), data.get("password", ""))
    if not user:
        DB.audit(data.get("username", "?"), "auth.fail", request.remote_addr)
        return jsonify({"error": "invalid credentials"}), 401
    token = AUTH.issue_token(user)
    DB.audit(user["username"], "auth.login", request.remote_addr)
    return jsonify({"token": token, "user": user,
                    "note": "stateless auth — token valid 12h" if token else "PyJWT missing; auth degraded"})


@app.post("/api/auth/users")
@AUTH.require("admin")
def auth_create_user():
    data = request.get_json(silent=True) or {}
    try:
        uid = AUTH.create_user(data.get("username", ""), data.get("password", ""),
                               data.get("role", "analyst"))
        DB.audit(_user()["username"], "user.create", data.get("username"), data.get("role"))
        return jsonify({"id": uid, "created": True}), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.get("/api/auth/me")
@AUTH.require("viewer")
def auth_me():
    return jsonify(_user())


# ---------------------------------------------------------------- 7. cases + graph + search
@app.post("/api/cases")
@AUTH.require("analyst")
def create_case():
    data = request.get_json(silent=True) or {}
    if not data.get("name"):
        return jsonify({"error": "name required"}), 400
    return jsonify(CASES.create_case(data["name"], data.get("description"),
                                     data.get("legal_basis"), _user()["username"])), 201


@app.get("/api/cases")
@AUTH.require("viewer")
def list_cases():
    u = _user()
    return jsonify(CASES.list_cases(u["username"], u["role"]))


@app.get("/api/cases/<int:case_id>")
@AUTH.require("viewer")
def get_case(case_id):
    case = CASES.get_case(case_id)
    return jsonify(case) if case else (jsonify({"error": "not found"}), 404)


@app.patch("/api/cases/<int:case_id>")
@AUTH.require("analyst")
def update_case(case_id):
    return jsonify(CASES.update_case(case_id, request.get_json(silent=True) or {},
                                     _user()["username"]))


@app.post("/api/cases/<int:case_id>/members")
@AUTH.require("analyst")
def add_member(case_id):
    data = request.get_json(silent=True) or {}
    return jsonify(CASES.add_member(case_id, data.get("username"),
                                    data.get("permission", "edit"), _user()["username"]))


@app.get("/api/cases/<int:case_id>/graph")
@AUTH.require("viewer")
def case_graph(case_id):
    return jsonify(CASES.get_graph(case_id))


@app.post("/api/cases/<int:case_id>/entities")
@AUTH.require("analyst")
def add_entity(case_id):
    data = request.get_json(silent=True) or {}
    eid = CASES.add_entity(case_id, data.get("type", "handle"), data.get("value"),
                           data.get("meta"))
    return jsonify({"id": eid}), 201


@app.post("/api/cases/<int:case_id>/link")
@AUTH.require("analyst")
def link_entities(case_id):
    data = request.get_json(silent=True) or {}
    return jsonify(CASES.link_entities(case_id, data.get("src_id"), data.get("dst_id"),
                                       data.get("relation"), data.get("weight", 1.0),
                                       data.get("source", "")))


@app.get("/api/search")
@AUTH.require("viewer")
def search_all():
    q = request.args.get("q", "")
    case_id = request.args.get("case_id", type=int)
    return jsonify(CASES.search_artifacts(q, case_id))


@app.get("/api/evidence/<int:artifact_id>/verify")
@AUTH.require("viewer")
def verify_evidence(artifact_id):
    """Recompute the stored SHA-256 and confirm the artifact is untampered."""
    res = DB.verify_artifact(artifact_id)
    if res is None:
        return jsonify({"error": "not found"}), 404
    DB.audit(_user()["username"], "evidence.verify", str(artifact_id), f"valid={res['valid']}")
    return jsonify(res)


# ---------------------------------------------------------------- 8. recon pipeline
@app.get("/api/recon/pipelines")
@AUTH.require("viewer")
def recon_pipelines():
    import modules.recon.pipeline as RECON
    return jsonify(RECON.list_pipelines())


@app.post("/api/recon/run")
@AUTH.require("analyst")
def recon_run():
    import modules.recon.pipeline as RECON
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "target required"}), 400
    ptype = data.get("type", "domain")
    case_id = data.get("case_id")
    result = RECON.run_pipeline(target, ptype, case_id, _user()["username"], _keys())
    DB.audit(_user()["username"], "recon.run", target, f"type={ptype} case={case_id}")
    return jsonify(result)


@app.get("/api/recon/deep/profiles")
@AUTH.require("viewer")
def recon_deep_profiles():
    import modules.deeprecon.deeprecon as DEEP
    return jsonify(DEEP.list_deep_profiles())


@app.post("/api/recon/deep")
@AUTH.require("analyst")
def recon_deep_run():
    import modules.deeprecon.deeprecon as DEEP
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "target required"}), 400
    axis = data.get("axis")
    case_id = data.get("case_id")
    q = _quota("deep_recon", 30)
    if q:
        return q
    result = DEEP.run_deep(target, axis, case_id, _user()["username"])
    DB.audit(_user()["username"], "recon.deep", target,
             f"axis={axis} type={result.get('detected_type')} case={case_id}")
    return jsonify(result)


# ------------------------------------------------- 8b. trackers
@app.get("/api/trackers")
@AUTH.require("viewer")
def trackers_list():
    import modules.trackers.trackers as TRK
    return jsonify(TRK.list_trackers())


@app.post("/api/trackers")
@AUTH.require("analyst")
def trackers_register():
    import modules.trackers.trackers as TRK
    data = request.get_json(silent=True) or {}
    r = TRK.register(data.get("kind"), data.get("target"),
                     data.get("case_id"), data.get("interval_min"),
                     _user()["username"])
    if r.get("error"):
        return jsonify(r), 400 if "unknown" in r["error"] else 409
    return jsonify(r)


@app.delete("/api/trackers/<int:tid>")
@AUTH.require("analyst")
def trackers_delete(tid):
    import modules.trackers.trackers as TRK
    r = TRK.remove(tid, _user()["username"])
    if r.get("error"):
        return jsonify(r), 404
    return jsonify(r)


@app.post("/api/trackers/<int:tid>/check")
@AUTH.require("analyst")
def trackers_check(tid):
    import modules.trackers.trackers as TRK
    r = TRK.check_tracker(tid, _user()["username"])
    if r.get("error"):
        return jsonify(r), 404
    return jsonify(r)


@app.post("/api/trackers/run_due")
@AUTH.require("analyst")
def trackers_run_due():
    import modules.trackers.trackers as TRK
    data = request.get_json(silent=True) or {}
    return jsonify(TRK.run_due(data.get("limit", 15)))


@app.get("/api/trackers/alerts")
@AUTH.require("viewer")
def trackers_alerts():
    import modules.trackers.trackers as TRK
    return jsonify(TRK.recent_alerts())


# ---------------------------------------------------------------- 9. dark-web
@app.post("/api/darkweb/search")
@AUTH.require("analyst")
def darkweb_search():
    import modules.darkweb.darkweb as DARKWEB
    data = request.get_json(silent=True) or {}
    out = DARKWEB.darkweb_search(data.get("query"), _keys(), data.get("case_id"),
                                 _user()["username"])
    return jsonify(out)


# ---------------------------------------------------------------- 10. SIM-swap
@app.post("/api/simswap/assess")
@AUTH.require("analyst")
def simswap_assess():
    import modules.simswap.simswap as SIMSWAP
    data = request.get_json(silent=True) or {}
    return jsonify(SIMSWAP.assess(data.get("number"), _keys(), data.get("case_id"),
                                  _user()["username"]))


# ---------------------------------------------------------------- 11. SS7 (authorized)
@app.get("/api/ss7/types")
@AUTH.require("viewer")
def ss7_types():
    import modules.ss7.ss7 as SS7
    return jsonify(SS7.request_types())


@app.post("/api/ss7/request")
@AUTH.require("analyst")
def ss7_request():
    import modules.ss7.ss7 as SS7
    data = request.get_json(silent=True) or {}
    req = SS7.build_request(data.get("req_type"), data.get("params"),
                            data.get("authority_ref"), data.get("case_id"),
                            _user()["username"])
    if req.get("error"):
        return jsonify(req), 400
    return jsonify(SS7.submit(req, data.get("carrier", "default"), _user()["username"]))


@app.post("/api/ss7/ingest/<int:artifact_id>")
@AUTH.require("analyst")
def ss7_ingest(artifact_id):
    import modules.ss7.ss7 as SS7
    return jsonify(SS7.ingest(artifact_id, request.get_json(silent=True) or {},
                              _user()["username"]))


@app.get("/api/ss7/requests")
@AUTH.require("viewer")
def ss7_requests():
    import modules.ss7.ss7 as SS7
    return jsonify(SS7.list_requests(request.args.get("case_id", type=int)))


# ---------------------------------------------------------------- 12. attribution
@app.post("/api/attribution/profile")
@AUTH.require("analyst")
def attribution_profile():
    import modules.attribution.profiler as ATTR
    data = request.get_json(silent=True) or {}
    ids = data.get("identifiers") or ([data.get("identifier")] if data.get("identifier") else [])
    return jsonify(ATTR.build_profile(ids, _keys(), data.get("case_id"),
                                      _user()["username"], data.get("use_ai", True)))


# ---------------------------------------------------------------- 13. watchlists + alerts
@app.post("/api/watchlist")
@AUTH.require("analyst")
def add_watch():
    data = request.get_json(silent=True) or {}
    return jsonify(CASES.add_watch(data.get("case_id"), data.get("entity_type"),
                                   data.get("entity_value"), data.get("checks"),
                                   data.get("interval_min", 360),
                                   _user()["username"])), 201


@app.get("/api/watchlist")
@AUTH.require("viewer")
def list_watch():
    return jsonify(CASES.list_watchlists(request.args.get("case_id", type=int)))


@app.post("/api/watchlist/sweep")
@AUTH.require("analyst")
def sweep_now():
    import modules.watchlist.sweeper as SWEEPER
    n = SWEEPER.run_due_sweeps()
    return jsonify({"swept": True, "alerts_raised": n})


@app.get("/api/alerts")
@AUTH.require("viewer")
def list_alerts():
    return jsonify(CASES.list_alerts(request.args.get("case_id", type=int),
                                     request.args.get("unack") == "1"))


@app.post("/api/alerts/<int:alert_id>/ack")
@AUTH.require("analyst")
def ack_alert(alert_id):
    CASES.acknowledge_alert(alert_id)
    return jsonify({"acknowledged": True})


# ---------------------------------------------------------------- 14. report + STIX export
@app.get("/api/report/<int:case_id>")
@AUTH.require("analyst")
def gen_report(case_id):
    import modules.report.report as REPORT
    rep = REPORT.generate_report(case_id, _user()["username"], True, _keys())
    return jsonify({k: v for k, v in rep.items() if k != "html"})


@app.get("/api/report/<int:case_id>/html")
@AUTH.require("analyst")
def gen_report_html(case_id):
    import modules.report.report as REPORT
    rep = REPORT.generate_report(case_id, _user()["username"], True, _keys())
    return Response(rep.get("html", ""), mimetype="text/html")


@app.get("/api/export/stix/<int:case_id>")
@AUTH.require("analyst")
def export_stix(case_id):
    import modules.export.stix as STIX
    out = STIX.export_case(case_id)
    return jsonify(out)


# ---------------------------------------------------------------- 15. GEOINT
@app.get("/api/geo/geocode")
@AUTH.require("analyst")
def geo_geocode():
    import modules.geo.geo as GEO
    return jsonify(GEO.geocode(request.args.get("place", "")))


@app.get("/api/geo/reverse")
@AUTH.require("analyst")
def geo_reverse():
    import modules.geo.geo as GEO
    return jsonify(GEO.reverse_geocode(request.args.get("lat", type=float),
                                       request.args.get("lon", type=float)))


@app.get("/api/geo/case/<int:case_id>")
@AUTH.require("viewer")
def geo_case(case_id):
    import modules.geo.geo as GEO
    return jsonify(GEO.case_points(case_id))


@app.get("/api/geo/within")
@AUTH.require("viewer")
def geo_within():
    import modules.geo.geo as GEO
    return jsonify(GEO.within_radius(request.args.get("case_id", type=int),
                                     request.args.get("lat", type=float),
                                     request.args.get("lon", type=float),
                                     request.args.get("radius", type=int, default=1000)))


@app.post("/api/geo/geocode_case")
@AUTH.require("analyst")
def geo_geocode_case():
    import modules.geo.geo as GEO
    data = request.get_json(silent=True) or {}
    return jsonify(GEO.geocode_to_case(data.get("place"), data.get("case_id"),
                                       _user()["username"]))


@app.get("/api/geo/export/<int:case_id>.geojson")
@AUTH.require("analyst")
def geo_export_json(case_id):
    import modules.geo.geo as GEO
    return jsonify(GEO.export_geojson(case_id))


@app.get("/api/geo/export/<int:case_id>.kml")
@AUTH.require("analyst")
def geo_export_kml(case_id):
    import modules.geo.geo as GEO
    return Response(GEO.export_kml(case_id), mimetype="application/vnd.google-earth.kml+xml")


# ---------------------------------------------------------------- 16. VEHICLE
@app.post("/api/vehicle/vin")
@AUTH.require("analyst")
def vehicle_vin():
    import modules.vehicle.vehicle as VEH
    data = request.get_json(silent=True) or {}
    vin = data.get("vin", "")
    out = VEH.decode_vin(vin)
    if data.get("case_id") and not out.get("error"):
        root = VEH._upsert(data["case_id"], "vehicle", f"vin:{vin}")
        DB.store_artifact(data["case_id"], root, "vehicle", "vehicle:vin_decode",
                          out, _user()["username"])
    DB.audit(_user()["username"], "vehicle.vin", vin)
    return jsonify(out)


@app.post("/api/vehicle/recalls")
@AUTH.require("analyst")
def vehicle_recalls():
    import modules.vehicle.vehicle as VEH
    data = request.get_json(silent=True) or {}
    return jsonify(VEH.recalls(data.get("vin", "")))


@app.post("/api/vehicle/plate_decode")
@AUTH.require("analyst")
def vehicle_plate_decode():
    import modules.vehicle.vehicle as VEH
    data = request.get_json(silent=True) or {}
    return jsonify(VEH.decode_plate(data.get("plate"), data.get("jurisdiction", "US")))


@app.post("/api/vehicle/reverse_plate")
@AUTH.require("analyst")
def vehicle_reverse():
    import modules.vehicle.vehicle as VEH
    data = request.get_json(silent=True) or {}
    out = VEH.reverse_plate_lookup(data.get("plate"), data.get("jurisdiction", "US"),
                                   data.get("authority_ref"), data.get("case_id"),
                                   _user()["username"])
    if out.get("error"):
        return jsonify(out), 400
    return jsonify(out)


@app.post("/api/vehicle/registration")
@AUTH.require("analyst")
def vehicle_registration():
    import modules.vehicle.vehicle as VEH
    data = request.get_json(silent=True) or {}
    out = VEH.registration_lookup(data.get("plate"), data.get("jurisdiction", "US"),
                                  data.get("authority_ref"), data.get("case_id"),
                                  _user()["username"])
    if out.get("error"):
        return jsonify(out), 400
    return jsonify(out)


@app.post("/api/vehicle/alpr")
@AUTH.require("analyst")
def vehicle_alpr():
    import modules.vehicle.vehicle as VEH
    data = request.get_json(silent=True) or {}
    return jsonify(VEH.ingest_plate_sighting(
        data.get("plate"), data.get("lat"), data.get("lon"), data.get("camera_id"),
        data.get("case_id"), _user()["username"], data.get("source", "alpr")))


@app.get("/api/vehicle/timeline")
@AUTH.require("viewer")
def vehicle_timeline():
    import modules.vehicle.vehicle as VEH
    return jsonify(VEH.plate_timeline(request.args.get("plate", ""),
                                      request.args.get("case_id", type=int)))


# ---------------------------------------------------------------- 17. CCTV
@app.get("/api/cctv/discover")
@AUTH.require("analyst")
def cctv_discover():
    import modules.cctv.cctv as CCTV
    return jsonify(CCTV.discover_cameras(request.args.get("q", ""),
                                         _keys().get("SHODAN_API_KEY", "")))


@app.post("/api/cctv/register")
@AUTH.require("analyst")
def cctv_register():
    import modules.cctv.cctv as CCTV
    data = request.get_json(silent=True) or {}
    return jsonify(CCTV.register_camera(data.get("ip"), data.get("port", 80),
                                        data.get("label"), data.get("lat"),
                                        data.get("lon"), data.get("case_id"),
                                        _user()["username"], data.get("meta")))


@app.get("/api/cctv/cameras")
@AUTH.require("viewer")
def cctv_cameras():
    import modules.cctv.cctv as CCTV
    return jsonify(CCTV.list_cameras(request.args.get("case_id", type=int)))


@app.post("/api/cctv/ingest")
@AUTH.require("analyst")
def cctv_ingest():
    import modules.cctv.cctv as CCTV
    data = request.get_json(silent=True) or {}
    return jsonify(CCTV.ingest_frame(data.get("camera_ref"), data.get("case_id"),
                                     _user()["username"], data.get("filename", "frame.jpg"),
                                     data.get("data_b64"), data.get("source", "authorized_feed"),
                                     data.get("note", "")))


# ---------------------------------------------------------------- 18. IoT register
@app.post("/api/iot/register")
@AUTH.require("analyst")
def iot_register():
    import modules.iot.iot as IOT
    data = request.get_json(silent=True) or {}
    return jsonify(IOT.register(data.get("name"), data.get("type", "generic"),
                                data.get("ip"), data.get("port"), data.get("meta"),
                                data.get("case_id"), _user()["username"]))


@app.get("/api/iot/devices")
@AUTH.require("viewer")
def iot_devices():
    import modules.iot.iot as IOT
    return jsonify(IOT.list_devices(request.args.get("case_id", type=int)))


@app.post("/api/iot/scan/<int:entity_id>")
@AUTH.require("analyst")
def iot_scan(entity_id):
    import modules.iot.iot as IOT
    return jsonify(IOT.scan_device(entity_id, _user()["username"]))


@app.post("/api/iot/scan_all")
@AUTH.require("analyst")
def iot_scan_all():
    import modules.iot.iot as IOT
    data = request.get_json(silent=True) or {}
    return jsonify(IOT.scan_all(data.get("case_id"), _user()["username"]))


@app.post("/api/iot/lawful_access/<int:entity_id>")
@AUTH.require("analyst")
def iot_lawful(entity_id):
    import modules.iot.iot as IOT
    data = request.get_json(silent=True) or {}
    out = IOT.lawful_access_request(entity_id, data.get("authority_ref"),
                                    data.get("action", "inspect"), _user()["username"])
    if out.get("error"):
        return jsonify(out), 400
    return jsonify(out)


# ---------------------------------------------------------------- 19. CORPORATE
@app.get("/api/corporate/search")
@AUTH.require("analyst")
def corp_search():
    import modules.corporate.corporate as CORP
    return jsonify(CORP.search_companies(request.args.get("q", ""),
                                         request.args.get("jurisdiction", "")))


@app.get("/api/corporate/officers")
@AUTH.require("analyst")
def corp_officers():
    import modules.corporate.corporate as CORP
    number = request.args.get("number", "")
    juris = request.args.get("jurisdiction", "")
    # Wikidata entity (Q...) -> free officers lookup
    if number.upper().startswith("Q") and number[1:].isdigit():
        return jsonify(CORP.wikidata_officers(number.upper()))
    return jsonify(CORP.company_officers(number, juris))


@app.post("/api/corporate/link")
@AUTH.require("analyst")
def corp_link():
    import modules.corporate.corporate as CORP
    data = request.get_json(silent=True) or {}
    return jsonify(CORP.link_company(data.get("case_id"), data.get("company_name"),
                                     data.get("jurisdiction"), data.get("officers"),
                                     _user()["username"]))


@app.post("/api/corporate/trace_person")
@AUTH.require("analyst")
def corp_trace():
    import modules.corporate.corporate as CORP
    data = request.get_json(silent=True) or {}
    return jsonify(CORP.trace_person(data.get("person"), data.get("case_id"),
                                     _user()["username"]))


# ---------------------------------------------------------------- 20. CRYPTO
@app.post("/api/crypto/address")
@AUTH.require("analyst")
def crypto_address():
    import modules.crypto.crypto as CRYPTO
    data = request.get_json(silent=True) or {}
    return jsonify(CRYPTO.address_overview(data.get("address"), data.get("case_id"),
                                           _user()["username"]))


@app.post("/api/crypto/transactions")
@AUTH.require("analyst")
def crypto_tx():
    import modules.crypto.crypto as CRYPTO
    data = request.get_json(silent=True) or {}
    return jsonify(CRYPTO.transactions(data.get("address"), data.get("limit", 50),
                                       data.get("case_id"), _user()["username"]))


@app.post("/api/crypto/trace")
@AUTH.require("analyst")
def crypto_trace():
    import modules.crypto.crypto as CRYPTO
    data = request.get_json(silent=True) or {}
    return jsonify(CRYPTO.trace_flow(data.get("address"), data.get("case_id"),
                                     _user()["username"]))


# ---------------------------------------------------------------- 21. SCREENING
@app.post("/api/screening/name")
@AUTH.require("analyst")
def screen_one():
    import modules.screening.screening as SCR
    data = request.get_json(silent=True) or {}
    return jsonify(SCR.screen_name(data.get("name", ""), data.get("threshold", 0.75)))


@app.post("/api/screening/batch")
@AUTH.require("analyst")
def screen_batch():
    import modules.screening.screening as SCR
    data = request.get_json(silent=True) or {}
    return jsonify(SCR.screen_batch(data.get("names", []), data.get("threshold", 0.75),
                                    data.get("case_id"), _user()["username"]))


@app.get("/api/screening/case/<int:case_id>")
@AUTH.require("analyst")
def screen_case(case_id):
    import modules.screening.screening as SCR
    return jsonify(SCR.screen_case_entities(case_id, 0.75, _user()["username"]))


@app.get("/api/screening/lists")
@AUTH.require("viewer")
def screen_lists():
    import modules.screening.screening as SCR
    return jsonify(SCR.lists_status())


# ---------------------------------------------------------------- 22. INFRA PIVOT
@app.post("/api/infra/ip")
@AUTH.require("analyst")
def infra_ip():
    import modules.infra.infra as INFRA
    data = request.get_json(silent=True) or {}
    return jsonify(INFRA.pivot_ip(data.get("ip"), data.get("case_id"),
                                  _user()["username"]))


@app.post("/api/infra/domain")
@AUTH.require("analyst")
def infra_domain():
    import modules.infra.infra as INFRA
    data = request.get_json(silent=True) or {}
    return jsonify(INFRA.pivot_domain(data.get("domain"), data.get("case_id"),
                                      _user()["username"]))


# ---------------------------------------------------------------- 23. quota helper (free-tier protection)
def _quota(source, limit=60):
    """Wrap free-API budgets; returns a 429 response tuple when exhausted, else None."""
    try:
        import modules.ops.ops as OPS
        r = OPS.quota_allow(source, limit)
        if r.get("allowed") is False:
            return (jsonify({"error": "rate limited", "source": source, "quota": r}), 429)
        OPS.quota_record(source)
    except Exception:
        pass
    return None


# ---------------------------------------------------------------- 24. PLAYBOOKS (auto-pivot chains)
@app.get("/api/playbooks")
@AUTH.require("viewer")
def pb_list():
    import modules.playbook.playbooks as PB
    return jsonify(PB.list_playbooks())


@app.get("/api/playbooks/<name>")
@AUTH.require("viewer")
def pb_get(name):
    import modules.playbook.playbooks as PB
    return jsonify(PB.get_playbook(name))


@app.post("/api/playbooks")
@AUTH.require("analyst")
def pb_save():
    import modules.playbook.playbooks as PB
    data = request.get_json(silent=True) or {}
    out = PB.save_playbook(data.get("name", ""), data.get("steps") or [],
                           _user()["username"], data.get("description", ""))
    return jsonify(out), 400 if out.get("error") else 201


@app.delete("/api/playbooks/<name>")
@AUTH.require("analyst")
def pb_del(name):
    import modules.playbook.playbooks as PB
    return jsonify(PB.delete_playbook(name))


@app.post("/api/playbooks/run")
@AUTH.require("analyst")
def pb_run():
    import modules.playbook.playbooks as PB
    data = request.get_json(silent=True) or {}
    q = _quota("playbook_run", 40)
    if q:
        return q
    out = PB.run_playbook(data.get("name"), data.get("target"),
                          data.get("case_id"), _user()["username"])
    if out.get("error"):
        return jsonify(out), 400
    return jsonify(out)


# ---------------------------------------------------------------- 25. FUSION (master timeline + entity resolution)
@app.get("/api/fusion/timeline/<int:case_id>")
@AUTH.require("viewer")
def fusion_timeline(case_id):
    import modules.fusion.fusion as FUSION
    return jsonify(FUSION.master_timeline(case_id, request.args.get("limit", 500, type=int)))


@app.post("/api/fusion/resolve")
@AUTH.require("analyst")
def fusion_resolve():
    import modules.fusion.fusion as FUSION
    data = request.get_json(silent=True) or {}
    dry = data.get("dry_run", True)
    if isinstance(dry, str):
        dry = dry.lower() not in ("0", "false", "no")
    out = FUSION.resolve_entities(data.get("case_id"),
                                  data.get("threshold", 0.86), bool(dry))
    if out.get("error"):
        return jsonify(out), 400
    return jsonify(out)


@app.get("/api/fusion/across")
@AUTH.require("viewer")
def fusion_across():
    import modules.fusion.fusion as FUSION
    return jsonify(FUSION.find_across_cases(request.args.get("value", "")))


# ---------------------------------------------------------------- 26. WEB ARCHIVE (Wayback CDX + change watch)
@app.get("/api/archive/cdx")
@AUTH.require("analyst")
def arch_cdx():
    import modules.archive.archive as ARC
    q = _quota("wayback", 60)
    if q:
        return q
    return jsonify(ARC.wayback_cdx(request.args.get("url", ""),
                                   request.args.get("limit", 50, type=int),
                                   request.args.get("from", "2005"),
                                   request.args.get("to", "2026")))


@app.get("/api/archive/history")
@AUTH.require("analyst")
def arch_history():
    import modules.archive.archive as ARC
    return jsonify(ARC.page_history(request.args.get("url", ""),
                                    request.args.get("limit", 100, type=int)))


@app.post("/api/archive/snapshot")
@AUTH.require("analyst")
def arch_snapshot():
    import modules.archive.archive as ARC
    data = request.get_json(silent=True) or {}
    out = ARC.fetch_snapshot(data.get("url"), data.get("timestamp"))
    if out.get("error"):
        return jsonify(out), 400
    return jsonify(out)


@app.post("/api/archive/diff")
@AUTH.require("analyst")
def arch_diff():
    import modules.archive.archive as ARC
    data = request.get_json(silent=True) or {}
    out = ARC.diff_versions(data.get("url"), data.get("ts1"), data.get("ts2"))
    if out.get("error"):
        return jsonify(out), 400
    return jsonify(out)


@app.post("/api/archive/watch")
@AUTH.require("analyst")
def arch_watch_add():
    import modules.archive.archive as ARC
    data = request.get_json(silent=True) or {}
    out = ARC.register_watch(data.get("url"), data.get("case_id"),
                             data.get("interval_min", 720), _user()["username"])
    if out.get("error"):
        return jsonify(out), 400
    return jsonify(out), 201


@app.get("/api/archive/watch")
@AUTH.require("viewer")
def arch_watch_list():
    import modules.archive.archive as ARC
    return jsonify(ARC.list_watch())


@app.post("/api/archive/watch/check/<int:wid>")
@AUTH.require("analyst")
def arch_watch_check(wid):
    import modules.archive.archive as ARC
    out = ARC.check_watch(wid)
    if out.get("error"):
        return jsonify(out), 404
    return jsonify(out)


# ---------------------------------------------------------------- 27. DEEP SEARCH (federated + dorks)
@app.post("/api/search/federated")
@AUTH.require("analyst")
def search_federated():
    import modules.searchx.searchx as SX
    data = request.get_json(silent=True) or {}
    q = _quota("federated_search", 60)
    if q:
        return q
    eng = data.get("engines")
    if isinstance(eng, str) and eng.strip():
        eng = [x.strip() for x in eng.split(",") if x.strip()]
    out = SX.federated(data.get("query", ""), eng)
    if out.get("error"):
        return jsonify(out), 400
    return jsonify(out)


@app.get("/api/search/dork/build")
@AUTH.require("viewer")
def search_dork_build():
    import modules.searchx.searchx as SX
    return jsonify(SX.dork_build(request.args.get("target", ""),
                                 request.args.get("kind")))


@app.post("/api/search/dork/run")
@AUTH.require("analyst")
def search_dork_run():
    import modules.searchx.searchx as SX
    data = request.get_json(silent=True) or {}
    q = _quota("dork_run", 60)
    if q:
        return q
    out = SX.dork_run(data.get("target", ""), data.get("kind"),
                      data.get("max_dorks", 4))
    if out.get("error"):
        return jsonify(out), 400
    return jsonify(out)


# ---------------------------------------------------------------- 28. NAME VARIANTS (international)
@app.get("/api/name/variants")
@AUTH.require("viewer")
def name_variants():
    import modules.namevar.namevar as NV
    return jsonify({"input": request.args.get("name", ""),
                    "variants": NV.variants(request.args.get("name", ""),
                                            request.args.get("max", 250, type=int),
                                            request.args.get("leet", "0") in ("1", "true"))})


@app.get("/api/name/cross_script")
@AUTH.require("viewer")
def name_cross():
    import modules.namevar.namevar as NV
    return jsonify({"input": request.args.get("name", ""),
                    "terms": NV.cross_script_search_terms(request.args.get("name", ""))})


@app.get("/api/name/homographs")
@AUTH.require("viewer")
def name_homographs():
    import modules.namevar.namevar as NV
    return jsonify(NV.domain_homographs(request.args.get("domain", "")))


@app.post("/api/name/confusables")
@AUTH.require("viewer")
def name_confusables():
    import modules.namevar.namevar as NV
    data = request.get_json(silent=True) or {}
    return jsonify(NV.detect_confusables(data.get("text", "")))


# ---------------------------------------------------------------- 29. REGIONAL platforms & engines
@app.get("/api/regional/telegram")
@AUTH.require("analyst")
def reg_telegram():
    import modules.regional.regional as REG
    q = _quota("telegram", 30)
    if q:
        return q
    return jsonify(REG.telegram_channel(request.args.get("channel", "")))


@app.post("/api/regional/search")
@AUTH.require("analyst")
def reg_search():
    import modules.regional.regional as REG
    data = request.get_json(silent=True) or {}
    engine = (data.get("engine") or "relay").lower()
    query = data.get("query", "")
    q = _quota(f"regional_{engine}", 40)
    if q:
        return q
    fn = {"baidu": REG.baidu_search, "yandex": REG.yandex_search,
          "weibo": REG.weibo_search, "relay": REG.searx_relay}.get(engine)
    if not fn:
        return jsonify({"error": "unknown engine",
                        "options": ["baidu", "yandex", "weibo", "relay"]}), 400
    return jsonify(fn(query))


@app.get("/api/regional/availability")
@AUTH.require("viewer")
def reg_avail():
    import modules.regional.regional as REG
    return jsonify(REG.availability(request.args.get("q", "test")))


# ---------------------------------------------------------------- 30. EMAIL deep-dive
@app.get("/api/email/validate")
@AUTH.require("viewer")
def email_validate():
    import modules.emailintel.emailintel as EI
    return jsonify(EI.validate(request.args.get("email", "")))


@app.get("/api/email/profile")
@AUTH.require("viewer")
def email_profile():
    import modules.emailintel.emailintel as EI
    return jsonify(EI.dns_profile(request.args.get("email", "")))


@app.post("/api/email/deep")
@AUTH.require("analyst")
def email_deep():
    import modules.emailintel.emailintel as EI
    data = request.get_json(silent=True) or {}
    q = _quota("email_deep", 60)
    if q:
        return q
    out = EI.deep(data.get("email", ""), data.get("case_id"), _user()["username"])
    if out.get("error"):
        return jsonify(out), 400
    return jsonify(out)


@app.post("/api/email/header")
@AUTH.require("analyst")
def email_header():
    import modules.emailintel.emailintel as EI
    data = request.get_json(silent=True) or {}
    out = EI.header_analyze(data.get("raw", ""))
    if out.get("error"):
        return jsonify(out), 400
    return jsonify(out)


@app.post("/api/email/anchor")
@AUTH.require("analyst")
def email_anchor():
    import modules.emailintel.emailintel as EI
    data = request.get_json(silent=True) or {}
    out = EI.anchor_graph(data.get("case_id"), data.get("email"),
                          data.get("links"), _user()["username"])
    if out.get("error"):
        return jsonify(out), 400
    return jsonify(out)


# ---------------------------------------------------------------- 31. GLOBAL COURTS
@app.get("/api/courts/search")
@AUTH.require("analyst")
def courts_search():
    import modules.courts.courts as CRT
    q = _quota("courts", 40)
    if q:
        return q
    prov = request.args.get("providers", "")
    prov = [x.strip() for x in prov.split(",") if x.strip()] or None
    return jsonify(CRT.search(request.args.get("q", ""), prov,
                              request.args.get("jurisdiction")))


@app.get("/api/courts/status")
@AUTH.require("viewer")
def courts_status():
    import modules.courts.courts as CRT
    return jsonify(CRT.providers_status())


# ---------------------------------------------------------------- 32. GLOBAL CORPORATE (GLEIF/VIES/CH)
@app.get("/api/worldcorp/gleif")
@AUTH.require("analyst")
def wc_gleif():
    import modules.worldcorp.worldcorp as WC
    q = _quota("gleif", 60)
    if q:
        return q
    return jsonify(WC.gleif_search(request.args.get("q", "")))


@app.get("/api/worldcorp/lei/<lei>")
@AUTH.require("viewer")
def wc_lei(lei):
    import modules.worldcorp.worldcorp as WC
    return jsonify(WC.gleif_by_lei(lei))


@app.get("/api/worldcorp/relationships/<lei>")
@AUTH.require("viewer")
def wc_rel(lei):
    import modules.worldcorp.worldcorp as WC
    return jsonify(WC.gleif_relationships(lei))


@app.get("/api/worldcorp/vat")
@AUTH.require("analyst")
def wc_vat():
    import modules.worldcorp.worldcorp as WC
    return jsonify(WC.vies_vat(request.args.get("vat", ""),
                               request.args.get("sandbox", "0") in ("1", "true")))


@app.get("/api/worldcorp/ch")
@AUTH.require("analyst")
def wc_ch():
    import modules.worldcorp.worldcorp as WC
    return jsonify(WC.companies_house(request.args.get("q", "")))


@app.post("/api/worldcorp/link")
@AUTH.require("analyst")
def wc_link():
    import modules.worldcorp.worldcorp as WC
    data = request.get_json(silent=True) or {}
    out = WC.link_to_case(data.get("case_id"), data.get("gleif_result"),
                          _user()["username"])
    if out.get("error"):
        return jsonify(out), 400
    return jsonify(out)


# ---------------------------------------------------------------- 33. MULTI-LIST SANCTIONS (sanx)
@app.post("/api/sanx/search")
@AUTH.require("analyst")
def sanx_search():
    import modules.sanx.sanx as SANX
    data = request.get_json(silent=True) or {}
    src = data.get("sources")
    if isinstance(src, str) and src.strip():
        src = [x.strip() for x in src.split(",") if x.strip()]
    out = SANX.search(data.get("name", ""), data.get("threshold", 0.75), src)
    if out.get("error"):
        return jsonify(out), 400
    return jsonify(out)


@app.get("/api/sanx/status")
@AUTH.require("viewer")
def sanx_status():
    import modules.sanx.sanx as SANX
    return jsonify(SANX.lists_status())


@app.get("/api/sanx/case/<int:case_id>")
@AUTH.require("analyst")
def sanx_case(case_id):
    import modules.sanx.sanx as SANX
    return jsonify(SANX.screen_case_entities(case_id, 0.75, _user()["username"]))


# ---------------------------------------------------------------- 34. WORLD RISK (GDELT + country intel)
@app.get("/api/risk/gdelt")
@AUTH.require("analyst")
def risk_gdelt():
    import modules.risk.risk as RISK
    q = _quota("gdelt", 30)
    if q:
        return q
    return jsonify(RISK.gdelt_news(request.args.get("q", ""),
                                   request.args.get("timespan", "3month"),
                                   request.args.get("max", 30, type=int)))


@app.get("/api/risk/gdelt/timeline")
@AUTH.require("analyst")
def risk_gdelt_tl():
    import modules.risk.risk as RISK
    q = _quota("gdelt", 30)
    if q:
        return q
    return jsonify(RISK.gdelt_timeline(request.args.get("q", ""),
                                       request.args.get("timespan", "3month")))


@app.get("/api/risk/country")
@AUTH.require("viewer")
def risk_country():
    import modules.risk.risk as RISK
    return jsonify(RISK.country_profile(request.args.get("c", "")))


@app.get("/api/risk/jurisdiction")
@AUTH.require("viewer")
def risk_jurisdiction():
    import modules.risk.risk as RISK
    return jsonify(RISK.jurisdiction_card(request.args.get("c", "")))


@app.post("/api/risk/overlay")
@AUTH.require("viewer")
def risk_overlay():
    import modules.risk.risk as RISK
    data = request.get_json(silent=True) or {}
    countries = data.get("countries") or []
    if isinstance(countries, str):
        countries = [x.strip() for x in countries.split(",") if x.strip()]
    return jsonify(RISK.overlay(countries))


# ---------------------------------------------------------------- 35. OPS (datasets / quota / health)
@app.get("/api/ops/datasets")
@AUTH.require("viewer")
def ops_datasets():
    import modules.ops.ops as OPS
    return jsonify(OPS.datasets_status())


@app.post("/api/ops/datasets/fetch")
@AUTH.require("analyst")
def ops_fetch():
    import modules.ops.ops as OPS
    data = request.get_json(silent=True) or {}
    out = OPS.fetch_dataset(data.get("name", ""),
                            data.get("max_mb", 100), _user()["username"])
    if out.get("error"):
        return jsonify(out), 400
    return jsonify(out)


@app.get("/api/ops/quota")
@AUTH.require("viewer")
def ops_quota():
    import modules.ops.ops as OPS
    return jsonify(OPS.quota_status())


@app.post("/api/ops/quota/allow")
@AUTH.require("viewer")
def ops_allow():
    import modules.ops.ops as OPS
    data = request.get_json(silent=True) or {}
    return jsonify(OPS.quota_allow(data.get("source", ""), data.get("limit", 60)))


@app.get("/api/ops/health")
@AUTH.require("viewer")
def ops_health():
    c = DB.get_db()
    rows = [dict(r) for r in c.execute(
        "SELECT * FROM ops_health ORDER BY last_check DESC").fetchall()]
    return jsonify(rows)


@app.post("/api/ops/health/run")
@AUTH.require("analyst")
def ops_health_run():
    import modules.ops.ops as OPS
    return jsonify(OPS.health_check(None, _user()["username"]))


# ---------------------------------------------------------------- 36. NARRATIVE (LLM evidence briefing)
@app.get("/api/narrative/digest/<int:case_id>")
@AUTH.require("viewer")
def narr_digest(case_id):
    import modules.narrative.narrative as NARR
    out = NARR.digest(case_id)
    if out.get("error"):
        return jsonify(out), 404
    return jsonify(out)


@app.post("/api/narrative/generate")
@AUTH.require("analyst")
def narr_generate():
    import modules.narrative.narrative as NARR
    data = request.get_json(silent=True) or {}
    q = _quota("narrative", 20)
    if q:
        return q
    out = NARR.generate(data.get("case_id"), _user()["username"],
                        data.get("focus", ""), data.get("engine", "auto"))
    if out.get("error"):
        return jsonify(out), 400
    return jsonify(out)


# ---------------------------------------------------------------- 37. GEO EXT (buildings / POIs / addressing)
@app.get("/api/geoext/buildings")
@AUTH.require("viewer")
def gx_buildings():
    import modules.geoext.geoext as GX
    q = _quota("overpass", 30)
    if q:
        return q
    return jsonify(GX.buildings_at(request.args.get("lat", type=float),
                                   request.args.get("lon", type=float),
                                   request.args.get("radius", 300, type=int),
                                   request.args.get("cap", 400, type=int)))


@app.get("/api/geoext/pois")
@AUTH.require("viewer")
def gx_pois():
    import modules.geoext.geoext as GX
    q = _quota("overpass", 30)
    if q:
        return q
    return jsonify(GX.pois_at(request.args.get("lat", type=float),
                              request.args.get("lon", type=float),
                              request.args.get("radius", 300, type=int),
                              request.args.get("cap", 400, type=int)))


@app.get("/api/geoext/landuse")
@AUTH.require("viewer")
def gx_landuse():
    import modules.geoext.geoext as GX
    q = _quota("overpass", 30)
    if q:
        return q
    return jsonify(GX.landuse_at(request.args.get("lat", type=float),
                                 request.args.get("lon", type=float),
                                 request.args.get("radius", 300, type=int)))


@app.get("/api/geoext/footprints")
@AUTH.require("viewer")
def gx_footprints():
    import modules.geoext.geoext as GX
    q = _quota("overpass", 30)
    if q:
        return q
    return jsonify(GX.footprints_geojson(request.args.get("lat", type=float),
                                         request.args.get("lon", type=float),
                                         request.args.get("radius", 300, type=int),
                                         request.args.get("cap", 200, type=int)))


@app.get("/api/geoext/mapillary")
@AUTH.require("analyst")
def gx_mapillary():
    import modules.geoext.geoext as GX
    return jsonify(GX.mapillary_images(request.args.get("lat", type=float),
                                       request.args.get("lon", type=float),
                                       request.args.get("radius", 200, type=int),
                                       request.args.get("cap", 20, type=int)))


@app.get("/api/geoext/zip")
@AUTH.require("viewer")
def gx_zip():
    import modules.geoext.geoext as GX
    return jsonify(GX.zip_lookup(request.args.get("cc", ""),
                                 request.args.get("zip", "")))


@app.get("/api/geoext/aerial")
@AUTH.require("viewer")
def gx_aerial():
    import modules.geoext.geoext as GX
    return jsonify(GX.openaerial_search(request.args.get("lat", type=float),
                                        request.args.get("lon", type=float),
                                        request.args.get("radius", 300, type=int)))


# ---------------------------------------------------------------- Part 1 + Part 2 module routes
from routes import EXTRA_META, register_all  # noqa: E402

try:
    register_all(app, CAPS, _user)
    log.info("extra module routes registered: %d modules", len(EXTRA_META))
except Exception as e:
    log.error("extra module route registration failed: %s", e)


# ---------------------------------------------------------------- background collector
def _loop():
    if not CAPS["threat_intel"]:
        return
    import time
    _, ti_collector, ti_processor = TI
    while True:
        try:
            for fn in ("fetch_urlhaus", "fetch_abuseipdb", "fetch_otx", "fetch_virustotal"):
                if hasattr(ti_collector, fn):
                    try:
                        getattr(ti_collector, fn)()
                    except Exception as e:
                        log.warning("%s: %s", fn, e)
            ti_processor.process_indicators()
        except Exception as e:
            log.error("auto collect: %s", e)
        time.sleep(C.COLLECT_INTERVAL_HOURS * 3600)

if __name__ == "__main__":
    threading.Thread(target=_loop, daemon=True).start()
    # watchlist sweep daemon — periodic checks + alerts (never blocks boot)
    try:
        import modules.watchlist.sweeper as SWEEPER
        SWEEPER.start_daemon(interval_sec=300)
        log.info("watchlist sweep daemon started")
    except Exception as e:
        log.warning("watchlist daemon unavailable: %s", e)
    # Wave 3: seed default auto-pivot playbooks (idempotent)
    try:
        import modules.playbook.playbooks as PB
        seeded = PB.seed_defaults()
        log.info("default playbooks seeded: %s", seeded)
    except Exception as e:
        log.warning("playbook seeding unavailable: %s", e)
    # Wave 3: web-archive change-watch daemon (Wayback diff -> alerts)
    try:
        import modules.archive.archive as ARC_W
        ARC_W.start_daemon(interval_sec=600)
        log.info("archive change-watch daemon started")
    except Exception as e:
        log.warning("archive daemon unavailable: %s", e)
    # Trackers: fingerprint+diff change-watchers over any subject
    try:
        import modules.trackers.trackers as TRK
        TRK.start_daemon(interval_sec=300)
        log.info("trackers daemon started (%d kinds)", len(TRK.TRACKERS))
    except Exception as e:
        log.warning("trackers daemon unavailable: %s", e)
    # Wave 3: fan-out hooks — archive-change checks ride along on due watchlist sweeps
    try:
        import modules.watchlist.sweeper as SW2
        import modules.archive.archive as ARC_H

        def _archive_case_hook(watch):
            try:
                cid = watch["case_id"]
            except Exception:
                try:
                    cid = watch.get("case_id")
                except Exception:
                    cid = None
            for w in (ARC_H.list_watch() or []):
                if cid is not None and w.get("case_id") == cid:
                    try:
                        ARC_H.check_watch(w["id"])
                    except Exception:
                        pass

        SW2.register_hook("archive_change", _archive_case_hook)
        log.info("fan-out hook registered: archive_change")
    except Exception as e:
        log.warning("fan-out hooks unavailable: %s", e)
    # Part 1 + Part 2 background daemons (each never blocks boot)
    _EXTRA_DAEMONS = (
        ("certstream", 1800), ("hostwatch", 900), ("darknet", 3600),
        ("exposure", 21600), ("feedstream", 600), ("supplychain", 10800),
        ("community", 1800), ("marketplace", 43200), ("phishkit", 7200),
        ("foia", 43200), ("dsar", 21600),
    )
    import importlib as _il
    for _n, _iv in _EXTRA_DAEMONS:
        try:
            _m = _il.import_module(f"modules.{_n}.{_n}")
            _m.start_daemon(interval_sec=_iv)
            log.info("%s daemon started", _n)
        except Exception as e:
            log.warning("%s daemon unavailable: %s", _n, e)
    log.info("Xaxglog on http://%s:%d modules=%s", C.HOST, C.PORT, CAPS)
    app.run(host=C.HOST, port=C.PORT, debug=os.getenv("FLASK_DEBUG", "0") == "1")
