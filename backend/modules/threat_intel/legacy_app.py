from flask import Flask, jsonify, request, session
from flask_cors import CORS
from database import get_connection, init_db
import json
import re
import requests
import os
import sqlite3
from google import genai
import time
from groq import Groq
from dotenv import load_dotenv
from cryptography.fernet import Fernet

load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

ABUSEIPDB_API_KEY  = os.getenv("ABUSEIPDB_API_KEY")
OTX_API_KEY        = os.getenv("OTX_API_KEY")
GEMINI_API_KEY     = os.getenv("GEMINI_API_KEY")
GROQ_API_KEY       = os.getenv("GROQ_API_KEY")
HIBP_API_KEY       = os.getenv("HIBP_API_KEY")
SHODAN_API_KEY     = os.getenv("SHODAN_API_KEY")
SECTRAILS_API_KEY  = os.getenv("SECURITYTRAILS_API_KEY")
INTELX_API_KEY     = os.getenv("INTELX_API_KEY")
URLHAUS_API_KEY    = os.getenv("URLHAUS_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(32).hex())
CORS(app, supports_credentials=True)

# Encryption setup for API key storage
ENCRYPTION_KEY_FILE = os.path.join(os.path.dirname(__file__), '.encryption_key')
if os.path.exists(ENCRYPTION_KEY_FILE):
    with open(ENCRYPTION_KEY_FILE, 'rb') as f:
        FERNET_KEY = f.read()
else:
    FERNET_KEY = Fernet.generate_key()
    with open(ENCRYPTION_KEY_FILE, 'wb') as f:
        f.write(FERNET_KEY)
fernet = Fernet(FERNET_KEY)

# Encrypted key storage in SQLite
KEYS_DB = os.path.join(os.path.dirname(__file__), 'user_keys.db')

def init_keys_db():
    conn = sqlite3.connect(KEYS_DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS user_keys (
            session_id TEXT NOT NULL,
            service    TEXT NOT NULL,
            encrypted_key TEXT NOT NULL,
            PRIMARY KEY (session_id, service)
        )
    """)
    conn.commit()
    conn.close()

init_keys_db()

# Create the indicator tables on startup so the app works on a fresh
# database (e.g. a hosted deploy where `python database.py` was never run).
init_db()

def save_user_key(session_id, service, api_key):
    encrypted = fernet.encrypt(api_key.encode()).decode()
    conn = sqlite3.connect(KEYS_DB)
    conn.execute(
        "INSERT OR REPLACE INTO user_keys (session_id, service, encrypted_key) VALUES (?, ?, ?)",
        (session_id, service, encrypted)
    )
    conn.commit()
    conn.close()

def get_user_key(session_id, service):
    conn = sqlite3.connect(KEYS_DB)
    row = conn.execute(
        "SELECT encrypted_key FROM user_keys WHERE session_id = ? AND service = ?",
        (session_id, service)
    ).fetchone()
    conn.close()
    if row:
        return fernet.decrypt(row[0].encode()).decode()
    return None

def get_all_user_keys(session_id):
    conn = sqlite3.connect(KEYS_DB)
    rows = conn.execute(
        "SELECT service FROM user_keys WHERE session_id = ?",
        (session_id,)
    ).fetchall()
    conn.close()
    return [r[0] for r in rows]

def delete_user_key(session_id, service):
    conn = sqlite3.connect(KEYS_DB)
    conn.execute(
        "DELETE FROM user_keys WHERE session_id = ? AND service = ?",
        (session_id, service)
    )
    conn.commit()
    conn.close()

def ensure_session():
    if 'sid' not in session:
        session['sid'] = os.urandom(16).hex()
    return session['sid']


# Resolve API key: server-side session store -> .env default
def get_key(name):
    default_map = {
        "abuseipdb":  ABUSEIPDB_API_KEY,
        "otx":        OTX_API_KEY,
        "gemini":     GEMINI_API_KEY,
        "groq":       GROQ_API_KEY,
        "hibp":           HIBP_API_KEY,
        "shodan":         SHODAN_API_KEY,
        "securitytrails": SECTRAILS_API_KEY,
        "intelx":         INTELX_API_KEY,
        "urlhaus":        URLHAUS_API_KEY,
        "virustotal":     VIRUSTOTAL_API_KEY,
    }
    sid = session.get('sid')
    if sid:
        user_key = get_user_key(sid, name)
        if user_key:
            return user_key
    return default_map.get(name, "")


def ai_generate(prompt):
    """Try Gemini first, fall back to Groq if Gemini fails."""
    gemini_key = get_key("gemini")
    groq_key   = get_key("groq")
    gemini_err = None

    # Try Gemini first
    if gemini_key:
        client = genai.Client(api_key=gemini_key)
        for attempt in range(2):
            try:
                response = client.models.generate_content(
                    model="gemini-2.5-flash",
                    contents=prompt
                )
                return {"text": response.text, "provider": "Gemini"}
            except Exception as e:
                err_str = str(e)
                if ("429" in err_str or "RESOURCE_EXHAUSTED" in err_str
                        or "503" in err_str or "UNAVAILABLE" in err_str):
                    if attempt == 0:
                        time.sleep(3)
                        continue
                gemini_err = err_str[:200]
                break

    # Fall back to Groq
    if groq_key:
        try:
            client = Groq(api_key=groq_key)
            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=2048
            )
            return {"text": response.choices[0].message.content, "provider": "Groq"}
        except Exception as e:
            groq_err = str(e)[:200]
            if gemini_err:
                raise Exception(f"Both AI providers failed. Gemini: {gemini_err} | Groq: {groq_err}")
            raise Exception(f"Groq API error: {groq_err}")

    if gemini_err:
        raise Exception(f"Gemini failed: {gemini_err} (no Groq key configured as fallback)")
    raise Exception("No AI API keys configured. Add a Gemini or Groq key in API Keys settings.")


# Health check
@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


# Save a user API key (encrypted, server-side)
@app.route("/api/keys", methods=["POST"])
def save_key():
    sid  = ensure_session()
    data = request.get_json()
    service = data.get("service", "").strip()
    key     = data.get("key", "").strip()

    if not service or not key:
        return jsonify({"error": "Missing service or key"}), 400

    valid_services = ["gemini", "groq", "hibp", "abuseipdb", "otx", "virustotal",
                      "shodan", "securitytrails", "intelx", "urlhaus"]
    if service not in valid_services:
        return jsonify({"error": "Unknown service"}), 400

    save_user_key(sid, service, key)
    return jsonify({"saved": True, "service": service})


# List which services have saved keys
@app.route("/api/keys", methods=["GET"])
def list_keys():
    sid = ensure_session()
    services = get_all_user_keys(sid)
    return jsonify({"services": services})


# Delete a saved key
@app.route("/api/keys/<service>", methods=["DELETE"])
def remove_key(service):
    sid = ensure_session()
    delete_user_key(sid, service)
    return jsonify({"deleted": True, "service": service})


# Validate a user-provided API key
@app.route("/api/validate-key", methods=["POST"])
def validate_key():
    data    = request.get_json()
    service = data.get("service", "")
    key     = data.get("key", "").strip()

    if not service or not key:
        return jsonify({"valid": False, "error": "Missing service or key"}), 400

    try:
        if service == "gemini":
            client = genai.Client(api_key=key)
            client.models.generate_content(
                model="gemini-2.5-flash",
                contents="Say OK"
            )
            return jsonify({"valid": True, "service": service})

        elif service == "groq":
            client = Groq(api_key=key)
            client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": "Say OK"}],
                max_tokens=5
            )
            return jsonify({"valid": True, "service": service})

        elif service == "abuseipdb":
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": key, "Accept": "application/json"},
                params={"ipAddress": "8.8.8.8", "maxAgeInDays": 1},
                timeout=8
            )
            if resp.status_code == 200:
                return jsonify({"valid": True, "service": service})
            return jsonify({"valid": False, "error": f"Status {resp.status_code}"})

        elif service == "otx":
            resp = requests.get(
                "https://otx.alienvault.com/api/v1/user/me",
                headers={"X-OTX-API-KEY": key},
                timeout=8
            )
            if resp.status_code == 200:
                return jsonify({"valid": True, "service": service})
            return jsonify({"valid": False, "error": f"Status {resp.status_code}"})

        elif service == "hibp":
            resp = requests.get(
                "https://haveibeenpwned.com/api/v3/breachedaccount/test@example.com",
                headers={"hibp-api-key": key, "user-agent": "OSINT-Dashboard"},
                timeout=10
            )
            # 404 = valid key, just no breaches; 401 = bad key
            if resp.status_code in (200, 404):
                return jsonify({"valid": True, "service": service})
            return jsonify({"valid": False, "error": f"Status {resp.status_code}"})

        elif service == "shodan":
            resp = requests.get(
                f"https://api.shodan.io/api-info?key={key}",
                timeout=8
            )
            if resp.status_code == 200:
                return jsonify({"valid": True, "service": service})
            return jsonify({"valid": False, "error": f"Status {resp.status_code}"})

        elif service == "securitytrails":
            resp = requests.get(
                "https://api.securitytrails.com/v1/ping",
                headers={"APIKEY": key},
                timeout=8
            )
            if resp.status_code == 200:
                return jsonify({"valid": True, "service": service})
            return jsonify({"valid": False, "error": f"Status {resp.status_code}"})

        elif service == "intelx":
            # free.intelx.io accepts both free-tier and paid keys; free.intelx.io
            # rejects free-tier keys with 401. Use free.* as the universal host.
            resp = requests.get(
                "https://free.intelx.io/authenticate/info",
                headers={"x-key": key},
                timeout=8
            )
            if resp.status_code == 200:
                return jsonify({"valid": True, "service": service})
            return jsonify({"valid": False, "error": f"Status {resp.status_code}"})

        elif service == "urlhaus":
            # URLhaus requires an Auth-Key header on all v1 endpoints.
            # Hitting a tiny endpoint with the key - 200 = valid, 403 = bad key.
            resp = requests.get(
                "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1/",
                headers={"Auth-Key": key},
                timeout=8
            )
            if resp.status_code == 200:
                return jsonify({"valid": True, "service": service})
            return jsonify({"valid": False, "error": f"Status {resp.status_code}"})

        elif service == "virustotal":
            resp = requests.get(
                "https://www.virustotal.com/api/v3/users/me",
                headers={"x-apikey": key},
                timeout=8
            )
            if resp.status_code == 200:
                return jsonify({"valid": True, "service": service})
            return jsonify({"valid": False, "error": f"Status {resp.status_code}"})

        else:
            return jsonify({"valid": False, "error": "Unknown service"}), 400

    except Exception as e:
        return jsonify({"valid": False, "error": str(e)})


# Get all threat indicators (with optional filters)
@app.route("/api/threats")
def get_threats():
    conn   = get_connection()
    cursor = conn.cursor()

    indicator_type = request.args.get("type")
    source         = request.args.get("source")
    active         = request.args.get("active")
    limit          = request.args.get("limit")

    query  = "SELECT * FROM threat_indicators WHERE 1=1"
    params = []

    if indicator_type:
        query += " AND indicator_type = ?"
        params.append(indicator_type)
    if source:
        query += " AND source = ?"
        params.append(source)
    if active:
        query += " AND is_active = ?"
        params.append(int(active))

    query += " ORDER BY threat_score DESC"
    if limit is not None:
        query += " LIMIT ?"
        params.append(int(limit))

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    threats = []
    for row in rows:
        item = dict(row)
        try:
            item["tags"] = json.loads(item["tags"] or "[]")
        except:
            item["tags"] = []
        threats.append(item)

    return jsonify({"count": len(threats), "threats": threats})


# Summary stats for the dashboard charts
@app.route("/api/stats")
def get_stats():
    conn   = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM threat_indicators")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM threat_indicators WHERE is_active = 1")
    active = cursor.fetchone()[0]

    cursor.execute("""
        SELECT source, COUNT(*) as count
        FROM threat_indicators
        GROUP BY source
    """)
    by_source = {row[0]: row[1] for row in cursor.fetchall()}

    cursor.execute("""
        SELECT indicator_type, COUNT(*) as count
        FROM threat_indicators
        GROUP BY indicator_type
    """)
    by_type = {row[0]: row[1] for row in cursor.fetchall()}

    cursor.execute("""
        SELECT threat_score, COUNT(*) as count
        FROM threat_indicators
        GROUP BY threat_score
        ORDER BY threat_score DESC
    """)
    by_score = [{"score": row[0], "count": row[1]} for row in cursor.fetchall()]

    conn.close()

    return jsonify({
        "total":     total,
        "active":    active,
        "by_source": by_source,
        "by_type":   by_type,
        "by_score":  by_score
    })


# Helper: detect what type of indicator was entered
def detect_indicator_type(value):
    # Four groups of numbers separated by dots = IP address
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
        return 'ip'
    # Starts with http:// or https:// = URL
    if value.startswith('http://') or value.startswith('https://'):
        return 'url'
    # Contains a dot but no slashes = domain name
    if '.' in value and '/' not in value:
        return 'domain'
    # 32-char hex = MD5 hash, 64-char hex = SHA256 hash
    if re.match(r'^[a-fA-F0-9]{32}$', value) or re.match(r'^[a-fA-F0-9]{64}$', value):
        return 'hash'
    return 'unknown'


# Live lookup from AbuseIPDB (IP addresses only)
def live_lookup_abuseipdb(ip, api_key):
    try:
        headers  = {"Key": api_key, "Accept": "application/json"}
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=8
        )
        data = response.json().get("data", {})
        return {
            "source":           "AbuseIPDB (live)",
            "confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports":    data.get("totalReports", 0),
            "country":          data.get("countryCode", "Unknown"),
            "isp":              data.get("isp", "Unknown"),
            "domain":           data.get("domain", ""),
            "last_reported":    data.get("lastReportedAt", "Never"),
            "is_whitelisted":   data.get("isWhitelisted", False),
            "usage_type":       data.get("usageType", "Unknown")
        }
    except Exception as e:
        return {"source": "AbuseIPDB (live)", "error": str(e)}


# Live lookup from AlienVault OTX
def live_lookup_otx(value, indicator_type, api_key):
    try:
        headers  = {"X-OTX-API-KEY": api_key}
        # OTX uses different path segments depending on the indicator type
        type_map = {"ip": "IPv4", "domain": "domain", "url": "url", "hash": "file"}
        otx_type = type_map.get(indicator_type, "IPv4")

        response = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{value}/general",
            headers=headers,
            timeout=8
        )
        data = response.json()

        pulse_info  = data.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)
        pulses      = pulse_info.get("pulses", [])

        # Summarise the top 5 most relevant threat reports mentioning this indicator
        pulse_summaries = []
        for p in pulses[:5]:
            pulse_summaries.append({
                "name":    p.get("name", "Unnamed"),
                "tags":    p.get("tags", []),
                "created": p.get("created", "")
            })

        return {
            "source":         "AlienVault OTX (live)",
            "pulse_count":    pulse_count,
            "pulses":         pulse_summaries,
            "reputation":     data.get("reputation", 0),
            "indicator_type": otx_type
        }
    except Exception as e:
        return {"source": "AlienVault OTX (live)", "error": str(e)}


# Live lookup from crt.sh (Certificate Transparency)
def live_lookup_crtsh(domain):
    """Query crt.sh with retry - the service is chronically overloaded and
    returns 502/504/timeouts roughly 30-50% of the time. Three attempts with
    backoff recovers from most transient failures."""
    last_err = None
    headers = {
        # crt.sh occasionally rejects requests with no User-Agent.
        "User-Agent": "OSINT-Dashboard/1.0",
        "Accept":     "application/json",
    }
    for attempt in range(3):
        try:
            response = requests.get(
                f"https://crt.sh/?q={domain}&output=json",
                headers=headers,
                timeout=20,
            )
            if response.status_code == 200:
                certs = response.json()
                subdomains = set()
                issuers = set()
                for cert in certs:
                    name = cert.get("name_value", "")
                    for line in name.split("\n"):
                        line = line.strip().lower()
                        if line and not line.startswith("*"):
                            subdomains.add(line)
                    issuer = cert.get("issuer_name", "")
                    if issuer:
                        for part in issuer.split(","):
                            if "CN=" in part:
                                issuers.add(part.split("CN=")[-1].strip())
                                break
                return {
                    "source":           "crt.sh",
                    "total_certs":      len(certs),
                    "subdomain_count":  len(subdomains),
                    "subdomains":       sorted(list(subdomains))[:20],
                    "issuers":          sorted(list(issuers))[:10],
                }
            # Retry on 5xx; bail on 4xx (client error, not transient).
            last_err = f"Status {response.status_code}"
            if response.status_code < 500:
                break
        except requests.exceptions.Timeout:
            last_err = "Timeout (crt.sh is slow or overloaded)"
        except requests.exceptions.RequestException as e:
            last_err = str(e)[:120]
        if attempt < 2:
            time.sleep(2 * (attempt + 1))  # 2s, then 4s
    return {"source": "crt.sh", "error": last_err or "Unknown error"}


# Live WHOIS lookup (domains only)
def live_lookup_whois(domain):
    try:
        import whois
        w = whois.whois(domain)
        # Handle dates that may be lists
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        expiration = w.expiration_date
        if isinstance(expiration, list):
            expiration = expiration[0]
        # Handle nameservers
        ns = w.name_servers
        if isinstance(ns, set):
            ns = sorted(list(ns))
        elif isinstance(ns, list):
            ns = sorted(ns)
        else:
            ns = [ns] if ns else []
        return {
            "source":          "WHOIS",
            "registrar":       w.registrar or "Unknown",
            "creation_date":   str(creation) if creation else "Unknown",
            "expiration_date": str(expiration) if expiration else "Unknown",
            "name_servers":    [s.lower() for s in ns[:6]],
            "status":          w.status[:3] if isinstance(w.status, list) else ([w.status] if w.status else []),
            "registrant":      w.org or w.name or "Redacted"
        }
    except Exception as e:
        return {"source": "WHOIS", "error": str(e)}


# Live Shodan lookup (IPs only)
def live_lookup_shodan(ip, api_key):
    try:
        response = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}?key={api_key}",
            timeout=10
        )
        if response.status_code == 404:
            return {"source": "Shodan", "error": "No information available for this IP"}
        if response.status_code != 200:
            return {"source": "Shodan", "error": f"Status {response.status_code}"}
        data = response.json()
        # Extract services from data array
        services = []
        for item in data.get("data", [])[:10]:
            services.append({
                "port":    item.get("port"),
                "product": item.get("product", "Unknown"),
                "version": item.get("version", ""),
            })
        return {
            "source":       "Shodan",
            "ports":        data.get("ports", []),
            "os":           data.get("os") or "Unknown",
            "org":          data.get("org") or "Unknown",
            "isp":          data.get("isp") or "Unknown",
            "vulns":        list(data.get("vulns", {}).keys()) if data.get("vulns") else [],
            "services":     services,
            "last_update":  data.get("last_update", "Unknown"),
            "city":         data.get("city") or "Unknown",
            "country_name": data.get("country_name") or "Unknown"
        }
    except Exception as e:
        return {"source": "Shodan", "error": str(e)}


# Live SecurityTrails lookup (domains only)
def live_lookup_securitytrails(domain, api_key):
    try:
        response = requests.get(
            f"https://api.securitytrails.com/v1/domain/{domain}",
            headers={"APIKEY": api_key},
            timeout=10
        )
        if response.status_code != 200:
            return {"source": "SecurityTrails", "error": f"Status {response.status_code}"}
        data = response.json()
        dns = data.get("current_dns", {})
        # Extract records
        a_records  = [r.get("ip", "") for r in dns.get("a", {}).get("values", [])]
        mx_records = [r.get("hostname", "") for r in dns.get("mx", {}).get("values", [])]
        ns_records = [r.get("nameserver", "") for r in dns.get("ns", {}).get("values", [])]
        # Get subdomain count
        sub_resp = requests.get(
            f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
            headers={"APIKEY": api_key},
            timeout=10
        )
        subdomain_count = 0
        subdomains = []
        if sub_resp.status_code == 200:
            sub_data = sub_resp.json()
            subdomains = sub_data.get("subdomains", [])[:15]
            subdomain_count = len(sub_data.get("subdomains", []))
        return {
            "source":          "SecurityTrails",
            "a_records":       a_records[:5],
            "mx_records":      mx_records[:5],
            "ns_records":      ns_records[:5],
            "subdomain_count": subdomain_count,
            "subdomains":      subdomains,
            "alexa_rank":      data.get("alexa_rank") or "Unranked"
        }
    except Exception as e:
        return {"source": "SecurityTrails", "error": str(e)}


# Live IntelligenceX lookup (all types)
def live_lookup_intelx(value, api_key):
    try:
        headers = {"x-key": api_key}
        # Step 1: start search
        search_resp = requests.post(
            "https://free.intelx.io/intelligent/search",
            headers=headers,
            json={"term": value, "maxresults": 10, "media": 0, "timeout": 5},
            timeout=15
        )
        if search_resp.status_code != 200:
            return {"source": "IntelligenceX", "error": f"Search failed: {search_resp.status_code}"}
        search_id = search_resp.json().get("id")
        if not search_id:
            return {"source": "IntelligenceX", "error": "No search ID returned"}
        # Step 2: fetch results (wait a moment for indexing)
        time.sleep(2)
        result_resp = requests.get(
            f"https://free.intelx.io/intelligent/search/result?id={search_id}",
            headers=headers,
            timeout=15
        )
        if result_resp.status_code != 200:
            return {"source": "IntelligenceX", "error": f"Results failed: {result_resp.status_code}"}
        data = result_resp.json()
        records = data.get("records", [])
        # Categorise by source type
        source_types = {}
        previews = []
        for r in records[:10]:
            bucket = r.get("bucket", "unknown")
            source_types[bucket] = source_types.get(bucket, 0) + 1
            previews.append({
                "name":   r.get("name", "Untitled"),
                "date":   r.get("date", ""),
                "bucket": bucket,
                "media":  r.get("mediah", "")
            })
        return {
            "source":        "IntelligenceX",
            "total_results": data.get("count", len(records)),
            "source_types":  source_types,
            "previews":      previews[:5]
        }
    except Exception as e:
        return {"source": "IntelligenceX", "error": str(e)}


# Enhanced lookup: local database + live APIs
@app.route("/api/lookup")
def lookup_indicator():
    value = request.args.get("value", "").strip()

    if not value:
        return jsonify({"error": "No value provided"}), 400

    # Work out what type of thing the user has searched for
    indicator_type = detect_indicator_type(value)

    # Step 1: search our local stored database first
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM threat_indicators
        WHERE indicator_value LIKE ?
        ORDER BY threat_score DESC
    """, (f"%{value}%",))
    rows = cursor.fetchall()
    conn.close()

    local_results = []
    for row in rows:
        item = dict(row)
        try:
            item["tags"] = json.loads(item["tags"] or "[]")
        except:
            item["tags"] = []
        local_results.append(item)

    # Step 2: query the live APIs in real time based on indicator type
    live_results = {}

    abuse_key    = get_key("abuseipdb")
    otx_key      = get_key("otx")
    shodan_key   = get_key("shodan")
    sectrails_key = get_key("securitytrails")
    intelx_key   = get_key("intelx")

    if indicator_type == "ip":
        live_results["abuseipdb"] = live_lookup_abuseipdb(value, abuse_key)
        live_results["otx"]       = live_lookup_otx(value, "ip", otx_key)
        if shodan_key:
            live_results["shodan"] = live_lookup_shodan(value, shodan_key)
    elif indicator_type in ("domain", "url"):
        live_results["otx"] = live_lookup_otx(value, indicator_type, otx_key)
        # crt.sh and WHOIS work best with plain domain names
        lookup_domain = value
        if indicator_type == "url":
            from urllib.parse import urlparse
            lookup_domain = urlparse(value).hostname or value
        live_results["crtsh"] = live_lookup_crtsh(lookup_domain)
        live_results["whois"] = live_lookup_whois(lookup_domain)
        if sectrails_key:
            live_results["securitytrails"] = live_lookup_securitytrails(lookup_domain, sectrails_key)
    elif indicator_type == "hash":
        live_results["otx"] = live_lookup_otx(value, "hash", otx_key)

    # IntelligenceX works for all indicator types
    if intelx_key:
        live_results["intelx"] = live_lookup_intelx(value, intelx_key)

    # Resolve domain/URL to IP so Protect can generate IP-based firewall rules
    resolved_ip = None
    if indicator_type in ("domain", "url"):
        try:
            import socket
            resolve_target = value
            if indicator_type == "url":
                from urllib.parse import urlparse
                resolve_target = urlparse(value).hostname or value
            resolved_ip = socket.gethostbyname(resolve_target)
        except:
            pass

    return jsonify({
        "query":          value,
        "indicator_type": indicator_type,
        "found":          len(local_results) > 0,
        "count":          len(local_results),
        "results":        local_results,
        "live":           live_results,
        "resolved_ip":    resolved_ip
    })


# AI Threat Summary (Gemini-powered)
@app.route("/api/ai-summary", methods=["POST"])
def ai_summary():
    conn   = get_connection()
    cursor = conn.cursor()

    # Gather current threat landscape data
    cursor.execute("SELECT COUNT(*) FROM threat_indicators")
    total = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM threat_indicators WHERE is_active = 1")
    active = cursor.fetchone()[0]

    cursor.execute("""
        SELECT source, COUNT(*) as count
        FROM threat_indicators GROUP BY source
    """)
    by_source = {row[0]: row[1] for row in cursor.fetchall()}

    cursor.execute("""
        SELECT indicator_type, COUNT(*) as count
        FROM threat_indicators GROUP BY indicator_type
    """)
    by_type = {row[0]: row[1] for row in cursor.fetchall()}

    # Top 15 highest-scoring threats with details
    cursor.execute("""
        SELECT indicator_value, indicator_type, source, threat_score,
               tags, description, is_active, country
        FROM threat_indicators
        ORDER BY threat_score DESC LIMIT 15
    """)
    top_threats = []
    for row in cursor.fetchall():
        item = dict(row)
        try:
            item["tags"] = json.loads(item["tags"] or "[]")
        except:
            item["tags"] = []
        top_threats.append(item)

    # Recent activity
    cursor.execute("""
        SELECT indicator_value, indicator_type, source, threat_score
        FROM threat_indicators
        ORDER BY last_seen DESC LIMIT 10
    """)
    recent = [dict(row) for row in cursor.fetchall()]
    conn.close()

    threat_data = {
        "total_indicators": total,
        "active_threats": active,
        "by_source": by_source,
        "by_type": by_type,
        "top_threats": top_threats,
        "recent_activity": recent
    }

    prompt = f"""You are a cybersecurity analyst writing a threat intelligence briefing for a non-technical audience. Based on the following threat data from our OSINT dashboard, write a clear, actionable summary.

THREAT DATA:
{json.dumps(threat_data, indent=2)}

Write your response in this exact structure:
1. **Threat Landscape Overview** (2-3 sentences: what's the overall picture?)
2. **Key Findings** (3-5 bullet points: what are the most important threats and why?)
3. **Risk Assessment** (1-2 sentences: how serious is this overall?)
4. **Recommended Actions** (3-4 bullet points: what should someone do about this?)

Keep the language simple - a manager or student should understand every sentence. Be specific about the threats you see in the data. Use plain English, not jargon."""

    try:
        result = ai_generate(prompt)
        return jsonify({
            "summary": result["text"],
            "provider": result["provider"],
            "threat_data": threat_data
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Have I Been Pwned - email breach lookup
@app.route("/api/breach-lookup")
def breach_lookup():
    email = request.args.get("email", "").strip()
    if not email:
        return jsonify({"error": "No email provided"}), 400

    # Basic email format check
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return jsonify({"error": "Invalid email format"}), 400

    results = {"email": email, "breaches": [], "pastes": [], "hibp_error": None}

    # Check HIBP (paid key required - non-fatal if missing/invalid)
    hibp_key = get_key("hibp")
    if hibp_key and hibp_key != "your-hibp-api-key-here":
        headers = {
            "hibp-api-key": hibp_key,
            "user-agent": "OSINT-Dashboard"
        }
        try:
            resp = requests.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers=headers,
                params={"truncateResponse": "false"},
                timeout=10
            )
            if resp.status_code == 200:
                results["breaches"] = resp.json()
            elif resp.status_code == 401:
                results["hibp_error"] = "HIBP API key invalid"
            elif resp.status_code == 429:
                results["hibp_error"] = "HIBP rate limited"
        except Exception as e:
            results["hibp_error"] = str(e)

        # Check pastes
        try:
            resp = requests.get(
                f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}",
                headers=headers,
                timeout=10
            )
            if resp.status_code == 200:
                results["pastes"] = resp.json()
        except:
            pass
    else:
        results["hibp_error"] = "No HIBP key configured (paid API - $3.50/month)"

    results["total_breaches"] = len(results["breaches"])
    results["total_pastes"]   = len(results["pastes"])

    # XposedOrNot (free, no key needed)
    xon_result = {"breaches": [], "error": None}
    try:
        resp = requests.get(
            f"https://api.xposedornot.com/v1/check-email/{email}",
            timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()
            if "breaches" in data and isinstance(data["breaches"], list):
                xon_result["breaches"] = data["breaches"]
            elif "breaches" in data and isinstance(data["breaches"], dict):
                # API sometimes returns {"breaches": {"domain": [...]}}
                for domain, details in data["breaches"].items():
                    if isinstance(details, list):
                        xon_result["breaches"].extend(details)
                    else:
                        xon_result["breaches"].append({"domain": domain, "details": details})
        # 404 = not found, which is fine
    except Exception as e:
        xon_result["error"] = str(e)
    results["xposedornot"] = xon_result

    # EmailRep (free, no key, 100 requests/day)
    emailrep_result = {"error": None}
    try:
        resp = requests.get(
            f"https://emailrep.io/{email}",
            headers={"User-Agent": "OSINT-Dashboard"},
            timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()
            emailrep_result["reputation"] = data.get("reputation", "unknown")
            emailrep_result["suspicious"] = data.get("suspicious", False)
            emailrep_result["references"] = data.get("references", 0)
            details = data.get("details", {})
            emailrep_result["credentials_leaked"] = details.get("credentials_leaked", False)
            emailrep_result["data_breach"] = details.get("data_breach", False)
            emailrep_result["malicious_activity"] = details.get("malicious_activity", False)
            emailrep_result["profiles"] = details.get("profiles", [])
            emailrep_result["domain_exists"] = details.get("domain_exists", None)
            emailrep_result["deliverable"] = details.get("deliverable", None)
            emailrep_result["spam"] = details.get("spam", False)
        elif resp.status_code == 429:
            emailrep_result["error"] = "Rate limited (100/day)"
    except Exception as e:
        emailrep_result["error"] = str(e)
    results["emailrep"] = emailrep_result

    return jsonify(results)


# Template-based Snort / YARA rule generation
def generate_template_rules(indicator_value, indicator_type, threat_score, tags, source, description):
    """Generate Snort and YARA rules from templates - instant, no AI needed."""
    from datetime import date
    import hashlib
    import re as _re

    today = date.today().isoformat()
    safe_name = _re.sub(r'[^a-zA-Z0-9]', '_', indicator_value)[:40]
    sid = int(hashlib.md5(indicator_value.encode()).hexdigest()[:6], 16)
    if threat_score >= 75:
        severity, priority = "critical", 1
    elif threat_score >= 50:
        severity, priority = "high", 2
    elif threat_score >= 25:
        severity, priority = "medium", 3
    else:
        severity, priority = "low", 4
    tags_str = ", ".join(tags[:5]) if tags else "none"

    # Snort rule
    if indicator_type == "ip":
        snort = (
            f'alert ip any any -> {indicator_value} any '
            f'(msg:"OSINT Alert - Malicious IP {indicator_value} [{source}]"; '
            f'sid:{sid}; rev:1; classtype:trojan-activity; '
            f'metadata:severity {severity}, source {source}; '
            f'reference:url,{source}; priority:{priority};)'
        )
    elif indicator_type == "domain":
        snort = (
            f'alert dns any any -> any any '
            f'(msg:"OSINT Alert - Malicious Domain {indicator_value} [{source}]"; '
            f'content:"{indicator_value}"; nocase; '
            f'sid:{sid}; rev:1; classtype:trojan-activity; '
            f'metadata:severity {severity}, source {source}; priority:{priority};)'
        )
    elif indicator_type == "url":
        from urllib.parse import urlparse
        parsed = urlparse(indicator_value)
        host = parsed.hostname or indicator_value
        path = parsed.path or "/"
        snort = (
            f'alert http any any -> any any '
            f'(msg:"OSINT Alert - Malicious URL [{source}]"; '
            f'content:"{host}"; http_header; nocase; '
            f'content:"{path}"; http_uri; nocase; '
            f'sid:{sid}; rev:1; classtype:trojan-activity; '
            f'metadata:severity {severity}, source {source}; priority:{priority};)'
        )
    elif indicator_type == "hash":
        hash_type = "md5" if len(indicator_value) == 32 else "sha256" if len(indicator_value) == 64 else "sha1"
        snort = (
            f'alert any any any -> any any '
            f'(msg:"OSINT Alert - Malicious File Hash [{source}]"; '
            f'content:"{indicator_value}"; nocase; '
            f'sid:{sid}; rev:1; classtype:trojan-activity; '
            f'metadata:severity {severity}, hash_type {hash_type}, source {source};)'
        )
    else:
        snort = (
            f'alert ip any any -> any any '
            f'(msg:"OSINT Alert - Suspicious Indicator [{source}]"; '
            f'content:"{indicator_value}"; nocase; '
            f'sid:{sid}; rev:1; classtype:trojan-activity;)'
        )

    # YARA rule
    if indicator_type == "hash":
        hash_type = "md5" if len(indicator_value) == 32 else "sha256" if len(indicator_value) == 64 else "sha1"
        yara_condition = f"        {hash_type}.digest(0, filesize) == \"{indicator_value.lower()}\""
        yara_import = f'import "{hash_type}"\n\n'
        yara_strings = ""
    else:
        yara_import = ""
        yara_strings = f'    strings:\n        $indicator = "{indicator_value}" ascii wide nocase\n\n'
        yara_condition = "        $indicator"

    yara = (
        f'{yara_import}'
        f'rule OSINT_{safe_name} {{\n'
        f'    meta:\n'
        f'        author = "OSINT Dashboard"\n'
        f'        description = "Detection for {indicator_type}: {indicator_value}"\n'
        f'        source = "{source}"\n'
        f'        date = "{today}"\n'
        f'        threat_score = "{threat_score}"\n'
        f'        severity = "{severity}"\n'
        f'        tags = "{tags_str}"\n'
        f'        reference = "{description[:100]}"\n\n'
        f'{yara_strings}'
        f'    condition:\n'
        f'{yara_condition}\n'
        f'}}'
    )

    # Firewall recommendation
    if indicator_type == "ip":
        firewall = f"Block all inbound and outbound traffic to/from {indicator_value} on your firewall. Add to your network blocklist immediately."
    elif indicator_type == "domain":
        firewall = f"Add {indicator_value} to your DNS sinkhole or blocklist. Block DNS resolution for this domain at your DNS resolver."
    elif indicator_type == "url":
        firewall = f"Block this URL at your web proxy or content filter. Add the domain to your DNS blocklist as well."
    elif indicator_type == "hash":
        firewall = f"Add this hash to your endpoint detection tool's blocklist. Quarantine any files matching this hash."
    else:
        firewall = f"Block this indicator at your network perimeter and monitor for related activity."

    return {
        "snort": snort,
        "yara": yara,
        "firewall": firewall,
        "indicator": indicator_value,
        "indicator_type": indicator_type,
        "severity": severity,
        "generated_at": today
    }


@app.route("/api/template-rules", methods=["POST"])
def template_rules():
    data = request.get_json()
    if not data or not data.get("indicator_value"):
        return jsonify({"error": "No indicator provided"}), 400

    result = generate_template_rules(
        indicator_value=data["indicator_value"],
        indicator_type=data.get("indicator_type", "unknown"),
        threat_score=data.get("threat_score", 0),
        tags=data.get("tags", []),
        source=data.get("source", "unknown"),
        description=data.get("description", "")
    )
    return jsonify(result)


# Snort / YARA rule generation (Gemini-powered)
@app.route("/api/generate-rules", methods=["POST"])
def generate_rules():
    data = request.get_json()
    if not data or not data.get("indicator_value"):
        return jsonify({"error": "No indicator provided"}), 400

    indicator_value = data["indicator_value"]
    indicator_type  = data.get("indicator_type", "unknown")
    threat_score    = data.get("threat_score", 0)
    tags            = data.get("tags", [])
    source          = data.get("source", "unknown")
    description     = data.get("description", "")

    prompt = f"""You are a cybersecurity engineer. Generate detection rules for the following threat indicator.

INDICATOR DETAILS:
- Value: {indicator_value}
- Type: {indicator_type}
- Threat Score: {threat_score}/100
- Source: {source}
- Tags: {json.dumps(tags)}
- Description: {description}

Generate the following:

1. **Snort Rule** - A valid Snort IDS rule that would detect network traffic involving this indicator. Include the rule header (action, protocol, source, destination, ports) and rule options (msg, content, sid, rev, classtype). Use appropriate protocol and content matching for the indicator type.

2. **YARA Rule** - A valid YARA rule that would detect this indicator in files or memory. Include the rule name, meta section (author, description, date, threat_level), strings section, and condition.

3. **Firewall Recommendation** - A brief, specific recommendation for blocking this indicator at the network perimeter (1-2 sentences).

4. **Additional Security Measures** - 2-3 specific, actionable security recommendations related to this type of threat.

Make the rules practical and ready to deploy. Use proper syntax that would pass validation."""

    try:
        result = ai_generate(prompt)
        return jsonify({
            "indicator": indicator_value,
            "indicator_type": indicator_type,
            "rules": result["text"],
            "provider": result["provider"]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Alerting: new high-score indicators since last check
@app.route("/api/alerts")
def get_alerts():
    since = request.args.get("since", "")
    min_score = int(request.args.get("min_score", 30))

    conn = get_connection()
    cursor = conn.cursor()

    if since:
        cursor.execute("""
            SELECT id, indicator_value, indicator_type, source, threat_score,
                   tags, description, first_seen
            FROM threat_indicators
            WHERE threat_score >= ? AND first_seen > ?
            ORDER BY threat_score DESC
            LIMIT 50
        """, (min_score, since))
    else:
        # Default: last 24 hours
        cursor.execute("""
            SELECT id, indicator_value, indicator_type, source, threat_score,
                   tags, description, first_seen
            FROM threat_indicators
            WHERE threat_score >= ? AND first_seen > datetime('now', '-1 day')
            ORDER BY threat_score DESC
            LIMIT 50
        """, (min_score,))

    rows = cursor.fetchall()
    conn.close()

    alerts = []
    for row in rows:
        item = dict(row)
        try:
            item["tags"] = json.loads(item["tags"] or "[]")
        except:
            item["tags"] = []
        alerts.append(item)

    return jsonify({"alerts": alerts, "count": len(alerts)})


# DNS resolve: get IP address for a domain
@app.route("/api/resolve")
def resolve_domain():
    domain = request.args.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "No domain provided"}), 400
    try:
        import socket
        ip = socket.gethostbyname(domain)
        return jsonify({"domain": domain, "ip": ip})
    except Exception as e:
        return jsonify({"domain": domain, "ip": None, "error": str(e)})


# Bulk protect: generate combined rules for a time period
@app.route("/api/bulk-protect", methods=["POST"])
def bulk_protect():
    data = request.get_json() or {}
    period = data.get("period", "1day")  # 12hr, 1day, 1week, 1month, all
    use_ai = data.get("use_ai", False)
    min_score = data.get("min_score", 0)

    period_map = {
        "12hr":   "-12 hours",
        "1day":   "-1 day",
        "1week":  "-7 days",
        "1month": "-30 days",
        "all":    None
    }
    sql_period = period_map.get(period, "-1 day")

    conn = get_connection()
    cursor = conn.cursor()

    if sql_period:
        cursor.execute("""
            SELECT indicator_value, indicator_type, source, threat_score, tags, description
            FROM threat_indicators
            WHERE first_seen > datetime('now', ?) AND threat_score >= ?
            ORDER BY threat_score DESC
        """, (sql_period, min_score))
    else:
        cursor.execute("""
            SELECT indicator_value, indicator_type, source, threat_score, tags, description
            FROM threat_indicators
            WHERE threat_score >= ?
            ORDER BY threat_score DESC
        """, (min_score,))

    rows = cursor.fetchall()
    conn.close()

    if not rows:
        return jsonify({"error": "No indicators found for this period"}), 404

    indicators = []
    for row in rows:
        item = dict(row)
        try:
            item["tags"] = json.loads(item["tags"] or "[]")
        except:
            item["tags"] = []
        indicators.append(item)

    # AI mode: send to AI for a comprehensive script
    if use_ai:
        summary_lines = []
        for ind in indicators[:50]:
            summary_lines.append(
                f"- {ind['indicator_type']}: {ind['indicator_value']} "
                f"(score: {ind['threat_score']}, source: {ind['source']})"
            )
        indicator_list = "\n".join(summary_lines)

        prompt = f"""You are a cybersecurity engineer. Generate a COMPLETE, ready-to-deploy protection script for the following {len(indicators)} threat indicators.

INDICATORS:
{indicator_list}

Generate:
1. A combined Snort rules file (all rules in one block, each with unique SID)
2. A combined YARA rules file (all rules in one block)
3. A firewall blocklist script (iptables commands for IPs, DNS sinkhole entries for domains)
4. A CSV blocklist that can be imported into any firewall/SIEM

Make it production-ready. Group by indicator type. Include comments."""

        try:
            result = ai_generate(prompt)
            return jsonify({
                "mode": "ai",
                "provider": result["provider"],
                "indicator_count": len(indicators),
                "period": period,
                "script": result["text"]
            })
        except Exception as e:
            return jsonify({"error": f"AI generation failed: {str(e)}"}), 500

    # Template mode: generate rules programmatically
    snort_rules = []
    yara_rules = []
    firewall_cmds = []
    csv_lines = ["indicator,type,source,score,action"]

    ips_seen = set()
    domains_seen = set()

    for ind in indicators:
        rules = generate_template_rules(
            indicator_value=ind["indicator_value"],
            indicator_type=ind["indicator_type"],
            threat_score=ind["threat_score"],
            tags=ind["tags"],
            source=ind["source"],
            description=ind.get("description", "")
        )
        snort_rules.append(rules["snort"])
        yara_rules.append(rules["yara"])
        csv_lines.append(
            f'{ind["indicator_value"]},{ind["indicator_type"]},{ind["source"]},{ind["threat_score"]},block'
        )

        if ind["indicator_type"] == "ip" and ind["indicator_value"] not in ips_seen:
            ips_seen.add(ind["indicator_value"])
            firewall_cmds.append(f'iptables -A INPUT -s {ind["indicator_value"]} -j DROP')
            firewall_cmds.append(f'iptables -A OUTPUT -d {ind["indicator_value"]} -j DROP')
        elif ind["indicator_type"] == "domain" and ind["indicator_value"] not in domains_seen:
            domains_seen.add(ind["indicator_value"])
            firewall_cmds.append(f'# DNS sinkhole: {ind["indicator_value"]}')
            firewall_cmds.append(f'echo "127.0.0.1 {ind["indicator_value"]}" >> /etc/hosts')

    script = f"""#
# OSINT Dashboard - Bulk Protection Script
# Generated: {datetime.now().isoformat()}
# Period: {period} | Indicators: {len(indicators)} | Min score: {min_score}
#

# SECTION 1: SNORT IDS RULES
# Save as: /etc/snort/rules/osint-threats.rules
# Add to snort.conf: include $RULE_PATH/osint-threats.rules

{chr(10).join(snort_rules)}

# SECTION 2: FIREWALL COMMANDS
# Run as root. For iptables-based firewalls.
# {len(ips_seen)} unique IPs, {len(domains_seen)} unique domains

{chr(10).join(firewall_cmds) if firewall_cmds else "# No IP or domain indicators in this period."}

# SECTION 3: CSV BLOCKLIST
# Import into your SIEM, firewall, or threat intelligence platform.

{chr(10).join(csv_lines)}
"""

    yara_combined = f"""// OSINT Dashboard - Combined YARA Rules
// Generated: {datetime.now().isoformat()}
// Indicators: {len(indicators)}

{chr(10).join(yara_rules)}
"""

    return jsonify({
        "mode": "template",
        "indicator_count": len(indicators),
        "period": period,
        "script": script,
        "yara": yara_combined,
        "stats": {
            "unique_ips": len(ips_seen),
            "unique_domains": len(domains_seen),
            "snort_rules": len(snort_rules),
            "yara_rules": len(yara_rules)
        }
    })


# Auto-collect: runs on startup + every 12 hours
def auto_collect_loop():
    import threading
    from collector import fetch_urlhaus, fetch_abuseipdb, fetch_otx, fetch_virustotal
    from processor import process_indicators

    def run_collect():
        try:
            print(f"\n[Auto-collect] Running at {datetime.now().isoformat()}")
            fetch_urlhaus()
            fetch_abuseipdb()
            fetch_otx()
            fetch_virustotal()
            process_indicators()
            print("[Auto-collect] Done.")
        except Exception as e:
            print(f"[Auto-collect] Error: {e}")

    def loop():
        # Collect immediately on startup
        run_collect()
        # Then every 12 hours
        while True:
            time.sleep(12 * 3600)
            run_collect()

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    print("[Auto-collect] Will collect now, then every 12 hours.")


from datetime import datetime

if __name__ == "__main__":
    auto_collect_loop()
    # Bind 0.0.0.0 and the host-provided $PORT so the service is reachable.
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
