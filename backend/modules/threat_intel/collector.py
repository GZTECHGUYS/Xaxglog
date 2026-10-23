import requests
import json
import sqlite3
from database import get_connection
from datetime import datetime
from dotenv import load_dotenv
from cryptography.fernet import Fernet
import os

load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))


# Key resolution
# The collector runs in a background thread without a Flask request
# context, so it can't call get_key(). It looks up the latest UI-saved
# key for each service directly, falling back to the env var. The dash
# is single-user, so "any saved key for this service" is unambiguous.

_KEYS_DB         = os.path.join(os.path.dirname(__file__), 'user_keys.db')
_FERNET_KEY_FILE = os.path.join(os.path.dirname(__file__), '.encryption_key')


def _load_fernet():
    if not os.path.exists(_FERNET_KEY_FILE):
        return None
    with open(_FERNET_KEY_FILE, 'rb') as f:
        return Fernet(f.read())


def _saved_key(service):
    if not os.path.exists(_KEYS_DB):
        return None
    fernet = _load_fernet()
    if fernet is None:
        return None
    try:
        conn = sqlite3.connect(_KEYS_DB)
        row = conn.execute(
            "SELECT encrypted_key FROM user_keys WHERE service = ? LIMIT 1",
            (service,),
        ).fetchone()
        conn.close()
        if row:
            return fernet.decrypt(row[0].encode()).decode()
    except Exception:
        return None
    return None


def resolve_key(service, env_var):
    """UI-saved key wins over .env so users can rotate keys from the dashboard."""
    return _saved_key(service) or os.getenv(env_var)


# URLhaus
def fetch_urlhaus():
    print("Fetching from URLhaus...")
    headers  = {"Auth-Key": resolve_key("urlhaus", "URLHAUS_API_KEY")}
    response = requests.get(
        "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/",
        headers=headers
    )
    data = response.json()

    if "urls" not in data or not data["urls"]:
        print(f"URLhaus: no data. Response: {data}")
        return

    conn   = get_connection()
    cursor = conn.cursor()
    count  = 0

    for entry in data["urls"]:
        raw_value = entry.get("url", "")
        if not raw_value:
            continue

        cursor.execute(
            "INSERT INTO raw_indicators (source, raw_value, raw_json) VALUES (?,?,?)",
            ("urlhaus", raw_value, json.dumps(entry))
        )
        raw_id = cursor.lastrowid
        tags   = entry.get("tags") or []

        cursor.execute("""
            INSERT INTO threat_indicators
            (raw_id, indicator_value, indicator_type, source, tags,
             threat_score, description, first_seen, last_seen, is_active)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (
            raw_id, raw_value, "url", "urlhaus", json.dumps(tags),
            0,  # processor will score this
            entry.get("threat", ""),
            entry.get("date_added", datetime.now().isoformat()),
            datetime.now().isoformat(),
            1 if entry.get("url_status") == "online" else 0
        ))
        count += 1

    conn.commit()
    conn.close()
    print(f"URLhaus: {count} indicators saved.")


# AbuseIPDB
def fetch_abuseipdb():
    print("Fetching from AbuseIPDB...")
    headers = {
        "Key":    resolve_key("abuseipdb", "ABUSEIPDB_API_KEY"),
        "Accept": "application/json"
    }
    # blacklist endpoint returns the top 1000 most-reported IPs
    params   = {"confidenceMinimum": 90, "limit": 100}
    response = requests.get(
        "https://api.abuseipdb.com/api/v2/blacklist",
        headers=headers,
        params=params
    )
    data = response.json()

    if "data" not in data:
        print(f"AbuseIPDB: no data. Response: {data}")
        return

    conn   = get_connection()
    cursor = conn.cursor()
    count  = 0

    for entry in data["data"]:
        ip = entry.get("ipAddress", "")
        if not ip:
            continue

        cursor.execute(
            "INSERT INTO raw_indicators (source, raw_value, raw_json) VALUES (?,?,?)",
            ("abuseipdb", ip, json.dumps(entry))
        )
        raw_id = cursor.lastrowid

        cursor.execute("""
            INSERT INTO threat_indicators
            (raw_id, indicator_value, indicator_type, source, tags,
             threat_score, description, country, first_seen, last_seen, is_active)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (
            raw_id, ip, "ip", "abuseipdb",
            json.dumps([]),
            0,  # processor will score
            f"Abuse confidence: {entry.get('abuseConfidenceScore', 0)}%",
            entry.get("countryCode", ""),
            entry.get("lastReportedAt", datetime.now().isoformat()),
            datetime.now().isoformat(),
            1
        ))
        count += 1

    conn.commit()
    conn.close()
    print(f"AbuseIPDB: {count} indicators saved.")


# AlienVault OTX
def fetch_otx():
    print("Fetching from AlienVault OTX...")
    headers  = {"X-OTX-API-KEY": resolve_key("otx", "OTX_API_KEY")}
    # Pull the latest 20 pulses from the subscribed feed
    response = requests.get(
        "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20",
        headers=headers
    )
    data = response.json()

    if "results" not in data:
        print(f"OTX: no data. Response: {data}")
        return

    conn   = get_connection()
    cursor = conn.cursor()
    count  = 0

    for pulse in data["results"]:
        tags = pulse.get("tags", [])
        for indicator in pulse.get("indicators", []):
            value = indicator.get("indicator", "")
            itype = indicator.get("type", "").lower()
            if not value:
                continue

            # Map OTX types to our standard types
            if "ip"     in itype: itype = "ip"
            elif "domain" in itype: itype = "domain"
            elif "url"    in itype: itype = "url"
            elif "hash"   in itype or "file" in itype: itype = "hash"
            else: itype = "url"  # default

            cursor.execute(
                "INSERT INTO raw_indicators (source, raw_value, raw_json) VALUES (?,?,?)",
                ("otx", value, json.dumps(indicator))
            )
            raw_id = cursor.lastrowid

            cursor.execute("""
                INSERT INTO threat_indicators
                (raw_id, indicator_value, indicator_type, source, tags,
                 threat_score, description, first_seen, last_seen, is_active)
                VALUES (?,?,?,?,?,?,?,?,?,?)
            """, (
                raw_id, value, itype, "otx", json.dumps(tags),
                0,
                pulse.get("name", ""),
                indicator.get("created", datetime.now().isoformat()),
                datetime.now().isoformat(),
                1
            ))
            count += 1

    conn.commit()
    conn.close()
    print(f"OTX: {count} indicators saved.")


# VirusTotal
def fetch_virustotal():
    print("Fetching from VirusTotal...")
    headers  = {"x-apikey": resolve_key("virustotal", "VIRUSTOTAL_API_KEY")}
    # Pull recently detected URLs - free tier allows this endpoint
    response = requests.get(
        "https://www.virustotal.com/api/v3/search?query=positives%3A1%2B&limit=40",
        headers=headers
    )

    if response.status_code != 200:
        print(f"VirusTotal: error {response.status_code}. {response.text[:200]}")
        return

    data = response.json()

    if "data" not in data:
        print(f"VirusTotal: no data.")
        return

    conn   = get_connection()
    cursor = conn.cursor()
    count  = 0

    for entry in data["data"]:
        attrs = entry.get("attributes", {})
        url   = attrs.get("url", "")
        if not url:
            continue

        stats      = attrs.get("last_analysis_stats", {})
        malicious  = stats.get("malicious", 0)
        total      = sum(stats.values()) or 1
        tags       = attrs.get("tags", [])

        cursor.execute(
            "INSERT INTO raw_indicators (source, raw_value, raw_json) VALUES (?,?,?)",
            ("virustotal", url, json.dumps(attrs))
        )
        raw_id = cursor.lastrowid

        cursor.execute("""
            INSERT INTO threat_indicators
            (raw_id, indicator_value, indicator_type, source, tags,
             threat_score, description, first_seen, last_seen, is_active)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (
            raw_id, url, "url", "virustotal", json.dumps(tags),
            0,
            f"Malicious detections: {malicious}/{total}",
            attrs.get("first_submission_date", datetime.now().isoformat()),
            datetime.now().isoformat(),
            1 if malicious > 0 else 0
        ))
        count += 1

    conn.commit()
    conn.close()
    print(f"VirusTotal: {count} indicators saved.")


# Runs all collectors then process
if __name__ == "__main__":
    fetch_urlhaus()
    fetch_abuseipdb()
    fetch_otx()
    fetch_virustotal()
    print("All sources collected.")
