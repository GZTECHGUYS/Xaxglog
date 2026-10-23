"""Xaxglog configuration — single place for env + paths."""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "..", "data")
OUTPUT_DIR = os.path.join(DATA_DIR, "outputs")
DB_PATH = os.path.join(DATA_DIR, "xaxglog.db")
RUNNER_DB = os.path.join(DATA_DIR, "runner_history.json")
CATALOG_DIR = os.path.join(BASE_DIR, "modules", "catalog")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Threat-feed keys (all optional — app degrades gracefully)
# UI-saved encrypted keys override these (see threat_intel legacy app).
URLHAUS_API_KEY = os.getenv("URLHAUS_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY", "")
INTELX_API_KEY = os.getenv("INTELX_API_KEY", "")
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")
NUM_API_KEY = os.getenv("NUM_API_KEY", "")  # apilayer phone validation
INTELX_API_KEY = os.getenv("INTELX_API_KEY", "")  # licensed dark-web/corpus index

# Authorized SS7 carrier gateway — point at your lawful-intercept / lawful-access
# endpoint. Leave empty to export requests for manual carrier submission.
SS7_GATEWAY_ENDPOINT = os.getenv("SS7_GATEWAY_ENDPOINT", "")
SS7_GATEWAY_TOKEN = os.getenv("SS7_GATEWAY_TOKEN", "")

# First-run admin password (used only to bootstrap the admin user).
XAXGLOG_ADMIN_PASSWORD = os.getenv("XAXGLOG_ADMIN_PASSWORD", "xaxglog-admin")

# Wave 3 optional providers (all free tiers; modules degrade gracefully without them)
CH_API_KEY = os.getenv("CH_API_KEY", "")                 # UK Companies House (free)
MAPILLARY_CLIENT_TOKEN = os.getenv("MAPILLARY_CLIENT_TOKEN", "")  # street-level imagery (free)
OPENSANCTIONS_BULK = os.getenv("OPENSANCTIONS_BULK", "0")         # "1" = bulk sanctions name index

FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "xaxglog-dev-change-me")
PORT = int(os.getenv("PORT", "5000"))
HOST = os.getenv("HOST", "0.0.0.0")
COLLECT_INTERVAL_HOURS = int(os.getenv("COLLECT_INTERVAL_HOURS", "12"))
DEFAULT_TIMEOUT = int(os.getenv("TOOL_TIMEOUT", "300"))
HTTP_TIMEOUT = int(os.getenv("HTTP_TIMEOUT", "12"))
MAX_HISTORY = 500
# No Docker in this deployment — plain `python app.py` + optional systemd service.
