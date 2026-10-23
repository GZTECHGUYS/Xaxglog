import json
import re
from database import get_connection
from datetime import datetime


# Scoring constants
#
# The score is a 0-100 prioritisation heuristic, NOT a calibrated probability.
# It blends five signals:
#
# 1. Source trust         0-40 pts   how curated/reliable the feed is
# (VT is derived from detection ratio)
# 2. Severity             0-25 pts   malware/TTP keywords in tags or desc
# 3. Tag richness         0-10 pts   more tags = more analyst context
# 4. Cross-source bonus   0-15 pts   the same indicator reported elsewhere
# 5. Recency              0-15 pts   freshly observed indicators rank higher
#
# Tier thresholds used by the UI and rule generator:  Critical >=75,
# High >=50, Medium >=25, Low <25.

SOURCE_TRUST = {
    "abuseipdb":  35,   # curated blacklist, IPs at >=90% reporter confidence
    "urlhaus":    30,   # active malware-distribution URLs
    "virustotal": 20,   # base; replaced by detection-ratio when present
    "otx":        15,   # community pulses, quality varies
}
DEFAULT_SOURCE_TRUST = 10

# Severity keywords. Matched as a substring against the lowercased tag or
# description so vocabulary variations ("credential theft", "credential-theft",
# "Credential Access") all hit.
SEVERE_KEYWORDS = (
    # Malware classes
    "malware", "ransom", "trojan", "backdoor", "rootkit", "dropper",
    "loader", "stealer", "wiper", "worm", "spyware",
    # C2 / infrastructure
    "c2", "c&c", "command and control", "command-and-control",
    # TTPs (MITRE-style)
    "exploit", " apt", "apt ", "persistence", "lateral move",
    "privilege escalat", "credential", "exfiltrat", "supply chain",
    "supply-chain",
    # Resource abuse
    "cryptojack", "coinminer",
)
MODERATE_KEYWORDS = (
    "phishing", "phish", "botnet", "scam", "spam", "malspam",
    "scanner", "brute force", "brute-force", "ddos",
    "denial of service", "suspicious",
)


def _normalised_text(entry):
    """Concatenate tags and description into a single lowercased blob
    we can keyword-match against."""
    tags_raw = entry.get("tags") or "[]"
    try:
        tags = json.loads(tags_raw)
    except Exception:
        tags = []
    description = entry.get("description") or ""
    return " ".join(tags).lower() + " " + description.lower(), tags


def _source_trust_pts(entry):
    source = (entry.get("source") or "").lower()
    if source == "virustotal":
        description = (entry.get("description") or "").lower()
        m = re.search(r"malicious detections:\s*(\d+)/(\d+)", description)
        if m:
            malicious, total = int(m.group(1)), int(m.group(2))
            if total > 0:
                return int((malicious / total) * 40)  # 0-40 by ratio
        return SOURCE_TRUST["virustotal"]
    return SOURCE_TRUST.get(source, DEFAULT_SOURCE_TRUST)


def _severity_pts(text):
    if any(kw in text for kw in SEVERE_KEYWORDS):
        return 25
    if any(kw in text for kw in MODERATE_KEYWORDS):
        return 15
    return 0


def _parse_first_seen(value):
    """Parse a first_seen timestamp across the formats different feeds use.

    Returns a timezone-aware datetime, or None if unparseable. URLhaus stores
    timestamps as '2026-03-30 20:33:08 UTC' (space-separated, literal UTC),
    which fromisoformat() rejects - we normalise it here so URLhaus rows
    don't silently lose their recency bonus.
    """
    if not value:
        return None
    s = value.strip()
    if s.endswith(" UTC"):
        s = s[:-4] + "+00:00"
    s = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        # Treat naive timestamps as UTC so age comparisons are consistent.
        dt = dt.replace(tzinfo=datetime.now().astimezone().tzinfo)
    return dt


def _recency_pts(first_seen):
    dt = _parse_first_seen(first_seen)
    if dt is None:
        return 0
    now = datetime.now(dt.tzinfo)
    age_days = (now - dt).days
    if age_days <= 1:
        return 15
    if age_days <= 7:
        return 10
    if age_days <= 30:
        return 5
    return 0


def _cross_source_pts(entry, conn):
    if not (conn and entry.get("indicator_value")):
        return 0
    cursor = conn.cursor()
    cursor.execute(
        "SELECT COUNT(DISTINCT source) FROM threat_indicators WHERE indicator_value = ?",
        (entry["indicator_value"],),
    )
    source_count = cursor.fetchone()[0]
    if source_count >= 3:
        return 15
    if source_count == 2:
        return 10
    return 0


def calculate_score(entry, conn=None):
    text, tags = _normalised_text(entry)

    score = 0
    score += _source_trust_pts(entry)
    score += _severity_pts(text)
    score += min(len(tags) * 2, 10)
    score += _cross_source_pts(entry, conn)
    score += _recency_pts(entry.get("first_seen"))

    return min(score, 100)


def process_indicators():
    """Score any indicators that don't have a score yet (threat_score = 0)."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, indicator_value, indicator_type,
               source, tags, description, is_active, first_seen
        FROM threat_indicators
        WHERE threat_score = 0
    """)

    rows = cursor.fetchall()

    if not rows:
        print("No unprocessed indicators found.")
        conn.close()
        return

    updated = 0
    for row in rows:
        entry = dict(row)
        score = calculate_score(entry, conn)

        cursor.execute(
            "UPDATE threat_indicators SET threat_score = ? WHERE id = ?",
            (score, entry["id"]),
        )
        updated += 1

    conn.commit()
    conn.close()
    print(f"Processed {updated} indicators.")


def rescore_all():
    """Recalculate scores for every indicator in place.

    Use this after changing the scoring algorithm - it updates each row
    without first zeroing it, so the dashboard never shows a window of
    score=0 values.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, indicator_value, indicator_type,
               source, tags, description, is_active, first_seen
        FROM threat_indicators
    """)
    rows = cursor.fetchall()
    print(f"Rescoring {len(rows)} indicators...")
    for row in rows:
        entry = dict(row)
        score = calculate_score(entry, conn)
        cursor.execute(
            "UPDATE threat_indicators SET threat_score = ? WHERE id = ?",
            (score, entry["id"]),
        )
    conn.commit()
    conn.close()
    print("Rescore complete.")


if __name__ == "__main__":
    rescore_all()
