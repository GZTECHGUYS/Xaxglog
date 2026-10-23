import sqlite3

DB_PATH = "osint.db"

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS raw_indicators (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            source      TEXT NOT NULL,
            raw_value   TEXT NOT NULL,
            raw_json    TEXT,
            fetched_at  DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_indicators (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            raw_id           INTEGER REFERENCES raw_indicators(id),
            indicator_value  TEXT NOT NULL,
            indicator_type   TEXT NOT NULL,
            source           TEXT NOT NULL,
            tags             TEXT,
            threat_score     INTEGER DEFAULT 0,
            country          TEXT,
            description      TEXT,
            first_seen       DATETIME,
            last_seen        DATETIME,
            is_active        INTEGER DEFAULT 1
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_type   ON threat_indicators(indicator_type)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_source ON threat_indicators(source)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_score  ON threat_indicators(threat_score)")

    conn.commit()
    conn.close()
    print("Database initialised successfully.")

if __name__ == "__main__":
    init_db()
