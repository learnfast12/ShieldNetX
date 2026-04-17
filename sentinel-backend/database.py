import aiosqlite
import hashlib
from datetime import datetime, timedelta

DB_PATH = "sentinel.db"

class Database:
    def __init__(self):
        self.db_path = DB_PATH

    async def init(self):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    url_hash TEXT NOT NULL,
                    ip_address TEXT,
                    country TEXT,
                    city TEXT,
                    threat_score INTEGER,
                    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS dwell_times (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url_hash TEXT NOT NULL,
                    dwell_ms INTEGER,
                    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            await db.execute("CREATE INDEX IF NOT EXISTS idx_url_hash ON scans(url_hash);")
            await db.commit()

    async def record_scan(self, url_hash, url, ip, country, city, score):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO scans (url, url_hash, ip_address, country, city, threat_score) VALUES (?,?,?,?,?,?)",
                (url, url_hash, ip, country, city, score)
            )
            await db.commit()

    async def get_click_velocity(self, url_hash):
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT COUNT(*) FROM scans WHERE url_hash=? AND scanned_at >= ?",
                (url_hash, one_hour_ago.isoformat())
            ) as cur:
                row = await cur.fetchone()
                count = row[0] if row else 0

        if count > 500: score = 20
        elif count > 100: score = 15
        elif count > 50: score = 10
        elif count > 10: score = 5
        else: score = 0

        return {
            "hits_last_hour": count,
            "score": score,
            "max_score": 20,
            "verdict": "High velocity blast detected" if score >= 15 else
                       "Moderate spread" if score >= 5 else "Normal / first seen"
        }

    async def get_dwell_analysis(self, url_hash):
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT AVG(dwell_ms) FROM dwell_times WHERE url_hash=?",
                (url_hash,)
            ) as cur:
                row = await cur.fetchone()
                avg_ms = row[0] if row and row[0] else None

        if avg_ms is None: score, verdict = 0, "No dwell data yet"
        elif avg_ms < 1500: score, verdict = 10, f"Exits in {avg_ms:.0f}ms — redirect trap"
        elif avg_ms < 4000: score, verdict = 5, f"Short dwell ({avg_ms:.0f}ms) — suspicious"
        else: score, verdict = 0, f"Normal dwell time ({avg_ms:.0f}ms)"

        return {"avg_dwell_ms": avg_ms, "score": score, "max_score": 10, "verdict": verdict}

    async def get_geo_velocity(self, url_hash):
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                """SELECT COUNT(DISTINCT country), COUNT(DISTINCT city)
                   FROM scans WHERE url_hash=? AND scanned_at >= ? AND country IS NOT NULL""",
                (url_hash, one_hour_ago.isoformat())
            ) as cur:
                row = await cur.fetchone()
                countries = row[0] if row else 0
                cities = row[1] if row else 0

        if countries >= 5: score = 15
        elif countries >= 3: score = 10
        elif cities >= 5: score = 5
        else: score = 0

        return {
            "distinct_countries": countries,
            "distinct_cities": cities,
            "score": score,
            "max_score": 15,
            "verdict": f"Spread across {countries} countries — mass blast!" if score >= 10
                       else f"Limited spread ({countries} countries, {cities} cities)"
        }

    async def get_recent_scans(self, limit=20):
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT url, country, threat_score, scanned_at FROM scans ORDER BY scanned_at DESC LIMIT ?",
                (limit,)
            ) as cur:
                rows = await cur.fetchall()
        return [{"url": r[0], "country": r[1], "score": r[2], "scanned_at": r[3]} for r in rows]
