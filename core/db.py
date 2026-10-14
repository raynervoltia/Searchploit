#!/usr/bin/env python3
"""
core/db.py — High-Performance SQLite Storage and Search Engine for Searchploit.
"""

import os
import sqlite3
import csv
from datetime import datetime
from core.display import Colors

DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "exploits.db")


class ExploitDB:
    def __init__(self, db_path=DEFAULT_DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        """Create tables and search indexes."""
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS exploits (
                id INTEGER PRIMARY KEY,
                file TEXT,
                description TEXT,
                date_published TEXT,
                author TEXT,
                type TEXT,
                platform TEXT,
                port TEXT,
                date_added TEXT,
                date_updated TEXT,
                verified INTEGER,
                codes TEXT,
                tags TEXT,
                aliases TEXT,
                screenshot_url TEXT,
                application_url TEXT,
                source_url TEXT
            )
        """)

        # Fast search indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_type ON exploits (type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_platform ON exploits (platform)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_date ON exploits (date_published DESC)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_codes ON exploits (codes)")

        self.conn.commit()

    def is_populated(self):
        """Check if database has data."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM exploits")
        count = cursor.fetchone()[0]
        return count > 0

    def get_count(self):
        """Return total record count."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM exploits")
        return cursor.fetchone()[0]

    def import_from_csv(self, csv_path):
        """
        Parse files_exploits.csv and bulk import into SQLite.
        """
        if not os.path.exists(csv_path):
            print(f"{Colors.RED}[!] CSV file tidak ditemukan: {csv_path}{Colors.RESET}")
            return False

        print(f"{Colors.CYAN}[*] Mengimpor data dari CSV ke SQLite database...{Colors.RESET}")
        cursor = self.conn.cursor()

        # Clean existing data
        cursor.execute("DELETE FROM exploits")

        insert_sql = """
            INSERT OR REPLACE INTO exploits (
                id, file, description, date_published, author, type, platform,
                port, date_added, date_updated, verified, codes, tags, aliases,
                screenshot_url, application_url, source_url
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """

        records = []
        count = 0
        with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                eid = row.get("id")
                if not eid or not eid.isdigit():
                    continue

                records.append((
                    int(eid),
                    row.get("file", ""),
                    row.get("description", ""),
                    row.get("date_published", ""),
                    row.get("author", ""),
                    (row.get("type", "") or "").lower().strip(),
                    (row.get("platform", "") or "").lower().strip(),
                    row.get("port", ""),
                    row.get("date_added", ""),
                    row.get("date_updated", ""),
                    1 if str(row.get("verified", "0")) == "1" else 0,
                    row.get("codes", ""),
                    row.get("tags", ""),
                    row.get("aliases", ""),
                    row.get("screenshot_url", ""),
                    row.get("application_url", ""),
                    row.get("source_url", "")
                ))
                count += 1

                if len(records) >= 5000:
                    cursor.executemany(insert_sql, records)
                    self.conn.commit()
                    records = []

        if records:
            cursor.executemany(insert_sql, records)
            self.conn.commit()

        print(f"{Colors.GREEN}[+] Berhasil mengimpor {count} exploit ke database lokal!{Colors.RESET}")
        return True

    def get_latest(self, limit=20, vuln_type=None, platform=None):
        """
        Fetch latest published exploits.
        """
        query = "SELECT * FROM exploits WHERE 1=1"
        params = []

        if vuln_type:
            query += " AND type = ?"
            params.append(vuln_type.lower())
        if platform:
            query += " AND platform = ?"
            params.append(platform.lower())

        query += " ORDER BY date_published DESC, id DESC LIMIT ?"
        params.append(limit)

        cursor = self.conn.cursor()
        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

    def search(self, query=None, vuln_type=None, platform=None, cve=None, author=None, limit=50):
        """
        Multi-criteria full search.
        """
        sql = "SELECT * FROM exploits WHERE 1=1"
        params = []

        if query:
            # Multi-token matching
            tokens = query.strip().split()
            for token in tokens:
                sql += " AND (description LIKE ? OR codes LIKE ? OR author LIKE ? OR file LIKE ?)"
                t_like = f"%{token}%"
                params.extend([t_like, t_like, t_like, t_like])

        if vuln_type:
            sql += " AND type = ?"
            params.append(vuln_type.lower())

        if platform:
            sql += " AND platform = ?"
            params.append(platform.lower())

        if cve:
            sql += " AND codes LIKE ?"
            params.append(f"%{cve}%")

        if author:
            sql += " AND author LIKE ?"
            params.append(f"%{author}%")

        sql += " ORDER BY date_published DESC, id DESC LIMIT ?"
        params.append(limit)

        cursor = self.conn.cursor()
        cursor.execute(sql, params)
        return [dict(row) for row in cursor.fetchall()]

    def get_by_id(self, eid):
        """Fetch exploit by ID."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM exploits WHERE id = ?", (eid,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_stats(self):
        """Return database summary stats."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM exploits")
        total = cursor.fetchone()[0]

        cursor.execute("SELECT type, COUNT(*) FROM exploits GROUP BY type ORDER BY COUNT(*) DESC")
        types_breakdown = cursor.fetchall()

        cursor.execute("SELECT platform, COUNT(*) FROM exploits GROUP BY platform ORDER BY COUNT(*) DESC LIMIT 10")
        top_platforms = cursor.fetchall()

        cursor.execute("SELECT MAX(date_published) FROM exploits")
        latest_date = cursor.fetchone()[0]

        return {
            "total": total,
            "types": types_breakdown,
            "top_platforms": top_platforms,
            "latest_date": latest_date
        }

    def close(self):
        self.conn.close()
