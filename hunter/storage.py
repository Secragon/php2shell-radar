import csv
import json
from pathlib import Path
import sqlite3


class Store:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY, document TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS assets(run_id TEXT, url TEXT, document TEXT NOT NULL,
                PRIMARY KEY(run_id, url));
        """)
        self.db.commit()

    def save_run(self, run):
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO runs VALUES(?,?)", (run["id"], json.dumps(run)))

    def save_asset(self, run_id, asset):
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO assets VALUES(?,?,?)", (run_id, asset.get("id", asset["url"]), json.dumps(asset)))

    def runs(self):
        return [json.loads(row[0]) for row in self.db.execute("SELECT document FROM runs ORDER BY rowid DESC")]

    def assets(self, run_id):
        return [json.loads(row[0]) for row in self.db.execute("SELECT document FROM assets WHERE run_id=? ORDER BY url", (run_id,))]

    def close(self):
        self.db.close()


RESULT_COLUMNS = ("Address", "HTTP", "PHP", "Version", "Active check", "Result")


def export_visible_results(path, rows):
    """Save the presentation rows, without stored scan telemetry or journal data."""
    if str(path).lower().endswith(".csv"):
        with open(path, "w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=RESULT_COLUMNS)
            writer.writeheader()
            for result in rows:
                row = {}
                for column in RESULT_COLUMNS:
                    value = result.get(column, "")
                    # Neutralize spreadsheet formula injection in untrusted headers/URLs.
                    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
                        value = "'" + value
                    row[column] = value
                writer.writerow(row)
    else:
        Path(path).write_text(json.dumps({"results": rows}, indent=2, ensure_ascii=False), encoding="utf-8")
