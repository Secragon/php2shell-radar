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


def export_report(path, run, assets):
    # No raw response bodies or cookie values are persisted.
    if str(path).lower().endswith(".csv"):
        columns = ["url", "site_url", "final_url", "connect_ip", "host", "ips", "source", "dns", "wildcard_ambiguous", "http_status", "php", "confidence", "version", "reported_versions", "technologies", "verdict", "verdict_reason", "assessment", "active", "patch_evidence", "tls", "error", "evidence", "response_observations", "detection_partial"]
        with open(path, "w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            for asset in assets:
                row = {}
                for column in columns:
                    value = asset.get(column, "")
                    if isinstance(value, (dict, list)):
                        value = json.dumps(value, ensure_ascii=False)
                    # Neutralize spreadsheet formula injection in untrusted headers/URLs.
                    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
                        value = "'" + value
                    row[column] = value
                writer.writerow(row)
    else:
        Path(path).write_text(json.dumps({"schema": "php2shell-hunter/1", "run": run, "assets": assets}, indent=2, ensure_ascii=False), encoding="utf-8")
