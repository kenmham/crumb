import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Set

from .config import CRUMB_DIR, DB_PATH


@dataclass
class Service:
    id: int
    name: str
    domain: str
    data_types: List[str]
    added_at: str
    last_used: Optional[str]
    status: str
    notes: str
    identifier: Optional[str] = None   # email/relay used to sign up
    hide_my_email: bool = False         # signed up via Apple Hide My Email
    source: Optional[str] = None       # where did this service get my data?


def get_conn() -> sqlite3.Connection:
    CRUMB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS services (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            name           TEXT NOT NULL,
            domain         TEXT UNIQUE NOT NULL,
            data_types     TEXT NOT NULL DEFAULT '[]',
            added_at       TEXT NOT NULL,
            last_used      TEXT,
            status         TEXT NOT NULL DEFAULT 'active',
            notes          TEXT NOT NULL DEFAULT '',
            identifier     TEXT,
            hide_my_email  INTEGER NOT NULL DEFAULT 0,
            source         TEXT
        );
        CREATE TABLE IF NOT EXISTS known_domains (
            domain      TEXT PRIMARY KEY,
            first_seen  TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS scan_log (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            scanned_at    TEXT NOT NULL,
            domains_found INTEGER NOT NULL DEFAULT 0,
            domains_added INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS scan_checkpoints (
            folder        TEXT PRIMARY KEY,
            last_date     TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS pending_candidates (
            folder              TEXT NOT NULL,
            domain              TEXT NOT NULL,
            name                TEXT NOT NULL,
            email_count         INTEGER NOT NULL DEFAULT 0,
            detected_data_types TEXT NOT NULL DEFAULT '[]',
            first_seen          TEXT,
            last_seen           TEXT,
            hide_my_email       INTEGER NOT NULL DEFAULT 0,
            identifier          TEXT,
            source              TEXT,
            next_checkpoint     TEXT,
            PRIMARY KEY (folder, domain)
        );
    """)
    # Migrate existing databases that predate these columns.
    existing = {r[1] for r in conn.execute("PRAGMA table_info(services)").fetchall()}
    if "identifier" not in existing:
        conn.execute("ALTER TABLE services ADD COLUMN identifier TEXT")
    if "hide_my_email" not in existing:
        conn.execute("ALTER TABLE services ADD COLUMN hide_my_email INTEGER NOT NULL DEFAULT 0")
    if "source" not in existing:
        conn.execute("ALTER TABLE services ADD COLUMN source TEXT")
    conn.commit()


def add_service(conn: sqlite3.Connection, name: str, domain: str, data_types: List[str],
                last_used: Optional[str] = None, status: str = "active", notes: str = "",
                identifier: Optional[str] = None, hide_my_email: bool = False,
                source: Optional[str] = None) -> None:
    conn.execute(
        "INSERT INTO services "
        "(name, domain, data_types, added_at, last_used, status, notes, identifier, hide_my_email, source) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (name, domain, json.dumps(data_types), datetime.now().isoformat(),
         last_used, status, notes, identifier, int(hide_my_email), source),
    )
    conn.commit()


def get_services(conn: sqlite3.Connection, status: Optional[str] = None,
                 data_type: Optional[str] = None,
                 source: Optional[str] = None) -> List[Service]:
    q, params = "SELECT * FROM services WHERE 1=1", []
    if status:
        q += " AND status = ?"
        params.append(status)
    if source is not None:
        q += " AND source = ?"
        params.append(source)
    q += " ORDER BY added_at DESC"
    services = [_row(r) for r in conn.execute(q, params).fetchall()]
    if data_type:
        services = [s for s in services if data_type in s.data_types]
    return services


def get_downstream(conn: sqlite3.Connection, name: str) -> List[Service]:
    """Return services whose source matches name (case-insensitive)."""
    rows = conn.execute(
        "SELECT * FROM services WHERE LOWER(source) = LOWER(?)", (name,)
    ).fetchall()
    return [_row(r) for r in rows]


def downstream_counts(conn: sqlite3.Connection) -> Dict[str, int]:
    """Return {service_name: count_of_services_sourced_from_it}."""
    rows = conn.execute(
        "SELECT source, COUNT(*) as n FROM services WHERE source IS NOT NULL GROUP BY source"
    ).fetchall()
    return {r["source"]: r["n"] for r in rows}


def update_service(conn: sqlite3.Connection, service_id: int, **fields) -> None:
    if not fields:
        return
    clause = ", ".join(f"{k} = ?" for k in fields)
    conn.execute(f"UPDATE services SET {clause} WHERE id = ?",
                 [*fields.values(), service_id])
    conn.commit()


def update_service_status(conn: sqlite3.Connection, service_id: int, status: str) -> None:
    conn.execute("UPDATE services SET status = ? WHERE id = ?", (status, service_id))
    conn.commit()


def get_known_domains(conn: sqlite3.Connection) -> Set[str]:
    return {r["domain"] for r in conn.execute("SELECT domain FROM known_domains").fetchall()}


def add_known_domains(conn: sqlite3.Connection, domains: Dict[str, str]) -> None:
    conn.executemany(
        "INSERT OR IGNORE INTO known_domains (domain, first_seen) VALUES (?,?)",
        list(domains.items()),
    )
    conn.commit()


def save_pending(conn: sqlite3.Connection, folder: str,
                 candidates: List[dict], next_checkpoint: str) -> None:
    conn.executemany(
        "INSERT OR REPLACE INTO pending_candidates "
        "(folder, domain, name, email_count, detected_data_types, first_seen, last_seen, "
        " hide_my_email, identifier, source, next_checkpoint) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        [(folder, c["domain"], c["name"], c["email_count"],
          json.dumps(c["detected_data_types"]),
          c.get("first_seen"), c.get("last_seen"),
          int(c.get("hide_my_email", False)), c.get("identifier"),
          c.get("source"), next_checkpoint)
         for c in candidates],
    )
    conn.commit()


def load_pending(conn: sqlite3.Connection,
                 folder: str) -> Optional[tuple]:
    """Return (candidates, next_checkpoint) if any pending exist for folder, else None."""
    rows = conn.execute(
        "SELECT * FROM pending_candidates WHERE folder = ? ORDER BY rowid", (folder,)
    ).fetchall()
    if not rows:
        return None
    candidates = [{
        "domain": r["domain"], "name": r["name"], "email_count": r["email_count"],
        "detected_data_types": json.loads(r["detected_data_types"]),
        "first_seen": r["first_seen"], "last_seen": r["last_seen"],
        "hide_my_email": bool(r["hide_my_email"]), "identifier": r["identifier"],
        "source": r["source"],
    } for r in rows]
    return candidates, rows[0]["next_checkpoint"]


def remove_pending(conn: sqlite3.Connection, folder: str, domain: str) -> None:
    conn.execute(
        "DELETE FROM pending_candidates WHERE folder = ? AND domain = ?", (folder, domain)
    )
    conn.commit()


def count_pending(conn: sqlite3.Connection, folder: str) -> int:
    return conn.execute(
        "SELECT COUNT(*) FROM pending_candidates WHERE folder = ?", (folder,)
    ).fetchone()[0]


def get_checkpoint(conn: sqlite3.Connection, folder: str) -> Optional[str]:
    """Return the IMAP SINCE date string for the last scan of this folder, or None."""
    row = conn.execute(
        "SELECT last_date FROM scan_checkpoints WHERE folder = ?", (folder,)
    ).fetchone()
    return row["last_date"] if row else None


def set_checkpoint(conn: sqlite3.Connection, folder: str, date_str: str) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO scan_checkpoints (folder, last_date) VALUES (?,?)",
        (folder, date_str),
    )
    conn.commit()


def log_scan(conn: sqlite3.Connection, domains_found: int, domains_added: int) -> None:
    conn.execute(
        "INSERT INTO scan_log (scanned_at, domains_found, domains_added) VALUES (?,?,?)",
        (datetime.now().isoformat(), domains_found, domains_added),
    )
    conn.commit()


def _row(row: sqlite3.Row) -> Service:
    return Service(
        id=row["id"], name=row["name"], domain=row["domain"],
        data_types=json.loads(row["data_types"]), added_at=row["added_at"],
        last_used=row["last_used"], status=row["status"], notes=row["notes"],
        identifier=row["identifier"], hide_my_email=bool(row["hide_my_email"]),
        source=row["source"],
    )
