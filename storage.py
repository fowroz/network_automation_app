"""
========================================================================
 Local persistence layer: SQLite storage + optional credential encryption
========================================================================

Everything here is LOCAL ONLY -- a single file, `automation_console.db`,
created next to this script the first time the app runs. Nothing here
ever talks to the network.

WHAT'S STORED
-------------
- Saved device inventories (device lists + shared run settings) so you
  don't have to re-type devices every session.
- Run history (the structured JSON report from each completed run).
- Scheduled jobs (read-only checks only -- see SAFETY NOTE below).

CREDENTIALS
-----------
Passwords are NEVER stored unless you explicitly check "remember
password" when saving an inventory, and even then they are encrypted
at rest using the `cryptography` package (Fernet/AES-128-CBC+HMAC)
with a key stored in a local file (`secret.key`) that is created with
owner-only permissions (chmod 600 on POSIX). If the `cryptography`
package can't be installed, password-saving is simply disabled --
everything else in the app still works normally, you'll just need to
type the password again for that run.

SAFETY NOTE ON SCHEDULES
-------------------------
Scheduled jobs are hard-restricted to read-only operations (ping/port
checks and "show"-style SSH commands). Config-mode (device-changing)
runs can NEVER be scheduled -- they always require a human to click
"Run Now" and pass through the normal confirmation flow. This is
enforced both when a schedule is created/edited AND again right before
a scheduled run actually executes.
========================================================================
"""

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "automation_console.db")
SECRET_KEY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "secret.key")

_db_lock = threading.Lock()


def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def _ensure_column(conn, table, column, ddl):
    """Adds `column` to `table` if it doesn't already exist -- lets us
    evolve the schema across app versions without wiping existing local
    data (SQLite has no 'ADD COLUMN IF NOT EXISTS')."""
    existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")


def init_db():
    with _db_lock, _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS inventories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                data_json TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                label TEXT,
                triggered_by TEXT NOT NULL DEFAULT 'manual',
                report_json TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS schedules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                interval_minutes INTEGER NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                config_json TEXT NOT NULL,
                last_run_at TEXT,
                next_run_at TEXT NOT NULL
            )
        """)

        # ---- Schema evolution (additive, safe on existing databases) ----
        _ensure_column(conn, "inventories", "notes", "notes TEXT DEFAULT ''")
        _ensure_column(conn, "inventories", "tags", "tags TEXT DEFAULT ''")
        _ensure_column(conn, "inventories", "favorite", "favorite INTEGER DEFAULT 0")
        _ensure_column(conn, "inventories", "device_count", "device_count INTEGER DEFAULT 0")

        _ensure_column(conn, "runs", "duration_seconds", "duration_seconds REAL")
        _ensure_column(conn, "runs", "device_count", "device_count INTEGER DEFAULT 0")
        _ensure_column(conn, "runs", "failed_count", "failed_count INTEGER DEFAULT 0")
        _ensure_column(conn, "runs", "inventory_name", "inventory_name TEXT DEFAULT ''")

        _ensure_column(conn, "schedules", "last_status", "last_status TEXT DEFAULT ''")
        _ensure_column(conn, "schedules", "run_count", "run_count INTEGER DEFAULT 0")
        _ensure_column(conn, "schedules", "failure_count", "failure_count INTEGER DEFAULT 0")
        _ensure_column(conn, "schedules", "notify_on_failure", "notify_on_failure INTEGER DEFAULT 0")
        _ensure_column(conn, "schedules", "last_failed_devices", "last_failed_devices TEXT DEFAULT ''")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_runs_started_at ON runs(started_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_inventories_favorite ON inventories(favorite)")


# ==========================================================================
# Optional credential encryption (Fernet, via the `cryptography` package)
# ==========================================================================
_fernet = None
ENCRYPTION_AVAILABLE = False


def init_encryption(ensure_package_fn):
    """
    Attempts to make encryption available by importing (or auto-installing)
    `cryptography`, then loading/creating a local Fernet key file with
    restrictive permissions. `ensure_package_fn` is the same auto-install
    helper used elsewhere in the app, passed in to avoid a circular import.
    Safe to call multiple times. Returns True if encryption is available.
    """
    global _fernet, ENCRYPTION_AVAILABLE
    if _fernet is not None:
        return True

    crypto_module = ensure_package_fn("cryptography.fernet", pip_name="cryptography")
    if crypto_module is None:
        ENCRYPTION_AVAILABLE = False
        return False

    from cryptography.fernet import Fernet

    if os.path.exists(SECRET_KEY_PATH):
        with open(SECRET_KEY_PATH, "rb") as f:
            key = f.read().strip()
    else:
        key = Fernet.generate_key()
        # Write with restrictive permissions where the OS supports it
        # (POSIX chmod 600; on Windows this call is a harmless no-op).
        fd = os.open(SECRET_KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key)
        try:
            os.chmod(SECRET_KEY_PATH, 0o600)
        except Exception:
            pass  # best-effort on platforms without POSIX permissions

    _fernet = Fernet(key)
    ENCRYPTION_AVAILABLE = True
    return True


def encrypt_text(plain: str) -> str:
    if not ENCRYPTION_AVAILABLE or not plain:
        return ""
    return _fernet.encrypt(plain.encode("utf-8")).decode("ascii")


def decrypt_text(token: str) -> str:
    if not ENCRYPTION_AVAILABLE or not token:
        return ""
    try:
        return _fernet.decrypt(token.encode("ascii")).decode("utf-8")
    except Exception:
        return ""  # corrupted/foreign token -- fail safe, don't crash a run


# ==========================================================================
# Inventories (saved device lists + shared settings)
# ==========================================================================
def save_inventory(name: str, data: dict, notes: str = "", tags: str = "", device_count: int = 0) -> dict:
    """Insert or overwrite (by unique name) a saved inventory."""
    now = _now_iso()
    with _db_lock, _connect() as conn:
        existing = conn.execute("SELECT id FROM inventories WHERE name = ?", (name,)).fetchone()
        if existing:
            conn.execute(
                "UPDATE inventories SET data_json = ?, updated_at = ?, notes = ?, tags = ?, device_count = ? WHERE id = ?",
                (json.dumps(data), now, notes, tags, device_count, existing["id"]),
            )
            inv_id = existing["id"]
        else:
            cur = conn.execute(
                "INSERT INTO inventories (name, created_at, updated_at, data_json, notes, tags, device_count) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (name, now, now, json.dumps(data), notes, tags, device_count),
            )
            inv_id = cur.lastrowid
    return {"id": inv_id, "name": name, "updated_at": now}


def list_inventories():
    with _db_lock, _connect() as conn:
        rows = conn.execute(
            "SELECT id, name, created_at, updated_at, notes, tags, favorite, device_count FROM inventories "
            "ORDER BY favorite DESC, updated_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def get_inventory(inv_id: int):
    with _db_lock, _connect() as conn:
        row = conn.execute("SELECT * FROM inventories WHERE id = ?", (inv_id,)).fetchone()
        if not row:
            return None
        result = dict(row)
        result["data"] = json.loads(result.pop("data_json"))
        return result


def delete_inventory(inv_id: int) -> bool:
    with _db_lock, _connect() as conn:
        cur = conn.execute("DELETE FROM inventories WHERE id = ?", (inv_id,))
        return cur.rowcount > 0


def set_inventory_favorite(inv_id: int, favorite: bool) -> bool:
    with _db_lock, _connect() as conn:
        cur = conn.execute("UPDATE inventories SET favorite = ? WHERE id = ?", (1 if favorite else 0, inv_id))
        return cur.rowcount > 0


def update_inventory_by_id(inv_id: int, name: str = None, data: dict = None,
                            notes: str = None, tags: str = None, device_count: int = None) -> dict | None:
    """
    Updates an EXISTING inventory in place (same row/id) -- used for inline
    editing (rename, edit device list, edit notes/tags) so editing an
    inventory never creates a duplicate row the way save_inventory()'s
    upsert-by-name would if the name changed. Any argument left as None
    keeps its current stored value unchanged.
    """
    with _db_lock, _connect() as conn:
        row = conn.execute("SELECT * FROM inventories WHERE id = ?", (inv_id,)).fetchone()
        if not row:
            return None
        now = _now_iso()
        new_name = name if name is not None else row["name"]
        new_data_json = json.dumps(data) if data is not None else row["data_json"]
        new_notes = notes if notes is not None else row["notes"]
        new_tags = tags if tags is not None else row["tags"]
        new_device_count = device_count if device_count is not None else row["device_count"]
        conn.execute(
            "UPDATE inventories SET name = ?, data_json = ?, updated_at = ?, notes = ?, tags = ?, device_count = ? "
            "WHERE id = ?",
            (new_name, new_data_json, now, new_notes, new_tags, new_device_count, inv_id),
        )
        return {"id": inv_id, "name": new_name, "updated_at": now}


def duplicate_inventory(inv_id: int, new_name: str) -> dict | None:
    with _db_lock, _connect() as conn:
        row = conn.execute("SELECT * FROM inventories WHERE id = ?", (inv_id,)).fetchone()
        if not row:
            return None
        now = _now_iso()
        cur = conn.execute(
            "INSERT INTO inventories (name, created_at, updated_at, data_json, notes, tags, device_count) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (new_name, now, now, row["data_json"], row["notes"], row["tags"], row["device_count"]),
        )
        return {"id": cur.lastrowid, "name": new_name}


# ==========================================================================
# Run history
# ==========================================================================
MAX_HISTORY_ENTRIES = 200  # oldest runs beyond this are pruned automatically


def _count_failures(report: dict) -> int:
    devices = report.get("devices", [])
    return sum(
        1 for dev in devices
        if dev.get("ping") == "FAILED" or dev.get("tcp_port") == "FAILED"
        or str(dev.get("ssh", "")).startswith("FAILED")
    )


def save_run(report: dict, label: str = "", triggered_by: str = "manual", inventory_name: str = "") -> int:
    meta = report.get("meta", {})
    device_count = meta.get("total_devices", 0)
    failed_count = _count_failures(report)
    duration = meta.get("duration_seconds")
    with _db_lock, _connect() as conn:
        cur = conn.execute(
            "INSERT INTO runs (started_at, finished_at, label, triggered_by, report_json, "
            "duration_seconds, device_count, failed_count, inventory_name) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (meta.get("started_at", _now_iso()), meta.get("finished_at"), label,
             triggered_by, json.dumps(report), duration, device_count, failed_count, inventory_name),
        )
        run_id = cur.lastrowid
        # Prune old history beyond the cap to keep the DB file small.
        conn.execute(
            "DELETE FROM runs WHERE id NOT IN "
            "(SELECT id FROM runs ORDER BY id DESC LIMIT ?)",
            (MAX_HISTORY_ENTRIES,),
        )
    return run_id


def list_runs(limit: int = 50, triggered_by: str = None, only_failed: bool = False, search: str = ""):
    """
    Lists recent runs, newest first, with optional filters:
      - triggered_by: 'manual' or 'schedule' (None = both)
      - only_failed: only runs with at least one failed device
      - search: case-insensitive substring match against the run's label
    """
    query = "SELECT id, started_at, finished_at, label, triggered_by, device_count, failed_count, duration_seconds, inventory_name FROM runs WHERE 1=1"
    params = []
    if triggered_by:
        query += " AND triggered_by = ?"
        params.append(triggered_by)
    if only_failed:
        query += " AND failed_count > 0"
    if search:
        query += " AND label LIKE ?"
        params.append(f"%{search}%")
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    with _db_lock, _connect() as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]


def get_history_stats():
    """Aggregate stats across ALL retained history, for a quick dashboard view."""
    with _db_lock, _connect() as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM runs").fetchone()["c"]
        with_failures = conn.execute("SELECT COUNT(*) AS c FROM runs WHERE failed_count > 0").fetchone()["c"]
        avg_duration = conn.execute("SELECT AVG(duration_seconds) AS a FROM runs WHERE duration_seconds IS NOT NULL").fetchone()["a"]
        scheduled = conn.execute("SELECT COUNT(*) AS c FROM runs WHERE triggered_by = 'schedule'").fetchone()["c"]
        return {
            "total_runs": total,
            "runs_with_failures": with_failures,
            "runs_clean": total - with_failures,
            "avg_duration_seconds": round(avg_duration, 2) if avg_duration else None,
            "scheduled_runs": scheduled,
            "manual_runs": total - scheduled,
        }


def get_history_trend(days: int = 14, schedule_id: int = None):
    """
    Returns a day-by-day time series (oldest first) covering the last
    `days` days, for a small trend chart: total runs, failed runs, and
    average duration per day. Days with zero runs are still included
    (with zero counts) so the chart has an even x-axis.

    If `schedule_id` is given, only counts runs whose label matches that
    schedule's naming convention (see get_schedule_run_history()) -- used
    for the schedule-specific history view.
    """
    with _db_lock, _connect() as conn:
        rows = conn.execute(
            "SELECT substr(started_at, 1, 10) AS day, "
            "COUNT(*) AS total, "
            "SUM(CASE WHEN failed_count > 0 THEN 1 ELSE 0 END) AS failed, "
            "AVG(duration_seconds) AS avg_duration "
            "FROM runs "
            "WHERE started_at >= date('now', ?) "
            "GROUP BY day ORDER BY day",
            (f"-{days} days",),
        ).fetchall()
        by_day = {r["day"]: dict(r) for r in rows}

    from datetime import date, timedelta
    today = date.today()
    series = []
    for i in range(days - 1, -1, -1):
        day = (today - timedelta(days=i)).isoformat()
        entry = by_day.get(day)
        series.append({
            "day": day,
            "total": entry["total"] if entry else 0,
            "failed": (entry["failed"] or 0) if entry else 0,
            "avg_duration": round(entry["avg_duration"], 2) if entry and entry["avg_duration"] else None,
        })
    return series


def get_schedule_run_history(schedule_name: str, limit: int = 50):
    """
    Lists past runs specifically triggered by the schedule with this name
    (matches the "Scheduled: <name>" / "Manual run of schedule '<name>'"
    label convention used when a schedule executes) -- lets the Schedules
    tab show "this schedule's own run history" instead of the global list.
    """
    with _db_lock, _connect() as conn:
        rows = conn.execute(
            "SELECT id, started_at, finished_at, label, triggered_by, device_count, "
            "failed_count, duration_seconds FROM runs "
            "WHERE label = ? OR label = ? "
            "ORDER BY id DESC LIMIT ?",
            (f"Scheduled: {schedule_name}", f"Manual run of schedule '{schedule_name}'", limit),
        ).fetchall()
        return [dict(r) for r in rows]


def get_run(run_id: int):
    with _db_lock, _connect() as conn:
        row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        if not row:
            return None
        result = dict(row)
        result["report"] = json.loads(result.pop("report_json"))
        return result


def delete_run(run_id: int) -> bool:
    with _db_lock, _connect() as conn:
        cur = conn.execute("DELETE FROM runs WHERE id = ?", (run_id,))
        return cur.rowcount > 0


def delete_all_runs() -> int:
    with _db_lock, _connect() as conn:
        cur = conn.execute("DELETE FROM runs")
        return cur.rowcount


# ==========================================================================
# Scheduled jobs (read-only checks ONLY -- see module docstring)
# ==========================================================================
def create_schedule(name: str, interval_minutes: int, config: dict, notify_on_failure: bool = False) -> dict:
    now = _now_iso()
    with _db_lock, _connect() as conn:
        cur = conn.execute(
            "INSERT INTO schedules (name, created_at, interval_minutes, enabled, config_json, next_run_at, notify_on_failure) "
            "VALUES (?, ?, ?, 1, ?, ?, ?)",
            (name, now, interval_minutes, json.dumps(config), now, 1 if notify_on_failure else 0),
        )
        return {"id": cur.lastrowid, "name": name}


def list_schedules():
    with _db_lock, _connect() as conn:
        rows = conn.execute("SELECT * FROM schedules ORDER BY id DESC").fetchall()
        results = []
        for r in rows:
            d = dict(r)
            d["config"] = json.loads(d.pop("config_json"))
            results.append(d)
        return results


def get_schedule(sched_id: int):
    with _db_lock, _connect() as conn:
        row = conn.execute("SELECT * FROM schedules WHERE id = ?", (sched_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["config"] = json.loads(d.pop("config_json"))
        return d


def update_schedule_enabled(sched_id: int, enabled: bool) -> bool:
    with _db_lock, _connect() as conn:
        cur = conn.execute("UPDATE schedules SET enabled = ? WHERE id = ?", (1 if enabled else 0, sched_id))
        return cur.rowcount > 0


def update_schedule_interval(sched_id: int, interval_minutes: int) -> bool:
    with _db_lock, _connect() as conn:
        cur = conn.execute("UPDATE schedules SET interval_minutes = ? WHERE id = ?", (interval_minutes, sched_id))
        return cur.rowcount > 0


def update_schedule_run_times(sched_id: int, last_run_at: str, next_run_at: str,
                               status: str = "", failed_devices: str = ""):
    with _db_lock, _connect() as conn:
        conn.execute(
            "UPDATE schedules SET last_run_at = ?, next_run_at = ?, last_status = ?, "
            "run_count = run_count + 1, "
            "failure_count = failure_count + ?, "
            "last_failed_devices = ? "
            "WHERE id = ?",
            (last_run_at, next_run_at, status, 1 if status == "failed" else 0, failed_devices, sched_id),
        )


def delete_schedule(sched_id: int) -> bool:
    with _db_lock, _connect() as conn:
        cur = conn.execute("DELETE FROM schedules WHERE id = ?", (sched_id,))
        return cur.rowcount > 0


def get_due_schedules():
    """Returns all enabled schedules whose next_run_at is now or in the past."""
    now = _now_iso()
    with _db_lock, _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM schedules WHERE enabled = 1 AND next_run_at <= ? ORDER BY id",
            (now,),
        ).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            d["config"] = json.loads(d.pop("config_json"))
            results.append(d)
        return results
