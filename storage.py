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

import redaction  # local module -- shared secret-pattern/key redaction, see redaction.py

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
        # Discriminator added for the Audit scheduler-unification feature
        # (Phase 4 of the integration strategy): a schedule's `config_json`
        # shape is entirely different for the two job types (automation's
        # full validate_payload() shape vs audit's {profile_id, devices,
        # device_type, ...} shape), so every codepath that touches a
        # schedule's config must branch on job_type. Existing rows created
        # before this column existed default to 'automation' (their only
        # possible type at the time), so no backfill/migration is needed.
        _ensure_column(conn, "schedules", "job_type", "job_type TEXT NOT NULL DEFAULT 'automation'")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS rollback_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                vendor TEXT NOT NULL,
                before_config TEXT NOT NULL,
                created_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                used_at TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_templates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT DEFAULT '',
                template_text TEXT NOT NULL,
                category TEXT DEFAULT 'Custom',
                tags TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

        # Structural clone of `runs` (deliberately, see integration strategy
        # doc §3) so both the automation engine's history and the read-only
        # audit/inventory-collector engine's history can render through the
        # same UI code via a UNION ALL + `kind` discriminator, instead of
        # needing two separate history views.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                profile_name TEXT NOT NULL,
                triggered_by TEXT NOT NULL DEFAULT 'manual',
                inventory_name TEXT DEFAULT '',
                device_count INTEGER DEFAULT 0,
                ok_count INTEGER DEFAULT 0,
                issue_count INTEGER DEFAULT 0,
                output_format TEXT DEFAULT 'csv',
                output_path TEXT DEFAULT '',
                duration_seconds REAL,
                report_json TEXT NOT NULL
            )
        """)

        # Correlates an audit_runs row back to the schedule that triggered
        # it (Phase 4: scheduler unification) -- mirrors how `runs` instead
        # correlates via a "Scheduled: <name>" label-matching convention,
        # but a real foreign-key-style column is cleaner since audit_runs
        # is a table we own end-to-end in this integration.
        _ensure_column(conn, "audit_runs", "schedule_id", "schedule_id INTEGER")
        _ensure_column(conn, "audit_runs", "schedule_name", "schedule_name TEXT DEFAULT ''")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_runs_started_at ON runs(started_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_inventories_favorite ON inventories(favorite)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_rollback_host_port ON rollback_snapshots(host, port)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_runs_started_at ON audit_runs(started_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_runs_schedule_id ON audit_runs(schedule_id)")

    _enable_incremental_vacuum()


# ==========================================================================
# Automated database pruning & compaction
# ==========================================================================
# save_run()/save_audit_run() already PRUNE old rows beyond
# MAX_HISTORY_ENTRIES/MAX_AUDIT_HISTORY_ENTRIES (and
# save_rollback_snapshot() prunes beyond MAX_ROLLBACK_SNAPSHOTS_PER_DEVICE),
# but a plain SQLite DELETE does not shrink the .db file on disk -- the
# freed pages are simply marked "free" and reused by FUTURE inserts,
# which is fine for steady-state size but means the file only ever grows
# (never shrinks) relative to its all-time peak. Over months of daily
# scheduled runs being pruned back down to the same row count, the file
# itself never gets smaller.
#
# SQLite's `auto_vacuum = INCREMENTAL` mode tracks freed pages and lets
# `PRAGMA incremental_vacuum` reclaim them cheaply and incrementally
# (unlike a full `VACUUM`, which rewrites the ENTIRE database file in one
# go -- slow and briefly needs up to 2x the disk space -- incremental
# vacuum only touches already-free pages a chunk at a time, so it's safe
# to run routinely without a noticeable pause).
def _enable_incremental_vacuum():
    """
    Switches the database to incremental-vacuum mode if it isn't
    already (a one-time, idempotent operation -- auto_vacuum mode is a
    property of the database FILE, not the connection, and switching
    modes on an existing database requires a one-time full VACUUM to
    take effect, which is why this only runs once, not on every
    startup). Safe to call every time init_db() runs; a no-op after the
    first successful call.
    """
    with _db_lock, _connect() as conn:
        current_mode = conn.execute("PRAGMA auto_vacuum").fetchone()[0]
        if current_mode == 2:  # 2 == INCREMENTAL, already configured
            return
        try:
            conn.execute("PRAGMA auto_vacuum = INCREMENTAL")
            # Changing auto_vacuum mode only takes effect after a VACUUM.
            # This one-time cost only happens once per database file,
            # ever (guarded by the auto_vacuum check above) -- every
            # subsequent startup just runs the cheap incremental_vacuum
            # below instead.
            conn.execute("VACUUM")
        except sqlite3.Error as exc:  # pragma: no cover - defensive, must never block startup
            print(f"[STORAGE] Could not enable incremental auto-vacuum (non-fatal): {exc}")


def compact_database(max_pages: int = 0) -> dict:
    """
    Reclaims disk space freed by pruned/deleted rows (old run history,
    rollback snapshots beyond their cap, deleted inventories/schedules,
    etc.) via `PRAGMA incremental_vacuum`. Called once at application
    startup (see app.py) -- cheap and safe to also call periodically
    (e.g. from the existing scheduler loop) if the database sees heavy
    churn, though startup-time is sufficient for this app's realistic
    usage pattern (a single local user, not a high-write-volume server).

    `max_pages=0` (the default) reclaims ALL currently-free pages in one
    call; a positive number limits how many pages are reclaimed in this
    call (useful if you want to spread the work across multiple calls
    instead of one potentially-larger one -- not needed at the modest
    scale this app operates at, but supported for completeness).

    Returns {freed_pages, page_size, freed_bytes, error} -- error is None
    on success. Never raises; a compaction failure is not allowed to
    prevent the app from starting.
    """
    try:
        with _db_lock, _connect() as conn:
            page_size = conn.execute("PRAGMA page_size").fetchone()[0]
            free_pages_before = conn.execute("PRAGMA freelist_count").fetchone()[0]
            if free_pages_before == 0:
                return {"freed_pages": 0, "page_size": page_size, "freed_bytes": 0, "error": None}
            conn.execute(f"PRAGMA incremental_vacuum({int(max_pages)})" if max_pages else "PRAGMA incremental_vacuum")
            free_pages_after = conn.execute("PRAGMA freelist_count").fetchone()[0]
        freed = max(0, free_pages_before - free_pages_after)
        return {"freed_pages": freed, "page_size": page_size, "freed_bytes": freed * page_size, "error": None}
    except sqlite3.Error as exc:  # pragma: no cover - defensive, must never block startup
        return {"freed_pages": 0, "page_size": 0, "freed_bytes": 0, "error": str(exc)}


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
    # Redact before persisting -- a manually-typed command's OUTPUT can
    # legitimately contain a plaintext secret (e.g. a backed-up
    # `show running-config` capturing "username bob secret hunter2", or
    # a device that echoes a password back in an error message) even
    # though the app never intentionally stores credentials. This is a
    # belt-and-suspenders net on top of the command-log-level redaction
    # already applied to logs/audit.log (see templates_engine's
    # sanitize_for_audit(), called at the point commands are logged) --
    # that one sanitizes the AUDIT LOG event; this one sanitizes the
    # REPORT that ends up sitting in automation_console.db long-term.
    sanitized_report = redaction.sanitize_structure(report)
    with _db_lock, _connect() as conn:
        cur = conn.execute(
            "INSERT INTO runs (started_at, finished_at, label, triggered_by, report_json, "
            "duration_seconds, device_count, failed_count, inventory_name) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (meta.get("started_at", _now_iso()), meta.get("finished_at"), label,
             triggered_by, json.dumps(sanitized_report), duration, device_count, failed_count, inventory_name),
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
# Audit run history (network_inventory_collector integration)
# ==========================================================================
# Deliberately mirrors the `runs` functions above 1:1 (save/list/get/delete)
# so the two histories can be merged with a simple UNION ALL for a unified
# "Recent Activity" view, rather than the UI needing two different shapes.
MAX_AUDIT_HISTORY_ENTRIES = 200


def save_audit_run(
    profile_name: str,
    report: dict,
    triggered_by: str = "manual",
    inventory_name: str = "",
    output_format: str = "csv",
    output_path: str = "",
    schedule_id: int = None,
    schedule_name: str = "",
) -> int:
    meta = report.get("meta", {})
    # Field-level `sensitive: true` redaction already happened upstream
    # (inventory_collector.fields.Field.redact(), applied per-value before
    # it's even placed in a row -- see collect.py), so audit report rows
    # are already safe by column. This is a second, structural pass (by
    # KEY name, e.g. if a future profile ever puts a raw credential under
    # a "password" key rather than through the Field/sensitive mechanism)
    # applied uniformly to every report_json before it's persisted.
    sanitized_report = redaction.sanitize_structure(report)
    with _db_lock, _connect() as conn:
        cur = conn.execute(
            "INSERT INTO audit_runs (started_at, finished_at, profile_name, triggered_by, "
            "inventory_name, device_count, ok_count, issue_count, output_format, output_path, "
            "duration_seconds, report_json, schedule_id, schedule_name) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                meta.get("started_at", _now_iso()), meta.get("finished_at"), profile_name,
                triggered_by, inventory_name, meta.get("device_count", 0),
                meta.get("ok_count", 0), meta.get("issue_count", 0),
                output_format, output_path, meta.get("duration_seconds"),
                json.dumps(sanitized_report), schedule_id, schedule_name,
            ),
        )
        run_id = cur.lastrowid
        conn.execute(
            "DELETE FROM audit_runs WHERE id NOT IN "
            "(SELECT id FROM audit_runs ORDER BY id DESC LIMIT ?)",
            (MAX_AUDIT_HISTORY_ENTRIES,),
        )
    return run_id


def get_audit_schedule_run_history(schedule_id: int, limit: int = 50):
    """Analogous to get_schedule_run_history() for automation schedules,
    but joins on the real schedule_id column instead of label-matching
    (audit_runs didn't exist yet when that label convention was chosen,
    so there was no reason to repeat its fragility here)."""
    with _db_lock, _connect() as conn:
        rows = conn.execute(
            "SELECT id, started_at, finished_at, profile_name, triggered_by, device_count, "
            "ok_count, issue_count, duration_seconds FROM audit_runs "
            "WHERE schedule_id = ? ORDER BY id DESC LIMIT ?",
            (schedule_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]


def list_audit_runs(limit: int = 50, profile_name: str = None):
    query = ("SELECT id, started_at, finished_at, profile_name, triggered_by, inventory_name, "
             "device_count, ok_count, issue_count, output_format, output_path, duration_seconds "
             "FROM audit_runs WHERE 1=1")
    params = []
    if profile_name:
        query += " AND profile_name = ?"
        params.append(profile_name)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with _db_lock, _connect() as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]


def get_audit_run(run_id: int):
    with _db_lock, _connect() as conn:
        row = conn.execute("SELECT * FROM audit_runs WHERE id = ?", (run_id,)).fetchone()
        if not row:
            return None
        result = dict(row)
        result["report"] = json.loads(result.pop("report_json"))
        return result


def delete_audit_run(run_id: int) -> bool:
    with _db_lock, _connect() as conn:
        cur = conn.execute("DELETE FROM audit_runs WHERE id = ?", (run_id,))
        return cur.rowcount > 0


def delete_all_audit_runs() -> int:
    with _db_lock, _connect() as conn:
        cur = conn.execute("DELETE FROM audit_runs")
        return cur.rowcount


def list_unified_activity(limit: int = 50):
    """
    UNION ALL across `runs` and `audit_runs`, newest first, tagged with a
    `kind` discriminator ('automation' | 'audit') -- backs the Overview
    dashboard's single interleaved Recent Activity feed (see integration
    strategy doc's "unified Recent Activity feed" design), so the caller
    never has to merge/sort two separate lists client-side.
    """
    with _db_lock, _connect() as conn:
        rows = conn.execute(
            """
            SELECT * FROM (
                SELECT id, started_at, finished_at, label AS title, triggered_by,
                       inventory_name, device_count, failed_count AS issue_count,
                       duration_seconds, 'automation' AS kind
                FROM runs
                UNION ALL
                SELECT id, started_at, finished_at, profile_name AS title, triggered_by,
                       inventory_name, device_count, issue_count,
                       duration_seconds, 'audit' AS kind
                FROM audit_runs
            )
            ORDER BY started_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_unified_trend(days: int = 14):
    """
    Day-by-day time series (oldest first) of automation-run counts AND
    audit-run counts side by side, for the Overview dashboard's merged
    14-day trend chart (see integration strategy doc §5, "merged 14-day
    trend chart"). Distinct from get_history_trend() (automation-only,
    used by the History tab's own chart, which also tracks failures/avg
    duration in more detail) -- this one is deliberately just "how much
    activity happened, of which kind" for an at-a-glance dashboard widget.
    """
    with _db_lock, _connect() as conn:
        auto_rows = conn.execute(
            "SELECT substr(started_at, 1, 10) AS day, COUNT(*) AS total FROM runs "
            "WHERE started_at >= date('now', ?) GROUP BY day",
            (f"-{days} days",),
        ).fetchall()
        audit_rows = conn.execute(
            "SELECT substr(started_at, 1, 10) AS day, COUNT(*) AS total FROM audit_runs "
            "WHERE started_at >= date('now', ?) GROUP BY day",
            (f"-{days} days",),
        ).fetchall()
    auto_by_day = {r["day"]: r["total"] for r in auto_rows}
    audit_by_day = {r["day"]: r["total"] for r in audit_rows}

    from datetime import date, timedelta
    today = date.today()
    series = []
    for i in range(days - 1, -1, -1):
        day = (today - timedelta(days=i)).isoformat()
        series.append({
            "day": day,
            "automation": auto_by_day.get(day, 0),
            "audit": audit_by_day.get(day, 0),
        })
    return series


def get_dashboard_summary():
    """
    Single-call aggregate for the Overview dashboard's "At a Glance" stat
    cards -- deliberately its own function (rather than making the
    frontend call 4-5 separate endpoints and assemble this itself) so the
    dashboard's definition of "the latest run of each kind" lives in one
    place, in Python, next to the queries it depends on.
    """
    with _db_lock, _connect() as conn:
        inventory_count = conn.execute("SELECT COUNT(*) AS c FROM inventories").fetchone()["c"]
        total_devices = conn.execute("SELECT COALESCE(SUM(device_count), 0) AS c FROM inventories").fetchone()["c"]
        active_schedules = conn.execute("SELECT COUNT(*) AS c FROM schedules WHERE enabled = 1").fetchone()["c"]
        total_schedules = conn.execute("SELECT COUNT(*) AS c FROM schedules").fetchone()["c"]

        last_run_row = conn.execute(
            "SELECT device_count, failed_count, started_at FROM runs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        last_audit_row = conn.execute(
            "SELECT device_count, ok_count, issue_count, started_at, profile_name FROM audit_runs "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()

    return {
        "inventory_count": inventory_count,
        "total_devices": total_devices,
        "active_schedules": active_schedules,
        "total_schedules": total_schedules,
        "last_automation_run": dict(last_run_row) if last_run_row else None,
        "last_audit_run": dict(last_audit_row) if last_audit_row else None,
    }


# ==========================================================================
# Scheduled jobs (read-only checks ONLY -- see module docstring)
# ==========================================================================
def create_schedule(name: str, interval_minutes: int, config: dict, notify_on_failure: bool = False,
                     job_type: str = "automation") -> dict:
    now = _now_iso()
    with _db_lock, _connect() as conn:
        cur = conn.execute(
            "INSERT INTO schedules (name, created_at, interval_minutes, enabled, config_json, next_run_at, "
            "notify_on_failure, job_type) VALUES (?, ?, ?, 1, ?, ?, ?, ?)",
            (name, now, interval_minutes, json.dumps(config), now, 1 if notify_on_failure else 0, job_type),
        )
        return {"id": cur.lastrowid, "name": name, "job_type": job_type}


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


# ==========================================================================
# Rollback safety net
# ==========================================================================
# Every config-mode run automatically snapshots each device's FULL
# running-config immediately before any changes are applied (independent
# of the optional before/after diff feature) and stores it here. If a
# change turns out to be bad, "Rollback" re-pushes that snapshot's
# config-mode commands to restore the device -- see rollback_helpers in
# app.py for the actual device-side replay logic; this module only
# stores/retrieves the snapshot text itself.
MAX_ROLLBACK_SNAPSHOTS_PER_DEVICE = 10


def save_rollback_snapshot(host: str, port: int, vendor: str, before_config: str, run_id: int = None) -> int:
    now = _now_iso()
    with _db_lock, _connect() as conn:
        cur = conn.execute(
            "INSERT INTO rollback_snapshots (run_id, host, port, vendor, before_config, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (run_id, host, port, vendor, before_config, now),
        )
        snap_id = cur.lastrowid
        # Keep only the N most recent snapshots per device so this table
        # doesn't grow unbounded on a heavily-automated device.
        conn.execute(
            "DELETE FROM rollback_snapshots WHERE host = ? AND port = ? AND id NOT IN "
            "(SELECT id FROM rollback_snapshots WHERE host = ? AND port = ? ORDER BY id DESC LIMIT ?)",
            (host, port, host, port, MAX_ROLLBACK_SNAPSHOTS_PER_DEVICE),
        )
        return snap_id


def list_rollback_snapshots(host: str = None, port: int = None, limit: int = 50):
    query = "SELECT id, run_id, host, port, vendor, created_at, used, used_at, length(before_config) AS size_chars FROM rollback_snapshots WHERE 1=1"
    params = []
    if host:
        query += " AND host = ?"
        params.append(host)
    if port:
        query += " AND port = ?"
        params.append(port)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with _db_lock, _connect() as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]


def get_rollback_snapshot(snap_id: int):
    with _db_lock, _connect() as conn:
        row = conn.execute("SELECT * FROM rollback_snapshots WHERE id = ?", (snap_id,)).fetchone()
        return dict(row) if row else None


def mark_rollback_snapshot_used(snap_id: int):
    with _db_lock, _connect() as conn:
        conn.execute(
            "UPDATE rollback_snapshots SET used = 1, used_at = ? WHERE id = ?",
            (_now_iso(), snap_id),
        )


def delete_rollback_snapshot(snap_id: int) -> bool:
    with _db_lock, _connect() as conn:
        cur = conn.execute("DELETE FROM rollback_snapshots WHERE id = ?", (snap_id,))
        return cur.rowcount > 0


# ==========================================================================
# App-wide settings (key/value store) -- currently used for global
# email/Slack alert configuration (see app.py's /settings/alerts routes).
# Secrets (SMTP password, Slack webhook URL) are stored encrypted the
# same way schedule/inventory credentials are, using the same Fernet key.
# ==========================================================================
def set_setting(key: str, value: dict):
    now = _now_iso()
    with _db_lock, _connect() as conn:
        conn.execute(
            "INSERT INTO settings (key, value_json, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at",
            (key, json.dumps(value), now),
        )


def get_setting(key: str, default=None):
    with _db_lock, _connect() as conn:
        row = conn.execute("SELECT value_json FROM settings WHERE key = ?", (key,)).fetchone()
        if not row:
            return default
        try:
            return json.loads(row["value_json"])
        except Exception:
            return default


# ==========================================================================
# User-saved custom templates (Jinja2 text saved under a name so it shows
# up alongside the built-in template library instead of being retyped/
# re-pasted every time -- see templates_engine.py for rendering/validation)
# ==========================================================================
def save_user_template(name: str, template_text: str, description: str = "",
                        category: str = "Custom", tags: str = "") -> dict:
    """Insert or overwrite (by unique name) a saved custom template."""
    now = _now_iso()
    with _db_lock, _connect() as conn:
        existing = conn.execute("SELECT id FROM user_templates WHERE name = ?", (name,)).fetchone()
        if existing:
            conn.execute(
                "UPDATE user_templates SET template_text = ?, description = ?, category = ?, "
                "tags = ?, updated_at = ? WHERE id = ?",
                (template_text, description, category, tags, now, existing["id"]),
            )
            tid = existing["id"]
        else:
            cur = conn.execute(
                "INSERT INTO user_templates (name, description, template_text, category, tags, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (name, description, template_text, category, tags, now, now),
            )
            tid = cur.lastrowid
    return {"id": tid, "name": name, "updated_at": now}


def list_user_templates():
    with _db_lock, _connect() as conn:
        rows = conn.execute(
            "SELECT id, name, description, category, tags, created_at, updated_at FROM user_templates "
            "ORDER BY updated_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def get_user_template(tid: int):
    with _db_lock, _connect() as conn:
        row = conn.execute("SELECT * FROM user_templates WHERE id = ?", (tid,)).fetchone()
        return dict(row) if row else None


def delete_user_template(tid: int) -> bool:
    with _db_lock, _connect() as conn:
        cur = conn.execute("DELETE FROM user_templates WHERE id = ?", (tid,))
        return cur.rowcount > 0
