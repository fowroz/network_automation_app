"""
========================================================================
 Professional logging setup for the Network Automation Console
========================================================================
Two separate log streams, both written to a local ./logs/ folder (created
automatically) next to app.py, in addition to the normal console output
you already see when running `python app.py`:

  logs/app.log    -- general application log (INFO+ by default; every
                     run start/finish, per-device connect attempts,
                     auth failures, schedule fires, alert deliveries,
                     errors/tracebacks). Rotates at 5MB x 5 backups so
                     it never grows unbounded.

  logs/audit.log  -- a compact, one-line-per-event AUDIT TRAIL specifically
                     for anything that could change a device's state:
                     every individual command sent in config-mode, every
                     backup taken, every rollback performed, who/what
                     triggered it (manual vs schedule), and whether it
                     succeeded. Written as JSON Lines (one JSON object per
                     line) so it's trivially greppable/parseable for
                     compliance review later, independent of the more
                     chatty app.log. Also rotates (5MB x 10 backups, kept
                     longer since it's smaller/more valuable).

Both are plain stdlib `logging` -- no extra packages required. Set the
environment variable AUTOMATION_LOG_LEVEL=DEBUG before starting the app
for verbose troubleshooting output (default: INFO).
========================================================================
"""
import json
import logging
import logging.handlers
import os
import threading
from datetime import datetime, timezone

APP_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(APP_DIR, "logs")
APP_LOG_PATH = os.path.join(LOG_DIR, "app.log")
AUDIT_LOG_PATH = os.path.join(LOG_DIR, "audit.log")

_setup_lock = threading.Lock()
_configured = False
_audit_logger = None
app_logger = logging.getLogger("netauto")


def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def setup_logging():
    """
    Idempotent -- safe to call multiple times (e.g. Flask's reloader
    re-executing this module). Only configures handlers once.
    """
    global _configured, _audit_logger
    with _setup_lock:
        if _configured:
            return app_logger

        os.makedirs(LOG_DIR, exist_ok=True)
        level_name = os.environ.get("AUTOMATION_LOG_LEVEL", "INFO").upper()
        level = getattr(logging, level_name, logging.INFO)

        fmt = logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(threadName)-14s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        app_logger.setLevel(level)
        app_logger.propagate = False

        file_handler = logging.handlers.RotatingFileHandler(
            APP_LOG_PATH, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8",
        )
        file_handler.setFormatter(fmt)
        file_handler.setLevel(level)
        app_logger.addHandler(file_handler)

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(fmt)
        console_handler.setLevel(level)
        app_logger.addHandler(console_handler)

        # Separate logger for the JSON-lines audit trail -- deliberately
        # NOT propagated to the console (would be noisy/duplicated) and
        # NOT using the human-readable formatter above, since each record
        # is already a complete JSON object written verbatim.
        audit_logger = logging.getLogger("netauto.audit")
        audit_logger.setLevel(logging.INFO)
        audit_logger.propagate = False
        audit_handler = logging.handlers.RotatingFileHandler(
            AUDIT_LOG_PATH, maxBytes=5 * 1024 * 1024, backupCount=10, encoding="utf-8",
        )
        audit_handler.setFormatter(logging.Formatter("%(message)s"))
        audit_logger.addHandler(audit_handler)
        _audit_logger = audit_logger

        _configured = True
        app_logger.info("=" * 70)
        app_logger.info("Logging initialized. Level=%s  app.log + audit.log in %s", level_name, LOG_DIR)
        app_logger.info("=" * 70)
        return app_logger


def get_logger():
    """Returns the shared application logger, configuring it on first use."""
    if not _configured:
        setup_logging()
    return app_logger


def log_audit(event_type: str, **fields):
    """
    Appends one JSON-line audit record. `event_type` is a short constant
    like 'config_command', 'backup', 'rollback', 'schedule_run',
    'alert_sent'. Any additional keyword fields are included verbatim
    (must be JSON-serializable -- callers should pass plain strings/
    numbers/bools/lists/dicts only). Never raises -- a failure to write
    an audit record should never take down an actual automation run.
    """
    if not _configured:
        setup_logging()
    try:
        record = {"ts": _now_iso(), "event": event_type}
        record.update(fields)
        _audit_logger.info(json.dumps(record, default=str))
    except Exception as exc:  # pragma: no cover - defensive, logging must never crash the app
        app_logger.warning("Failed to write audit record (%s): %s", event_type, exc)


def tail_log_file(which: str, lines: int = 200):
    """
    Returns the last `lines` lines of either the 'app' or 'audit' log
    file as a single string, or an error message if the file doesn't
    exist yet (e.g. brand new install, nothing logged yet). Reads the
    whole file (these logs are capped at a few MB by rotation, so this
    stays fast) then keeps only the tail -- simplest correct approach
    for a local single-user tool.
    """
    path = APP_LOG_PATH if which == "app" else AUDIT_LOG_PATH if which == "audit" else None
    if path is None:
        return f"Unknown log '{which}'. Expected 'app' or 'audit'."
    if not os.path.exists(path):
        return "(no log entries yet)"
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()
        return "".join(all_lines[-lines:]) if all_lines else "(empty)"
    except Exception as exc:
        return f"Could not read log file: {exc}"
