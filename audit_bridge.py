"""
========================================================================
 Audit Bridge -- integrates network_inventory_collector as a library
========================================================================
Phase 1 ("Plumbing") of the integration strategy documented at
/home/user/integration_strategy/INTEGRATION_STRATEGY.md: the read-only,
YAML-profile-driven inventory/audit collector is imported directly as a
Python package (`inventory_collector/`, vendored alongside this app --
see that package's own docstrings for FR-*/NFR-*/AC-* references) rather
than run as a second process or shelled out to. This keeps everything in
ONE Flask process with ONE scheduler/thread-pool, per the architecture
decision in the strategy doc.

This module is deliberately the ONLY place in the automation app that
imports `inventory_collector.*` -- if the vendored collector package is
ever upgraded or swapped, this is the seam that needs to change.

NAMING (see integration strategy doc, "naming disambiguation" section):
    - the automation app's "Inventories" (saved device list + creds)
      are reused here as an Audit run's device source ("Audit Targets"
      in the UI) via `devices_from_automation_payload()`.
    - the collector's YAML manifests are called "Audit Profiles" in the
      UI (matching the collector's own internal `Profile` class name),
      to avoid colliding with the automation app's unrelated "Config
      Templates" (Jinja2 push templates).
========================================================================
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from pathlib import Path

from inventory_collector import output as collector_output
from inventory_collector.collect import STATUS_OK, default_connect
from inventory_collector.profile import Profile, ProfileError, load_profile
from inventory_collector.runner import run_device_mode, run_table_mode

APP_DIR = os.path.dirname(os.path.abspath(__file__))
PROFILES_DIR = os.path.join(APP_DIR, "audit_profiles")
REPORTS_DIR = os.path.join(APP_DIR, "reports")


class AuditBridgeError(RuntimeError):
    """Raised for any structural problem discovered before contacting a
    device (bad/unknown profile, empty device list, etc.) -- mirrors the
    automation app's own validate_payload() pattern of failing fast with
    one clear, user-facing message instead of a traceback."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ==========================================================================
# Profile discovery
# ==========================================================================
def list_profiles() -> list:
    """
    Returns a list of dicts describing every *.yaml/*.yml file under
    audit_profiles/, e.g.:
        {id, name, mode, output_format, field_count, enabled_field_count,
         columns, unique_commands, valid, error}
    A structurally broken profile is reported inline (valid=False, error=
    "...") rather than raising, so one bad YAML file doesn't take down the
    whole Audit tab's profile picker.
    """
    results = []
    if not os.path.isdir(PROFILES_DIR):
        return results
    for fname in sorted(os.listdir(PROFILES_DIR)):
        if not fname.lower().endswith((".yaml", ".yml")):
            continue
        path = Path(PROFILES_DIR) / fname
        entry = {"id": fname, "path": str(path)}
        try:
            profile = load_profile(path)
            entry.update({
                "name": profile.name,
                "mode": profile.mode,
                "output_format": profile.output_format,
                "valid": True,
                "error": None,
            })
            if profile.mode == "device":
                entry["field_count"] = len(profile.fields)
                entry["enabled_field_count"] = len(profile.enabled_fields())
                entry["columns"] = [f.column for f in profile.enabled_fields()]
                entry["unique_commands"] = sorted(profile.unique_commands())
            else:
                entry["field_count"] = len(profile.table_columns)
                entry["enabled_field_count"] = entry["field_count"]
                entry["columns"] = list(profile.row_prefix) + list(profile.table_columns)
                entry["unique_commands"] = [profile.iterate_cfg.get("command")]
        except ProfileError as exc:
            entry.update({
                "name": fname, "mode": None, "output_format": None,
                "valid": False, "error": str(exc),
                "field_count": 0, "enabled_field_count": 0,
                "columns": [], "unique_commands": [],
            })
        results.append(entry)
    return results


def get_profile(profile_id: str) -> Profile:
    """Loads one profile by its filename (`id`), refusing anything that
    would escape audit_profiles/ (defense in depth -- profile_id always
    comes from a dropdown populated by list_profiles() above, but a
    direct API call shouldn't be able to path-traverse regardless)."""
    if not profile_id or "/" in profile_id or "\\" in profile_id or profile_id.startswith("."):
        raise AuditBridgeError(f"Invalid audit profile id '{profile_id}'.")
    path = (Path(PROFILES_DIR) / profile_id).resolve()
    if path.parent != Path(PROFILES_DIR).resolve() or not path.exists():
        raise AuditBridgeError(f"Unknown audit profile '{profile_id}'.")
    try:
        return load_profile(path)
    except ProfileError as exc:
        raise AuditBridgeError(str(exc)) from exc


# ==========================================================================
# Inventory bridge: automation-app device shape -> collector device shape
# ==========================================================================
def devices_from_automation_payload(devices: list, device_type: str,
                                     shared_username: str = "", shared_password: str = "") -> list:
    """
    Converts the automation app's device-list shape (`host`/`port`/
    optional per-device `username`/`password`, exactly as saved in a
    device Inventory or typed into the Run tab) into the collector's
    expected device-row shape (`ip`/`device_type`/`port`/`username`/
    `password`).

    A per-device username/password (e.g. a mixed-credential CSV upload)
    always takes priority over the shared audit-wide credentials --
    identical fallback order to the automation engine's own
    `effective_username`/`effective_password` logic in run_device_checks(),
    so the same saved Inventory behaves the same way whether it's used to
    run automation or an audit.
    """
    rows = []
    for d in devices:
        row = {
            "ip": d.get("host", ""),
            "device_type": device_type,
            "port": d.get("port", 22),
        }
        username = d.get("username") or shared_username
        password = d.get("password") or shared_password
        if username:
            row["username"] = username
        if password:
            row["password"] = password
        rows.append(row)
    return rows


# ==========================================================================
# Running an audit
# ==========================================================================
def _build_meta(started_at: str, device_count: int, rows: list, duration: float, mode: str) -> dict:
    if mode == "device":
        ok_count = sum(1 for r in rows if r.get("STATUS") == STATUS_OK)
        issue_count = len(rows) - ok_count
    else:
        # Table mode's run_table_mode() flattens successful devices' rows
        # only and currently discards per-device status on failure (a
        # known upstream limitation of inventory_collector's table-mode
        # runner) -- ok/issue counts aren't meaningful per-row here, so we
        # report device_count/row_count instead of a misleading OK split.
        ok_count = None
        issue_count = None
    return {
        "started_at": started_at,
        "finished_at": _now_iso(),
        "duration_seconds": duration,
        "device_count": device_count,
        "row_count": len(rows),
        "ok_count": ok_count,
        "issue_count": issue_count,
    }


def run_audit(
    profile_id: str,
    devices: list,
    device_type: str,
    shared_username: str = "",
    shared_password: str = "",
    workers: int = 10,
    write_report_file: bool = False,
    progress_cb=None,
) -> dict:
    """
    Runs one audit profile against `devices` (already in automation-app
    shape: [{host, port, [username], [password]}, ...]) and returns a
    structured report dict:
        {meta, mode, profile_id, profile_name, output_format,
         output_path, columns, rows}

    Never prompts for credentials (`allow_prompt=False`, since a web
    request thread must never block on interactive input) -- a device
    with no resolvable username/password is reported as AUTH_FAILED like
    any other per-device failure (FR-4), not a hang or a 500.

    `progress_cb(completed, total)`, if given, is forwarded straight to
    inventory_collector.runner's own progress hook -- used by app.py to
    drive the Overview dashboard's persistent global run indicator
    (Phase 6) without this module needing to know about Flask/threading
    globals at all.

    `write_report_file` defaults to False (on-demand generation, see
    "Data Management & Reporting Lifecycle" below) -- `output_path` in
    the returned dict is None unless the caller explicitly opts into a
    physical file on disk. The row/column DATA is always returned either
    way, and `storage.save_audit_run()` already persists the full
    report_json to SQLite, which is the actual durable source of truth
    for a completed run -- see render_report_bytes() below for how a
    downloadable file is produced on demand from that JSON instead.
    """
    profile = get_profile(profile_id)

    if not isinstance(devices, list) or not devices:
        raise AuditBridgeError("At least one device is required to run an audit.")

    collector_devices = devices_from_automation_payload(devices, device_type, shared_username, shared_password)

    started_at = _now_iso()
    t0 = time.time()

    if profile.mode == "table":
        rows = run_table_mode(collector_devices, profile, workers=workers, allow_prompt=False,
                               connect_fn=default_connect, progress_cb=progress_cb)
        columns = list(profile.row_prefix) + list(profile.table_columns)
    else:
        rows = run_device_mode(collector_devices, profile, workers=workers, allow_prompt=False,
                                connect_fn=default_connect, progress_cb=progress_cb)
        rows.sort(key=lambda r: r.get("TARGET_IP", ""))
        columns = [f.column for f in profile.enabled_fields()]

    duration = round(time.time() - t0, 2)
    meta = _build_meta(started_at, len(devices), rows, duration, profile.mode)

    # write_report_file=True is kept ONLY for anyone extending this
    # module outside the web app (e.g. a script that genuinely wants a
    # persistent file each run) -- the Flask routes in app.py never pass
    # it, precisely to avoid the "reports/ fills up over months of
    # scheduled runs" problem this on-demand-generation change fixes.
    output_path = None
    if write_report_file:
        try:
            os.makedirs(REPORTS_DIR, exist_ok=True)
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            out_path = Path(REPORTS_DIR) / f"{profile.name}_{stamp}.{profile.output_format}"
            if profile.output_format == "json":
                collector_output.write_json(rows, out_path, mode="overwrite")
            elif profile.output_format == "xlsx":
                collector_output.write_xlsx(rows, columns, out_path, sheet_name=profile.name[:31],
                                             mode="overwrite", include_metadata=profile.include_metadata)
            else:
                collector_output.write_csv(rows, columns, out_path, mode="overwrite",
                                            include_metadata=profile.include_metadata)
            output_path = str(out_path)
        except Exception:
            output_path = None  # the report is still returned/rendered even if the file write failed

    return {
        "meta": meta,
        "mode": profile.mode,
        "profile_id": profile_id,
        "profile_name": profile.name,
        "output_format": profile.output_format,
        "output_path": output_path,
        "columns": columns,
        "rows": rows,
    }


def render_report_bytes(report: dict) -> tuple:
    """
    Generates a downloadable report file IN MEMORY from an already-
    completed report dict (as returned by run_audit(), or reconstructed
    from a stored audit_runs row's report_json) -- no disk write at all.
    Returns (bytes, mimetype, filename_suggestion).

    This is what /audit/history/<id>/download calls: the on-disk
    report.output_path field (almost always None now that
    write_report_file defaults to False) is no longer the source of
    truth for "can this run still be downloaded" -- the report_json
    already sitting in automation_console.db is, and always will be for
    as long as that history row exists (governed by
    MAX_AUDIT_HISTORY_ENTRIES, same as every other retained run).
    """
    fmt = (report.get("output_format") or "csv").lower()
    columns = report.get("columns") or []
    rows = report.get("rows") or []
    include_metadata = report.get("mode") != "table"  # table-mode rows already carry TARGET_IP/TIMESTAMP
    profile_name = report.get("profile_name") or "audit_report"

    if fmt == "json":
        data = collector_output.render_json_bytes(rows)
        return data, "application/json", f"{profile_name}.json"
    if fmt == "xlsx":
        data = collector_output.render_xlsx_bytes(rows, columns, sheet_name=profile_name,
                                                    include_metadata=include_metadata)
        return data, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", f"{profile_name}.xlsx"
    data = collector_output.render_csv_bytes(rows, columns, include_metadata=include_metadata)
    return data, "text/csv", f"{profile_name}.csv"


# ==========================================================================
# Overview dashboard: Health & Compliance Snapshot (Phase 5)
# ==========================================================================
# Deliberately keyed off the exact column names the built-in security_audit
# / capacity_audit profiles declare (see audit_profiles/*.yaml) -- this is
# the one place in the integration that "knows" what those two specific
# profiles look like, rather than the Overview dashboard being a fully
# generic report viewer. If a user edits/replaces those YAML files with
# different column names, these findings simply stop appearing (no error)
# since every lookup below is a soft .get() with a safe fallback.
CPU_WARN_THRESHOLD_PERCENT = 80.0


def derive_compliance_findings(security_report: dict = None, capacity_report: dict = None) -> list:
    """
    Scans the most recent security_audit / capacity_audit reports (as
    returned by run_audit(), or reconstructed from a stored audit_runs
    row's `report_json`) for a small set of known-interesting conditions,
    returning a list of finding dicts:
        {severity: "warn"|"ok", text, link_view, fixable_with_template}
    `link_view` names the tab the Overview dashboard should cross-link to
    (see integration strategy doc's "⚡ Act on this" cross-linking design).
    Returns an empty list (not an error) if no reports are available yet.
    """
    findings = []

    if security_report:
        rows = security_report.get("rows", [])
        # transport input value examples: "ssh" (good), "telnet" / "all" /
        # "telnet ssh" (telnet still permitted) -- flag anything that
        # mentions telnet or allows "all" transports.
        def _allows_telnet(value):
            v = str(value or "").strip().lower()
            return "telnet" in v or v == "all"

        telnet_hosts = [r.get("TARGET_IP") for r in rows if _allows_telnet(r.get("TELNET ENABLED ON VTY"))]
        if telnet_hosts:
            findings.append({
                "severity": "warn",
                "text": f"{len(telnet_hosts)} device(s) may have telnet enabled on VTY lines",
                "link_view": "auditView",
                "fixable_with_template": None,
            })

        no_pw_encryption = [r.get("TARGET_IP") for r in rows
                             if r.get("PASSWORD ENCRYPTION ON") in ("NO", None, "")
                             and r.get("STATUS") == "OK"]
        ok_count = sum(1 for r in rows if r.get("STATUS") == "OK")
        if no_pw_encryption:
            findings.append({
                "severity": "warn",
                "text": f"{len(no_pw_encryption)} device(s) do not have password-encryption enabled",
                "link_view": "auditView",
                "fixable_with_template": "custom",
            })
        elif ok_count:
            findings.append({
                "severity": "ok",
                "text": f"{ok_count}/{len(rows)} device(s) have password-encryption enabled",
                "link_view": None,
                "fixable_with_template": None,
            })

    if capacity_report:
        rows = capacity_report.get("rows", [])
        for r in rows:
            cpu_5min = r.get("CPU 5MIN %")
            if isinstance(cpu_5min, (int, float)) and cpu_5min >= CPU_WARN_THRESHOLD_PERCENT:
                findings.append({
                    "severity": "warn",
                    "text": f"{r.get('HOSTNAME') or r.get('TARGET_IP')}: CPU 5-min average at {cpu_5min}%",
                    "link_view": "auditView",
                    "fixable_with_template": None,
                })

    return findings


# ==========================================================================
# Report diffing across audit runs (compliance-history comparison)
# ==========================================================================
# Columns never worth showing in a diff even if their value technically
# changed -- they're metadata ABOUT the collection itself (when it ran),
# not about the device's state, and would otherwise make every device
# show up as "changed" on every single run.
_DIFF_IGNORE_COLUMNS = frozenset({"TIMESTAMP"})


def _row_key(row: dict) -> str:
    """Identifies "the same device" across two different runs. Prefers
    HOSTNAME (stable across DHCP/IP renumbering) when the profile
    collected one, falling back to TARGET_IP (always present)."""
    hostname = row.get("HOSTNAME")
    if hostname and hostname != "N/A":
        return str(hostname)
    return str(row.get("TARGET_IP", ""))


def diff_audit_runs(old_report: dict, new_report: dict) -> dict:
    """
    Compares two completed audit run reports (same or different
    profiles, though comparing runs of the SAME profile is the
    intended/meaningful use -- e.g. "hardware_audit from last week vs.
    today") and returns a structured diff:
        {
          old_run_meta: {profile_name, started_at},
          new_run_meta: {profile_name, started_at},
          columns: [...],                    # union of both reports' columns
          added_devices: [{key, row}, ...],   # present in new, not old
          removed_devices: [{key, row}, ...], # present in old, not new
          changed_devices: [
              {key, changes: {column: {old, new}}}, ...
          ],
          unchanged_count: int,
        }
    Device-mode reports only (table-mode reports don't have a stable
    natural key across runs -- an interface list -- so diffing them is
    out of scope here; the caller should guard against mode == "table").
    Never raises on merely-different columns between the two reports
    (e.g. comparing a profile before/after a field was added) -- a
    column present in only one side is still compared, treating its
    absence on the other side as a value of None.
    """
    old_rows = {_row_key(r): r for r in old_report.get("rows", [])}
    new_rows = {_row_key(r): r for r in new_report.get("rows", [])}
    all_columns = list(dict.fromkeys(
        list(old_report.get("columns", [])) + list(new_report.get("columns", []))
    ))

    old_keys = set(old_rows)
    new_keys = set(new_rows)

    added_devices = [{"key": k, "row": new_rows[k]} for k in sorted(new_keys - old_keys)]
    removed_devices = [{"key": k, "row": old_rows[k]} for k in sorted(old_keys - new_keys)]

    changed_devices = []
    unchanged_count = 0
    for key in sorted(old_keys & new_keys):
        old_row, new_row = old_rows[key], new_rows[key]
        changes = {}
        for col in all_columns:
            if col in _DIFF_IGNORE_COLUMNS:
                continue
            old_val = old_row.get(col)
            new_val = new_row.get(col)
            if old_val != new_val:
                changes[col] = {"old": old_val, "new": new_val}
        if changes:
            changed_devices.append({"key": key, "changes": changes})
        else:
            unchanged_count += 1

    return {
        "old_run_meta": {
            "profile_name": old_report.get("profile_name"),
            "started_at": old_report.get("meta", {}).get("started_at"),
        },
        "new_run_meta": {
            "profile_name": new_report.get("profile_name"),
            "started_at": new_report.get("meta", {}).get("started_at"),
        },
        "columns": all_columns,
        "added_devices": added_devices,
        "removed_devices": removed_devices,
        "changed_devices": changed_devices,
        "unchanged_count": unchanged_count,
    }
