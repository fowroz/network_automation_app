"""
Per-device collection engine.

This is where FR-2 (command de-duplication/caching), FR-4 (graceful
failure), and FR-5 (session hygiene) live: connect to a device ONCE, run
every unique command referenced by the profile's enabled fields EXACTLY
ONCE, extract every field from the appropriate cached command output, and
always disconnect -- regardless of whether extraction (or even the
connection itself) succeeded.

`collect_device()` is intentionally decoupled from Netmiko via a small
`connect_fn` seam (see `default_connect`) so tests can inject a fake
connection without touching the network (see tests/test_collect.py).
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Callable, Optional

from .credentials import CredentialResolutionError
from .fields import Field
from .profile import Profile
from .textfsm_support import parse_with_custom_template, parse_with_ntc_templates

LOG = logging.getLogger("collector.collect")

STATUS_OK = "OK"
STATUS_PARTIAL = "PARTIAL"
STATUS_UNREACHABLE = "UNREACHABLE"
STATUS_AUTH_FAILED = "AUTH_FAILED"
STATUS_ERROR = "ERROR"

META_COLUMNS = ["TIMESTAMP", "TARGET_IP", "STATUS", "MISSING_FIELDS", "ERROR"]


class DeviceConnection:
    """Minimal protocol a `connect_fn` must satisfy -- deliberately much
    narrower than Netmiko's full ConnectHandler surface, so a test double
    only needs to implement `send_command` and `disconnect`."""

    def send_command(self, command: str, read_timeout: float = 60) -> str:  # pragma: no cover - protocol only
        raise NotImplementedError

    def disconnect(self) -> None:  # pragma: no cover - protocol only
        raise NotImplementedError


def default_connect(device: dict, credentials: dict, timeout: float = 30) -> DeviceConnection:
    """Real Netmiko-backed connection factory -- the default `connect_fn`
    used outside of tests. Imports Netmiko lazily so the rest of this
    package (and its tests) can run without Netmiko installed if only the
    parsing/profile logic is being exercised."""
    from netmiko import ConnectHandler

    params = {
        "device_type": device["device_type"],
        "host": device["ip"],
        "username": credentials["username"],
        "password": credentials["password"],
        "port": int(device.get("port") or 22),
        "timeout": timeout,
        "banner_timeout": timeout,
        "auth_timeout": timeout,
    }
    if credentials.get("secret"):
        params["secret"] = credentials["secret"]
    return ConnectHandler(**params)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _empty_row(device: dict, fields: list) -> dict:
    row = {
        "TIMESTAMP": _now_iso(),
        "TARGET_IP": device.get("ip", ""),
        "STATUS": STATUS_OK,
        "MISSING_FIELDS": "",
        "ERROR": "",
    }
    for f in fields:
        row[f.column] = f.default
    return row


def _run_unique_commands(conn: DeviceConnection, commands: set, read_timeout: float, device_ip: str) -> dict:
    """FR-2: executes every unique command exactly once, returning
    {command: raw_output_text}. A single command's failure doesn't abort
    the others -- it's recorded as an empty string, which every Field's
    extraction path already treats as "no match" (-> default)."""
    cache = {}
    for cmd in sorted(commands):
        start = time.monotonic()
        try:
            LOG.debug("[%s] sending: %s", device_ip, cmd)
            output = conn.send_command(cmd, read_timeout=read_timeout)
            cache[cmd] = output or ""
            LOG.debug("[%s] '%s' completed in %.2fs, %d bytes of output",
                      device_ip, cmd, time.monotonic() - start, len(cache[cmd]))
        except Exception as exc:
            LOG.warning("[%s] command '%s' failed: %s", device_ip, cmd, exc)
            cache[cmd] = ""
    return cache


def _extract_field(field: Field, device_type: str, command_output: dict, command_records: dict) -> object:
    """Dispatches to regex- or TextFSM-based extraction for one field,
    using whichever raw/parsed cache already has this field's command."""
    if field.parser == "textfsm":
        if field.command not in command_records:
            records = []
            try:
                if field.textfsm_template:
                    records = parse_with_custom_template(field.textfsm_template, command_output.get(field.command, ""))
                else:
                    records = parse_with_ntc_templates(device_type, field.command, command_output.get(field.command, ""))
            except Exception as exc:
                LOG.warning("TextFSM parsing error for field '%s': %s", field.name, exc)
            command_records[field.command] = records
        return field.extract_from_records(command_records[field.command])
    return field.extract_from_text(command_output.get(field.command, ""))


def collect_device(
    device: dict,
    profile: Profile,
    credentials: dict,
    connect_fn: Callable[[dict, dict, float], DeviceConnection] = default_connect,
    connect_timeout: float = 30,
    command_timeout: float = 60,
) -> dict:
    """
    Connects to ONE device, collects every enabled+platform-applicable
    field, and ALWAYS disconnects (FR-5). Never raises -- any failure
    (auth, timeout, unexpected exception) is captured into the returned
    row's STATUS/ERROR columns instead (FR-4), so a caller can run this
    across many devices (e.g. from a thread pool) without needing its own
    try/except per device.
    """
    fields = profile.fields_for_platform(device.get("device_type", ""))
    row = _empty_row(device, fields)

    conn: Optional[DeviceConnection] = None
    try:
        conn = connect_fn(device, credentials, connect_timeout)

        unique_commands = {f.command for f in fields}
        command_output = _run_unique_commands(conn, unique_commands, command_timeout, device.get("ip", ""))
        command_records: dict = {}

        missing_required = []
        for f in fields:
            value = _extract_field(f, device.get("device_type", ""), command_output, command_records)
            row[f.column] = f.redact(value)
            if f.required and value == f.default:
                missing_required.append(f.name)

        if missing_required:
            row["STATUS"] = STATUS_PARTIAL
            row["MISSING_FIELDS"] = ",".join(missing_required)

    except Exception as exc:
        _classify_and_record_error(row, exc)
    finally:
        if conn is not None:
            try:
                conn.disconnect()
            except Exception as exc:  # pragma: no cover - best-effort cleanup only
                LOG.debug("[%s] error while disconnecting (ignored): %s", device.get("ip"), exc)

    LOG.info("[%s] %s%s", device.get("ip"), row["STATUS"],
              f" (missing: {row['MISSING_FIELDS']})" if row["MISSING_FIELDS"] else "")
    return row


def _classify_and_record_error(row: dict, exc: Exception) -> None:
    """Maps a raised exception to one of the FR-4 status values. Netmiko's
    exception classes are imported lazily/defensively so this still works
    (falling back to STATUS_ERROR) in a test environment without Netmiko."""
    try:
        from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
    except ImportError:  # pragma: no cover
        NetmikoAuthenticationException = NetmikoTimeoutException = ()  # type: ignore

    message = str(exc)[:200]
    if isinstance(exc, CredentialResolutionError):
        row["STATUS"] = STATUS_AUTH_FAILED
    elif NetmikoAuthenticationException and isinstance(exc, NetmikoAuthenticationException):
        row["STATUS"] = STATUS_AUTH_FAILED
    elif NetmikoTimeoutException and isinstance(exc, NetmikoTimeoutException):
        row["STATUS"] = STATUS_UNREACHABLE
    else:
        row["STATUS"] = STATUS_ERROR
        message = f"{type(exc).__name__}: {message}"
    row["ERROR"] = message
