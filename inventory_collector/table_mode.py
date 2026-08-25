"""
Table mode (§3.5) -- "1 row per sub-object" collection, e.g. one CSV row
per interface instead of one row per device. Only usable with
`parser: textfsm` (a regex has no natural notion of "a list of objects"),
since TextFSM/ntc-templates already returns a list-of-dicts per command,
which maps directly onto "one output row per dict".

Distinct from the per-field regex/TextFSM extraction in fields.py:
table mode's `iterate` block runs ONE command per device and turns its
*entire* parsed record list into rows, copying a handful of "row_prefix"
values (usually simple device-mode fields, e.g. hostname/mgmt_ip)
onto every resulting row so the sub-objects stay attributable to their
parent device.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Callable, Optional

from .collect import STATUS_ERROR, STATUS_OK, STATUS_UNREACHABLE, STATUS_AUTH_FAILED, DeviceConnection, default_connect
from .credentials import CredentialResolutionError
from .profile import Profile
from .textfsm_support import parse_with_custom_template, parse_with_ntc_templates

LOG = logging.getLogger("collector.table_mode")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def collect_device_table(
    device: dict,
    profile: Profile,
    credentials: dict,
    connect_fn: Callable[[dict, dict, float], DeviceConnection] = default_connect,
    connect_timeout: float = 30,
    command_timeout: float = 60,
) -> dict:
    """
    Runs a table-mode profile's `iterate.command` against ONE device and
    returns {"status": ..., "error": ..., "rows": [ {col: val, ...}, ... ]}.

    Every produced row additionally carries whatever `row_prefix` columns
    are configured (resolved from `device` -- e.g. row_prefix: [ip, site]
    pulls straight from the inventory row; row_prefix names that aren't
    inventory columns are left blank rather than raising, since the
    "richer" case of deriving them from OTHER device-mode fields first is
    intentionally left to a future integration between the two modes).
    """
    iterate_cmd = profile.iterate_cfg.get("command")
    parser = profile.iterate_cfg.get("parser", "textfsm")
    textfsm_template = profile.iterate_cfg.get("textfsm_template")
    row_prefix_cols = profile.row_prefix
    data_columns = profile.table_columns

    result = {"status": STATUS_OK, "error": "", "rows": []}
    conn: Optional[DeviceConnection] = None
    try:
        conn = connect_fn(device, credentials, connect_timeout)
        raw_output = conn.send_command(iterate_cmd, read_timeout=command_timeout) or ""

        if parser == "textfsm":
            if textfsm_template:
                records = parse_with_custom_template(textfsm_template, raw_output)
            else:
                records = parse_with_ntc_templates(device.get("device_type", ""), iterate_cmd, raw_output)
        else:
            raise ValueError(f"Table mode only supports parser: textfsm currently (got '{parser}').")

        prefix_values = {col: device.get(col, "") for col in row_prefix_cols}
        for record in records:
            row = dict(prefix_values)
            for col in data_columns:
                value = record.get(col, "")
                if isinstance(value, list):
                    value = "; ".join(str(v) for v in value)
                row[col] = value
            row["TIMESTAMP"] = _now_iso()
            row["TARGET_IP"] = device.get("ip", "")
            result["rows"].append(row)

    except CredentialResolutionError as exc:
        result["status"] = STATUS_AUTH_FAILED
        result["error"] = str(exc)[:200]
    except Exception as exc:
        try:
            from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
        except ImportError:  # pragma: no cover
            NetmikoAuthenticationException = NetmikoTimeoutException = ()  # type: ignore
        if NetmikoAuthenticationException and isinstance(exc, NetmikoAuthenticationException):
            result["status"] = STATUS_AUTH_FAILED
        elif NetmikoTimeoutException and isinstance(exc, NetmikoTimeoutException):
            result["status"] = STATUS_UNREACHABLE
        else:
            result["status"] = STATUS_ERROR
        result["error"] = f"{type(exc).__name__}: {exc}"[:200]
    finally:
        if conn is not None:
            try:
                conn.disconnect()
            except Exception as exc:  # pragma: no cover
                LOG.debug("[%s] error while disconnecting (ignored): %s", device.get("ip"), exc)

    LOG.info("[%s] table-mode: %s, %d row(s)", device.get("ip"), result["status"], len(result["rows"]))
    return result
