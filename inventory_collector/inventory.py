"""
Device inventory loading & filtering (FR-1).

The device list always comes from an external CSV (or YAML list) file --
never hardcoded in Python. Expected CSV columns:
    ip, device_type, username, password, port, site, role
`username`/`password` are optional per-row (see credentials.py for the
fallback chain: CSV value -> environment variable -> interactive prompt).
Any additional columns (e.g. `site`, `role`) are preserved and usable with
`--filter key=value`.
"""
from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Optional

import yaml

LOG = logging.getLogger("collector.inventory")

REQUIRED_COLUMNS = {"ip", "device_type"}


class InventoryError(ValueError):
    """Raised for a structurally invalid inventory file (missing required
    columns, empty file, bad YAML, etc.) -- always raised before any
    device is contacted."""


def _normalize_row(row: dict) -> dict:
    """Strips whitespace from every key/value and drops entirely-empty
    optional columns (so a blank 'password' cell means 'not supplied',
    not the literal string '' overriding a fallback credential)."""
    normalized = {}
    for k, v in row.items():
        if k is None:
            continue  # stray extra column from a malformed CSV row
        key = k.strip()
        value = (v or "").strip() if isinstance(v, str) else v
        normalized[key] = value
    return normalized


def load_inventory_csv(path: Path) -> list:
    path = Path(path)
    if not path.exists():
        raise InventoryError(f"Inventory file not found: {path}")

    with path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None:
            raise InventoryError(f"Inventory file {path} is empty or has no header row.")
        header = {h.strip() for h in reader.fieldnames}
        missing = REQUIRED_COLUMNS - header
        if missing:
            raise InventoryError(
                f"Inventory file {path} is missing required column(s): {', '.join(sorted(missing))}. "
                f"Found columns: {', '.join(sorted(header))}."
            )
        rows = [_normalize_row(r) for r in reader]

    rows = [r for r in rows if r.get("ip")]  # skip blank/trailing lines
    if not rows:
        raise InventoryError(f"Inventory file {path} has a header but no device rows.")

    for i, row in enumerate(rows, start=1):
        if not row.get("device_type"):
            raise InventoryError(f"Inventory file {path}, row {i} ({row.get('ip')}): missing 'device_type'.")

    return rows


def load_inventory_yaml(path: Path) -> list:
    path = Path(path)
    if not path.exists():
        raise InventoryError(f"Inventory file not found: {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise InventoryError(f"Inventory file {path} is not valid YAML: {exc}") from exc

    devices = raw.get("devices") if isinstance(raw, dict) else raw
    if not isinstance(devices, list) or not devices:
        raise InventoryError(f"Inventory file {path} must contain a non-empty list of devices.")

    rows = [_normalize_row(d) for d in devices]
    for i, row in enumerate(rows, start=1):
        missing = REQUIRED_COLUMNS - set(row)
        if missing:
            raise InventoryError(f"Inventory file {path}, device #{i}: missing required key(s): {', '.join(missing)}.")
    return rows


def load_inventory(path: Path) -> list:
    """Dispatches to the CSV or YAML loader based on file extension."""
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix in (".yaml", ".yml"):
        return load_inventory_yaml(path)
    return load_inventory_csv(path)


def apply_filters(devices: list, filters: list) -> list:
    """`filters` is a list of "key=value" strings (as passed via repeated
    `--filter site=DC1 --filter role=access-switch` CLI flags); a device
    row must match ALL of them (AND semantics) to be kept. A filter key
    that doesn't exist on a given row simply excludes that row rather
    than raising, since inventories commonly have optional/sparse columns."""
    if not filters:
        return devices
    parsed = []
    for flt in filters:
        if "=" not in flt:
            raise InventoryError(f"Invalid --filter '{flt}' -- expected 'key=value'.")
        key, _, value = flt.partition("=")
        parsed.append((key.strip(), value.strip()))

    def matches(device: dict) -> bool:
        return all(device.get(k) == v for k, v in parsed)

    return [d for d in devices if matches(d)]
