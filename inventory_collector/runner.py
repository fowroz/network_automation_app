"""
Concurrency runner (FR-6) -- collects many devices in parallel using a
thread pool (SSH is I/O-bound, so threads -- not processes -- are the
right tool here; this mirrors Netmiko's own recommended concurrency
pattern). Devices must complete independently: one device's failure must
never block or abort any other device's collection (FR-4).
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

from .collect import DeviceConnection, collect_device, default_connect
from .credentials import CredentialResolutionError, CredentialResolver
from .profile import Profile
from .table_mode import collect_device_table

LOG = logging.getLogger("collector.runner")


def _row_with_credential_failure(device: dict, profile: Profile, exc: Exception) -> dict:
    """Builds a device-mode row for a device whose credentials couldn't
    be resolved at all (so collect_device() was never even called)."""
    from .collect import STATUS_AUTH_FAILED, _empty_row

    fields = profile.fields_for_platform(device.get("device_type", ""))
    row = _empty_row(device, fields)
    row["STATUS"] = STATUS_AUTH_FAILED
    row["ERROR"] = str(exc)[:200]
    return row


def run_device_mode(
    devices: list,
    profile: Profile,
    workers: int = 10,
    allow_prompt: bool = True,
    connect_fn: Callable[[dict, dict, float], DeviceConnection] = default_connect,
    connect_timeout: float = 30,
    command_timeout: float = 60,
    progress_cb: Callable[[int, int], None] = None,
) -> list:
    """Runs `collect_device()` across `devices` using up to `workers`
    concurrent threads. Returns the list of result rows in COMPLETION
    order (not necessarily input order) -- callers that need a stable
    order should sort by TARGET_IP afterward.

    `progress_cb`, if given, is called as `progress_cb(completed, total)`
    after each device finishes -- optional hook added for the automation
    app's integration (see audit_bridge.py) to drive a live "N / M devices
    complete" UI indicator without this package needing to know anything
    about Flask or any UI at all. Never called with an exception raised
    from inside it propagating out (best-effort only)."""
    resolver = CredentialResolver(allow_prompt=allow_prompt)
    rows = []
    total = len(devices)

    def task(device):
        try:
            creds = resolver.resolve(device)
        except CredentialResolutionError as exc:
            return _row_with_credential_failure(device, profile, exc)
        return collect_device(device, profile, creds, connect_fn=connect_fn,
                               connect_timeout=connect_timeout, command_timeout=command_timeout)

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(task, d): d for d in devices}
        for future in as_completed(futures):
            device = futures[future]
            try:
                rows.append(future.result())
            except Exception as exc:  # pragma: no cover - defensive: collect_device already catches everything
                LOG.error("[%s] unexpected worker failure: %s", device.get("ip"), exc)
                rows.append(_row_with_credential_failure(device, profile, exc))
            if progress_cb is not None:
                try:
                    progress_cb(len(rows), total)
                except Exception:  # pragma: no cover - a broken UI callback must never abort a collection run
                    pass

    return rows


def run_table_mode(
    devices: list,
    profile: Profile,
    workers: int = 10,
    allow_prompt: bool = True,
    connect_fn: Callable[[dict, dict, float], DeviceConnection] = default_connect,
    connect_timeout: float = 30,
    command_timeout: float = 60,
    progress_cb: Callable[[int, int], None] = None,
) -> list:
    """Same concurrency model as run_device_mode, but flattens every
    device's produced sub-object rows into a single combined list.
    `progress_cb` -- see run_device_mode()'s docstring -- is called once
    per DEVICE completed (not per output row), matching the "N / M
    devices complete" semantics used everywhere else in the app."""
    resolver = CredentialResolver(allow_prompt=allow_prompt)
    all_rows = []
    total = len(devices)
    completed = 0

    def task(device):
        try:
            creds = resolver.resolve(device)
        except CredentialResolutionError as exc:
            return {"status": "AUTH_FAILED", "error": str(exc)[:200], "rows": []}
        return collect_device_table(device, profile, creds, connect_fn=connect_fn,
                                     connect_timeout=connect_timeout, command_timeout=command_timeout)

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(task, d): d for d in devices}
        for future in as_completed(futures):
            device = futures[future]
            try:
                result = future.result()
                all_rows.extend(result["rows"])
            except Exception as exc:  # pragma: no cover - defensive
                LOG.error("[%s] unexpected worker failure: %s", device.get("ip"), exc)
            completed += 1
            if progress_cb is not None:
                try:
                    progress_cb(completed, total)
                except Exception:  # pragma: no cover
                    pass

    return all_rows
