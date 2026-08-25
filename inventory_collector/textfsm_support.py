"""
TextFSM parsing support (§3.4) -- structured parsing of tabular CLI output
(e.g. `show ip interface brief`, `show cdp neighbors`) via ntc-templates,
for fields/profiles that declare `parser: textfsm` instead of a regex.

LAZY LOADING
------------
`textfsm` and `ntc-templates` are comparatively heavy (ntc-templates in
particular bundles hundreds of vendor template files) and are only ever
needed by a profile that actually declares `parser: textfsm` or
`mode: table`. Importing (and, if missing, pip-installing) them
unconditionally at application startup -- as network_automation_app's
app.py used to do -- adds real startup latency and memory footprint to
every single run of the app, even for users who only ever use the
regex-based Audit Profiles (hardware_audit, security_audit,
capacity_audit) or don't use the Audit tab at all.

Instead, the actual import is deferred to the FIRST TIME one of the
parse_with_*() functions below is actually called -- i.e. the first time
a profile that needs it is actually executed. `is_textfsm_installed()`
provides a fast, import-free availability check (via
`importlib.util.find_spec`) for UI/health-check purposes that doesn't
pay the loading cost just to answer "is this available".
"""
from __future__ import annotations

import importlib
import importlib.util
import logging
import subprocess
import sys
from pathlib import Path
from typing import Optional

LOG = logging.getLogger("collector.textfsm")

# Cache populated on first real use (see _load()) -- None means "not
# attempted yet", True/False means "attempted, here's the result".
TEXTFSM_AVAILABLE: Optional[bool] = None

_ntc_parse_output = None
_textfsm_module = None
_load_lock_attempted = False


def is_textfsm_installed() -> bool:
    """
    Fast, IMPORT-FREE check of whether the `textfsm` and `ntc-templates`
    packages are present on disk -- uses importlib.util.find_spec, which
    only consults the module finder/path (no module code is executed,
    no heavy ntc-templates template files are loaded), so this is safe
    to call from a hot path like /health or /audit/profiles without
    paying the real import cost. Does NOT attempt to install anything.
    """
    try:
        return (
            importlib.util.find_spec("textfsm") is not None
            and importlib.util.find_spec("ntc_templates") is not None
        )
    except (ImportError, ValueError):  # pragma: no cover - defensive
        return False


def _ensure_package(import_name: str, pip_name: str) -> bool:
    """Minimal local auto-installer (mirrors app.py's ensure_package())
    -- kept independent of app.py so this module has no dependency on
    the Flask app at all (it's also used by the standalone collector.py
    CLI, which never imports app.py)."""
    try:
        importlib.import_module(import_name)
        return True
    except ImportError:
        LOG.info("Installing optional dependency '%s' (first use of a TextFSM/table-mode profile)...", pip_name)
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", pip_name])
            importlib.import_module(import_name)
            return True
        except Exception as exc:
            LOG.warning("Could not install '%s': %s", pip_name, exc)
            return False


def _load() -> bool:
    """Performs the actual (heavy) import on first call only; every
    subsequent call is a cheap cached-boolean return. Thread-safe enough
    for this app's purposes -- worst case under a race, the import
    happens twice, which is harmless (idempotent) rather than unsafe."""
    global TEXTFSM_AVAILABLE, _ntc_parse_output, _textfsm_module
    if TEXTFSM_AVAILABLE is not None:
        return TEXTFSM_AVAILABLE

    ok = _ensure_package("textfsm", "textfsm") and _ensure_package("ntc_templates", "ntc-templates")
    if ok:
        try:
            from ntc_templates.parse import parse_output as ntc_parse_output
            import textfsm as textfsm_module
            _ntc_parse_output = ntc_parse_output
            _textfsm_module = textfsm_module
            TEXTFSM_AVAILABLE = True
        except ImportError:  # pragma: no cover - install reported ok but import still failed
            TEXTFSM_AVAILABLE = False
    else:
        TEXTFSM_AVAILABLE = False
    return TEXTFSM_AVAILABLE


class TextFSMUnavailableError(RuntimeError):
    """Raised when a profile uses parser: textfsm but the textfsm/
    ntc-templates packages aren't installed (and couldn't be auto-installed)."""


def parse_with_ntc_templates(platform: str, command: str, raw_output: str) -> list:
    """
    Parses `raw_output` (the CLI response for `command`, run against a
    device of Netmiko-style `platform`) into a list of dicts using the
    matching ntc-templates TextFSM template. Returns an EMPTY list (never
    raises) if no template exists for this platform/command combination
    or if parsing otherwise fails -- callers should treat that the same
    as "no matches" (the field's `default` applies), consistent with how
    a non-matching regex is handled.

    Triggers the lazy import (see module docstring) on first call.
    """
    if not _load():
        raise TextFSMUnavailableError(
            "parser: textfsm was used but the 'textfsm' and/or 'ntc-templates' packages "
            "are not installed and could not be auto-installed. Install them with: "
            "pip install textfsm ntc-templates"
        )
    try:
        records = _ntc_parse_output(platform=platform, command=command, data=raw_output or "")
        return records or []
    except Exception as exc:
        LOG.warning("TextFSM parsing failed for platform=%s command=%r: %s", platform, command, exc)
        return []


def parse_with_custom_template(template_path: Path, raw_output: str) -> list:
    """Parses `raw_output` using an explicit .textfsm template file (the
    `textfsm_template` field attribute) instead of looking one up in
    ntc-templates -- for a platform/command ntc-templates doesn't cover.
    Triggers the lazy import (see module docstring) on first call."""
    if not _load():
        raise TextFSMUnavailableError(
            "parser: textfsm was used but the 'textfsm' package is not installed and could "
            "not be auto-installed. Install it with: pip install textfsm"
        )
    template_path = Path(template_path)
    if not template_path.exists():
        LOG.warning("Custom TextFSM template not found: %s", template_path)
        return []
    try:
        with template_path.open() as fh:
            fsm = _textfsm_module.TextFSM(fh)
        rows = fsm.ParseText(raw_output or "")
        return [dict(zip(fsm.header, row)) for row in rows]
    except Exception as exc:
        LOG.warning("Custom TextFSM parsing failed using template %s: %s", template_path, exc)
        return []
