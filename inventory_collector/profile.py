"""
Profile loading & validation.

A "profile" is the external YAML file that declares everything about one
audit run: which fields to collect (see fields.py), where the device
inventory comes from, and how/where to write the report. Loading a
profile NEVER touches the network -- all validation here is static
(YAML syntax, required keys, regex compile checks, duplicate columns,
schema-change policy value, etc.) so `--validate` can catch a broken
profile with zero devices contacted.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import yaml

from .fields import Field, FieldDefinitionError

LOG = logging.getLogger("collector.profile")

VALID_OUTPUT_FORMATS = {"csv", "xlsx", "json"}
VALID_OUTPUT_MODES = {"append", "overwrite"}
VALID_SCHEMA_CHANGE_POLICIES = {"new_file", "expand", "error"}
VALID_MODES = {"device", "table"}


class ProfileError(ValueError):
    """Raised for any structural problem with a profile file -- bad YAML,
    missing keys, invalid field definitions, duplicate columns, bad
    output/schema-change settings, etc. Always raised before any device
    is contacted."""


class Profile:
    """A fully parsed & validated profile, ready to drive a collection run."""

    def __init__(self, raw: dict, source_path: Optional[Path] = None):
        self.source_path = source_path
        self.name: str = raw.get("profile", source_path.stem if source_path else "unnamed")
        self.mode: str = raw.get("mode", "device")

        output = raw.get("output") or {}
        self.output_format: str = output.get("format", "csv")
        self.output_path: str = output.get("path", "./reports/inventory_{date}.csv")
        self.output_mode: str = output.get("mode", "append")
        self.include_metadata: bool = bool(output.get("include_metadata", True))
        self.on_schema_change: str = output.get("on_schema_change", "new_file")

        devices_cfg = raw.get("devices") or {}
        self.inventory_source: Optional[str] = devices_cfg.get("source")

        self.raw_fields = raw.get("fields") or []
        self.fields: list[Field] = self._build_fields(self.raw_fields)

        # ---- table mode config (§3.5) ----
        self.iterate_cfg = raw.get("iterate") or {}
        self.table_columns = raw.get("columns") or []
        self.row_prefix = self.iterate_cfg.get("row_prefix") or []

        self._validate()

    # ------------------------------------------------------------------
    @staticmethod
    def _build_fields(raw_fields: list) -> list:
        fields = []
        errors = []
        for i, spec in enumerate(raw_fields):
            try:
                fields.append(Field(spec, index=i))
            except FieldDefinitionError as exc:
                errors.append(str(exc))
        if errors:
            raise ProfileError("Profile has invalid field definition(s):\n  - " + "\n  - ".join(errors))
        return fields

    def _validate(self):
        errors = []

        if self.mode not in VALID_MODES:
            errors.append(f"mode must be one of {sorted(VALID_MODES)}, got '{self.mode}'.")
        if self.output_format not in VALID_OUTPUT_FORMATS:
            errors.append(f"output.format must be one of {sorted(VALID_OUTPUT_FORMATS)}, got '{self.output_format}'.")
        if self.output_mode not in VALID_OUTPUT_MODES:
            errors.append(f"output.mode must be one of {sorted(VALID_OUTPUT_MODES)}, got '{self.output_mode}'.")
        if self.on_schema_change not in VALID_SCHEMA_CHANGE_POLICIES:
            errors.append(
                f"output.on_schema_change must be one of {sorted(VALID_SCHEMA_CHANGE_POLICIES)}, "
                f"got '{self.on_schema_change}'."
            )

        if self.mode == "device":
            if not self.fields:
                errors.append("Profile has no fields defined (need at least one under 'fields:').")
            seen_columns = {}
            for f in self.fields:
                seen_columns.setdefault(f.column, []).append(f.name)
            dupes = {col: names for col, names in seen_columns.items() if len(names) > 1}
            if dupes:
                for col, names in dupes.items():
                    errors.append(f"Duplicate column name '{col}' used by fields: {', '.join(names)}.")
        else:  # table mode
            if not self.iterate_cfg.get("command"):
                errors.append("Table mode requires 'iterate.command'.")
            if not self.table_columns:
                errors.append("Table mode requires at least one entry under 'columns:'.")

        if not self.inventory_source and self.mode == "device":
            LOG.debug("Profile '%s' has no devices.source -- inventory must be supplied via --inventory.", self.name)

        if errors:
            raise ProfileError(f"Profile '{self.name}' validation failed:\n  - " + "\n  - ".join(errors))

    # ------------------------------------------------------------------
    def enabled_fields(self) -> list:
        return [f for f in self.fields if f.enabled]

    def unique_commands(self) -> set:
        """All distinct CLI commands referenced by enabled fields -- this
        is exactly the set FR-2 requires be issued (once each) per device."""
        return {f.command for f in self.enabled_fields()}

    def fields_for_platform(self, device_type: str) -> list:
        return [f for f in self.fields if f.applies_to(device_type)]


def load_profile_dict(raw: dict, source_path: Optional[Path] = None) -> Profile:
    """Builds a Profile from an already-parsed dict (used by tests that
    want to construct a profile in-memory without a file on disk)."""
    return Profile(raw, source_path=source_path)


def load_profile(path: Path) -> Profile:
    """Reads and validates a YAML profile file. Raises ProfileError (with
    every problem found, not just the first) on any structural issue --
    bad YAML syntax, missing keys, invalid regex, duplicate columns,
    invalid enum values, etc. Never touches the network."""
    path = Path(path)
    if not path.exists():
        raise ProfileError(f"Profile file not found: {path}")
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ProfileError(f"Could not read profile file {path}: {exc}") from exc

    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ProfileError(f"Profile file {path} is not valid YAML: {exc}") from exc

    if not isinstance(raw, dict):
        raise ProfileError(f"Profile file {path} must contain a YAML mapping/object at the top level.")

    return Profile(raw, source_path=path)
