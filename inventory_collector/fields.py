"""
Field definitions -- the heart of the "no hardcoded data points" requirement.

A `Field` is built entirely from a dict parsed out of a YAML profile (see
profile.py). Nothing about which fields exist, what command they run, or
what regex/TextFSM key they extract is known to this module ahead of time;
it only knows *how* to interpret a field's declared attributes.

Supported extraction attributes (see the feature spec, section 3.1):
    name, column, command, regex, group, occurrence, separator, default,
    transform, required, enabled, platforms, parser, textfsm_key, sensitive

Two parser backends are supported:
    - "regex"   (default): re.findall() against the raw CLI text.
    - "textfsm": structured parsing via ntc-templates (falls back to the
      "textfsm_template" field attribute for a custom .textfsm file if the
      built-in ntc-templates library doesn't have a template for this
      platform/command combination).
"""
from __future__ import annotations

import logging
import re
from typing import Any, Optional

LOG = logging.getLogger("collector.fields")

# ---------------------------------------------------------------------------
# Transform registry -- referenced by name from a profile's `transform:` key.
# Deliberately a plain dict (not eval/exec) so a profile can only ever
# invoke one of these pre-approved, side-effect-free functions -- a YAML
# profile is configuration, not code, and must never be able to execute
# arbitrary Python.
# ---------------------------------------------------------------------------
def _to_int(value: str):
    cleaned = re.sub(r"[^\d-]", "", str(value)) or "0"
    return int(cleaned)


def _to_float(value: str):
    cleaned = re.sub(r"[^\d.\-]", "", str(value)) or "0"
    return float(cleaned)


def _cidr_to_mask(value: str) -> str:
    """Converts a bare prefix length ('24') to a dotted-decimal netmask
    ('255.255.255.0'). If `value` doesn't look like a plain prefix length,
    it's returned unchanged (e.g. it might already be a dotted mask, or a
    combined 'ip/prefix' string another transform should handle first)."""
    text = str(value).strip()
    if not text.isdigit():
        return value
    prefix = int(text)
    if not (0 <= prefix <= 32):
        return value
    bits = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF if prefix else 0
    return ".".join(str((bits >> shift) & 0xFF) for shift in (24, 16, 8, 0))


TRANSFORMS = {
    "upper": lambda v: str(v).upper(),
    "lower": lambda v: str(v).lower(),
    "strip": lambda v: str(v).strip(),
    "int": _to_int,
    "float": _to_float,
    "cidr_to_mask": _cidr_to_mask,
}

VALID_OCCURRENCES = {"first", "last", "all", "join", "count"}
VALID_PARSERS = {"regex", "textfsm"}

REDACTED_PLACEHOLDER = "<REDACTED>"


class FieldDefinitionError(ValueError):
    """Raised when a field's YAML spec is structurally invalid (bad regex,
    missing required key, unknown transform/occurrence/parser, etc.) --
    always raised at PROFILE LOAD TIME (see profile.load_profile), never
    while actually talking to a device, so a broken profile is caught by
    `--validate` before any device is ever contacted."""


class Field:
    """A single dynamically-declared data point, built from one entry in
    a profile's `fields:` list."""

    def __init__(self, spec: dict, *, index: int = 0):
        if not isinstance(spec, dict):
            raise FieldDefinitionError(f"Field #{index}: must be a mapping/object, got {type(spec).__name__}.")

        missing = [k for k in ("name", "column", "command") if not spec.get(k)]
        if missing:
            raise FieldDefinitionError(f"Field #{index}: missing required key(s): {', '.join(missing)}.")

        self.name: str = str(spec["name"])
        self.column: str = str(spec["column"])
        self.command: str = str(spec["command"])
        self.group: int = int(spec.get("group", 1))
        self.occurrence: str = spec.get("occurrence", "first")
        self.separator: str = spec.get("separator", "; ")
        self.default: Any = spec.get("default", "N/A")
        self.transform: Optional[str] = spec.get("transform")
        self.required: bool = bool(spec.get("required", False))
        self.enabled: bool = bool(spec.get("enabled", True))
        self.platforms: Optional[list] = spec.get("platforms")
        self.sensitive: bool = bool(spec.get("sensitive", False))
        self.parser: str = spec.get("parser", "regex")
        self.textfsm_key: Optional[str] = spec.get("textfsm_key")
        self.textfsm_template: Optional[str] = spec.get("textfsm_template")
        self.regex_src: Optional[str] = spec.get("regex")

        if self.occurrence not in VALID_OCCURRENCES:
            raise FieldDefinitionError(
                f"Field '{self.name}': occurrence must be one of {sorted(VALID_OCCURRENCES)}, got '{self.occurrence}'."
            )
        if self.parser not in VALID_PARSERS:
            raise FieldDefinitionError(
                f"Field '{self.name}': parser must be one of {sorted(VALID_PARSERS)}, got '{self.parser}'."
            )
        if self.transform is not None and self.transform not in TRANSFORMS:
            raise FieldDefinitionError(
                f"Field '{self.name}': unknown transform '{self.transform}'. "
                f"Available: {sorted(TRANSFORMS)}."
            )
        if self.group < 1:
            raise FieldDefinitionError(f"Field '{self.name}': group must be >= 1, got {self.group}.")

        if self.parser == "regex":
            if not self.regex_src:
                raise FieldDefinitionError(f"Field '{self.name}': 'regex' is required unless parser: textfsm.")
            try:
                self.regex = re.compile(self.regex_src, re.MULTILINE)
            except re.error as exc:
                raise FieldDefinitionError(f"Field '{self.name}': invalid regex '{self.regex_src}': {exc}") from exc
        else:  # textfsm
            self.regex = None
            if not self.textfsm_key:
                raise FieldDefinitionError(f"Field '{self.name}': parser: textfsm requires 'textfsm_key'.")

    def applies_to(self, device_type: str) -> bool:
        """Whether this field should run for a device of the given
        Netmiko-style device_type (e.g. 'cisco_ios'). A field with no
        `platforms` list applies to every platform."""
        if not self.enabled:
            return False
        if self.platforms is None:
            return True
        return device_type in self.platforms

    # ------------------------------------------------------------------
    # Extraction
    # ------------------------------------------------------------------
    def extract_from_text(self, raw_output: str) -> Any:
        """Regex-based extraction against the cached raw CLI text for
        this field's command. Never raises -- any failure (bad match,
        transform error) falls back to `self.default`."""
        if self.regex is None:
            return self.default
        try:
            matches = self.regex.findall(raw_output or "")
        except Exception as exc:  # pragma: no cover - defensive, regex is pre-compiled/validated
            LOG.error("Regex evaluation failed for field '%s': %s", self.name, exc)
            return self.default

        def pick_group(m):
            if isinstance(m, tuple):
                idx = self.group - 1
                return m[idx] if 0 <= idx < len(m) else m[0]
            return m

        values = [pick_group(m) for m in matches]
        return self._reduce_and_transform(values)

    def extract_from_records(self, records: list) -> Any:
        """TextFSM-based extraction: `records` is the list of dicts
        ntc-templates (or a custom template) produced for this field's
        command. Pulls `self.textfsm_key` out of every record."""
        values = []
        for rec in records or []:
            if isinstance(rec, dict) and self.textfsm_key in rec:
                val = rec[self.textfsm_key]
                # ntc-templates often returns a list-per-field even for
                # single-value columns -- normalize to a scalar per record.
                if isinstance(val, list):
                    val = val[0] if val else ""
                values.append(val)
        return self._reduce_and_transform(values)

    def _reduce_and_transform(self, values: list) -> Any:
        """Applies `occurrence` reduction then `transform`, exactly the
        same way regardless of which parser produced `values`."""
        # Empty strings still "count" as a match for occurrence=count
        # (the pattern/key matched, even if the captured text is blank),
        # but for first/last/join/all we treat a run of pure empties the
        # same as "no match" so a blank line doesn't silently become the
        # visible value instead of the configured default.
        non_empty = [v for v in values if str(v).strip() != ""]

        if self.occurrence == "count":
            result: Any = len(values)
        elif not non_empty:
            return self.default
        elif self.occurrence == "all":
            result = list(non_empty)
        elif self.occurrence == "join":
            result = self.separator.join(str(v) for v in non_empty)
        elif self.occurrence == "last":
            result = non_empty[-1]
        else:  # "first"
            result = non_empty[0]

        if self.transform and isinstance(result, str):
            try:
                result = TRANSFORMS[self.transform](result)
            except Exception as exc:
                LOG.warning("Transform '%s' failed for field '%s' on value %r: %s",
                            self.transform, self.name, result, exc)
        return result

    def redact(self, value: Any) -> Any:
        """Returns REDACTED_PLACEHOLDER instead of `value` if this field
        is marked sensitive AND the value isn't already the field's own
        'no match' default (so a redacted-looking column doesn't hide the
        fact that a sensitive field simply didn't match anything)."""
        if self.sensitive and value != self.default:
            return REDACTED_PLACEHOLDER
        return value

    def __repr__(self):  # pragma: no cover - debugging aid only
        return f"Field(name={self.name!r}, column={self.column!r}, command={self.command!r})"
