"""
========================================================================
 Shared secret-redaction patterns and helpers
========================================================================
Single source of truth for "does this string look like it contains a
device secret" -- used by BOTH templates_engine.py (redacting rendered
config text before it's written to logs/audit.log) and storage.py
(redacting report_json structures before they're written to SQLite).
Previously these lived only in templates_engine.py; pulling them out
here means there's exactly one regex table to keep up to date instead
of two copies quietly drifting apart.

WHAT THIS DOES NOT DO
----------------------
This is a best-effort, pattern-based safety net for FREE-TEXT strings
(device command output, rendered config, diff lines) where we don't
otherwise know a value's sensitivity. It is NOT a substitute for:
  - Field-level `sensitive: true` flags (inventory_collector/fields.py's
    Field.redact()), which are authoritative and applied BEFORE a value
    ever reaches a report dict.
  - Not storing secrets in the first place (the app already avoids that
    almost everywhere -- see storage.py's module docstring).
It exists to catch secrets that show up incidentally inside free text
that IS legitimately stored (e.g. a manually-typed config command, or
a `show running-config` backup captured as part of a run's command
log) -- text nobody explicitly flagged as sensitive, but that plainly
contains one anyway (e.g. "username bob secret hunter2").
========================================================================
"""
import re

REDACTED_PLACEHOLDER = "<REDACTED>"

# Line-oriented patterns: "<keyword> <value>" -> "<keyword> <REDACTED>".
# Kept intentionally narrow (keyword-anchored) to avoid false-positive
# redaction of ordinary audit data that merely contains the word
# "password" as a column label rather than an actual secret value (e.g.
# a "PASSWORD ENCRYPTION ON" column's value is "YES"/"NO", never matched
# by these patterns since they require the keyword immediately followed
# by the value on the same line).
LINE_PATTERNS = [
    (re.compile(r"(\bsecret\b)\s+\S+", re.IGNORECASE), r"\1 " + REDACTED_PLACEHOLDER),
    (re.compile(r"(\bpassword\b)\s+\S+", re.IGNORECASE), r"\1 " + REDACTED_PLACEHOLDER),
    (re.compile(r"(\bpassphrase\b)\s+\S+", re.IGNORECASE), r"\1 " + REDACTED_PLACEHOLDER),
    (re.compile(r"(snmp-server community)\s+\S+", re.IGNORECASE), r"\1 " + REDACTED_PLACEHOLDER),
    (re.compile(r"(pre-shared-key)\s+\S+", re.IGNORECASE), r"\1 " + REDACTED_PLACEHOLDER),
    (re.compile(r"(set system login user \S+ authentication plain-text-password)\s+\S+", re.IGNORECASE),
     r"\1 " + REDACTED_PLACEHOLDER),
    (re.compile(r"(key-string)\s+\S+", re.IGNORECASE), r"\1 " + REDACTED_PLACEHOLDER),
    (re.compile(r"(auth-key|authentication-key)\s+\S+", re.IGNORECASE), r"\1 " + REDACTED_PLACEHOLDER),
    (re.compile(r"(community-string)\s+\S+", re.IGNORECASE), r"\1 " + REDACTED_PLACEHOLDER),
    # Bare "key <value>" -- e.g. `tacacs server ...` / `radius server ...`
    # sub-config-mode shared-secret lines ("key S3cret"). Line-start
    # anchored (^, MULTILINE) rather than \b-bounded like the patterns
    # above, specifically so it does NOT also fire on unrelated uses of
    # the word "key" that aren't the first token on a config line (e.g.
    # "ip dhcp snooping" output mentioning a "key" in prose, or a column
    # header) -- config sub-commands always start the line with (optional
    # leading whitespace then) the keyword.
    (re.compile(r"^(\s*key)\s+\S+", re.IGNORECASE | re.MULTILINE), r"\1 " + REDACTED_PLACEHOLDER),
]

# Dict-key hints: if a mapping key, once normalized (lowercased, with
# any run of non-alphanumeric characters collapsed to a single
# underscore), EXACTLY matches one of these, its VALUE is replaced
# wholesale with REDACTED_PLACEHOLDER -- used when walking structured
# data (e.g. a device dict with a literal "password" key) where the
# value itself IS the secret (no "keyword: value" text to pattern-match
# against, unlike a rendered config line).
#
# Deliberately an EXACT-match allowlist rather than a fuzzy substring
# check: a naive `"password" in key.lower()` would also nuke perfectly
# legitimate audit report columns like "PASSWORD ENCRYPTION ON" (a
# YES/NO compliance flag, not a secret) or "SNMP RO COMMUNITY SET"
# (already redacted upstream by Field.redact() and just says whether
# one is configured). Only real secret-value field names go here.
SENSITIVE_KEY_NAMES = frozenset({
    "password", "passwd", "pwd", "secret", "passphrase",
    "private_key_passphrase", "jump_password", "jump_private_key_passphrase",
    "private_key_text", "jump_private_key_text",
    "community", "snmp_community", "ro_community", "rw_community",
    "pre_shared_key", "psk", "auth_key", "authentication_key",
    "api_key", "apikey", "token", "webhook_url", "webhook",
})

_KEY_NORMALIZE_RE = re.compile(r"[^a-z0-9]+")


def _normalize_key(key: str) -> str:
    return _KEY_NORMALIZE_RE.sub("_", key.lower()).strip("_")


def sanitize_text(text) -> str:
    """Redacts secret-looking substrings in a block of free text (a
    rendered config, a device command's output, a diff line, etc).
    Safe to call on any value, including None/empty/non-strings."""
    if not text or not isinstance(text, str):
        return text
    result = text
    for pattern, repl in LINE_PATTERNS:
        result = pattern.sub(repl, result)
    return result


def _key_looks_sensitive(key) -> bool:
    if not isinstance(key, str):
        return False
    return _normalize_key(key) in SENSITIVE_KEY_NAMES


def sanitize_structure(value, _depth=0):
    """
    Recursively walks a JSON-like structure (dicts/lists/strings/
    numbers) and returns a sanitized DEEP COPY:
      - dict values whose KEY looks sensitive (see SENSITIVE_KEY_HINTS)
        are replaced outright with REDACTED_PLACEHOLDER (unless already
        falsy/empty, which is left alone -- nothing to redact).
      - every other string value has sanitize_text() applied (catches
        secrets embedded in free text under an innocuous-looking key,
        e.g. a "output" key containing a captured "show running-config").
      - numbers/bools/None pass through unchanged.
    Depth-limited defensively (100 levels) so a pathological/cyclic
    structure can't cause unbounded recursion.
    """
    if _depth > 100:
        return value
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if _key_looks_sensitive(k) and v:
                out[k] = REDACTED_PLACEHOLDER
            else:
                out[k] = sanitize_structure(v, _depth + 1)
        return out
    if isinstance(value, list):
        return [sanitize_structure(v, _depth + 1) for v in value]
    if isinstance(value, str):
        return sanitize_text(value)
    return value
