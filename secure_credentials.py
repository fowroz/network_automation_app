"""
========================================================================
 Session-bound ephemeral credential handling
========================================================================
Backs the "🔒 Ephemeral run" toggle on the Run tab and Audit tab: an
opt-in mode for a ONE-TIME run where credentials are held in a mutable,
explicitly-zeroable buffer instead of an ordinary Python `str`, and are
actively wiped the moment the run (the request-handling generator /
worker thread) finishes -- success, failure, or cancellation.

HONEST LIMITATION (read before assuming this is a cryptographic guarantee)
---------------------------------------------------------------------
Python strings are immutable and CPython provides no supported API to
force-zero an arbitrary `str`'s backing memory in place. paramiko/
netmiko's authentication calls require a real `str`, so at the exact
moment a password is used to authenticate, a normal, immutable,
garbage-collected `str` copy unavoidably exists for that brief window --
no pure-Python SSH client can avoid this, and this app makes no claim to
the contrary.

What THIS module actually guarantees:
  1. Outside of that brief in-flight authentication window, the
     plaintext credential is stored ONLY in a `bytearray` (a real,
     mutable buffer) rather than sitting as a `str` for the entire
     lifetime of the request/payload dict.
  2. `SecureValue.wipe()` synchronously overwrites every byte of that
     buffer with zeros and drops the reference -- a real, verifiable
     action (unlike merely doing `del` on a str and hoping the GC gets
     to it), and is always called in a `finally` block so it runs
     whether the run succeeded, failed, or was cancelled.
  3. Ephemeral mode is only meaningful for a ONE-TIME interactive run
     (Run tab / Audit tab "Run now"). It intentionally has no effect on
     saved Inventories or Schedules, which by definition need their
     credentials to remain retrievable (encrypted at rest) between runs
     -- there is no such thing as an "ephemeral schedule".
========================================================================
"""


class SecureValue:
    """A credential value backed by a mutable bytearray instead of an
    immutable str, so it can be actively zeroed once no longer needed.
    `bool(value)` and `len(value)` work as expected on the wrapper
    itself so most "is this credential set?" checks don't need to call
    reveal() first."""

    __slots__ = ("_buf",)

    def __init__(self, value):
        if isinstance(value, SecureValue):
            value = value.reveal()
        self._buf = bytearray((value or "").encode("utf-8"))

    def reveal(self) -> str:
        """Materializes the plaintext as a normal str -- unavoidable at
        the point of actual use (e.g. handing it to paramiko), since
        that's the API surface those libraries require. Call this as
        late as possible, right before the value is actually needed."""
        return self._buf.decode("utf-8") if self._buf else ""

    def wipe(self):
        """Synchronously overwrites every byte with zero, then drops
        the buffer. Idempotent -- safe to call more than once, and safe
        to call on an already-empty value."""
        for i in range(len(self._buf)):
            self._buf[i] = 0
        self._buf = bytearray()

    def __bool__(self):
        return len(self._buf) > 0

    def __len__(self):
        return len(self._buf)

    def __repr__(self):  # pragma: no cover - never print the value itself
        return f"SecureValue(len={len(self._buf)})"


# Field names, across both the Run tab's shared payload and a per-device
# dict, that are ever wrapped when ephemeral mode is on. Usernames are
# deliberately excluded -- they aren't secrets in the same sense a
# password/passphrase/private key is, and wrapping them would add
# overhead for no real confidentiality benefit.
EPHEMERAL_SHARED_FIELDS = (
    "password", "private_key_text", "private_key_passphrase",
    "jump_password", "jump_private_key_text", "jump_private_key_passphrase",
)
EPHEMERAL_DEVICE_FIELDS = ("password",)


def reveal(value) -> str:
    """Returns a plain str regardless of whether `value` is a
    SecureValue (ephemeral mode) or an ordinary str/None (legacy /
    non-ephemeral) -- the one helper every consumption site calls, so
    callers never need an isinstance check of their own."""
    if isinstance(value, SecureValue):
        return value.reveal()
    return value or ""


def wrap_payload_for_ephemeral(payload: dict) -> None:
    """Mutates `payload` IN PLACE, replacing each of
    EPHEMERAL_SHARED_FIELDS (and each device's EPHEMERAL_DEVICE_FIELDS)
    with a SecureValue wrapper. Called once, immediately after
    validate_payload() resolves a cleaned payload, only when the caller
    requested ephemeral mode."""
    for field in EPHEMERAL_SHARED_FIELDS:
        if payload.get(field):
            payload[field] = SecureValue(payload[field])
    for device in payload.get("devices", []):
        for field in EPHEMERAL_DEVICE_FIELDS:
            if device.get(field):
                device[field] = SecureValue(device[field])


def wipe_payload(payload: dict) -> None:
    """Wipes every SecureValue found in `payload` (shared fields + each
    device's fields) -- a no-op for any field that was never wrapped
    (i.e. always safe to call even on a non-ephemeral payload). Always
    call this from a `finally` block so it runs regardless of how the
    run ended."""
    for field in EPHEMERAL_SHARED_FIELDS:
        value = payload.get(field)
        if isinstance(value, SecureValue):
            value.wipe()
    for device in payload.get("devices", []):
        for field in EPHEMERAL_DEVICE_FIELDS:
            value = device.get(field)
            if isinstance(value, SecureValue):
                value.wipe()
