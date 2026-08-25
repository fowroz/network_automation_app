"""
Credential resolution -- FR-1 ("Support credentials from environment
variables / prompt / vault -- never plaintext in the repo") and NFR-1
("No hardcoded credentials ... anywhere in the Python source").

Resolution order for username/password, per device:
    1. A non-empty value already present on the device's inventory row
       (e.g. a per-site override column in the CSV/YAML).
    2. The NETCOLLECT_USERNAME / NETCOLLECT_PASSWORD environment
       variables (a simple, script-friendly "vault" integration point --
       a real vault lookup can populate these env vars before invoking
       this tool, so the tool itself never needs vault-specific code).
    3. An interactive prompt (only when running attended; disabled with
       --no-prompt for unattended/CI use, in which case a device missing
       credentials is skipped with STATUS=AUTH_FAILED rather than the
       whole run hanging on an interactive prompt).

Nothing here ever writes a resolved credential back to disk, and no
credential value is ever logged (see logging_setup.py's redaction).
"""
from __future__ import annotations

import getpass
import logging
import os
from typing import Optional

LOG = logging.getLogger("collector.credentials")

ENV_USERNAME = "NETCOLLECT_USERNAME"
ENV_PASSWORD = "NETCOLLECT_PASSWORD"
ENV_SECRET = "NETCOLLECT_SECRET"  # enable-secret / privileged-mode password


class CredentialResolutionError(RuntimeError):
    """Raised when no credential could be resolved for a device and
    interactive prompting is disabled (--no-prompt)."""


class CredentialResolver:
    """
    Resolves username/password/secret for each device using the fallback
    chain described above. Prompts (if allowed) happen AT MOST ONCE per
    process for a shared/global credential -- callers that want distinct
    per-device interactive prompting can still supply per-row inventory
    values, which always take priority.
    """

    def __init__(self, allow_prompt: bool = True):
        self.allow_prompt = allow_prompt
        self._prompted_username: Optional[str] = None
        self._prompted_password: Optional[str] = None
        self._prompted_secret: Optional[str] = None
        self._prompt_attempted = False

    def _maybe_prompt(self):
        if self._prompt_attempted or not self.allow_prompt:
            return
        self._prompt_attempted = True
        try:
            if not os.environ.get(ENV_USERNAME):
                self._prompted_username = input("Username (used for any device without its own credentials): ").strip()
            if not os.environ.get(ENV_PASSWORD):
                self._prompted_password = getpass.getpass("Password: ")
        except (EOFError, KeyboardInterrupt):
            LOG.warning("Interactive credential prompt was interrupted; devices without their own "
                        "credentials or environment variables will be marked AUTH_FAILED.")

    def resolve(self, device: dict) -> dict:
        """Returns {"username": str|None, "password": str|None, "secret": str|None}
        for one device row, or raises CredentialResolutionError if nothing
        could be resolved and prompting is disabled/failed."""
        username = device.get("username") or os.environ.get(ENV_USERNAME)
        password = device.get("password") or os.environ.get(ENV_PASSWORD)
        secret = device.get("secret") or os.environ.get(ENV_SECRET)

        if not username or not password:
            self._maybe_prompt()
            username = username or self._prompted_username
            password = password or self._prompted_password
            secret = secret or self._prompted_secret

        if not username or not password:
            raise CredentialResolutionError(
                f"No credentials available for {device.get('ip')} (no per-device username/password, "
                f"no {ENV_USERNAME}/{ENV_PASSWORD} environment variables, and interactive prompting "
                f"was {'unavailable' if self.allow_prompt else 'disabled (--no-prompt)'})."
            )
        return {"username": username, "password": password, "secret": secret}
