"""Resolve credential refs like ``local:sc_nitro`` to credentials, with a lockout guard.

Only the ``local`` scheme exists in v1. Other providers (e.g. a future ``bitwarden:``)
register under their own scheme without any change to device configuration.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from scalar.secrets.base import Credential, CredentialError, SecretProvider, validate_entry_name
from scalar.secrets.vault import EntryMeta, Vault


class UnknownScheme(CredentialError):
    pass


class CredentialBlocked(CredentialError):
    """Raised instead of using a credential that a device already rejected."""


@dataclass(frozen=True, slots=True)
class CredentialRef:
    scheme: str
    name: str

    @classmethod
    def parse(cls, ref: str) -> CredentialRef:
        scheme, sep, name = ref.partition(":")
        if not sep or not scheme or not name:
            raise CredentialError(f"invalid credential ref {ref!r}; expected '<scheme>:<name>'")
        return cls(scheme, validate_entry_name(name))

    def __str__(self) -> str:
        return f"{self.scheme}:{self.name}"


class LocalVaultProvider:
    scheme = "local"

    def __init__(self, vault: Vault) -> None:
        self.vault = vault

    def get(self, name: str) -> Credential:
        return self.vault.get(name)


class LockoutGuard:
    """Stop using a credential on a device after the device rejects it once.

    NetScaler accounts can be locked out by repeated failures. A rejected credential stays
    blocked for that device until an admin rotates it or clears the block explicitly.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._blocked: dict[tuple[str, str], datetime] = {}
        self._versions: dict[tuple[str, str], bytes] = {}

    def check(self, device: str, ref: CredentialRef,
              credential: Credential | None = None) -> None:
        key = (device, str(ref))
        with self._lock:
            if credential is not None:
                version = hashlib.sha256(credential.to_json_bytes()).digest()
                previous = self._versions.get(key)
                if previous is not None and previous != version:
                    self._blocked.pop(key, None)
                self._versions[key] = version
            since = self._blocked.get(key)
        if since is not None:
            raise CredentialBlocked(
                f"{ref} was rejected by {device} at {since.isoformat()}; not retrying. "
                f"Rotate it with 'scalar cred rotate {ref.name}' or clear the block."
            )

    def record_rejection(self, device: str, ref: CredentialRef) -> None:
        with self._lock:
            self._blocked.setdefault((device, str(ref)), datetime.now(UTC))

    def clear(self, ref: CredentialRef, device: str | None = None) -> None:
        with self._lock:
            for key in list(self._blocked):
                if key[1] == str(ref) and (device is None or key[0] == device):
                    del self._blocked[key]

    def blocked(self) -> list[tuple[str, str, datetime]]:
        with self._lock:
            return [(d, r, t) for (d, r), t in sorted(self._blocked.items())]


class Resolver:
    def __init__(self, providers: list[SecretProvider], guard: LockoutGuard | None = None) -> None:
        self._providers = {p.scheme: p for p in providers}
        self.guard = guard or LockoutGuard()

    def resolve(self, ref: str | CredentialRef, *, device: str | None = None) -> Credential:
        r = ref if isinstance(ref, CredentialRef) else CredentialRef.parse(ref)
        try:
            provider = self._providers[r.scheme]
        except KeyError:
            raise UnknownScheme(
                f"no credential provider for scheme {r.scheme!r} "
                f"(available: {', '.join(sorted(self._providers))})"
            ) from None
        credential = provider.get(r.name)
        if device is not None:
            self.guard.check(device, r, credential)
        return credential


def stale_entries(vault: Vault, max_age_days: int,
                  now: datetime | None = None) -> list[EntryMeta]:
    """Entries whose secret has not been updated within ``max_age_days``."""
    cutoff = (now or datetime.now(UTC)) - timedelta(days=max_age_days)
    return [m for m in vault.list_meta() if m.updated < cutoff]
