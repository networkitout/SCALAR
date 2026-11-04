"""Credential value type and the provider protocol."""

from __future__ import annotations

import json
import re
from typing import Any, Protocol, runtime_checkable

from netrescale.redact import registry

ENTRY_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class CredentialError(Exception):
    """Base error for credential storage and resolution."""


class Credential:
    """A NetScaler login. Sensitive fields are only reachable through explicit reveal_* calls.

    repr/str never include secret material, and every secret value is registered with the
    process-wide redaction registry as soon as the object is created.
    """

    __slots__ = ("_password", "_ssh_private_key", "username")

    def __init__(self, username: str, password: str, ssh_private_key: str | None = None) -> None:
        if not username:
            raise CredentialError("username must not be empty")
        if not password and not ssh_private_key:
            raise CredentialError("a password or an SSH private key is required")
        self.username = username
        self._password = password
        self._ssh_private_key = ssh_private_key
        registry.register(password)
        registry.register(ssh_private_key)

    def reveal_password(self) -> str:
        return self._password

    def reveal_ssh_private_key(self) -> str | None:
        return self._ssh_private_key

    @property
    def has_ssh_key(self) -> bool:
        return self._ssh_private_key is not None

    def to_json_bytes(self) -> bytes:
        doc: dict[str, Any] = {"username": self.username, "password": self._password}
        if self._ssh_private_key is not None:
            doc["ssh_private_key"] = self._ssh_private_key
        return json.dumps(doc, separators=(",", ":")).encode()

    @classmethod
    def from_json_bytes(cls, data: bytes) -> Credential:
        try:
            doc = json.loads(data)
            return cls(doc["username"], doc.get("password", ""), doc.get("ssh_private_key"))
        except (ValueError, KeyError, TypeError) as exc:
            raise CredentialError("malformed credential payload") from exc

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Credential):
            return NotImplemented
        return (
            self.username == other.username
            and self._password == other._password
            and self._ssh_private_key == other._ssh_private_key
        )

    __hash__ = None  # type: ignore[assignment]

    def __repr__(self) -> str:
        key = ", ssh_key=<set>" if self._ssh_private_key else ""
        return f"Credential(username={self.username!r}, password=<hidden>{key})"

    __str__ = __repr__


def validate_entry_name(name: str) -> str:
    if not ENTRY_NAME_RE.match(name):
        raise CredentialError(
            f"invalid credential name {name!r}: use 1-64 chars of letters, digits, '.', '_', '-'"
        )
    return name


@runtime_checkable
class SecretProvider(Protocol):
    """A source of credentials addressed as '<scheme>:<name>'."""

    scheme: str

    def get(self, name: str) -> Credential: ...
