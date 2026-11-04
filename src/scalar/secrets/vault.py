"""Encrypted local credential vault.

File format (JSON, mode 0600):
    {
      "format": "scalar-vault",
      "format_version": 1,
      "key_id": "<16 hex>",
      "key_check": {"nonce": b64, "ct": b64},
      "entries": {
        "<name>": {"nonce": b64, "ct": b64, "created": iso, "updated": iso, "rotated_by": str}
      }
    }

Every entry is AES-256-GCM encrypted with a fresh 96-bit nonce and AAD
``nrv1|<key_id>|<name>``, so ciphertext can't be moved between names or vault keys
without failing authentication. ``key_check`` lets a wrong master key be detected
even when the vault is empty.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import secrets
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from scalar.secrets.base import Credential, CredentialError, validate_entry_name

FORMAT = "scalar-vault"
FORMAT_VERSION = 1
KEY_LEN = 32
NONCE_LEN = 12
_KEY_CHECK_NAME = "__keycheck__"
_KEY_CHECK_PLAINTEXT = b"scalar-vault-key-check-v1"


class VaultError(CredentialError):
    pass


class VaultKeyMismatch(VaultError):
    pass


class VaultEntryNotFound(VaultError):
    pass


@dataclass(frozen=True, slots=True)
class EntryMeta:
    name: str
    created: datetime
    updated: datetime
    rotated_by: str


def generate_key() -> bytes:
    return secrets.token_bytes(KEY_LEN)


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


def _now() -> datetime:
    return datetime.now(UTC)


def _aad(key_id: str, name: str) -> bytes:
    return f"nrv1|{key_id}|{name}".encode()


def _seal(aes: AESGCM, key_id: str, name: str, plaintext: bytes) -> dict[str, str]:
    nonce = secrets.token_bytes(NONCE_LEN)
    return {"nonce": _b64e(nonce), "ct": _b64e(aes.encrypt(nonce, plaintext, _aad(key_id, name)))}


def _open(aes: AESGCM, key_id: str, name: str, blob: dict[str, Any]) -> bytes:
    try:
        return aes.decrypt(_b64d(blob["nonce"]), _b64d(blob["ct"]), _aad(key_id, name))
    except (InvalidTag, KeyError, ValueError, TypeError) as exc:
        raise VaultError(f"entry {name!r} failed authentication (tampered or wrong key)") from exc


class Vault:
    """In-memory view of a vault file. Mutations are persisted atomically on each call."""

    def __init__(self, path: Path, key: bytes, doc: dict[str, Any]) -> None:
        if len(key) != KEY_LEN:
            raise VaultError("vault master key must be 32 bytes")
        self.path = path
        self._aes = AESGCM(key)
        self._doc = doc
        self._verify_key()

    # ---- construction -------------------------------------------------------------------

    @classmethod
    def create(cls, path: Path, key: bytes) -> Vault:
        if path.exists():
            raise VaultError(f"refusing to overwrite existing vault at {path}")
        doc = cls._empty_doc(key)
        vault = cls(path, key, doc)
        vault._save()
        return vault

    @classmethod
    def open(cls, path: Path, key: bytes) -> Vault:
        try:
            raw = path.read_bytes()
        except FileNotFoundError as exc:
            raise VaultError(f"vault not found at {path}") from exc
        return cls.from_bytes(path, key, raw)

    @classmethod
    def from_bytes(cls, path: Path, key: bytes, raw: bytes) -> Vault:
        try:
            doc = json.loads(raw)
        except ValueError as exc:
            raise VaultError("vault file is not valid JSON (truncated or corrupted?)") from exc
        if not isinstance(doc, dict) or doc.get("format") != FORMAT:
            raise VaultError("not a scalar vault file")
        if doc.get("format_version") != FORMAT_VERSION:
            raise VaultError(f"unsupported vault format_version {doc.get('format_version')!r}")
        if not isinstance(doc.get("entries"), dict) or not isinstance(doc.get("key_id"), str):
            raise VaultError("vault file is missing required fields")
        return cls(path, key, doc)

    @staticmethod
    def _empty_doc(key: bytes) -> dict[str, Any]:
        key_id = secrets.token_hex(8)
        return {
            "format": FORMAT,
            "format_version": FORMAT_VERSION,
            "key_id": key_id,
            "key_check": _seal(AESGCM(key), key_id, _KEY_CHECK_NAME, _KEY_CHECK_PLAINTEXT),
            "entries": {},
        }

    def _verify_key(self) -> None:
        try:
            plain = _open(self._aes, self.key_id, _KEY_CHECK_NAME, self._doc["key_check"])
        except VaultError as exc:
            raise VaultKeyMismatch("master key does not match this vault") from exc
        if plain != _KEY_CHECK_PLAINTEXT:
            raise VaultKeyMismatch("master key does not match this vault")

    # ---- read ---------------------------------------------------------------------------

    @property
    def key_id(self) -> str:
        return str(self._doc["key_id"])

    def names(self) -> list[str]:
        return sorted(self._doc["entries"])

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name in self._doc["entries"]

    def __iter__(self) -> Iterator[str]:
        return iter(self.names())

    def meta(self, name: str) -> EntryMeta:
        e = self._entry(name)
        return EntryMeta(
            name=name,
            created=datetime.fromisoformat(e["created"]),
            updated=datetime.fromisoformat(e["updated"]),
            rotated_by=e.get("rotated_by", ""),
        )

    def list_meta(self) -> list[EntryMeta]:
        return [self.meta(n) for n in self.names()]

    def get(self, name: str) -> Credential:
        return Credential.from_json_bytes(_open(self._aes, self.key_id, name, self._entry(name)))

    def _entry(self, name: str) -> dict[str, Any]:
        try:
            entry: dict[str, Any] = self._doc["entries"][name]
        except KeyError:
            raise VaultEntryNotFound(f"no credential named {name!r}") from None
        return entry

    # ---- write --------------------------------------------------------------------------

    def set(self, name: str, cred: Credential, actor: str) -> None:
        validate_entry_name(name)
        now = _now().isoformat()
        prev = self._doc["entries"].get(name)
        entry = _seal(self._aes, self.key_id, name, cred.to_json_bytes())
        entry.update(created=prev["created"] if prev else now, updated=now, rotated_by=actor)
        self._commit({**self._doc["entries"], name: entry})

    def delete(self, name: str) -> None:
        self._entry(name)
        self._commit({n: e for n, e in self._doc["entries"].items() if n != name})

    def _commit(self, entries: dict[str, Any]) -> None:
        """Persist first, then swap in memory, so a failed write leaves both views unchanged."""
        doc = {**self._doc, "entries": entries}
        atomic_write(self.path, _dumps(doc), backup=True)
        self._doc = doc

    def rekey(self, new_key: bytes) -> Vault:
        """Re-encrypt every entry under a new master key and key_id; returns the new vault.

        All entries are decrypted before anything is written, so a corrupt entry aborts the
        rekey without touching the file on disk.
        """
        plain = {n: _open(self._aes, self.key_id, n, e) for n, e in self._doc["entries"].items()}
        doc = self._empty_doc(new_key)
        new_aes = AESGCM(new_key)
        for name, pt in plain.items():
            old = self._doc["entries"][name]
            entry = _seal(new_aes, doc["key_id"], name, pt)
            entry.update(created=old["created"], updated=old["updated"],
                         rotated_by=old.get("rotated_by", ""))
            doc["entries"][name] = entry
        new = Vault(self.path, new_key, doc)
        new._save()
        return new

    def to_bytes(self) -> bytes:
        return _dumps(self._doc)

    def _save(self) -> None:
        atomic_write(self.path, self.to_bytes(), backup=True)


def _dumps(doc: dict[str, Any]) -> bytes:
    return json.dumps(doc, indent=2, sort_keys=True).encode()


def atomic_write(path: Path, data: bytes, *, backup: bool = False, mode: int = 0o600) -> None:
    """Write ``data`` to ``path`` so readers only ever see the old or the new content.

    Writes to a temp file in the same directory, fsyncs it, optionally keeps the previous
    file as ``<path>.bak``, then renames into place and fsyncs the directory (POSIX).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        if path.exists() and hasattr(os, "chown"):
            # Root-run admin commands must not take ownership away from the service user.
            st = path.stat()
            with contextlib.suppress(PermissionError):
                os.chown(tmp, st.st_uid, st.st_gid)
        if backup and path.exists():
            bak = path.with_name(path.name + ".bak")
            atomic_write(bak, path.read_bytes(), mode=mode)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()
        raise
    if hasattr(os, "O_DIRECTORY"):
        dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
