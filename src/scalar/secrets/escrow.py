"""Passphrase-wrapped escrow of the vault master key, and full vault backup bundles.

The master key is normally sealed with systemd-creds using this host's key, which does not
survive a server rebuild. The escrow file wraps the same key with a key derived from an
admin passphrase (Argon2id, RFC 9106 second recommended parameters) so the vault can be
restored on a new host.
"""

from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from scalar.secrets.vault import KEY_LEN, NONCE_LEN, Vault, VaultError, atomic_write

ESCROW_FORMAT = "scalar-escrow"
BACKUP_FORMAT = "scalar-vault-backup"
MIN_PASSPHRASE_LEN = 16


@dataclass(frozen=True, slots=True)
class KdfParams:
    time_cost: int = 3
    memory_cost_kib: int = 64 * 1024
    parallelism: int = 4


DEFAULT_KDF = KdfParams()


class EscrowError(VaultError):
    pass


def _derive(passphrase: str, salt: bytes, p: KdfParams) -> bytes:
    return hash_secret_raw(
        secret=passphrase.encode(),
        salt=salt,
        time_cost=p.time_cost,
        memory_cost=p.memory_cost_kib,
        parallelism=p.parallelism,
        hash_len=KEY_LEN,
        type=Type.ID,
    )


def check_passphrase_strength(passphrase: str) -> None:
    if len(passphrase) < MIN_PASSPHRASE_LEN:
        raise EscrowError(f"escrow passphrase must be at least {MIN_PASSPHRASE_LEN} characters")


def wrap_key(master_key: bytes, key_id: str, passphrase: str,
             kdf: KdfParams = DEFAULT_KDF) -> dict[str, Any]:
    check_passphrase_strength(passphrase)
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(NONCE_LEN)
    wrapping = AESGCM(_derive(passphrase, salt, kdf))
    ct = wrapping.encrypt(nonce, master_key, f"nrescrow1|{key_id}".encode())
    return {
        "format": ESCROW_FORMAT,
        "format_version": 1,
        "key_id": key_id,
        "kdf": {"alg": "argon2id", "t": kdf.time_cost, "m_kib": kdf.memory_cost_kib,
                "p": kdf.parallelism, "salt": base64.b64encode(salt).decode()},
        "nonce": base64.b64encode(nonce).decode(),
        "ct": base64.b64encode(ct).decode(),
    }


def unwrap_key(doc: dict[str, Any], passphrase: str) -> tuple[bytes, str]:
    """Return (master_key, key_id). Raises EscrowError on a wrong passphrase or tampering."""
    if doc.get("format") != ESCROW_FORMAT:
        raise EscrowError("not a scalar escrow document")
    try:
        k = doc["kdf"]
        if k["alg"] != "argon2id":
            raise EscrowError(f"unsupported KDF {k['alg']!r}")
        params = KdfParams(time_cost=int(k["t"]), memory_cost_kib=int(k["m_kib"]),
                           parallelism=int(k["p"]))
        if not (1 <= params.time_cost <= 10 and 8 <= params.memory_cost_kib <= 262144
                and 1 <= params.parallelism <= 8):
            raise EscrowError("backup KDF parameters exceed supported safety limits")
        salt = base64.b64decode(k["salt"])
        nonce = base64.b64decode(doc["nonce"])
        ct = base64.b64decode(doc["ct"])
        key_id = str(doc["key_id"])
    except (KeyError, ValueError, TypeError) as exc:
        raise EscrowError("escrow document is malformed") from exc
    try:
        key = AESGCM(_derive(passphrase, salt, params)).decrypt(
            nonce, ct, f"nrescrow1|{key_id}".encode())
    except InvalidTag:
        raise EscrowError("wrong passphrase, or the escrow file was modified") from None
    return key, key_id


def write_escrow(path: Path, master_key: bytes, key_id: str, passphrase: str,
                 kdf: KdfParams = DEFAULT_KDF) -> None:
    doc = wrap_key(master_key, key_id, passphrase, kdf)
    atomic_write(path, json.dumps(doc, indent=2).encode())


def make_backup(vault: Vault, master_key: bytes, passphrase: str,
                kdf: KdfParams = DEFAULT_KDF) -> bytes:
    """Self-contained backup: the vault ciphertext plus the passphrase-wrapped master key."""
    return json.dumps({
        "format": BACKUP_FORMAT,
        "format_version": 1,
        "escrow": wrap_key(master_key, vault.key_id, passphrase, kdf),
        "vault": json.loads(vault.to_bytes()),
    }, indent=2).encode()


def restore_backup(raw: bytes, passphrase: str, dest: Path) -> tuple[Vault, bytes]:
    """Unwrap the key, verify it against the vault, and write the vault to ``dest``.

    Returns (vault, master_key). The caller must re-seal master_key for the new host.
    """
    try:
        doc = json.loads(raw)
    except ValueError as exc:
        raise EscrowError("backup is not valid JSON") from exc
    if doc.get("format") != BACKUP_FORMAT:
        raise EscrowError("not a scalar vault backup")
    key, key_id = unwrap_key(doc["escrow"], passphrase)
    vault_bytes = json.dumps(doc["vault"]).encode()
    vault = Vault.from_bytes(dest, key, vault_bytes)  # verifies key_check
    if vault.key_id != key_id:
        raise EscrowError("backup escrow key_id does not match the vault")
    for name in vault.names():
        vault.get(name)  # authenticate every entry before writing anything
    if dest.exists():
        raise EscrowError(f"refusing to overwrite existing vault at {dest}")
    vault._save()
    return vault, key
