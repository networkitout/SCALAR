"""Seal and load the vault master key with systemd-creds (systemd >= 250; Ubuntu 24.04 has 255).

With no TPM the credential is encrypted with the host key in
/var/lib/systemd/credential.secret (root-only). The running service never calls
systemd-creds itself: the unit's ``LoadCredentialEncrypted=`` decrypts the credential into
``$CREDENTIALS_DIRECTORY`` (ramfs, readable only by the service user) before start.
"""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
from pathlib import Path

from scalar.secrets.vault import KEY_LEN, VaultError

VAULT_KEY_CRED_NAME = "scalar.vault-key"
DEFAULT_CREDSTORE = Path("/etc/credstore.encrypted")


class SystemdCredsError(VaultError):
    pass


def _encode_key(key: bytes) -> bytes:
    return base64.b64encode(key) + b"\n"


def _decode_key(data: bytes) -> bytes:
    try:
        key = base64.b64decode(data.strip(), validate=True)
    except ValueError as exc:
        raise SystemdCredsError("vault key credential is not valid base64") from exc
    if len(key) != KEY_LEN:
        raise SystemdCredsError("vault key credential has the wrong length")
    return key


def load_key_from_credentials_directory(name: str = VAULT_KEY_CRED_NAME) -> bytes:
    """Used by the daemon: read the key systemd decrypted for us."""
    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if not cred_dir:
        raise SystemdCredsError(
            "CREDENTIALS_DIRECTORY is not set; run under the scalar systemd unit "
            f"with LoadCredentialEncrypted={name}"
        )
    try:
        return _decode_key((Path(cred_dir) / name).read_bytes())
    except FileNotFoundError as exc:
        raise SystemdCredsError(f"credential {name!r} not present in {cred_dir}") from exc


def _systemd_creds() -> str:
    exe = shutil.which("systemd-creds")
    if not exe:
        raise SystemdCredsError("systemd-creds not found (requires systemd >= 250)")
    return exe


def seal_key(key: bytes, out_path: Path, name: str = VAULT_KEY_CRED_NAME,
             with_key: str = "host") -> None:
    """Root-only: encrypt the key to ``out_path`` (bound to ``name``) via systemd-creds."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_name(f".{out_path.name}.tmp")
    try:
        subprocess.run(  # noqa: S603 - fixed argv, no shell
            [_systemd_creds(), "encrypt", f"--with-key={with_key}", f"--name={name}",
             "-", str(tmp)],
            input=_encode_key(key), check=True, capture_output=True,
        )
        os.chmod(tmp, 0o600)
        os.replace(tmp, out_path)
    except subprocess.CalledProcessError as exc:
        tmp.unlink(missing_ok=True)
        raise SystemdCredsError(
            f"systemd-creds encrypt failed: {exc.stderr.decode(errors='replace').strip()}"
        ) from exc


def unseal_key(path: Path, name: str = VAULT_KEY_CRED_NAME) -> bytes:
    """Root-only: decrypt a sealed key file (used by offline admin commands)."""
    try:
        res = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [_systemd_creds(), "decrypt", f"--name={name}", str(path), "-"],
            check=True, capture_output=True,
        )
    except subprocess.CalledProcessError as exc:
        raise SystemdCredsError(
            f"systemd-creds decrypt failed: {exc.stderr.decode(errors='replace').strip()}"
        ) from exc
    return _decode_key(res.stdout)
