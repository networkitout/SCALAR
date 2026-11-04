import base64
import json
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from netrescale.redact import registry
from netrescale.secrets.base import Credential, CredentialError
from netrescale.secrets.escrow import (
    EscrowError,
    KdfParams,
    make_backup,
    restore_backup,
    unwrap_key,
    wrap_key,
)
from netrescale.secrets.resolver import (
    CredentialBlocked,
    CredentialRef,
    LocalVaultProvider,
    Resolver,
    UnknownScheme,
    stale_entries,
)
from netrescale.secrets.vault import (
    Vault,
    VaultEntryNotFound,
    VaultError,
    VaultKeyMismatch,
    generate_key,
)

FAST_KDF = KdfParams(time_cost=1, memory_cost_kib=1024, parallelism=1)
PASSPHRASE = "correct horse battery staple"


@pytest.fixture
def key() -> bytes:
    return generate_key()


@pytest.fixture
def vault(tmp_path: Path, key: bytes) -> Vault:
    return Vault.create(tmp_path / "vault", key)


def cred(user: str = "nr_nitro", pw: str = "s3cret-Pa55") -> Credential:
    return Credential(user, pw)


def test_roundtrip_and_reopen(vault: Vault, key: bytes) -> None:
    vault.set("nr_nitro", cred(), actor="uid:1000")
    reopened = Vault.open(vault.path, key)
    assert reopened.get("nr_nitro") == cred()
    assert reopened.names() == ["nr_nitro"]
    meta = reopened.meta("nr_nitro")
    assert meta.rotated_by == "uid:1000"


def test_file_never_contains_plaintext(vault: Vault) -> None:
    vault.set("nr_sweep", cred("nr_sweep", "hunter2-very-secret"), actor="t")
    raw = vault.path.read_bytes()
    assert b"hunter2-very-secret" not in raw
    assert b"nr_sweep" in raw  # names are metadata, intentionally visible
    assert b'"username"' not in raw


def test_wrong_key_rejected_even_when_empty(vault: Vault) -> None:
    with pytest.raises(VaultKeyMismatch):
        Vault.open(vault.path, generate_key())


def test_swapping_ciphertext_between_names_fails(vault: Vault, key: bytes) -> None:
    vault.set("a", cred("a", "password-a"), actor="t")
    vault.set("b", cred("b", "password-b"), actor="t")
    doc = json.loads(vault.path.read_bytes())
    doc["entries"]["a"], doc["entries"]["b"] = doc["entries"]["b"], doc["entries"]["a"]
    vault.path.write_text(json.dumps(doc))
    v = Vault.open(vault.path, key)
    with pytest.raises(VaultError, match="failed authentication"):
        v.get("a")


def test_bit_flip_detected(vault: Vault, key: bytes) -> None:
    vault.set("a", cred(), actor="t")
    doc = json.loads(vault.path.read_bytes())
    ct = bytearray(base64.b64decode(doc["entries"]["a"]["ct"]))
    ct[0] ^= 0x01
    doc["entries"]["a"]["ct"] = base64.b64encode(bytes(ct)).decode()
    vault.path.write_text(json.dumps(doc))
    with pytest.raises(VaultError):
        Vault.open(vault.path, key).get("a")


def test_tampered_key_id_detected(vault: Vault, key: bytes) -> None:
    vault.set("a", cred(), actor="t")
    doc = json.loads(vault.path.read_bytes())
    doc["key_id"] = "0" * 16
    vault.path.write_text(json.dumps(doc))
    with pytest.raises(VaultKeyMismatch):
        Vault.open(vault.path, key)


def test_truncated_file_rejected(vault: Vault, key: bytes) -> None:
    vault.set("a", cred(), actor="t")
    vault.path.write_bytes(vault.path.read_bytes()[:40])
    with pytest.raises(VaultError, match="not valid JSON"):
        Vault.open(vault.path, key)


def test_nonces_unique_across_writes(vault: Vault) -> None:
    seen: set[str] = set()
    for i in range(300):
        vault.set("a", cred(pw=f"password-{i}"), actor="t")
        nonce = json.loads(vault.path.read_bytes())["entries"]["a"]["nonce"]
        assert nonce not in seen
        seen.add(nonce)


def test_failed_write_leaves_old_vault_intact(
    vault: Vault, key: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault.set("a", cred(pw="original-pw"), actor="t")
    before = vault.path.read_bytes()

    def boom(*_a: object, **_k: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr("netrescale.secrets.vault.os.replace", boom)
    with pytest.raises(OSError):
        vault.set("a", cred(pw="new-pw-xxxx"), actor="t")
    assert vault.path.read_bytes() == before
    assert vault.get("a") == cred(pw="original-pw")  # in-memory view unchanged too
    assert not list(vault.path.parent.glob(".vault.*.tmp"))


def test_backup_file_kept(vault: Vault) -> None:
    vault.set("a", cred(pw="first-pw"), actor="t")
    vault.set("a", cred(pw="second-pw"), actor="t")
    assert vault.path.with_name("vault.bak").exists()


def test_delete_and_missing(vault: Vault) -> None:
    vault.set("a", cred(), actor="t")
    vault.delete("a")
    with pytest.raises(VaultEntryNotFound):
        vault.get("a")
    with pytest.raises(VaultEntryNotFound):
        vault.delete("a")


@pytest.mark.parametrize("bad", ["", "-lead", "has space", "a" * 65, "x/y", "semi;colon"])
def test_invalid_names_rejected(vault: Vault, bad: str) -> None:
    with pytest.raises(CredentialError):
        vault.set(bad, cred(), actor="t")


def test_refuses_to_overwrite_existing(vault: Vault, key: bytes) -> None:
    with pytest.raises(VaultError, match="refusing"):
        Vault.create(vault.path, key)


def test_rekey_preserves_entries(vault: Vault, key: bytes) -> None:
    for i in range(5):
        vault.set(f"dev{i}", cred(f"user{i}", f"password-{i}"), actor="t")
    old_key_id = vault.key_id
    new_key = generate_key()
    new = vault.rekey(new_key)
    assert new.key_id != old_key_id
    reopened = Vault.open(vault.path, new_key)
    for i in range(5):
        assert reopened.get(f"dev{i}") == cred(f"user{i}", f"password-{i}")
    with pytest.raises(VaultKeyMismatch):
        Vault.open(vault.path, key)


def test_credential_repr_hides_secret() -> None:
    c = Credential("u", "topsecret-value", ssh_private_key="-----BEGIN KEY-----")
    assert "topsecret" not in repr(c)
    assert "BEGIN" not in str(c)
    assert registry.contains_secret("leak: topsecret-value")


# ---- escrow / backup ---------------------------------------------------------------------


def test_escrow_roundtrip_and_wrong_passphrase(key: bytes) -> None:
    doc = wrap_key(key, "abcd", PASSPHRASE, FAST_KDF)
    assert unwrap_key(doc, PASSPHRASE) == (key, "abcd")
    with pytest.raises(EscrowError, match="wrong passphrase"):
        unwrap_key(doc, PASSPHRASE + "x")


def test_escrow_key_id_bound(key: bytes) -> None:
    doc = wrap_key(key, "abcd", PASSPHRASE, FAST_KDF)
    doc["key_id"] = "ffff"
    with pytest.raises(EscrowError):
        unwrap_key(doc, PASSPHRASE)


def test_short_passphrase_rejected(key: bytes) -> None:
    with pytest.raises(EscrowError, match="at least"):
        wrap_key(key, "abcd", "short", FAST_KDF)


def test_backup_restore_on_new_host(vault: Vault, key: bytes, tmp_path: Path) -> None:
    vault.set("nr_nitro", cred(), actor="t")
    vault.set("nr_sweep", cred("nr_sweep", "sweep-password"), actor="t")
    bundle = make_backup(vault, key, PASSPHRASE, FAST_KDF)
    assert b"sweep-password" not in bundle

    dest = tmp_path / "newhost" / "vault"
    _restored, restored_key = restore_backup(bundle, PASSPHRASE, dest)
    assert restored_key == key
    assert Vault.open(dest, key).get("nr_sweep") == cred("nr_sweep", "sweep-password")
    with pytest.raises(EscrowError):
        restore_backup(bundle, "the wrong passphrase!!", tmp_path / "other" / "vault")


# ---- resolver ----------------------------------------------------------------------------


def test_resolver_and_lockout_guard(vault: Vault) -> None:
    vault.set("nr_nitro", cred(), actor="t")
    r = Resolver([LocalVaultProvider(vault)])
    assert r.resolve("local:nr_nitro", device="ns1") == cred()

    ref = CredentialRef.parse("local:nr_nitro")
    r.guard.record_rejection("ns1", ref)
    with pytest.raises(CredentialBlocked):
        r.resolve(ref, device="ns1")
    assert r.resolve(ref, device="ns2") == cred()  # other devices unaffected
    r.guard.clear(ref)
    assert r.resolve(ref, device="ns1") == cred()


def test_lockout_only_released_when_credential_changes(vault: Vault) -> None:
    vault.set("nr_nitro", cred(), actor="first")
    resolver = Resolver([LocalVaultProvider(vault)])
    ref = CredentialRef.parse("local:nr_nitro")
    resolver.resolve(ref, device="ns1")
    resolver.guard.record_rejection("ns1", ref)

    vault.set("unrelated", cred("other", "other-password"), actor="admin")
    with pytest.raises(CredentialBlocked):
        resolver.resolve(ref, device="ns1")
    vault.set("nr_nitro", cred(), actor="admin")
    with pytest.raises(CredentialBlocked):
        resolver.resolve(ref, device="ns1")

    replacement = cred("nr_nitro", "rotated-password")
    vault.set("nr_nitro", replacement, actor="admin")
    assert resolver.resolve(ref, device="ns1") == replacement
    assert resolver.guard.blocked() == []


@pytest.mark.parametrize("bad", ["nr_nitro", "local:", ":x", "local:bad name"])
def test_bad_refs(bad: str) -> None:
    with pytest.raises(CredentialError):
        CredentialRef.parse(bad)


def test_unknown_scheme(vault: Vault) -> None:
    with pytest.raises(UnknownScheme, match="bitwarden"):
        Resolver([LocalVaultProvider(vault)]).resolve("bitwarden:abc")


def test_stale_entries(vault: Vault) -> None:
    vault.set("old", cred(), actor="t")
    future = datetime.now(UTC) + timedelta(days=91)
    assert [m.name for m in stale_entries(vault, 90, now=future)] == ["old"]
    assert stale_entries(vault, 90) == []


@settings(max_examples=40, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(user=st.text(min_size=1, max_size=40), pw=st.text(min_size=1, max_size=200))
def test_roundtrip_property(user: str, pw: str) -> None:
    with tempfile.TemporaryDirectory() as d:
        k = generate_key()
        p = Path(d) / "vault"
        Vault.create(p, k).set("e", Credential(user, pw), actor="t")
        assert Vault.open(p, k).get("e") == Credential(user, pw)
