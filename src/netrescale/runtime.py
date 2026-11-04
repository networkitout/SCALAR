"""Wiring shared by the daemon and the CLI: vault access, credential resolution, clients."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from netrescale.config import DEFAULT_CONFIG_PATH, Config, Device
from netrescale.secrets.base import Credential
from netrescale.secrets.resolver import CredentialRef, LockoutGuard, Resolver
from netrescale.secrets.systemd_creds import (
    VAULT_KEY_CRED_NAME,
    load_key_from_credentials_directory,
    unseal_key,
)
from netrescale.secrets.vault import Vault
from netrescale.transport.nitro import NitroClient, NitroTarget

KeyLoader = Callable[[], bytes]


def default_key_loader(cfg: Config) -> KeyLoader:
    """Inside the systemd unit: $CREDENTIALS_DIRECTORY. Otherwise (root CLI): systemd-creds."""

    def load() -> bytes:
        if os.environ.get("CREDENTIALS_DIRECTORY"):
            return load_key_from_credentials_directory(VAULT_KEY_CRED_NAME)
        return unseal_key(cfg.paths.sealed_vault_key)

    return load


@dataclass
class ReloadingVaultProvider:
    """Local vault provider that re-reads the file when it changes on disk.

    Writes are atomic renames, so a changed (mtime, size, inode) means a complete new file.
    """

    path: Path
    key: bytes
    scheme: str = "local"
    _vault: Vault | None = field(default=None, init=False)
    _stamp: tuple[int, int, int] | None = field(default=None, init=False)

    def _stat(self) -> tuple[int, int, int]:
        st = self.path.stat()
        return (st.st_mtime_ns, st.st_size, st.st_ino)

    @property
    def vault(self) -> Vault:
        stamp = self._stat()
        if self._vault is None or stamp != self._stamp:
            self._vault = Vault.open(self.path, self.key)
            self._stamp = stamp
        return self._vault

    def get(self, name: str) -> Credential:
        return self.vault.get(name)


@dataclass
class Runtime:
    cfg: Config
    key_loader: KeyLoader
    guard: LockoutGuard = field(default_factory=LockoutGuard)
    # Tests (and the emulator) inject a transport; production builds a pinned one.
    nitro_transport: Callable[[Device], httpx.AsyncBaseTransport] | None = None
    config_path: Path = DEFAULT_CONFIG_PATH
    _provider: ReloadingVaultProvider | None = field(default=None, init=False)
    _resolver: Resolver | None = field(default=None, init=False)
    _device_locks: dict[str, asyncio.Lock] = field(default_factory=dict, init=False)

    def device_lock(self, name: str) -> asyncio.Lock:
        return self._device_locks.setdefault(name, asyncio.Lock())

    @property
    def provider(self) -> ReloadingVaultProvider:
        if self._provider is None:
            self._provider = ReloadingVaultProvider(self.cfg.paths.vault, self.key_loader())
        return self._provider

    @property
    def resolver(self) -> Resolver:
        if self._resolver is None:
            self._resolver = Resolver([self.provider], self.guard)
        return self._resolver

    def nitro_target(self, d: Device) -> NitroTarget:
        return NitroTarget(
            name=d.name,
            host=d.nsip,
            port=d.nitro_port or self.cfg.defaults.nitro_port,
            spki_pin=d.spki_pin,
            spki_pinning=d.spki_pinning,
            ca_bundle=d.ca_bundle or self.cfg.defaults.ca_bundle,
        )

    def nitro_client(self, d: Device, credential: str | None = None) -> NitroClient:
        """A read-only NITRO client for ``d``; ``credential`` overrides its NITRO account
        (e.g. the FIM account). Login rejections lock out only that device and credential."""
        ref = CredentialRef.parse(credential or self.cfg.nitro_ref(d))
        return NitroClient(
            self.nitro_target(d),
            lambda: self.resolver.resolve(ref, device=d.name),
            on_auth_rejected=lambda: self.guard.record_rejection(d.name, ref),
            transport=self.nitro_transport(d) if self.nitro_transport else None,
        )
