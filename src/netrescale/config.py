"""Configuration file models (/etc/netrescale/config.yaml).

The config holds no secrets. Credentials are referenced as ``local:<name>`` and live in the
encrypted vault.
"""

from __future__ import annotations

import ipaddress
import re
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

from netrescale.secrets.base import CredentialError
from netrescale.secrets.resolver import CredentialRef

DEFAULT_CONFIG_PATH = Path("/etc/netrescale/config.yaml")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _check_ref(v: str) -> str:
    try:
        CredentialRef.parse(v)
    except CredentialError as exc:
        raise ValueError(str(exc)) from None
    return v


def _check_ip(v: str) -> str:
    return str(ipaddress.ip_address(v))


class DeviceMode(StrEnum):
    OBSERVE = "observe"  # NITRO config polling, stats and exposure only
    ACTIVE = "active"  # also SSH log pulls and host sweeps (only after `probe` passes)


class Intervals(_Strict):
    config_probe: Annotated[int, Field(ge=15)] = 60
    config_full: Annotated[int, Field(ge=600)] = 21600
    stats: Annotated[int, Field(ge=15)] = 60
    log_pull: Annotated[int, Field(ge=60)] = 900
    sweep: Annotated[int, Field(ge=3600)] = 21600
    syslog_silence_alert: Annotated[int, Field(ge=60)] = 900


class FimDefaults(_Strict):
    """File-integrity monitoring over NITRO systemfile (see collect/fim.py). Tier A paths
    (boot hooks, SSH keys, crontabs, httpd.conf) are checked on every config probe."""

    # A separate account whose command policy only lists/reads the FIM paths
    # (`netrescale snippets` prints it), so nr_nitro can stay narrowed to /var/log.
    credential: str = "local:nr_fim"
    webroot_interval: Annotated[int, Field(ge=300, le=900)] = 600  # Tier B walk
    rehash_interval: Annotated[int, Field(ge=300, le=3600)] = 900  # re-hash unchanged files
    max_entries: Annotated[int, Field(ge=100, le=50000)] = 5000  # per Tier B directory tree
    max_depth: Annotated[int, Field(ge=1, le=16)] = 8
    walk_seconds: Annotated[int, Field(ge=10, le=300)] = 90  # per Tier B pass
    max_hashes: Annotated[int, Field(ge=1, le=5000)] = 200  # content fetches per Tier B pass

    _v_credential = field_validator("credential")(_check_ref)


class Defaults(_Strict):
    nitro_credential: str = "local:nr_nitro"
    sweep_credential: str = "local:nr_sweep"
    nitro_port: Annotated[int, Field(ge=1, le=65535)] = 443
    ssh_port: Annotated[int, Field(ge=1, le=65535)] = 22
    ca_bundle: str | None = None
    intervals: Intervals = Intervals()
    fim: FimDefaults = FimDefaults()

    _v_nitro = field_validator("nitro_credential", "sweep_credential")(_check_ref)


class DeviceFim(_Strict):
    enabled: bool = False  # opt-in per device, after the account and policy are applied
    credential: str | None = None  # overrides defaults.fim.credential

    @field_validator("credential")
    @classmethod
    def _v_ref(cls, v: str | None) -> str | None:
        return _check_ref(v) if v is not None else v


class Device(_Strict):
    name: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")]
    nsip: str
    mode: DeviceMode = DeviceMode.OBSERVE
    spki_pin: str | None = None
    spki_pinning: bool = True
    ca_bundle: str | None = None
    ssh_hostkey: str | None = None
    nitro_port: Annotated[int | None, Field(ge=1, le=65535)] = None
    ssh_port: Annotated[int | None, Field(ge=1, le=65535)] = None
    nitro_credential: str | None = None
    sweep_credential: str | None = None
    firmware_variant: Literal["fips", "ndcpp"] | None = None
    syslog_sources: list[str] = []
    timezone: str = "UTC"
    date_format: Literal["MMDDYYYY", "DDMMYYYY", "YYYYMMDD"] = "YYYYMMDD"
    fim: DeviceFim = DeviceFim()

    _v_ip = field_validator("nsip")(_check_ip)

    @field_validator("timezone")
    @classmethod
    def _timezone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except ZoneInfoNotFoundError as exc:
            raise ValueError("unknown device timezone") from exc
        return value

    @field_validator("nitro_credential", "sweep_credential")
    @classmethod
    def _v_ref(cls, v: str | None) -> str | None:
        return _check_ref(v) if v is not None else v

    @field_validator("syslog_sources")
    @classmethod
    def _v_sources(cls, v: list[str]) -> list[str]:
        return [_check_ip(ip) for ip in v]

    @model_validator(mode="after")
    def _active_requires_hostkey(self) -> Device:
        if self.mode is DeviceMode.ACTIVE and not self.ssh_hostkey:
            raise ValueError(f"{self.name}: mode 'active' requires a pinned ssh_hostkey")
        return self


class HaPair(_Strict):
    name: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")]
    nodes: Annotated[list[str], Field(min_length=2, max_length=2)]
    sync_grace_seconds: Annotated[int, Field(ge=30)] = 180


class SmtpSink(_Strict):
    host: str
    port: Annotated[int, Field(ge=1, le=65535)] = 587
    starttls: bool = True
    sender: str
    recipients: Annotated[list[str], Field(min_length=1)]
    credential: str | None = None  # optional SMTP auth, from the vault
    min_severity: Literal["info", "low", "medium", "high", "critical"] = "medium"

    @field_validator("credential")
    @classmethod
    def _credential(cls, value: str | None) -> str | None:
        return _check_ref(value) if value is not None else None

    @model_validator(mode="after")
    def _auth_requires_tls(self) -> SmtpSink:
        if self.credential and not self.starttls:
            raise ValueError("notify.smtp.credential requires starttls: true")
        return self


class SiemSink(_Strict):
    host: str
    port: Annotated[int, Field(ge=1, le=65535)] = 6514
    transport: Literal["tls", "tcp"] = "tls"
    format: Literal["json", "cef"] = "json"
    ca_bundle: str | None = None
    min_severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    forward_events: bool = False


class WebhookSink(_Strict):
    url: Annotated[str, Field(pattern=r"^https://")]
    format: Literal["generic", "slack"] = "generic"
    min_severity: Literal["info", "low", "medium", "high", "critical"] = "high"


class Notify(_Strict):
    smtp: SmtpSink | None = None
    siem: SiemSink | None = None
    webhook: WebhookSink | None = None
    daily_digest_hour_utc: Annotated[int, Field(ge=0, le=23)] = 7


class Retention(_Strict):
    raw_days: Annotated[int, Field(ge=1)] = 365
    events_days: Annotated[int, Field(ge=1)] = 90
    findings_days: Annotated[int, Field(ge=1)] = 400


class Syslog(_Strict):
    enabled: bool = True
    poll_seconds: Annotated[int, Field(ge=1, le=60)] = 5
    batch_lines: Annotated[int, Field(ge=1, le=10000)] = 500
    max_line_bytes: Annotated[int, Field(ge=1024, le=1048576)] = 262144
    source_days: Annotated[int, Field(ge=1)] = 2
    admin_networks: list[str] = []
    admin_users: list[str] = []

    @field_validator("admin_networks")
    @classmethod
    def _networks(cls, values: list[str]) -> list[str]:
        return [str(ipaddress.ip_network(value, strict=False)) for value in values]


class Web(_Strict):
    host: str = "127.0.0.1"
    port: Annotated[int, Field(ge=1024, le=65535)] = 8080
    public_url: str | None = None
    allow_http: bool = False
    allowed_hosts: list[str] = ["localhost", "127.0.0.1"]
    session_hours: Annotated[int, Field(ge=1, le=24)] = 8
    # Host-managed: lets the dashboard change appliance addresses, TLS trust, credential
    # references and notification destinations. The web cannot change this flag itself.
    allow_sensitive_settings: bool = False

    @property
    def require_https(self) -> bool:
        return bool(self.public_url and urlsplit(self.public_url).scheme == "https")

    @model_validator(mode="after")
    def _transport(self) -> Web:
        address = ipaddress.ip_address(self.host)
        if self.public_url:
            parsed = urlsplit(self.public_url)
            _ = parsed.port
            schemes = {"https", "http"} if self.allow_http else {"https"}
            if (parsed.scheme not in schemes or not parsed.hostname or parsed.username
                    or parsed.password or parsed.query or parsed.fragment
                    or parsed.path not in ("", "/")):
                raise ValueError("web.public_url must be an HTTPS origin without credentials "
                                 "or path; HTTP requires web.allow_http: true")
        elif not address.is_loopback and not self.allow_http:
            raise ValueError("public web listeners require an HTTPS reverse proxy "
                             "and web.public_url, or explicit web.allow_http: true")
        if not self.allowed_hosts or any(
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.\-]{0,252}", host)
            for host in self.allowed_hosts):
            raise ValueError("web.allowed_hosts must explicitly name the accepted hosts")
        return self


class Paths(_Strict):
    state_dir: Path = Path("/var/lib/netrescale")
    log_dir: Path = Path("/var/log/netrescale")
    vault: Path = Path("/var/lib/netrescale/vault")
    sealed_vault_key: Path = Path("/etc/credstore.encrypted/netrescale.vault-key")
    control_socket: Path = Path("/run/netrescale/control.sock")


class Config(_Strict):
    paths: Paths = Paths()
    admin_group: str = "netrescale-admin"
    max_credential_age_days: Annotated[int, Field(ge=1)] = 90
    database_url: str = "postgresql+psycopg:///netrescale"
    defaults: Defaults = Defaults()
    devices: list[Device] = []
    ha_pairs: list[HaPair] = []
    notify: Notify = Notify()
    retention: Retention = Retention()
    syslog: Syslog = Syslog()
    web: Web = Web()

    @field_validator("database_url")
    @classmethod
    def _database(cls, value: str) -> str:
        try:
            parsed = make_url(value)
            if parsed.drivername != "postgresql+psycopg" or not parsed.database:
                raise ValueError
            if parsed.port is not None and not 1 <= parsed.port <= 65535:
                raise ValueError
        except (ValueError, ArgumentError) as exc:
            raise ValueError("database_url must be a valid postgresql+psycopg URL") from exc
        return value

    @model_validator(mode="after")
    def _cross_checks(self) -> Config:
        names = [d.name for d in self.devices]
        dupes = {n for n in names if names.count(n) > 1}
        if dupes:
            raise ValueError(f"duplicate device names: {sorted(dupes)}")
        nsips = [d.nsip for d in self.devices]
        if len(set(nsips)) != len(nsips):
            raise ValueError("two devices share an nsip")
        senders: dict[str, str] = {}
        for device in self.devices:
            for address in [device.nsip, *device.syslog_sources]:
                if address in senders and senders[address] != device.name:
                    raise ValueError(f"syslog source {address} belongs to multiple devices")
                senders[address] = device.name
        known = set(names)
        paired: set[str] = set()
        for pair in self.ha_pairs:
            for node in pair.nodes:
                if node not in known:
                    raise ValueError(f"HA pair {pair.name}: unknown device {node!r}")
                if node in paired:
                    raise ValueError(f"device {node!r} is in more than one HA pair")
                paired.add(node)
        if self.retention.events_days > self.retention.raw_days:
            raise ValueError("retention.events_days cannot exceed retention.raw_days")
        return self

    def device(self, name: str) -> Device:
        for d in self.devices:
            if d.name == name:
                return d
        raise KeyError(f"no device named {name!r}")

    def pair_of(self, name: str) -> HaPair | None:
        return next((p for p in self.ha_pairs if name in p.nodes), None)

    def nitro_ref(self, d: Device) -> str:
        return d.nitro_credential or self.defaults.nitro_credential

    def sweep_ref(self, d: Device) -> str:
        return d.sweep_credential or self.defaults.sweep_credential

    def fim_ref(self, d: Device) -> str:
        return d.fim.credential or self.defaults.fim.credential

    def credential_users(self) -> dict[str, list[str]]:
        """credential ref -> device names that use it."""
        out: dict[str, list[str]] = {}
        for d in self.devices:
            out.setdefault(self.nitro_ref(d), []).append(d.name)
            if d.mode is DeviceMode.ACTIVE:
                out.setdefault(self.sweep_ref(d), []).append(d.name)
            if d.fim.enabled and d.name not in out.setdefault(self.fim_ref(d), []):
                out[self.fim_ref(d)].append(d.name)
        return out


def load_config(path: Path = DEFAULT_CONFIG_PATH) -> Config:
    with path.open(encoding="utf-8") as fh:
        doc = yaml.safe_load(fh) or {}
    return Config.model_validate(doc)
