"""Audited application administration, executed only by the local monitoring daemon."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import ssl
import tempfile
import time
import uuid
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

import httpx
import yaml
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError

from scalar import __version__
from scalar.appliance import device_snippet
from scalar.collect.config_poller import ConfigPoller
from scalar.collect.device_logs import LOG_FILES, DeviceLogStore, LogSource
from scalar.collect.features import detect_features
from scalar.config import Config, load_config
from scalar.control import ControlError, ControlRequest
from scalar.detect.config_diff import diff_configs
from scalar.detect.config_risk import load_risk_rules
from scalar.detect.exposure import assess, load_cve_data
from scalar.detect.findings import (
    Finding,
    finding_document,
    from_exposure,
)
from scalar.detect.hunt_rules import HuntRuleStore, RuleRevisionConflict, run_worker, templates
from scalar.detect.rules import RuleError
from scalar.detect.severity import Severity
from scalar.parse.version import parse_version
from scalar.redact import registry
from scalar.rsyslog import nftables_conf, rsyslog_conf
from scalar.runtime import Runtime
from scalar.secrets.base import Credential, CredentialError
from scalar.secrets.escrow import make_backup, restore_backup
from scalar.secrets.vault import atomic_write
from scalar.store.archive import RawArchive
from scalar.store.database import Database
from scalar.store.snapshots import FileSnapshotStore
from scalar.transport.nitro import AuthRejected, NitroError, PermissionDenied
from scalar.transport.tls import PinMismatch, fetch_peer_cert
from scalar.web.auth import AuthenticationError, Role, load_accounts, update_user

_DEVICE_LOCKED = ("nsip", "ca_bundle", "nitro_port", "nitro_credential", "sweep_credential",
                  "ssh_hostkey", "mode")


def sensitive_changes(current: Config, candidate: Config) -> list[str]:
    """Settings that decide where credentials and evidence are sent; the browser may not
    change them unless the host owner opted in. TLS pins stay editable (device.pin)."""
    found: list[str] = []
    old, new = current.model_dump(mode="json"), candidate.model_dump(mode="json")
    if old["web"].get("allow_sensitive_settings") != new["web"].get("allow_sensitive_settings"):
        found.append("web.allow_sensitive_settings")
    for key in ("nitro_credential", "sweep_credential", "ca_bundle", "nitro_port"):
        if old["defaults"][key] != new["defaults"][key]:
            found.append(f"defaults.{key}")
    if old["defaults"]["fim"]["credential"] != new["defaults"]["fim"]["credential"]:
        found.append("defaults.fim.credential")
    known = {device["name"]: device for device in old["devices"]}
    for device in new["devices"]:
        before = known.get(device["name"])
        if before is None:
            found.append(f"devices.{device['name']} (new appliance)")
            continue
        found.extend(f"devices.{device['name']}.{key}" for key in _DEVICE_LOCKED
                     if before.get(key) != device.get(key))
        if before["fim"]["credential"] != device["fim"]["credential"]:
            found.append(f"devices.{device['name']}.fim.credential")
    for sink in ("smtp", "siem", "webhook"):
        if old["notify"].get(sink) is None and new["notify"].get(sink) is None:
            continue
        before_sink, after_sink = old["notify"].get(sink) or {}, new["notify"].get(sink) or {}
        found.extend(f"notify.{sink}.{key}" for key in sorted(set(before_sink) | set(after_sink))
                     if key not in {"min_severity", "format", "forward_events", "sender",
                                    "recipients"}
                     and before_sink.get(key) != after_sink.get(key))
    return found


ADMIN_ACTIONS = frozenset(
    {
        "settings.get",
        "settings.validate",
        "settings.save",
        "settings.apply",
        "users.list",
        "users.save",
        "users.delete",
        "credentials.list",
        "credentials.save",
        "credentials.delete",
        "credentials.test",
        "audit.list",
        "vault.status",
        "vault.backup",
        "vault.restore",
        "monitor.pause",
        "monitor.resume",
        "database.initialize",
        "device.pin",
        "setup.snippets",
        "setup.rsyslog",
        "setup.firewall",
        "rules.validate",
        "rules.save",
        "rules.delete",
        "rules.enabled",
    }
)
OPERATOR_ACTIONS = frozenset(
    {
        "platform.status",
        "device.probe",
        "device.exposure",
        "device.poll",
        "rules.list",
        "rules.export",
        "rules.templates",
        "archive.search",
        "archive.verify",
        "tools.hunt",
        "tools.diff",
        "logs.list",
        "logs.fetch",
        "logs.read",
        "logs.hunt",
        "hunts.list",
        "hunts.get",
        "notifications.test",
    }
)
SELF_ACTIONS = frozenset({"account.password"})
READ_ACTIONS = frozenset(
    {
        "settings.get",
        "settings.validate",
        "users.list",
        "credentials.list",
        "audit.list",
        "vault.status",
        "platform.status",
        "rules.list",
        "rules.export",
        "rules.templates",
        "rules.validate",
        "archive.search",
        "archive.verify",
        "tools.hunt",
        "tools.diff",
        "logs.list",
        "logs.read",
        "logs.hunt",
        "hunts.list",
        "hunts.get",
        "setup.snippets",
        "setup.rsyslog",
        "setup.firewall",
    }
)


class Parameters(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Named(Parameters):
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class UserUpdate(Named):
    password: SecretStr | None = Field(default=None, min_length=16, max_length=256)
    role: Role = "viewer"
    enabled: bool = True
    create: bool = False


class CredentialUpdate(Named):
    username: str = Field(min_length=1, max_length=256)
    password: SecretStr | None = Field(default=None, max_length=4096)
    ssh_private_key: SecretStr | None = Field(default=None, max_length=32768)
    remove_ssh_key: bool = False
    create: bool = False


class ConfigUpdate(Parameters):
    document: dict[str, Any]
    revision: str = Field(min_length=0, max_length=64)


class DeviceOperation(Parameters):
    device: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")


class ArchiveOperation(DeviceOperation):
    days: int = Field(default=7, ge=1, le=3650)
    query: str = Field(default="", max_length=200)
    limit: int = Field(default=100, ge=1, le=1000)
    expected_head: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


class BackupOperation(Parameters):
    passphrase: SecretStr = Field(min_length=16, max_length=256)


class RestoreOperation(BackupOperation):
    backup: str = Field(max_length=3 * 1024 * 1024)
    confirmation: Literal["RESTORE"]


class SnippetsOperation(DeviceOperation):
    server_ip: str


class HuntOperation(Parameters):
    text: str = Field(min_length=1, max_length=1048576)
    source: LogSource = "nslog"
    device: str = Field(default="uploaded", pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")


class LogFetch(DeviceOperation):
    sources: list[LogSource] = Field(default_factory=lambda: list(LOG_FILES), min_length=1,
                                      max_length=len(LOG_FILES))


class LogSelection(DeviceOperation):
    source: LogSource
    sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


class HuntHistory(Parameters):
    days: int = Field(default=30, ge=1, le=3650)
    device: str = Field(default="", max_length=63)
    source: LogSource | Literal[""] = ""
    offset: int = Field(default=0, ge=0, le=1000000)
    limit: int = Field(default=25, ge=1, le=50)


class HuntIdentity(Parameters):
    id: str = Field(pattern=r"^[a-f0-9]{32}$")


class RuleInput(Parameters):
    text: str = Field(min_length=1, max_length=262144)
    revision: str = Field(default="", pattern=r"^(?:[a-f0-9]{64})?$")


class RuleIdentity(Parameters):
    id: str = Field(pattern=r"^custom-[a-z0-9][a-z0-9._-]{0,55}$")
    revision: str = Field(pattern=r"^(?:[a-f0-9]{64})?$")


class RuleEnabled(RuleIdentity):
    enabled: bool


class DiffOperation(Parameters):
    before: str = Field(max_length=1048576)
    after: str = Field(max_length=1048576)


class PasswordChange(Parameters):
    current_password: SecretStr = Field(min_length=1, max_length=256)
    password: SecretStr = Field(min_length=16, max_length=256)


def appliance_failure(error: Exception) -> ControlError:
    causes: list[BaseException] = []
    cause: BaseException | None = error
    while cause is not None and len(causes) < 10 and cause not in causes:
        causes.append(cause)
        cause = cause.__cause__ or cause.__context__
    if any(isinstance(item, PinMismatch) for item in causes):
        message = ("The ADC TLS key does not match the saved SPKI pin. Inspect its TLS key, "
                   "verify the fingerprint independently, then save it.")
    elif any(isinstance(item, ssl.SSLCertVerificationError) for item in causes):
        message = ("ADC certificate validation failed. Self-signed HTTPS is supported with "
                   "a verified SPKI pin; a CA bundle is only needed for CA-based validation.")
    elif any(isinstance(item, ssl.SSLError) for item in causes):
        message = ("ADC TLS handshake failed. Polling uses NITRO over HTTPS, not SSH. Check "
                   "the management HTTPS port and TLS 1.2+ support; an HTTP-only endpoint "
                   "cannot be used by the current appliance transport.")
    elif isinstance(error, NitroError | CredentialError):
        message = registry.scrub(str(error))
    elif isinstance(error, httpx.TimeoutException | TimeoutError):
        message = ("The ADC connection timed out. Check its management IP, HTTPS port, "
                   "routing, appliance ACLs, and scalar.service IPAddressAllow. "
                   "The web service's network permissions do not allow appliance polling.")
    elif isinstance(error, httpx.TransportError | OSError):
        message = ("Cannot connect to the ADC. Check the management IP and HTTPS port, "
                   "and allow the ADC address in scalar.service IPAddressAllow. "
                   "Also check routing, firewall rules, and appliance management ACLs.")
    else:
        message = "Appliance request failed"
    return ControlError(message[:2000], 502)


def revision(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else ""


class Administration:
    def __init__(
        self,
        rt: Runtime,
        database: Database,
        callbacks: dict[str, Callable[[], Awaitable[dict[str, Any]]]] | None = None,
    ) -> None:
        self.rt = rt
        self.database = database
        self.callbacks = callbacks or {}
        self._lock = asyncio.Lock()
        self.applied_revision = revision(rt.config_path)
        self.audit_path = rt.cfg.paths.state_dir / "administration.jsonl"

    @property
    def users_path(self) -> Path:
        return self.rt.cfg.paths.state_dir / "web-users.json"

    def _audit(self, request: ControlRequest, outcome: str, *,
               request_id: str = "", duration_ms: float | None = None,
               error: ControlError | None = None, error_type: str | None = None) -> None:
        self.audit_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        target = request.parameters.get("name", request.parameters.get("device"))
        document = {
            "at": datetime.now(UTC).isoformat(),
            "actor": request.actor,
            "action": request.action,
            "outcome": outcome,
            "target": registry.scrub(str(target)[:128]) if target is not None else None,
            "request_id": request_id, "duration_ms": duration_ms,
            "error": registry.scrub(str(error))[:2000] if error else None,
            "error_type": error_type,
            "status": error.status if error else None,
        }
        descriptor = os.open(self.audit_path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "ab") as stream:
            stream.write(json.dumps(document).encode() + b"\n")
            stream.flush()
            os.fsync(stream.fileno())

    async def execute(self, request: ControlRequest) -> dict[str, Any]:
        async with self._lock:
            started = time.monotonic()
            request_id = uuid.uuid4().hex

            async def record(outcome: str, error: ControlError | None = None,
                             error_type: str | None = None) -> None:
                await asyncio.to_thread(
                    self._audit, request, outcome, request_id=request_id,
                    duration_ms=round((time.monotonic() - started) * 1000, 1),
                    error=error, error_type=error_type,
                )

            accounts = await asyncio.to_thread(load_accounts, self.users_path)
            account = accounts.get(request.actor)
            permitted = (
                account is not None
                and account.enabled
                and (
                    (request.action in ADMIN_ACTIONS and account.role == "admin")
                    or (
                        request.action in OPERATOR_ACTIONS and account.role in ("admin", "operator")
                    )
                    or request.action in SELF_ACTIONS
                )
            )
            if not permitted:
                error = ControlError("This operation is not permitted for your account", 403)
                await record("denied", error, "AuthorizationError")
                raise error
            await record("requested")
            try:
                result = await self._dispatch(request)
            except ValidationError as exc:
                locations = [
                    ".".join(str(part) for part in error["loc"])
                    for error in exc.errors(include_input=False, include_context=False)
                ]
                error = ControlError("Invalid fields: " + ", ".join(locations), 422)
                await record("invalid", error, type(exc).__name__)
                raise error from None
            except (AuthenticationError, CredentialError) as exc:
                error = ControlError(registry.scrub(str(exc)), 400)
                await record("rejected", error, type(exc).__name__)
                raise error from None
            except RuleRevisionConflict as exc:
                error = ControlError(str(exc), 409)
                await record("conflict", error, type(exc).__name__)
                raise error from None
            except RuleError as exc:
                error = ControlError(registry.scrub(str(exc)), 422)
                await record("invalid", error, type(exc).__name__)
                raise error from None
            except (NitroError, httpx.TransportError, ssl.SSLError) as exc:
                error = appliance_failure(exc)
                await record("failed", error, type(exc).__name__)
                raise error from None
            except ControlError as exc:
                await record("rejected", exc, type(exc).__name__)
                raise
            except Exception as exc:  # noqa: BLE001
                error = ControlError(
                    "Operation failed; check daemon health and host permissions", 500)
                await record("failed", error, type(exc).__name__)
                raise error from None
            if result.get("errors"):
                detail = "; ".join(f"{item.get('path', '')}: {item.get('error', '')}"
                                   for item in result["errors"])
                await record("partial", ControlError(detail, 207), "PartialResult")
            else:
                await record("completed")
            return result

    async def _dispatch(self, request: ControlRequest) -> dict[str, Any]:
        action, values = request.action, request.parameters
        parameters: Parameters
        if action == "account.password":
            parameters = PasswordChange.model_validate(values)
            user = load_accounts(self.users_path)[request.actor]
            try:
                await asyncio.to_thread(
                    PasswordHasher().verify,
                    user.password_hash,
                    parameters.current_password.get_secret_value(),
                )
            except VerificationError:
                raise ControlError("Current password is incorrect", 403) from None
            await asyncio.to_thread(
                update_user,
                self.users_path,
                request.actor,
                password=parameters.password.get_secret_value(),
            )
            return {"changed": True, "sign_in_required": True}
        if action in self.callbacks:
            Parameters.model_validate(values)
            result = await self.callbacks[action]()
            if action == "settings.apply":
                self.applied_revision = revision(self.rt.config_path)
            return result
        if action == "settings.get":
            Parameters.model_validate(values)
            cfg = load_config(self.rt.config_path) if self.rt.config_path.exists() else self.rt.cfg
            current = revision(self.rt.config_path)
            return {
                "document": cfg.model_dump(mode="json"),
                "revision": current,
                "pending_apply": cfg != self.rt.cfg,
                "schema": Config.model_json_schema(),
                "host_managed": ["paths", "admin_group"],
            }
        if action in ("settings.validate", "settings.save"):
            parameters = ConfigUpdate.model_validate(values)
            candidate = Config.model_validate(parameters.document)
            if (
                candidate.paths != self.rt.cfg.paths
                or candidate.admin_group != self.rt.cfg.admin_group
            ):
                raise ControlError(
                    "Storage paths and the OS admin group require a host migration; "
                    "they cannot be changed while the daemon is running",
                    409,
                )
            if not self.rt.cfg.web.allow_sensitive_settings:
                locked = sensitive_changes(self.rt.cfg, candidate)
                if locked:
                    raise ControlError(
                        "These settings can only be changed on the host (edit the config file "
                        "or set web.allow_sensitive_settings there): " + ", ".join(locked),
                        403,
                    )
            response: dict[str, Any] = {
                "valid": True,
                "revision": revision(self.rt.config_path),
                "pending_apply": False,
                "warnings": self._settings_warnings(candidate),
            }
            if action == "settings.validate":
                return response
            await asyncio.to_thread(self._save_settings, candidate, parameters.revision)
            response["revision"] = revision(self.rt.config_path)
            response["saved"] = True
            try:
                if "settings.apply" in self.callbacks:
                    activation = await self.callbacks["settings.apply"]()
                else:
                    previous = self.rt.cfg
                    self.rt.cfg = candidate
                    activation = {"applied": True, "workers_reloaded": False,
                                  "web_reload": candidate.web != previous.web
                                  or candidate.database_url != previous.database_url}
            except Exception as exc:  # noqa: BLE001
                detail = (registry.scrub(str(exc)) if isinstance(exc, ControlError)
                          else f"Settings activation failed ({type(exc).__name__}); check Health")
                return {**response, "applied": False, "pending_apply": True,
                        "errors": [{"path": "Settings activation", "error": detail}]}
            response.update(activation)
            response["pending_apply"] = not bool(activation.get("applied"))
            if not response["pending_apply"]:
                self.applied_revision = response["revision"]
            return response
        if action == "users.list":
            Parameters.model_validate(values)
            users = await asyncio.to_thread(load_accounts, self.users_path)
            return {
                "items": [
                    {"name": name, "role": user.role, "enabled": user.enabled}
                    for name, user in sorted(users.items())
                ]
            }
        if action == "users.save":
            parameters = UserUpdate.model_validate(values)
            if parameters.name == request.actor and (
                not parameters.enabled or parameters.role != "admin"
            ):
                raise ControlError(
                    "You cannot disable or demote your own administrator session", 409
                )
            password = parameters.password.get_secret_value() if parameters.password else None
            registry.register(password)
            await asyncio.to_thread(
                update_user,
                self.users_path,
                parameters.name,
                password=password,
                role=parameters.role,
                enabled=parameters.enabled,
                create_only=parameters.create,
            )
            return {"saved": parameters.name}
        if action == "users.delete":
            parameters = Named.model_validate(values)
            if parameters.name == request.actor:
                raise ControlError("You cannot delete your own account", 409)
            await asyncio.to_thread(update_user, self.users_path, parameters.name, remove=True)
            return {"deleted": parameters.name}
        if action == "credentials.list":
            Parameters.model_validate(values)
            return await asyncio.to_thread(self._credentials)
        if action == "credentials.save":
            parameters = CredentialUpdate.model_validate(values)
            await asyncio.to_thread(self._save_credential, parameters, request.actor)
            return {"saved": parameters.name}
        if action == "credentials.delete":
            parameters = Named.model_validate(values)
            references = self._credential_users().get(f"local:{parameters.name}", [])
            if references:
                raise ControlError(
                    "Credential is still referenced by " + ", ".join(references), 409
                )
            await asyncio.to_thread(self.rt.provider.vault.delete, parameters.name)
            return {"deleted": parameters.name}
        if action == "audit.list":
            Parameters.model_validate(values)
            return {"items": await asyncio.to_thread(self._audit_records)}
        if action == "vault.status":
            Parameters.model_validate(values)
            vault = self.rt.provider.vault
            return {
                "entries": len(vault.names()),
                "key_id": vault.key_id,
                "backup_available": vault.path.with_name(vault.path.name + ".bak").exists(),
            }
        if action == "platform.status":
            Parameters.model_validate(values)
            return {
                "administration": "available",
                "warnings": self._settings_warnings(self.rt.cfg),
                "database": await asyncio.to_thread(self.database.counts),
            }
        if action == "credentials.test":
            parameters = Named.model_validate(values)
            devices = [
                device
                for device in self.rt.cfg.devices
                if self.rt.cfg.nitro_ref(device) == f"local:{parameters.name}"
            ]
            if not devices:
                raise ControlError("No active appliance references this NITRO credential", 409)
            results = []
            for device in devices:
                try:
                    result = await self._device_operation("device.probe", device.name)
                    results.append({"device": device.name, "ok": True, **result})
                except (NitroError, CredentialError, OSError, ValueError,
                        httpx.TransportError, ControlError) as exc:
                    results.append(
                        {
                            "device": device.name,
                            "ok": False,
                            "error": str(exc) if isinstance(exc, ControlError)
                            else str(appliance_failure(exc)),
                        }
                    )
            return {"items": results}
        if action in ("device.probe", "device.exposure", "device.poll"):
            parameters = DeviceOperation.model_validate(values)
            return await self._device_operation(action, parameters.device)
        if action == "logs.fetch":
            parameters = LogFetch.model_validate(values)
            return await self._device_operation(action, parameters.device,
                                                sources=parameters.sources)
        if action in ("logs.list", "logs.read", "logs.hunt"):
            parameters = (DeviceOperation.model_validate(values) if action == "logs.list"
                          else LogSelection.model_validate(values))
            try:
                self.rt.cfg.device(parameters.device)
            except KeyError:
                raise ControlError("Device is not in the applied inventory", 409) from None
            logs = DeviceLogStore(self.rt.cfg.paths.state_dir / "device-logs")
            if isinstance(parameters, LogSelection):
                capture = await asyncio.to_thread(logs.read, parameters.device, parameters.source)
                if capture is None:
                    raise ControlError("Fetch this log before opening it or running a hunt", 404)
                if parameters.sha256 and parameters.sha256 != capture["sha256"]:
                    raise ControlError("Log capture changed; refresh the log list "
                                       "and try again", 409)
                if action == "logs.read":
                    scrubbed: dict[str, Any] = registry.scrub_value(capture)
                    return scrubbed
                result = await self._run_hunt(request.actor, HuntOperation(
                    text=capture["text"] or "\n", device=parameters.device,
                    source=parameters.source), capture=logs.metadata(capture))
                return {**result, "capture": logs.metadata(capture)}
            return {"device": parameters.device,
                    "items": await asyncio.to_thread(logs.list, parameters.device)}
        if action == "device.pin":
            parameters = DeviceOperation.model_validate(values)
            cfg = load_config(self.rt.config_path) if self.rt.config_path.exists() else self.rt.cfg
            try:
                device = cfg.device(parameters.device)
            except KeyError:
                raise ControlError(
                    "Save the device settings before inspecting its TLS key", 409) from None
            try:
                certificate = await asyncio.to_thread(
                    fetch_peer_cert, device.nsip, device.nitro_port or cfg.defaults.nitro_port
                )
            except OSError as exc:
                raise appliance_failure(exc) from None
            return {"certificate": asdict(certificate), "requires_verification": True}
        if action == "rules.list":
            Parameters.model_validate(values)
            catalog = await asyncio.to_thread(self.hunt_rules.catalog)
            return {
                "revision": catalog["revision"],
                "items": [
                    {
                        "id": item["document"]["id"], "title": item["document"]["title"],
                        "severity": item["document"]["severity"],
                        "sources": item["document"].get("sources", []),
                        "cve": item["document"].get("cve", []),
                        "references": item["document"].get("references", []),
                        "origin": item["origin"], "enabled": item["enabled"],
                        "provenance": item["document"].get("provenance", "Bundled rule"),
                        "updated_at": item.get("updated_at"),
                        "yaml": yaml.safe_dump(item["document"], sort_keys=False),
                    }
                    for item in catalog["items"]
                ]
            }
        if action in ("rules.validate", "rules.save"):
            parameters = RuleInput.model_validate(values)
            checked = await run_worker({"mode": "validate", "text": parameters.text,
                                        "lists": self._hunt_lists()})
            result = {"valid": True, "tested": checked["tested"],
                      "rules": [document["id"] for document in checked["documents"]]}
            if action == "rules.save":
                result["revision"] = await asyncio.to_thread(
                    self.hunt_rules.save, checked["documents"], parameters.revision, request.actor)
            return result
        if action == "rules.templates":
            Parameters.model_validate(values)
            pack = await asyncio.to_thread(templates)
            return {"source": pack["source"], "items": [
                {"id": rule["id"], "title": rule["title"], "description": rule["description"],
                 "yaml": yaml.safe_dump(rule, sort_keys=False)} for rule in pack["items"]
            ], "yaml": yaml.safe_dump(pack["items"], sort_keys=False)}
        if action == "rules.delete":
            parameters = RuleIdentity.model_validate(values)
            current = await asyncio.to_thread(self.hunt_rules.delete, parameters.id,
                                              parameters.revision)
            return {"deleted": parameters.id, "revision": current}
        if action == "rules.enabled":
            parameters = RuleEnabled.model_validate(values)
            _revision, saved = await asyncio.to_thread(self.hunt_rules.read)
            if parameters.id not in saved["rules"]:
                raise ControlError("Only custom hunt rules can be changed", 404)
            document = {**saved["rules"][parameters.id]["document"], "enabled": parameters.enabled}
            if parameters.enabled:
                await run_worker({"mode": "validate", "text": yaml.safe_dump(document),
                                  "lists": self._hunt_lists()})
            current = await asyncio.to_thread(self.hunt_rules.save, [document],
                                              parameters.revision, request.actor)
            return {"id": parameters.id, "enabled": parameters.enabled, "revision": current}
        if action == "rules.export":
            Parameters.model_validate(values)
            _revision, saved = await asyncio.to_thread(self.hunt_rules.read)
            return {"filename": "scalar-hunt-rules.yaml",
                    "content": yaml.safe_dump(
                        [entry["document"] for entry in saved["rules"].values()], sort_keys=False)}
        if action in ("archive.search", "archive.verify"):
            parameters = ArchiveOperation.model_validate(values)
            self.rt.cfg.device(parameters.device)
            return await asyncio.to_thread(self._archive, action, parameters)
        if action == "tools.hunt":
            parameters = HuntOperation.model_validate(values)
            return await self._run_hunt(request.actor, parameters)
        if action == "hunts.list":
            parameters = HuntHistory.model_validate(values)
            return await asyncio.to_thread(
                self.database.hunt_history, datetime.now(UTC) - timedelta(days=parameters.days),
                device=parameters.device, source=parameters.source,
                offset=parameters.offset, limit=parameters.limit,
            )
        if action == "hunts.get":
            parameters = HuntIdentity.model_validate(values)
            try:
                return await asyncio.to_thread(self.database.hunt, parameters.id)
            except KeyError:
                raise ControlError("Hunt run not found or expired by retention", 404) from None
        if action == "tools.diff":
            parameters = DiffOperation.model_validate(values)
            diff = await asyncio.to_thread(
                diff_configs, parameters.before, parameters.after, load_risk_rules()
            )
            return {
                "diff": registry.scrub(diff.render()),
                "severity": str(diff.max_severity),
                "changes": len(diff.changes),
            }
        if action in ("setup.rsyslog", "setup.firewall"):
            Parameters.model_validate(values)
            cfg = load_config(self.rt.config_path) if self.rt.config_path.exists() else self.rt.cfg
            return {
                "content": rsyslog_conf(cfg) if action == "setup.rsyslog" else nftables_conf(cfg)
            }
        if action == "setup.snippets":
            import ipaddress

            parameters = SnippetsOperation.model_validate(values)
            server_ip = str(ipaddress.ip_address(parameters.server_ip))
            cfg = load_config(self.rt.config_path) if self.rt.config_path.exists() else self.rt.cfg
            return {"content": device_snippet(cfg, cfg.device(parameters.device), server_ip)}
        if action == "database.initialize":
            Parameters.model_validate(values)
            await asyncio.to_thread(self.database.initialize)
            return {"initialized": True}
        if action == "notifications.test":
            Parameters.model_validate(values)
            finding = Finding(
                f"notification-test|{datetime.now(UTC).isoformat()}",
                "notification-test",
                "Delivery test",
                Severity.CRITICAL,
                "health",
                None,
                f"Notification test requested by {request.actor}",
            )
            targets = self._targets(finding)
            if not targets:
                raise ControlError("No notification channels are configured", 409)
            await asyncio.to_thread(self.database.save_finding, finding, targets)
            return {"queued": targets}
        if action == "vault.backup":
            parameters = BackupOperation.model_validate(values)
            passphrase = parameters.passphrase.get_secret_value()
            registry.register(passphrase)
            payload = await asyncio.to_thread(
                make_backup, self.rt.provider.vault, self.rt.provider.key, passphrase
            )
            return {
                "filename": "scalar-vault-backup.json",
                "content_base64": base64.b64encode(payload).decode(),
            }
        if action == "vault.restore":
            parameters = RestoreOperation.model_validate(values)
            if "monitor.pause" not in self.callbacks:
                raise ControlError(
                    "Restore requires the running daemon's maintenance controls", 409
                )
            await self.callbacks["monitor.pause"]()
            await asyncio.to_thread(self._restore, parameters)
            return {"restored": True, "monitoring": "paused", "host_key_preserved": True}
        raise ControlError("Operation is unavailable in this daemon", 501)

    def _targets(self, finding: Finding) -> list[str]:
        return [
            name
            for name in ("smtp", "siem", "webhook")
            if (config := getattr(self.rt.cfg.notify, name)) is not None
            and finding.severity >= Severity.parse(config.min_severity)
        ]

    async def _device_operation(self, action: str, name: str, *,
                                sources: list[LogSource] | None = None) -> dict[str, Any]:
        try:
            device = self.rt.cfg.device(name)
        except KeyError:
            raise ControlError("Device is not in the applied inventory. "
                               "Save its settings before polling.", 409) from None
        if (device.spki_pinning and not device.spki_pin
            and not (device.ca_bundle or self.rt.cfg.defaults.ca_bundle)):
            raise ControlError("TLS verification is not configured for this ADC. Self-signed "
                               "HTTPS is supported: inspect and verify its SPKI fingerprint, "
                               "then save the pin.", 409)
        if device.spki_pinning and device.spki_pin and self.rt.nitro_transport is None:
            try:
                valid_pin = len(base64.b64decode(device.spki_pin, validate=True)) == 32
            except ValueError:
                valid_pin = False
            if not valid_pin:
                raise ControlError("The SPKI pin is not a valid SHA-256 fingerprint. "
                                   "Use Inspect TLS key, verify the fingerprint, "
                                   "then save it.", 409)
        async with self.rt.device_lock(name), self.rt.nitro_client(device) as client:
            if action == "logs.fetch":
                logs = DeviceLogStore(self.rt.cfg.paths.state_dir / "device-logs")
                captures, errors = [], []
                for source in dict.fromkeys(sources or LOG_FILES):
                    path = Path(LOG_FILES[source])
                    try:
                        async with asyncio.timeout(15):
                            content = await client.system_file(path.name, str(path.parent))
                        captures.append(await asyncio.to_thread(logs.put, name, source, content))
                    except AuthRejected:
                        raise
                    except PermissionDenied:
                        raise ControlError(
                            "The ADC command policy denies read-only systemfile access. Ask its "
                            "administrator to review log-read permissions, or upload exported "
                            "logs instead.", 403) from None
                    except (NitroError, httpx.TransportError, TimeoutError) as exc:
                        errors.append({"source": source, "path": str(path),
                                       "error": str(appliance_failure(exc))})
                return {"device": name, "captures": captures, "errors": errors}
            if action == "device.poll":
                poller = ConfigPoller(
                    name,
                    FileSnapshotStore(self.rt.cfg.paths.state_dir / "configs"),
                    load_risk_rules(),
                    full_refresh=timedelta(0),
                )
                alerts = await poller.tick(client)
                for finding in alerts:
                    await asyncio.to_thread(
                        self.database.save_finding, finding, self._targets(finding)
                    )
                await asyncio.to_thread(poller.acknowledge)
                return {"findings": [finding_document(finding) for finding in alerts]}
            version = await client.version_string()
            if action == "device.exposure":
                report = assess(
                    name,
                    parse_version(version, device.firmware_variant),
                    await detect_features(client),
                    load_cve_data(),
                )
                for finding in from_exposure(report):
                    await asyncio.to_thread(
                        self.database.save_finding, finding, self._targets(finding)
                    )
                return {
                    "version": version,
                    "warnings": report.warnings,
                    "lifecycle": report.lifecycle_status,
                    "results": [
                        {
                            "cve": result.advisory.id,
                            "status": str(result.status),
                            "fixed_in": str(result.fixed_in) if result.fixed_in else None,
                            "gate": result.gate_detail,
                        }
                        for result in report.results
                    ],
                }
            state = await client.config_state()
            running, saved = await client.running_config(), await client.saved_config()
            return {
                "version": version,
                "state": state,
                "ha_nodes": await client.ha_nodes(),
                "running_bytes": len(running),
                "saved_bytes": len(saved),
            }

    def _restore(self, parameters: RestoreOperation) -> None:
        passphrase = parameters.passphrase.get_secret_value()
        registry.register(passphrase)
        raw = base64.b64decode(parameters.backup, validate=True)
        with tempfile.TemporaryDirectory(dir=self.rt.cfg.paths.state_dir) as directory:
            imported, _key = restore_backup(raw, passphrase, Path(directory) / "vault")
            required = [ref[6:] for ref in self._credential_users() if ref.startswith("local:")]
            missing = [name for name in required if name not in imported]
            if missing:
                raise ControlError(
                    "Backup is missing referenced credentials: " + ", ".join(missing), 409
                )
            restored = imported.rekey(self.rt.provider.key)
            atomic_write(self.rt.cfg.paths.vault, restored.to_bytes(), backup=True)

    @property
    def hunt_rules(self) -> HuntRuleStore:
        return HuntRuleStore(self.rt.cfg.paths.state_dir / "hunt-rules.json")

    def _hunt_lists(self) -> dict[str, list[str]]:
        return {name: getattr(self.rt.cfg.syslog, name)
                for name in ("admin_networks", "admin_users")}

    async def _run_hunt(self, actor: str, parameters: HuntOperation, *,
                        capture: dict[str, Any] | None = None) -> dict[str, Any]:
        rules = await asyncio.to_thread(self.hunt_rules.active)
        context = {
            "input_sha256": (capture["sha256"] if capture
                             else hashlib.sha256(parameters.text.encode()).hexdigest()),
            "input_bytes": capture["retained_bytes"] if capture else len(parameters.text.encode()),
            "input_encoding": "original capture bytes" if capture else "UTF-8 submitted text",
            "capture": capture,
            "origin": "device" if capture else "upload", "app_version": __version__,
            "rules": rules,
            "rules_sha256": hashlib.sha256(json.dumps(rules, sort_keys=True).encode()).hexdigest(),
        }
        identity = await asyncio.to_thread(self.database.start_hunt, actor, parameters.device,
                                          parameters.source, context)
        try:
            packet = {"mode": "scan", "rules": rules, "lists": self._hunt_lists(),
                      **parameters.model_dump()}
            if capture and not capture["retained_bytes"]:
                packet["text"] = ""
            try:
                device = self.rt.cfg.device(parameters.device)
            except KeyError:
                pass
            else:
                packet.update(date_format=device.date_format, timezone=device.timezone)
            result = await run_worker(packet)
        except asyncio.CancelledError:
            await asyncio.shield(asyncio.to_thread(
                self.database.finish_hunt, identity, None, error="Hunt interrupted"))
            raise
        except Exception as exc:
            await asyncio.to_thread(self.database.finish_hunt, identity, None,
                                    error=registry.scrub(str(exc))[:1000])
            raise
        document = await asyncio.to_thread(self.database.finish_hunt, identity, result)
        return {**document["result"], "run": {
            key: document[key] for key in ("id", "actor", "started_at", "completed_at")
        }}

    def _archive(self, action: str, parameters: ArchiveOperation) -> dict[str, Any]:
        archive = RawArchive(self.rt.cfg.paths.state_dir / "archive")
        since = datetime.now(UTC) - timedelta(days=parameters.days)
        if action == "archive.verify":
            checked = archive.verify(
                parameters.device, since=since.date(), expected_head=parameters.expected_head
            )
            return {"verified_batches": checked, "chain_head": archive.head(parameters.device)}
        path = archive.root / parameters.device / "manifest.jsonl"
        if not path.exists():
            return {"items": [], "truncated": False}
        results = []
        with path.open("rb") as stream:
            for line in stream:
                document = json.loads(line)
                if datetime.fromisoformat(document["stored_at"]) < since:
                    continue
                raw = archive.read(
                    document["path"],
                    document["sha256"],
                    document["size"],
                    offset=document["offset"],
                    length=document["compressed_size"],
                )
                for entry in raw.decode("latin-1").splitlines():
                    if parameters.query.casefold() in entry.casefold():
                        results.append({"line": registry.scrub(entry), "raw_ref": document["path"]})
                        if len(results) >= parameters.limit:
                            return {"items": results, "truncated": True}
        return {"items": results, "truncated": False}

    def _save_settings(self, candidate: Config, expected: str) -> None:
        path = self.rt.config_path
        lock_path = self.rt.cfg.paths.state_dir / "settings.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            import fcntl
        except ModuleNotFoundError:
            if revision(path) != expected:
                raise ControlError(
                    "Settings changed since you opened the form. Reload before saving.", 409
                ) from None
            raw = yaml.safe_dump(candidate.model_dump(mode="json"), sort_keys=False).encode()
            atomic_write(path, raw, backup=True, mode=0o640)
            return
        with lock_path.open("a") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            try:
                if revision(path) != expected:
                    raise ControlError(
                        "Settings changed since you opened the form. Reload before saving.", 409
                    )
                raw = yaml.safe_dump(candidate.model_dump(mode="json"), sort_keys=False).encode()
                atomic_write(path, raw, backup=True, mode=0o640)
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    @staticmethod
    def _settings_warnings(cfg: Config) -> list[str]:
        warnings = []
        if not cfg.devices:
            warnings.append("No appliances are configured")
        if any(device.mode != "observe" for device in cfg.devices):
            warnings.append("Active SSH collection is not implemented; monitoring will not start")
        if any(device.spki_pinning and not device.spki_pin
               and not (device.ca_bundle or cfg.defaults.ca_bundle) for device in cfg.devices):
            warnings.append("Some appliances do not have a TLS pin or CA trust configured")
        if cfg.web.allow_http:
            warnings.append("Dashboard HTTP is enabled: passwords and sessions cross the "
                            "network unencrypted")
        if cfg.notify.siem and cfg.notify.siem.transport == "tcp":
            warnings.append("SIEM forwarding uses plaintext TCP; use TLS")
        if cfg.notify.smtp and not cfg.notify.smtp.starttls:
            warnings.append("SMTP does not use STARTTLS; notifications are sent in cleartext")
        if cfg.notify.siem and cfg.notify.siem.forward_events:
            warnings.append("Raw-event SIEM forwarding is not implemented")
        return warnings

    def _credential_users(self) -> dict[str, list[str]]:
        config = load_config(self.rt.config_path) if self.rt.config_path.exists() else self.rt.cfg
        references = self.rt.cfg.credential_users()
        for ref, names in config.credential_users().items():
            references[ref] = sorted(set(references.get(ref, [])) | set(names))
        for cfg in (config, self.rt.cfg):
            if cfg.notify.smtp and cfg.notify.smtp.credential:
                references.setdefault(cfg.notify.smtp.credential, []).append("SMTP relay")
        return references

    def _credentials(self) -> dict[str, Any]:
        vault = self.rt.provider.vault
        references = self._credential_users()
        return {
            "items": [
                {
                    "name": item.name,
                    "username": vault.get(item.name).username,
                    "has_password": bool(vault.get(item.name).reveal_password()),
                    "has_ssh_key": vault.get(item.name).has_ssh_key,
                    "created": item.created.isoformat(),
                    "updated": item.updated.isoformat(),
                    "rotated_by": item.rotated_by,
                    "users": references.get(f"local:{item.name}", []),
                }
                for item in vault.list_meta()
            ],
            "blocked": [
                {"device": device, "credential": ref, "since": since.isoformat()}
                for device, ref, since in self.rt.guard.blocked()
            ],
        }

    def _save_credential(self, update: CredentialUpdate, actor: str) -> None:
        vault = self.rt.provider.vault
        previous = vault.get(update.name) if update.name in vault else None
        if update.create and previous is not None:
            raise ControlError("Credential already exists", 409)
        password = (
            update.password.get_secret_value()
            if update.password is not None
            else previous.reveal_password()
            if previous
            else ""
        )
        ssh_key = (
            update.ssh_private_key.get_secret_value()
            if update.ssh_private_key is not None
            else previous.reveal_ssh_private_key()
            if previous
            else None
        )
        if update.remove_ssh_key:
            ssh_key = None
        vault.set(update.name, Credential(update.username, password, ssh_key), actor=f"web:{actor}")

    def _audit_records(self) -> list[dict[str, Any]]:
        if not self.audit_path.exists():
            return []
        with self.audit_path.open() as stream:
            return list(reversed([json.loads(line) for line in deque(stream, maxlen=200)]))
