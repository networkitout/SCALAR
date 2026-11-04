import base64
import json
import ssl
from pathlib import Path

import httpx
import pytest
import yaml
from sqlalchemy import create_engine

from scalar.administration import Administration
from scalar.config import Config
from scalar.control import ControlError, ControlRequest
from scalar.runtime import Runtime
from scalar.secrets.base import Credential
from scalar.secrets.vault import Vault, generate_key
from scalar.store.database import Database
from scalar.transport.nitro import PermissionDenied
from scalar.transport.tls import PinMismatch
from scalar.web.auth import load_accounts, set_password, update_user
from tests.emulator.nitro import FakeNitro

PASSWORD = "administration-test-password"


async def test_malformed_spki_fails_before_creating_a_network_client(admin) -> None:  # type: ignore[no-untyped-def]
    handler, fake = admin
    handler.rt.nitro_transport = None
    with pytest.raises(ControlError, match="not a valid SHA-256 fingerprint"):
        await call(handler, "device.poll", {"device": "gateway"})
    assert fake.login_attempts == 0


async def test_wrapped_certificate_error_keeps_tls_diagnostic(admin,
                                                           monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    handler, _fake = admin

    async def fail(action: str, name: str) -> dict[str, object]:
        raise httpx.ConnectError("connect failed") from ssl.SSLCertVerificationError(1, "untrusted")

    monkeypatch.setattr(handler, "_device_operation", fail)
    with pytest.raises(ControlError, match="certificate validation failed"):
        await call(handler, "device.poll", {"device": "gateway"})


@pytest.mark.parametrize("error,expected", [
    (PinMismatch("192.0.2.10", "expected", "actual"), "SPKI pin"),
    (ssl.SSLCertVerificationError(1, "untrusted certificate"), "Self-signed HTTPS is supported"),
    (ssl.SSLError(1, "WRONG_VERSION_NUMBER"), "HTTP-only endpoint"),
    (httpx.ConnectError("connection failed"), "IPAddressAllow"),
    (httpx.ConnectTimeout("connect timeout"), "timed out"),
    (PermissionDenied("gateway: command policy denies configuration reads"), "command policy"),
])
async def test_device_failures_return_actionable_errors(admin, monkeypatch: pytest.MonkeyPatch,
                                                       error: Exception, expected: str) -> None:  # type: ignore[no-untyped-def]
    handler, _fake = admin

    async def fail(action: str, name: str) -> dict[str, object]:
        raise error

    monkeypatch.setattr(handler, "_device_operation", fail)
    with pytest.raises(ControlError, match=expected) as result:
        await call(handler, "device.poll", {"device": "gateway"})
    assert result.value.status == 502
    assert "Operation failed;" not in str(result.value)
    records = [json.loads(line) for line in handler.audit_path.read_text().splitlines()]
    assert expected in records[-1]["error"]
    assert records[-1]["status"] == 502
    assert records[-1]["error_type"] == type(error).__name__
    assert records[-1]["duration_ms"] >= 0
    assert records[-1]["request_id"] == records[-2]["request_id"]


async def test_missing_pin_and_unapplied_devices_fail_before_login(admin) -> None:  # type: ignore[no-untyped-def]
    handler, fake = admin
    device = handler.rt.cfg.devices[0].model_copy(update={"spki_pin": None})
    handler.rt.cfg = handler.rt.cfg.model_copy(update={"devices": [device]})
    with pytest.raises(ControlError, match="Self-signed HTTPS is supported"):
        await call(handler, "device.poll", {"device": "gateway"})
    with pytest.raises(ControlError, match="applied inventory"):
        await call(handler, "device.poll", {"device": "new-device"})
    assert fake.login_attempts == 0


async def test_disabling_spki_allows_ca_mode_device_operations(admin) -> None:  # type: ignore[no-untyped-def]
    handler, fake = admin
    device = handler.rt.cfg.devices[0].model_copy(update={"spki_pinning": False, "spki_pin": None})
    handler.rt.cfg = handler.rt.cfg.model_copy(update={"devices": [device]})
    assert (await call(handler, "device.probe", {"device": "gateway"}))["version"]
    assert fake.login_attempts == 1
    assert not any("TLS pin" in warning for warning in handler._settings_warnings(handler.rt.cfg))


async def test_pin_inspection_reports_network_restrictions(admin,
                                                         monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    from scalar import administration

    handler, fake = admin

    def unavailable(host: str, port: int):  # type: ignore[no-untyped-def]
        raise PermissionError("blocked")

    monkeypatch.setattr(administration, "fetch_peer_cert", unavailable)
    with pytest.raises(ControlError, match="IPAddressAllow"):
        await call(handler, "device.pin", {"device": "gateway"})
    assert fake.login_attempts == 0


async def test_appliance_error_messages_redact_registered_secrets(admin,
                                                                 monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    handler, _fake = admin

    async def fail(action: str, name: str) -> dict[str, object]:
        raise PermissionDenied("rejected nitro-password")

    monkeypatch.setattr(handler, "_device_operation", fail)
    with pytest.raises(ControlError) as result:
        await call(handler, "device.poll", {"device": "gateway"})
    assert "nitro-password" not in str(result.value)
    assert "nitro-password" not in handler.audit_path.read_text()


async def test_empty_inventory_can_be_validated_and_saved(admin) -> None:  # type: ignore[no-untyped-def]
    handler, _fake = admin
    settings = await call(handler, "settings.get")
    settings["document"]["devices"] = []
    settings["document"]["ha_pairs"] = []
    parameters = {"document": settings["document"], "revision": settings["revision"]}
    assert (await call(handler, "settings.validate", parameters))["valid"]
    await call(handler, "settings.save", parameters)
    saved = yaml.safe_load(handler.rt.config_path.read_text())
    assert saved["devices"] == [] and saved["ha_pairs"] == []
    assert handler.rt.provider.vault.names() == ["sc_nitro"]


@pytest.mark.linux
async def test_daemon_can_replace_read_only_backup_after_cli_admin(admin) -> None:  # type: ignore[no-untyped-def]
    handler, _fake = admin
    backup = handler.rt.cfg.paths.vault.with_name("vault.bak")
    previous = handler.rt.cfg.paths.vault.read_bytes()
    backup.write_bytes(b"old backup")
    backup.chmod(0o400)
    await call(handler, "credentials.save", {"name": "sc_nitro", "username": "sc_nitro",
                                             "password": "updated-from-browser"})
    assert backup.read_bytes() == previous
    assert handler.rt.provider.vault.get("sc_nitro").reveal_password() == "updated-from-browser"


async def test_browser_log_hunt_preserves_high_byte_detection(admin) -> None:  # type: ignore[no-untyped-def]
    handler, _fake = admin
    line = ('2026/10/05:10:00:00 GMT gateway 0-PPE-0 : default AAA Message 1 0 : '
            '"Authentication is rejected for \x89\x01\xfe"')
    result = await call(handler, "tools.hunt", {"text": line, "device": "gateway"}, actor="operator")
    assert "cve-2025-5777-garbage-username" in {item["rule_id"] for item in result["findings"]}


async def test_device_log_fetch_review_and_offline_hunt(admin) -> None:  # type: ignore[no-untyped-def]
    handler, fake = admin
    fake.files["/var/log/ns.log"] = (
        b'2026/10/05:10:00:00 GMT gateway 0-PPE-0 : default AAA Message 1 0 : '
        b'"Authentication is rejected for \x89\x01\xfe"\nnitro-password\n')
    fetched = await call(handler, "logs.fetch", {"device": "gateway", "sources": ["nslog", "auth"]},
                         actor="operator")
    assert len(fetched["captures"]) == 1 and len(fetched["errors"]) == 1
    assert fetched["errors"][0]["source"] == "auth"
    latest = json.loads(handler.audit_path.read_text().splitlines()[-1])
    assert latest["outcome"] == "partial" and "/var/log/auth.log" in latest["error"]
    assert "text" not in fetched["captures"][0]
    items = (await call(handler, "logs.list", {"device": "gateway"}, actor="operator"))["items"]
    assert len(items) == 8 and items[0]["capture"]["lines"] == 2
    selection = {"device": "gateway", "source": "nslog", "sha256": fetched["captures"][0]["sha256"]}
    requests = len(fake.requests)
    viewed = await call(handler, "logs.read", selection, actor="operator")
    assert "nitro-password" not in viewed["text"]
    stored_counts = handler.database.counts()
    result = await call(handler, "logs.hunt", selection, actor="operator")
    assert "cve-2025-5777-garbage-username" in {item["rule_id"] for item in result["findings"]}
    history = await call(handler, "hunts.get", {"id": result["run"]["id"]}, actor="operator")
    assert history["context"]["input_sha256"] == selection["sha256"]
    assert history["context"]["input_bytes"] == fetched["captures"][0]["retained_bytes"]
    assert len(fake.requests) == requests
    assert handler.database.counts() == stored_counts
    capture = handler.rt.cfg.paths.state_dir / "device-logs" / "gateway" / "nslog.json"
    assert capture.stat().st_mode & 0o777 == 0o600
    fake.files["/var/log/ns.log"] = b"new capture\n"
    await call(handler, "logs.fetch", {"device": "gateway", "sources": ["nslog"]})
    with pytest.raises(ControlError, match="capture changed"):
        await call(handler, "logs.hunt", selection)


async def test_log_fetch_preserves_permission_and_lockout_guards(admin) -> None:  # type: ignore[no-untyped-def]
    handler, fake = admin
    fake.denied.add("systemfile")
    with pytest.raises(ControlError, match="command policy"):
        await call(handler, "logs.fetch", {"device": "gateway"})
    assert len([request for request in fake.requests if request.url.path.endswith("systemfile")]) == 1
    fake.denied.clear()
    fake.users["sc_nitro"] = "changed-at-appliance"
    with pytest.raises(ControlError, match="login rejected"):
        await call(handler, "logs.fetch", {"device": "gateway"})
    attempts = fake.login_attempts
    with pytest.raises(ControlError):
        await call(handler, "logs.fetch", {"device": "gateway"})
    assert fake.login_attempts == attempts


async def test_hunts_are_saved_and_retrievable_after_handler_restart(admin) -> None:  # type: ignore[no-untyped-def]
    handler, fake = admin
    result = await call(handler, "tools.hunt", {"text": "ordinary log entry"}, actor="operator")
    assert result["findings"] == []
    history = await call(handler, "hunts.list", {}, actor="operator")
    assert history["total"] == 1
    assert history["items"][0]["id"] == result["run"]["id"]
    restarted = Administration(handler.rt, handler.database)
    saved = await call(restarted, "hunts.get", {"id": result["run"]["id"]}, actor="operator")
    assert saved["actor"] == "operator" and saved["result"]["findings"] == []
    assert saved["context"]["origin"] == "upload"
    assert not fake.requests
    assert handler.database.counts() == {"events": 0, "findings": 0, "pending_notifications": 0}
    with pytest.raises(ControlError) as denied:
        await call(handler, "hunts.list", {}, actor="viewer")
    assert denied.value.status == 403


async def test_failed_hunt_is_retained(admin) -> None:  # type: ignore[no-untyped-def]
    handler, _fake = admin
    with pytest.raises(ControlError, match="10000"):
        await call(handler, "tools.hunt", {"text": "line\n" * 10001})
    history = await call(handler, "hunts.list")
    assert history["items"][0]["status"] == "failed"
    saved = await call(handler, "hunts.get", {"id": history["items"][0]["id"]})
    assert "10000" in saved["error"]


async def test_custom_rule_management_and_historical_rule_snapshot(admin) -> None:  # type: ignore[no-untyped-def]
    from tests.unit.test_rules import custom_rule

    handler, _fake = admin
    text = yaml.safe_dump(custom_rule())
    catalog = await call(handler, "rules.list")
    parameters = {"text": text, "revision": catalog["revision"]}
    with pytest.raises(ControlError) as denied:
        await call(handler, "rules.save", parameters, actor="operator")
    assert denied.value.status == 403
    assert (await call(handler, "rules.validate", parameters))["tested"] == 2
    saved = await call(handler, "rules.save", parameters)
    result = await call(handler, "tools.hunt", {"text": "suspicious-marker"}, actor="operator")
    assert "custom-test" in {finding["rule_id"] for finding in result["findings"]}
    with pytest.raises(ControlError) as conflict:
        await call(handler, "rules.save", parameters)
    assert conflict.value.status == 409
    disabled = await call(handler, "rules.enabled", {"id": "custom-test", "enabled": False,
                                                     "revision": saved["revision"]})
    again = await call(handler, "tools.hunt", {"text": "suspicious-marker"})
    assert "custom-test" not in {finding["rule_id"] for finding in again["findings"]}
    exported = await call(handler, "rules.export")
    assert yaml.safe_load(exported["content"])[0]["enabled"] is False
    await call(handler, "rules.delete", {"id": "custom-test", "revision": disabled["revision"]})
    history = await call(handler, "hunts.get", {"id": result["run"]["id"]})
    assert any(rule["id"] == "custom-test" for rule in history["context"]["rules"])
    assert "custom-test" in {finding["rule_id"] for finding in history["result"]["findings"]}


@pytest.mark.parametrize("parameters", [
    {"device": "gateway", "sources": ["../../nsconfig/ns.conf"]},
    {"device": "../gateway"}, {"device": "gateway", "sources": []},
    {"device": "gateway", "path": "/etc/passwd"},
])
async def test_log_fetch_rejects_arbitrary_paths(admin, parameters) -> None:  # type: ignore[no-untyped-def]
    handler, fake = admin
    with pytest.raises(ControlError) as error:
        await call(handler, "logs.fetch", parameters)
    assert error.value.status == 422
    assert not fake.requests


def test_retained_device_logs_are_bounded_and_integrity_checked(tmp_path: Path) -> None:
    from scalar.collect.device_logs import DeviceLogStore

    logs = DeviceLogStore(tmp_path)
    metadata = logs.put("gateway", "nslog", b"old line\n" * 12000 + b"latest line\n")
    assert metadata["truncated"] and metadata["lines"] == 10000
    metadata = logs.put("gateway", "nslog", b"old line" * 200000 + b"\nlatest line\n")
    assert metadata["truncated"] and metadata["retained_bytes"] <= 1048576
    captured = logs.read("gateway", "nslog")
    assert captured is not None and captured["text"] == "latest line\n"
    path = tmp_path / "gateway" / "nslog.json"
    document = json.loads(path.read_bytes())
    document["text"] = "changed"
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="integrity"):
        logs.read("gateway", "nslog")


@pytest.mark.parametrize("update", [
    {"database_url": "sqlite:///unsafe.db"},
    {"defaults": {"nitro_port": 70000}},
    {"web": {"allowed_hosts": ["bad*host"]}},
    {"web": {"public_url": "https://example.invalid:bad"}},
])
async def test_unsafe_settings_do_not_replace_configuration(admin, update) -> None:  # type: ignore[no-untyped-def]
    handler, _fake = admin
    current = await call(handler, "settings.get")
    original = handler.rt.config_path.read_bytes()
    current["document"].update(update)
    with pytest.raises(ControlError, match="Invalid fields"):
        await call(handler, "settings.save", {"document": current["document"],
                                              "revision": current["revision"]})
    assert handler.rt.config_path.read_bytes() == original


@pytest.fixture
def admin(tmp_path: Path):  # type: ignore[no-untyped-def]
    config_path = tmp_path / "config.yaml"
    cfg = Config.model_validate(
        {
            "paths": {
                "state_dir": str(tmp_path),
                "vault": str(tmp_path / "vault"),
                "control_socket": str(tmp_path / "control.sock"),
            },
            "devices": [{"name": "gateway", "nsip": "192.0.2.10", "spki_pin": "test-pin"}],
        }
    )
    config_path.write_text(yaml.safe_dump(cfg.model_dump(mode="json")))
    key = generate_key()
    Vault.create(cfg.paths.vault, key).set(
        "sc_nitro", Credential("sc_nitro", "nitro-password"), "test"
    )
    users = tmp_path / "web-users.json"
    set_password(users, "admin", PASSWORD)
    update_user(users, "viewer", password=PASSWORD, role="viewer")
    update_user(users, "operator", password=PASSWORD, role="operator")
    fake = FakeNitro()
    runtime = Runtime(
        cfg, lambda: key, nitro_transport=lambda device: fake.transport(), config_path=config_path
    )
    database = Database(create_engine(f"sqlite:///{tmp_path / 'index.db'}"))
    database.initialize()
    return Administration(runtime, database), fake


async def call(admin, action: str, parameters=None, actor: str = "admin"):  # type: ignore[no-untyped-def]
    return await admin.execute(
        ControlRequest(actor=actor, action=action, parameters=parameters or {})
    )


async def test_role_and_action_allowlist_enforced_daemon_side(admin) -> None:  # type: ignore[no-untyped-def]
    handler, _fake = admin
    for actor in ("viewer", "operator", "unknown"):
        with pytest.raises(ControlError, match="not permitted"):
            await call(handler, "settings.get", actor=actor)
    with pytest.raises(ControlError, match="not permitted"):
        await call(handler, "shell", {"command": "whoami"})


async def test_settings_validate_save_and_conflict(admin) -> None:  # type: ignore[no-untyped-def]
    handler, _fake = admin
    original = await call(handler, "settings.get")
    original["document"]["retention"]["raw_days"] = 500
    parameters = {"document": original["document"], "revision": original["revision"]}
    assert (await call(handler, "settings.validate", parameters))["valid"]
    saved = await call(handler, "settings.save", parameters)
    assert saved["applied"] and not saved["pending_apply"]
    assert handler.rt.cfg.retention.raw_days == 500
    assert not (await call(handler, "settings.get"))["pending_apply"]
    assert yaml.safe_load(handler.rt.config_path.read_text())["retention"]["raw_days"] == 500
    assert handler.rt.config_path.with_suffix(".yaml.bak").exists()
    with pytest.raises(ControlError, match="changed since"):
        await call(handler, "settings.save", parameters)


async def test_failed_activation_keeps_saved_revision_for_one_button_retry(admin) -> None:  # type: ignore[no-untyped-def]
    handler, _fake = admin
    calls = 0

    async def activate():  # type: ignore[no-untyped-def]
        nonlocal calls
        calls += 1
        if calls == 1:
            raise ControlError("Activation temporarily unavailable", 503)
        handler.rt.cfg = Config.model_validate(yaml.safe_load(handler.rt.config_path.read_text()))
        return {"applied": True, "web_reload": False}

    handler.callbacks["settings.apply"] = activate
    settings = await call(handler, "settings.get")
    settings["document"]["retention"]["findings_days"] = 200
    parameters = {"document": settings["document"], "revision": settings["revision"]}
    failed = await call(handler, "settings.save", parameters)
    assert failed["saved"] and not failed["applied"]
    assert failed["revision"] != settings["revision"]
    assert failed["errors"][0]["error"] == "Activation temporarily unavailable"
    assert (await call(handler, "settings.get"))["pending_apply"]
    parameters["revision"] = failed["revision"]
    retried = await call(handler, "settings.save", parameters)
    assert retried["applied"] and not retried["pending_apply"]
    assert handler.rt.cfg.retention.findings_days == 200


async def test_invalid_settings_do_not_replace_config(admin) -> None:  # type: ignore[no-untyped-def]
    handler, _fake = admin
    before = handler.rt.config_path.read_bytes()
    document = (await call(handler, "settings.get"))["document"]
    document["retention"]["raw_days"] = -1
    with pytest.raises(ControlError, match="Invalid fields"):
        await call(handler, "settings.save", {"document": document, "revision": ""})
    assert handler.rt.config_path.read_bytes() == before


async def test_credentials_write_only_and_in_use_deletion(admin) -> None:  # type: ignore[no-untyped-def]
    handler, _fake = admin
    password = "a-private-appliance-password"
    await call(
        handler,
        "credentials.save",
        {"name": "other", "username": "monitor", "password": password, "create": True},
    )
    result = await call(handler, "credentials.list")
    assert password not in json.dumps(result)
    assert next(item for item in result["items"] if item["name"] == "other")["has_password"] is True
    assert password not in handler.audit_path.read_text()
    assert handler.rt.provider.vault.get("other").reveal_password() == password
    await call(handler, "credentials.delete", {"name": "other"})
    with pytest.raises(ControlError, match="referenced"):
        await call(handler, "credentials.delete", {"name": "sc_nitro"})


async def test_credential_choices_distinguish_passwords_without_revealing_secrets(admin) -> None:  # type: ignore[no-untyped-def]
    handler, _fake = admin
    private_key = "test-only-private-ssh-key-material"
    await call(handler, "credentials.save", {"name": "ssh-only", "username": "sweep-user",
                                             "ssh_private_key": private_key, "create": True})
    result = await call(handler, "credentials.list")
    entries = {item["name"]: item for item in result["items"]}
    assert entries["sc_nitro"]["has_password"] is True
    assert entries["ssh-only"]["has_password"] is False
    assert entries["ssh-only"]["has_ssh_key"] is True
    assert private_key not in json.dumps(result)
    assert "nitro-password" not in json.dumps(result)


async def test_web_user_management_does_not_return_hashes(admin) -> None:  # type: ignore[no-untyped-def]
    handler, _fake = admin
    await call(
        handler,
        "users.save",
        {"name": "new", "password": PASSWORD, "role": "operator", "enabled": True, "create": True},
    )
    result = await call(handler, "users.list")
    assert PASSWORD not in json.dumps(result) and "argon2" not in json.dumps(result)
    assert load_accounts(handler.users_path)["new"].role == "operator"
    with pytest.raises(ControlError, match="own account"):
        await call(handler, "users.delete", {"name": "admin"})
    await call(handler, "users.delete", {"name": "new"})
    assert "new" not in load_accounts(handler.users_path)


async def test_read_only_device_operations_share_lockout_guard(admin) -> None:  # type: ignore[no-untyped-def]
    handler, fake = admin
    assert (await call(handler, "device.probe", {"device": "gateway"}, actor="operator"))["version"]
    await call(handler, "device.poll", {"device": "gateway"}, actor="operator")
    results = await call(handler, "device.exposure", {"device": "gateway"}, actor="operator")
    assert "results" in results
    assert all(
        request.method == "GET" or request.url.path.endswith(("/login", "/logout"))
        for request in fake.requests
    )
    fake.users["sc_nitro"] = "new-password"
    result = await call(handler, "credentials.test", {"name": "sc_nitro"})
    assert not result["items"][0]["ok"]
    attempts = fake.login_attempts
    await call(handler, "credentials.test", {"name": "sc_nitro"})
    assert fake.login_attempts == attempts


async def test_backup_restore_preserves_host_key_and_redacts_audit(admin) -> None:  # type: ignore[no-untyped-def]
    handler, _fake = admin
    paused = []

    async def pause():  # type: ignore[no-untyped-def]
        paused.append(True)
        return {"paused": True}

    handler.callbacks["monitor.pause"] = pause
    key = handler.rt.provider.key
    backup = await call(handler, "vault.backup", {"passphrase": PASSWORD})
    assert b"nitro-password" not in base64.b64decode(backup["content_base64"])
    await call(
        handler,
        "credentials.save",
        {"name": "sc_nitro", "username": "sc_nitro", "password": "different-password"},
    )
    await call(
        handler,
        "vault.restore",
        {"passphrase": PASSWORD, "backup": backup["content_base64"], "confirmation": "RESTORE"},
    )
    assert paused and handler.rt.provider.key == key
    assert handler.rt.provider.vault.get("sc_nitro").reveal_password() == "nitro-password"
    assert PASSWORD not in handler.audit_path.read_text()


async def test_offline_tools_and_generated_setup_are_available(admin) -> None:  # type: ignore[no-untyped-def]
    handler, _fake = admin
    rules = await call(handler, "rules.list", actor="operator")
    assert rules["items"]
    result = await call(
        handler, "tools.diff", {"before": "", "after": "add system user x secret\n"}
    )
    assert "secret" not in result["diff"]
    assert (await call(handler, "setup.rsyslog"))["content"]
    assert (await call(handler, "setup.firewall"))["content"]
    assert (
        "sc_nitro"
        in (
            await call(handler, "setup.snippets", {"device": "gateway", "server_ip": "192.0.2.100"})
        )["content"]
    )


@pytest.mark.parametrize("edit", [
    lambda d: d["devices"][0].update(nsip="198.51.100.9"),
    lambda d: d["devices"][0].update(ca_bundle="/tmp/attacker.pem"),
    lambda d: d["devices"][0].update(nitro_credential="local:sc_other"),
    lambda d: d["defaults"].update(sweep_credential="local:sc_other"),
    lambda d: d["devices"].append({**d["devices"][0], "name": "added", "nsip": "198.51.100.9"}),
])
async def test_web_cannot_redirect_appliance_credentials(admin, edit) -> None:  # type: ignore[no-untyped-def]
    handler, _fake = admin
    settings = await call(handler, "settings.get")
    edit(settings["document"])
    parameters = {"document": settings["document"], "revision": settings["revision"]}
    for action in ("settings.validate", "settings.save"):
        with pytest.raises(ControlError) as result:
            await call(handler, action, parameters)
        assert result.value.status == 403


async def test_web_can_still_change_benign_settings(admin) -> None:  # type: ignore[no-untyped-def]
    handler, _fake = admin
    settings = await call(handler, "settings.get")
    settings["document"]["retention"]["events_days"] = 30
    parameters = {"document": settings["document"], "revision": settings["revision"]}
    assert (await call(handler, "settings.validate", parameters))["valid"]


async def test_plaintext_transports_produce_warnings(admin) -> None:  # type: ignore[no-untyped-def]
    handler, _fake = admin
    document = (await call(handler, "settings.get"))["document"]
    document["notify"]["siem"] = {"host": "siem.example.internal", "transport": "tcp"}
    candidate = Config.model_validate(document)
    warnings = handler._settings_warnings(candidate)
    assert any("plaintext TCP" in warning for warning in warnings)
