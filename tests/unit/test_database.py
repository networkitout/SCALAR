import os
import uuid
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.schema import CreateSchema, DropSchema

from scalar.config import Config
from scalar.daemon.service import Service
from scalar.detect.config_diff import diff_configs
from scalar.detect.config_risk import load_risk_rules
from scalar.detect.findings import Finding, from_config_diff, from_rule_hit
from scalar.detect.rules import ListMatcher, RuleEngine, load_rules
from scalar.detect.severity import Severity
from scalar.parse.nslog import LogEvent, parse_line
from scalar.runtime import Runtime
from scalar.secrets.base import Credential
from scalar.secrets.vault import Vault, generate_key
from scalar.store.database import (
    NOTIFY_KEYS_PER_RULE,
    Database,
    IndexedEvent,
    events,
    hunt_runs,
)
from scalar.web.data import WebData
from tests.emulator.nitro import FakeNitro
from tests.unit.test_service import CollectSink, stop_after

NOW = datetime(2026, 10, 5, tzinfo=UTC)


@pytest.fixture(params=["sqlite", "postgresql"])
def database(tmp_path: Path, request: pytest.FixtureRequest) -> Iterator[Database]:
    schema = "test_" + uuid.uuid4().hex
    base = None
    if request.param == "postgresql":
        url = os.environ.get("SCALAR_TEST_DATABASE_URL")
        if not url:
            pytest.skip("set SCALAR_TEST_DATABASE_URL for PostgreSQL integration tests")
        base = create_engine(url)
        with base.begin() as connection:
            connection.execute(CreateSchema(schema))
        engine = create_engine(url, connect_args={"options": f"-c search_path={schema}"})
    else:
        engine = create_engine(f"sqlite:///{tmp_path / 'index.db'}")
    database = Database(engine)
    database.initialize()
    try:
        yield database
    finally:
        database.close()
        if base is not None:
            with base.begin() as connection:
                connection.execute(DropSchema(schema, cascade=True))
            base.dispose()


def finding() -> Finding:
    return Finding(
        "test-key", "test-rule", "Test", Severity.HIGH, "health", "gateway", "Test finding", NOW
    )


def test_schema_and_durable_delivery(database: Database) -> None:
    database.check()
    database.save_finding(finding(), ["smtp"], NOW)
    restarted = Database(database.engine)
    delivery = restarted.pending(NOW)[0]
    assert delivery.finding == finding()
    assert restarted.counts() == {"events": 0, "findings": 1, "pending_notifications": 1}
    restarted.delivery_result(delivery, "relay unavailable", NOW)
    assert restarted.pending(NOW + timedelta(seconds=29)) == []
    retry = restarted.pending(NOW + timedelta(seconds=30))[0]
    assert retry.attempts == 1
    restarted.delivery_result(retry, None, NOW + timedelta(seconds=30))
    assert restarted.pending(NOW + timedelta(days=1)) == []


def test_successful_sinks_are_not_retried(database: Database) -> None:
    database.save_finding(finding(), ["smtp", "siem"], NOW)
    for delivery in database.pending(NOW):
        database.delivery_result(delivery, None if delivery.sink == "siem" else "offline", NOW)
    assert [delivery.sink for delivery in database.pending(NOW + timedelta(minutes=1))] == ["smtp"]


def test_hunt_history_survives_reopen_without_notifications(database: Database) -> None:
    Credential("admin", "hunt-test-secret")
    identity = database.start_hunt("operator", "gateway", "nslog",
                                   {"input_sha256": "abc", "rules": ["test-rule"]}, NOW)
    assert database.hunt(identity)["status"] == "running"
    result = {"findings": [{"summary": "hunt-test-secret"}], "lines": 10}
    database.finish_hunt(identity, result, now=NOW + timedelta(seconds=1))
    restarted = Database(database.engine)
    stored = restarted.hunt(identity)
    assert stored["result"]["findings"][0]["summary"] == "***REDACTED***"
    assert stored["context"]["rules"] == ["test-rule"]
    assert stored["actor"] == "operator" and stored["status"] == "complete"
    page = restarted.hunt_history(NOW, device="gateway", source="nslog")
    assert page["total"] == 1 and page["items"][0]["finding_count"] == 1
    assert "document" not in page["items"][0]
    assert restarted.hunt_history(NOW, device="other")["total"] == 0
    assert restarted.hunt_history(NOW, offset=1)["items"] == []
    assert restarted.counts() == {"events": 0, "findings": 0, "pending_notifications": 0}


def test_hunt_table_upgrade_preserves_existing_data(database: Database) -> None:
    database.save_finding(finding(), ["smtp"], NOW)
    hunt_runs.drop(database.engine)
    database.initialize()
    assert database.counts() == {"events": 0, "findings": 1, "pending_notifications": 1}
    identity = database.start_hunt("admin", "gateway", "nslog", {}, NOW)
    assert database.hunt(identity)["status"] == "running"


def test_empty_failed_hunts_and_retention(database: Database) -> None:
    empty = database.start_hunt("admin", "uploaded", "auth", {}, NOW)
    database.finish_hunt(empty, {"findings": [], "lines": 1}, now=NOW)
    failed = database.start_hunt("admin", "gateway", "nslog", {}, NOW)
    database.finish_hunt(failed, None, error="Hunt exceeded its time limit", now=NOW)
    assert database.hunt(failed)["status"] == "failed"
    assert database.hunt_history(NOW)["total"] == 2
    database.initialize()
    assert database.hunt(empty)["result"]["findings"] == []
    database.prune(90, 400, NOW + timedelta(days=401))
    assert database.hunt_history(NOW)["items"] == []
    with pytest.raises(KeyError, match="hunt run"):
        database.hunt(empty)


def test_replay_and_persistent_suppression(database: Database) -> None:
    database.save_finding(finding(), ["smtp"], NOW)
    database.save_finding(finding(), ["smtp"], NOW)
    database.save_finding(replace(finding(), observed_at=NOW + timedelta(minutes=1)), ["smtp"], NOW)
    assert len(database.pending(NOW)) == 1
    database.delivery_result(database.pending(NOW)[0], None, NOW)
    database.save_finding(
        replace(finding(), observed_at=NOW + timedelta(hours=1)), ["smtp"], NOW + timedelta(hours=1)
    )
    assert database.pending(NOW + timedelta(hours=1)) == []
    database.save_finding(
        replace(finding(), observed_at=NOW + timedelta(hours=7)), ["smtp"], NOW + timedelta(hours=7)
    )
    assert len(database.pending(NOW + timedelta(hours=7))) == 1


def _command_finding(command: str, seq: int, remote_ip: str = "192.0.2.1") -> Finding:
    line = (f"2026/10/05:00:00:{seq:02d} GMT gateway 0-PPE-0 : default GUI CMD_EXECUTED {seq} 0 : "
            f'User admin - Remote_ip {remote_ip} - Command "{command}" - Status "Success"')
    rule = next(r for r in load_rules() if r.id == "mgmt-high-risk-command")
    hits = RuleEngine([rule]).evaluate(parse_line("nslog", line, "gateway"))
    assert len(hits) == 1
    return from_rule_hit(hits[0])


def _queued(database: Database, sink: str, at: datetime) -> list[str]:
    return [d.finding.dedup_key for d in database.pending(at) if d.sink == sink]


def test_distinct_evidence_for_one_rule_is_queued_separately(database: Database) -> None:
    benign = _command_finding("add system user ops ****", 1)
    attacker = _command_finding("bind system user ops superuser 0", 2)
    repeat = _command_finding("add system user ops ****", 3)
    second_ip = _command_finding("add system user ops ****", 4, "203.0.113.9")
    assert benign.dedup_key == repeat.dedup_key != attacker.dedup_key != second_ip.dedup_key
    for item in (benign, attacker, repeat, second_ip):
        database.save_finding(item, ["smtp", "siem"], NOW)
    assert sorted(_queued(database, "smtp", NOW)) == sorted(
        {item.dedup_key for item in (benign, attacker, second_ip)})
    assert len(_queued(database, "siem", NOW)) == 4


def test_siem_sink_is_never_suppressed_but_replays_are_idempotent(database: Database) -> None:
    later = replace(finding(), observed_at=NOW + timedelta(minutes=1))
    for item in (finding(), finding(), later):
        database.save_finding(item, ["smtp", "siem"], NOW)
    sinks = sorted(d.sink for d in database.pending(NOW))
    assert sinks == ["siem", "siem", "smtp"]
    for delivery in database.pending(NOW):
        database.delivery_result(delivery, None, NOW)
    database.save_finding(replace(finding(), observed_at=NOW + timedelta(hours=1)),
                          ["smtp", "siem"], NOW + timedelta(hours=1))
    assert [d.sink for d in database.pending(NOW + timedelta(hours=1))] == ["siem"]


def test_oversized_attacker_fields_are_clamped(database: Database) -> None:
    """Indexed columns stay bounded, independent of the parser's own limits (PostgreSQL
    rejects btree index rows over ~2.7 kB)."""
    event = LogEvent("nslog", "gateway", "raw oversized line", ts=NOW, feature="A" * 200,
                     event="CMD_EXECUTED", fields={"User": "\xe9" * 5000,
                                                   "Client_ip": "fe80::1%" + "a" * 80})
    assert event.event_type is not None and len(event.event_type) > 128
    database.ingest([IndexedEvent(event, "archive/reference", NOW)], [], NOW)
    with database.engine.connect() as connection:
        row = connection.execute(
            select(events.c.event_type, events.c.client_ip, events.c.username)).one()
    assert row.event_type == event.event_type[:128]
    assert row.client_ip is None  # a scoped address is never stored
    assert row.username == "\xe9" * 256


def _gateway_findings(lines: list[str], lists: dict[str, ListMatcher] | None = None,
                      device: str = "gateway") -> list[Finding]:
    engine = RuleEngine(load_rules(), lists or {})
    return [from_rule_hit(hit) for line in lines
            for hit in engine.evaluate(parse_line("nslog", line, device))]


def _flood(database: Database, items: list[Finding]) -> dict[str, int]:
    database.ingest([], [(item, ["smtp", "siem"]) for item in items], NOW)
    queued = [d.sink for d in database.pending(NOW, limit=10_000)]
    return {sink: queued.count(sink) for sink in ("smtp", "siem")}


def test_unauthenticated_probe_flood_queues_one_email(database: Database) -> None:
    probes = _gateway_findings([
        f"2026/10/05:00:00:00 GMT gateway 0-PPE-0 : default AAA Message {i} 0 : "
        f'"Authentication is rejected for {chr(0x80 + i % 120)}{chr(0x90 + i % 100)}u{i}"'
        for i in range(200)])
    assert len(probes) == 200
    assert _flood(database, probes) == {"smtp": 1, "siem": 200}


def test_unexpected_ip_gui_session_queues_one_email(database: Database) -> None:
    session = _gateway_findings([
        f"2026/10/05:00:00:00 GMT gateway 0-PPE-0 : default GUI CMD_EXECUTED {i} 0 : User admin "
        f'- Remote_ip 198.51.100.7 - Command "show lb vserver vs-{i}" - Status "Success"'
        for i in range(300)], {"admin_networks": ListMatcher(["10.0.0.0/8"]),
                               "admin_users": ListMatcher(["admin"])})
    assert {f.rule_id for f in session} == {"mgmt-from-unexpected-ip"}
    assert _flood(database, session) == {"smtp": 1, "siem": 300}


def test_distinct_keys_per_rule_are_capped_for_email(database: Database) -> None:
    def spray(device: str) -> list[Finding]:
        return _gateway_findings([
            f"2026/10/05:00:00:00 GMT {device} 0-PPE-0 : default GUI CMD_EXECUTED {i} 0 : "
            f'User guess{i} - Remote_ip 10.1.1.1 - Command "login guess{i}" - Status "ERROR"'
            for i in range(40)], {"admin_users": ListMatcher(["admin"])}, device)

    first = [f for f in spray("gateway") if f.rule_id == "mgmt-unknown-admin-user"]
    assert len({f.dedup_key for f in first}) == 40
    assert _flood(database, first) == {"smtp": NOTIFY_KEYS_PER_RULE, "siem": 40}
    other = [*spray("gateway-2"), _command_finding("add system user ops ****", 1)]
    database.ingest([], [(item, ["smtp"]) for item in other], NOW)
    queued = [d.finding for d in database.pending(NOW, limit=10_000) if d.sink == "smtp"]
    assert sum(f.device == "gateway-2" and f.rule_id == "mgmt-unknown-admin-user"
               for f in queued) == NOTIFY_KEYS_PER_RULE
    assert any(f.rule_id == "mgmt-high-risk-command" for f in queued)
    for delivery in database.pending(NOW, limit=10_000):
        database.delivery_result(delivery, None, NOW)
    later = replace(first[-1], observed_at=NOW + timedelta(hours=7))
    database.save_finding(later, ["smtp"], NOW + timedelta(hours=7))
    assert len(database.pending(NOW + timedelta(hours=7))) == 1


def test_critical_is_delivered_before_a_backlog(database: Database) -> None:
    flood = [replace(finding(), dedup_key=f"flood-{i}", observed_at=NOW + timedelta(seconds=i))
             for i in range(150)]
    database.ingest([], [(item, ["siem"]) for item in flood], NOW)
    critical = replace(finding(), dedup_key="critical", severity=Severity.CRITICAL)
    database.save_finding(critical, ["siem"], NOW + timedelta(seconds=1))
    batch = database.pending(NOW + timedelta(seconds=2))
    assert len(batch) == 100 and batch[0].finding.dedup_key == "critical"
    low = replace(finding(), dedup_key="low", severity=Severity.LOW)
    database.save_finding(low, ["siem"], NOW - timedelta(minutes=1))
    assert database.pending(NOW + timedelta(seconds=2), limit=200)[-1].finding.dedup_key == "low"


def _attempt(database: Database, at: datetime, errors: dict[tuple[str, str], str]) -> None:
    """Deliver every due row at ``at``; (sink, dedup_key) in ``errors`` fails with that text."""
    for delivery in database.pending(at):
        error = errors.get((delivery.sink, delivery.finding.dedup_key))
        database.delivery_result(delivery, error, at)


def test_sink_backlog_summarizes_undelivered_rows_per_sink(database: Database) -> None:
    def queue(key: str, at: datetime, *sinks: str) -> None:
        database.save_finding(Finding(key, "r", "t", Severity.HIGH, "health", None, "s"),
                              list(sinks), now=at)

    minute = timedelta(minutes=1)
    queue("a", NOW, "smtp", "webhook")
    _attempt(database, NOW + minute, {("smtp", "a"): "timeout 1"})
    queue("b", NOW + 2 * minute, "smtp", "webhook")
    _attempt(database, NOW + 3 * minute, {("smtp", "a"): "timeout 2", ("smtp", "b"): "timeout 2b",
                                          ("webhook", "b"): "550 rejected"})
    queue("c", NOW + 4 * minute, "smtp")
    backlog = database.sink_backlog(NOW + 5 * minute)
    smtp, webhook = backlog["smtp"], backlog["webhook"]
    assert (smtp.count, smtp.oldest_queued, smtp.max_attempts) == (3, NOW, 2)
    assert smtp.last_error == "timeout 2"  # retried last: its backoff ends last
    assert smtp.failing_since == NOW and smtp.last_delivered is None
    assert (webhook.count, webhook.oldest_queued, webhook.max_attempts) == (1, NOW + 2 * minute, 1)
    assert webhook.failing_since == NOW + 2 * minute  # queued after the last delivery
    assert webhook.last_delivered == NOW + minute
    assert database.sink_backlog(NOW + 3 * minute)["smtp"].count == 2  # c not queued yet
    # A later delivery passes "b": it is stuck, not an outage.
    queue("d", NOW + 5 * minute, "webhook")
    _attempt(database, NOW + 6 * minute, {("webhook", "b"): "550 rejected"})
    webhook = database.sink_backlog(NOW + 7 * minute)["webhook"]
    assert (webhook.count, webhook.max_attempts, webhook.failing_since) == (1, 2, None)
    assert webhook.last_delivered == NOW + 6 * minute
    assert [d.queued_at for d in database.pending(NOW + 9 * minute)
            if d.sink == "webhook"] == [NOW + 2 * minute]
    _attempt(database, NOW + 2 * timedelta(hours=2), {})
    assert database.sink_backlog(NOW + timedelta(hours=5)) == {}


def _audit_event(database: Database, at: datetime, *, feature: str = "GUI",
                 source: str = "nslog", command: str = "add lb vserver v HTTP") -> None:
    line = (f"{at:%Y/%m/%d:%H:%M:%S} GMT gateway 0-PPE-0 : default {feature} CMD_EXECUTED 1 0 : "
            f'User admin - Remote_ip 192.0.2.1 - Command "{command}" - Status "Success"')
    event = parse_line("nslog", line, "gateway")
    event.source = source
    database.ingest([IndexedEvent(event, f"archive/{source}", NOW)], [], NOW)


def test_audit_since_ignores_future_and_non_management_events(database: Database) -> None:
    _audit_event(database, NOW + timedelta(hours=2), command="forged future")
    _audit_event(database, NOW + timedelta(minutes=3), command="clock skew")
    _audit_event(database, NOW, feature="SSLVPN", command="other feature")
    _audit_event(database, NOW, source="httpaccess", command="mislabelled source")
    _audit_event(database, NOW, feature="API", command="real change")
    trail = database.audit_since("gateway", NOW - timedelta(minutes=5), now=NOW)
    assert trail == ["admin@192.0.2.1: clock skew", "admin@192.0.2.1: real change"]
    assert trail.future_ignored == 1 and trail.future_max == timedelta(hours=2)
    assert "admin@192.0.2.1: forged future" in database.audit_since(
        "gateway", NOW, now=NOW + timedelta(hours=2))


def test_audit_since_finds_a_change_behind_many_read_only_commands(database: Database) -> None:
    _audit_event(database, NOW - timedelta(minutes=4), command="add lb vserver v HTTP")
    for i in range(150):
        _audit_event(database, NOW - timedelta(minutes=3) + timedelta(seconds=i),
                     command=f"show lb vserver v{i}")
    trail = database.audit_since("gateway", NOW - timedelta(minutes=5), now=NOW)
    assert trail == ["admin@192.0.2.1: add lb vserver v HTTP"]
    assert trail.future_ignored == 0 and trail.future_max is None


def test_appliance_clock_ahead_is_reported_on_unattributed_change(database: Database) -> None:
    _audit_event(database, NOW + timedelta(minutes=12), command="add lb vserver v HTTP")
    trail = database.audit_since("gateway", NOW - timedelta(minutes=5), now=NOW)
    assert trail == [] and trail.future_ignored == 1
    diff = diff_configs("set ns hostName a\n", "set ns hostName a\nadd lb vserver v HTTP\n",
                        load_risk_rules())
    change = from_config_diff("gateway", diff, kind="running", attribution=trail,
                              snapshot_id="s1")
    assert change.severity is Severity.HIGH and change.evidence["unattributed"] is True
    assert "dated up to 12 min in the future" in change.summary
    assert change.evidence["audit_clock_skew"] in change.summary
    assert change.evidence["attribution"] == [] and type(change.evidence["attribution"]) is list


def test_events_and_alerts_commit_together_and_deduplicate(database: Database) -> None:
    event = parse_line(
        "nslog",
        "2026/10/05:00:00:00 GMT gateway 0-PPE-0 : default GUI CMD_EXECUTED 1 0 : "
        'User admin - Remote_ip 192.0.2.1 - Command "save config" - Status "Success"',
        "gateway",
    )
    record = IndexedEvent(event, "archive/reference", NOW)
    for _ in range(2):
        database.ingest([record], [(finding(), ["smtp"])], NOW)
    assert database.counts() == {"events": 1, "findings": 1, "pending_notifications": 1}
    assert database.audit_since("gateway", NOW) == ["admin@192.0.2.1: save config"]


def test_failed_transaction_does_not_index_events(
    database: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise RuntimeError("storage failure")

    monkeypatch.setattr(database, "_save_finding", fail)
    record = IndexedEvent(parse_line("nslog", "line", "gateway"), "archive/reference", NOW)
    with pytest.raises(RuntimeError, match="storage failure"):
        database.ingest([record], [(finding(), ["smtp"])], NOW)
    assert database.counts()["events"] == 0


def test_secret_redaction_before_json_escaping(database: Database) -> None:
    secret = 'test-quoted"credential\nwith-newline'
    Credential("admin", secret)
    database.save_finding(replace(finding(), summary=f"value: {secret}"), ["smtp"], NOW)
    assert database.pending(NOW)[0].finding.summary == "value: ***REDACTED***"


def test_retention_keeps_undelivered_findings(database: Database) -> None:
    database.save_finding(finding(), ["smtp"], NOW)
    future = NOW + timedelta(days=500)
    database.prune(90, 400, future)
    assert database.counts()["findings"] == 1
    database.delivery_result(database.pending(future)[0], None, future)
    database.prune(90, 400, future)
    assert database.counts()["findings"] == 0


def test_malformed_log_fields_do_not_block_postgresql(database: Database) -> None:
    event = parse_line("nslog", "malformed username\x00\x89", "gateway")
    event.fields["User"] = "garbage\x00username"
    database.ingest([IndexedEvent(event, "archive/reference", NOW)], [], NOW)
    database.save_finding(replace(finding(), dedup_key="garbage\x00key"), ["smtp"], NOW)
    assert database.counts()["events"] == 1
    assert len(database.pending(NOW)) == 1


async def test_appliance_to_durable_alert_workflow(database: Database, tmp_path: Path) -> None:
    cfg = Config.model_validate({
        "devices": [{"name": "gateway", "nsip": "192.0.2.10",
                     "spki_pin": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}],
        "paths": {"state_dir": str(tmp_path / "state"), "log_dir": str(tmp_path / "logs"),
                  "vault": str(tmp_path / "vault")},
        "notify": {},
    })
    key = generate_key()
    Vault.create(cfg.paths.vault, key).set(
        "sc_nitro", Credential("sc_nitro", "nitro-password"), actor="test")
    fake = FakeNitro(running="set ns hostName gateway\n", saved="set ns hostName gateway\n")
    sink = CollectSink()
    service = Service(Runtime(cfg, lambda: key, nitro_transport=lambda device: fake.transport()),
                      sinks=[sink], database=database)

    def change(step: int) -> None:
        if step == 2:
            fake.running += "add system user other hash -encrypted\n"
            fake.lastconfigchangedtime = "changed"

    stop_after(service, 3, change)
    await service.config_loop(cfg.devices[0])
    directory = cfg.paths.log_dir / "syslog" / cfg.devices[0].nsip
    directory.mkdir(parents=True)
    (directory / "2026-10-05.log").write_text(
        '2026/10/05:10:00:00 GMT gateway 0-PPE-0 : default GUI CMD_EXECUTED 1 0 : '
        'User admin - Command "add system user other ****" - Status "Success"\n')
    assert service.pipeline.poll(cfg.devices[0]) == 1
    assert sink.sent == []
    await service.deliver_pending()
    assert {finding.rule_id for finding in sink.sent} >= {"config-running", "mgmt-high-risk-command"}
    assert database.counts()["pending_notifications"] == 0
    assert service.pipeline.archive.verify("gateway") == 1


def test_web_read_models_on_storage_backend(database: Database, tmp_path: Path) -> None:
    cfg = Config.model_validate({
        "paths": {"state_dir": str(tmp_path)},
        "devices": [{"name": "gateway", "nsip": "192.0.2.10"}],
        "notify": {"webhook": {"url": "https://example.invalid/private-destination-token"}},
    })
    now = datetime.now(UTC)
    database.save_finding(replace(finding(), observed_at=now), ["webhook"], now)
    data = WebData(cfg, database)
    options = {"days": 1, "minimum": "high", "device": "gateway", "category": "health",
               "query": "TEST", "offset": 0, "limit": 25}
    result = data.search("findings", **options)
    assert result["total"] == 1 and result["items"][0]["device"] == "gateway"
    options["query"] = "%"
    assert data.search("findings", **options)["total"] == 0
    assert data.overview()["severity"]["high"] == 1
    delivery = data.delivery()["sinks"][0]
    assert delivery["pending"] == 1 and delivery["destination"] == "example.invalid"
    health = data.health()
    assert health["database"]["available"]
    assert health["database"]["findings"] == 1
    assert health["database"]["hunt_runs"] == 0
    assert health["database"]["pending_notifications"] == 1
    if database.engine.dialect.name == "postgresql":
        assert health["database"]["database_bytes"] > 0
