"""PostgreSQL event index, findings, and transactional notification outbox."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    and_,
    case,
    create_engine,
    delete,
    exists,
    func,
    insert,
    or_,
    select,
    update,
)
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import Connection, Engine

from scalar.detect.findings import (
    AuditTrail,
    Finding,
    finding_document,
    finding_from_document,
)
from scalar.detect.severity import Severity
from scalar.parse.nslog import LogEvent
from scalar.redact import registry

SCHEMA_VERSION = 1
SUPPRESS_REPEATS_FOR = timedelta(hours=6)
UNSUPPRESSED_SINKS = frozenset({"siem"})  # the SIEM gets every finding and correlates itself
AUDIT_EVENT_TYPES = ("CLI CMD_EXECUTED", "GUI CMD_EXECUTED", "API CMD_EXECUTED")
AUDIT_FUTURE_ALLOWANCE = timedelta(minutes=5)  # clock skew; later events are untrusted
AUDIT_RESULTS = 100
AUDIT_SCAN_LIMIT = 5000  # newest management events read to find AUDIT_RESULTS changes
NOTIFY_KEYS_PER_RULE = 10  # distinct log-rule keys per rule, device and sink per window
EVENT_TYPE_MAX = 128
CLIENT_IP_MAX = 45
USERNAME_MAX = 256
metadata = MetaData()
schema_version = Table("scalar_schema", metadata, Column("version", Integer, primary_key=True))
events = Table(
    "events",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("observed_at", DateTime(timezone=True), nullable=False, index=True),
    Column("received_at", DateTime(timezone=True), nullable=False),
    Column("device", String(63), nullable=False, index=True),
    Column("event_type", String(EVENT_TYPE_MAX), index=True),
    Column("username", Text, index=True),
    Column("client_ip", String(CLIENT_IP_MAX), index=True),
    Column("raw_ref", Text, nullable=False),
    Column("document", JSON, nullable=False),
)
findings = Table(
    "findings",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("dedup_key", Text, nullable=False, index=True),
    Column("observed_at", DateTime(timezone=True), nullable=False, index=True),
    Column("stored_at", DateTime(timezone=True), nullable=False),
    Column("severity", Integer, nullable=False),
    Column("document", JSON, nullable=False),
)
outbox = Table(
    "notifications_outbox",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("finding_id", ForeignKey("findings.id", ondelete="CASCADE"), nullable=False),
    Column("sink", String(64), nullable=False),
    Column("queued_at", DateTime(timezone=True), nullable=False),
    Column("next_attempt", DateTime(timezone=True), nullable=False, index=True),
    Column("attempts", Integer, nullable=False, default=0),
    Column("delivered_at", DateTime(timezone=True)),
    Column("error", Text),
)
hunt_runs = Table(
    "hunt_runs", metadata,
    Column("id", String(32), primary_key=True),
    Column("started_at", DateTime(timezone=True), nullable=False, index=True),
    Column("completed_at", DateTime(timezone=True)),
    Column("actor", String(64), nullable=False),
    Column("device", String(63), nullable=False, index=True),
    Column("source", String(32), nullable=False),
    Column("status", String(16), nullable=False),
    Column("finding_count", Integer, nullable=False, default=0),
    Column("document", JSON, nullable=False),
)


@dataclass(frozen=True)
class IndexedEvent:
    event: LogEvent
    raw_ref: str
    received_at: datetime
    identity: str | None = None

    def __post_init__(self) -> None:
        if self.identity is None:
            value = f"{self.event.device}\0{self.event.source}\0{self.event.raw}".encode()
            object.__setattr__(self, "identity", hashlib.sha256(value).hexdigest())


def _client_ip(event: LogEvent) -> str | None:
    value = event.ip_field("Client_ip") or event.ip_field("Remote_ip")
    return value if value is not None and len(value) <= CLIENT_IP_MAX else None


def _rule_prefix(finding: Finding) -> str | None:
    """``rule|device|`` for log-rule findings whose key separates evidence (RuleHit.dedup_key);
    these share NOTIFY_KEYS_PER_RULE."""
    prefix = f"{finding.rule_id}|{finding.device}|"
    if finding.category != "log_rule" or not finding.dedup_key.startswith(prefix):
        return None
    return prefix


@dataclass(frozen=True)
class PendingDelivery:
    id: str
    sink: str
    finding: Finding
    attempts: int
    queued_at: datetime | None = None


@dataclass(frozen=True)
class SinkBacklog:
    """Undelivered notifications of one sink (Database.sink_backlog)."""

    sink: str
    count: int  # undelivered rows
    oldest_queued: datetime  # queued_at of the oldest undelivered row
    max_attempts: int  # most delivery attempts of an undelivered row; 0: none tried yet
    last_error: str | None  # error of the failed row retried last (latest next_attempt)
    # Oldest failed row queued at or after the sink's last delivery. Older failed rows were
    # passed by a later delivery: stuck (a rejected message), not an outage.
    failing_since: datetime | None
    last_delivered: datetime | None


def _aware(value: datetime | None) -> datetime | None:
    """SQLite returns naive UTC datetimes."""
    return value.replace(tzinfo=UTC) if value is not None and value.tzinfo is None else value


class Database:
    def __init__(self, url: str | Engine) -> None:
        if isinstance(url, Engine):
            self.engine = url
        else:
            if not url.startswith("postgresql+psycopg:"):
                raise ValueError("database_url must use postgresql+psycopg")
            self.engine = create_engine(
                url,
                pool_pre_ping=True,
                pool_timeout=10,
                connect_args={"connect_timeout": 10, "options": "-c statement_timeout=30000"},
            )

    def initialize(self) -> None:
        metadata.create_all(self.engine)
        with self.engine.begin() as connection:
            versions = list(connection.scalars(select(schema_version.c.version)))
            if not versions:
                connection.execute(insert(schema_version).values(version=SCHEMA_VERSION))
            elif versions != [SCHEMA_VERSION]:
                raise ValueError("unsupported database schema version")

    def check(self) -> None:
        with self.engine.connect() as connection:
            if list(connection.scalars(select(schema_version.c.version))) != [SCHEMA_VERSION]:
                raise ValueError("database schema is not initialized; run scalar db init")

    @staticmethod
    def _insert_missing(connection: Connection, table: Table, values: Any) -> None:
        statement = (
            pg_insert(table) if connection.dialect.name == "postgresql" else sqlite_insert(table)
        )
        connection.execute(statement.values(values).on_conflict_do_nothing())

    @staticmethod
    def _suppressed(
        connection: Connection, sink: str, finding: Finding, stored_key: str, now: datetime
    ) -> bool:
        """The same key is still pending on this sink or was delivered recently, or the
        finding's rule already queued NOTIFY_KEYS_PER_RULE distinct keys for this device."""
        prefix = _rule_prefix(finding)
        if connection.dialect.name == "postgresql":
            lock = int.from_bytes(
                hashlib.sha256(f"{sink}\0{prefix or finding.dedup_key}".encode()).digest()[:8],
                signed=True,
            )
            connection.execute(select(func.pg_advisory_xact_lock(lock)))
        active = or_(
            outbox.c.delivered_at.is_(None),
            outbox.c.delivered_at >= now - SUPPRESS_REPEATS_FOR,
        )
        recent = (
            select(outbox.c.id)
            .join(findings)
            .where(findings.c.dedup_key == stored_key, outbox.c.sink == sink, active)
            .limit(1)
        )
        if connection.scalar(recent) is not None:
            return True
        if prefix is None:
            return False
        queued = (
            select(func.count(func.distinct(findings.c.dedup_key)))
            .select_from(outbox.join(findings))
            .where(
                outbox.c.sink == sink,
                or_(active, outbox.c.queued_at >= now - SUPPRESS_REPEATS_FOR),
                findings.c.dedup_key.startswith(prefix.replace("\x00", "\\x00"),
                                                autoescape=True),
            )
        )
        return (connection.scalar(queued) or 0) >= NOTIFY_KEYS_PER_RULE

    def _save_finding(
        self, connection: Connection, finding: Finding, targets: Sequence[str], now: datetime
    ) -> None:
        """Store the finding and queue it per sink. A sink other than the SIEM skips it when
        the same dedup_key is still pending there or was delivered recently, and caps how many
        distinct keys one log rule queues per device (see _suppressed)."""
        document = finding_document(finding)
        document["dedup_key"] = document["dedup_key"].replace("\x00", "\\x00")
        material = f"{finding.dedup_key}\0{finding.observed_at.isoformat()}"
        line = document["evidence"].get("line") if finding.category == "log_rule" else None
        if line:  # one finding per matching line, also when lines share key and second
            material += f"\0{line}"
        identity = hashlib.sha256(material.encode("utf-8", "backslashreplace")).hexdigest()
        self._insert_missing(
            connection,
            findings,
            {
                "id": identity,
                "dedup_key": document["dedup_key"],
                "observed_at": finding.observed_at,
                "stored_at": now,
                "severity": int(finding.severity),
                "document": document,
            },
        )
        for sink in targets:
            if sink not in UNSUPPRESSED_SINKS and self._suppressed(
                connection, sink, finding, document["dedup_key"], now
            ):
                continue
            delivery_id = hashlib.sha256(f"{identity}\0{sink}".encode()).hexdigest()
            self._insert_missing(
                connection,
                outbox,
                {
                    "id": delivery_id,
                    "finding_id": identity,
                    "sink": sink,
                    "queued_at": now,
                    "next_attempt": now,
                    "attempts": 0,
                },
            )

    def save_finding(
        self, finding: Finding, targets: Sequence[str], now: datetime | None = None
    ) -> None:
        with self.engine.begin() as connection:
            self._save_finding(connection, finding, targets, now or datetime.now(UTC))

    def ingest(
        self,
        batch: Sequence[IndexedEvent],
        alerts: Sequence[tuple[Finding, Sequence[str]]],
        now: datetime | None = None,
    ) -> None:
        received = now or datetime.now(UTC)
        rows = []
        for record in batch:
            event = record.event
            document = json.loads(json.dumps(registry.scrub_value(asdict(event)), default=str))
            rows.append(
                {
                    "id": record.identity,
                    "observed_at": event.ts or record.received_at,
                    "received_at": record.received_at,
                    "device": event.device,
                    "event_type": (event.event_type or "")[:EVENT_TYPE_MAX] or None,
                    "username": registry.scrub(event.fields.get("User", "")).replace(
                        "\x00", "\\x00")[:USERNAME_MAX] or None,
                    "client_ip": _client_ip(event),
                    "raw_ref": record.raw_ref,
                    "document": document,
                }
            )
        with self.engine.begin() as connection:
            if rows:
                self._insert_missing(connection, events, rows)
            for finding, targets in alerts:
                self._save_finding(connection, finding, targets, received)

    def pending(self, now: datetime | None = None, limit: int = 100) -> list[PendingDelivery]:
        """Due deliveries, most severe first, so a backlog never delays a critical finding."""
        query = (
            select(outbox.c.id, outbox.c.sink, outbox.c.attempts, outbox.c.queued_at,
                   findings.c.document)
            .join(findings)
            .where(
                outbox.c.delivered_at.is_(None), outbox.c.next_attempt <= (now or datetime.now(UTC))
            )
            .order_by(findings.c.severity.desc(), outbox.c.queued_at)
            .limit(limit)
        )
        with self.engine.connect() as connection:
            return [
                PendingDelivery(row.id, row.sink, finding_from_document(row.document),
                                row.attempts, _aware(row.queued_at))
                for row in connection.execute(query)
            ]

    def sink_backlog(self, now: datetime | None = None) -> dict[str, SinkBacklog]:
        """Undelivered outbox rows per sink, among those queued by ``now``. The outbox is
        durable, so this outlives daemon restarts (see SinkBacklog.failing_since)."""
        at = now or datetime.now(UTC)
        delivered = (
            select(outbox.c.sink, func.max(outbox.c.delivered_at).label("at"))
            .where(outbox.c.delivered_at.is_not(None))
            .group_by(outbox.c.sink)
            .subquery()
        )
        undelivered = (outbox.c.delivered_at.is_(None), outbox.c.queued_at <= at)
        failed = outbox.c.attempts > 0
        since_delivery = or_(delivered.c.at.is_(None), outbox.c.queued_at >= delivered.c.at)
        summary = (
            select(
                outbox.c.sink,
                func.count(),
                func.min(outbox.c.queued_at),
                func.max(outbox.c.attempts),
                func.min(case((and_(failed, since_delivery), outbox.c.queued_at))),
                func.max(delivered.c.at),
            )
            .select_from(outbox.outerjoin(delivered, delivered.c.sink == outbox.c.sink))
            .where(*undelivered)
            .group_by(outbox.c.sink)
        )
        ranked = (
            select(
                outbox.c.sink,
                outbox.c.error,
                func.row_number()
                .over(
                    partition_by=outbox.c.sink,
                    order_by=(outbox.c.next_attempt.desc(), outbox.c.attempts.desc(),
                              outbox.c.id),
                )
                .label("rank"),
            )
            .where(*undelivered, failed, outbox.c.error.is_not(None))
            .subquery()
        )
        with self.engine.connect() as connection:
            errors: dict[str, str] = {
                sink: error for sink, error in connection.execute(
                    select(ranked.c.sink, ranked.c.error).where(ranked.c.rank == 1))
            }
            rows = list(connection.execute(summary))
        result = {}
        for sink, count, oldest, attempts, failing, last in rows:
            error = errors.get(sink)
            result[sink] = SinkBacklog(
                sink=sink,
                count=int(count),
                oldest_queued=_aware(oldest) or at,
                max_attempts=int(attempts or 0),
                last_error=registry.scrub(error) if error else None,
                failing_since=_aware(failing),
                last_delivered=_aware(last),
            )
        return result

    def delivery_result(
        self, delivery: PendingDelivery, error: str | None, now: datetime | None = None
    ) -> None:
        at = now or datetime.now(UTC)
        delay = min(3600, 30 * 2 ** min(delivery.attempts, 7))
        with self.engine.begin() as connection:
            connection.execute(
                update(outbox)
                .where(outbox.c.id == delivery.id)
                .values(
                    attempts=outbox.c.attempts + 1,
                    delivered_at=at if error is None else None,
                    next_attempt=at + timedelta(seconds=delay),
                    error=registry.scrub(error).replace("\x00", "\\x00")[:2000] if error else None,
                )
            )

    def recent_findings(
        self, since: datetime, min_severity: Severity = Severity.INFO, limit: int = 1000
    ) -> list[dict[str, Any]]:
        query = (
            select(findings.c.document)
            .where(findings.c.observed_at >= since, findings.c.severity >= int(min_severity))
            .order_by(findings.c.observed_at.desc())
            .limit(limit)
        )
        with self.engine.connect() as connection:
            return list(connection.scalars(query))

    def start_hunt(self, actor: str, device: str, source: str, context: dict[str, Any],
                   now: datetime | None = None) -> str:
        at = now or datetime.now(UTC)
        identity = uuid.uuid4().hex
        document = registry.scrub_value({
            "id": identity, "actor": actor, "device": device, "source": source,
            "started_at": at.isoformat(), "context": context,
            "status": "running", "result": None,
        })
        with self.engine.begin() as connection:
            connection.execute(insert(hunt_runs).values(
                id=identity, actor=actor, device=device, source=source,
                started_at=at, status="running", finding_count=0, document=document,
            ))
        return identity

    def finish_hunt(self, identity: str, result: dict[str, Any] | None, *,
                    error: str | None = None, now: datetime | None = None) -> dict[str, Any]:
        at = now or datetime.now(UTC)
        with self.engine.begin() as connection:
            stored = connection.scalar(select(hunt_runs.c.document)
                                       .where(hunt_runs.c.id == identity))
            if stored is None:
                raise KeyError("hunt run not found")
            document: dict[str, Any] = registry.scrub_value({
                **stored, "completed_at": at.isoformat(),
                "status": "failed" if error else "complete",
                "error": error, "result": result,
            })
            connection.execute(update(hunt_runs).where(hunt_runs.c.id == identity).values(
                completed_at=at, status=document["status"], document=document,
                finding_count=len((result or {}).get("findings", [])),
            ))
        return document

    def hunt(self, identity: str) -> dict[str, Any]:
        with self.engine.connect() as connection:
            document = connection.scalar(select(hunt_runs.c.document)
                                         .where(hunt_runs.c.id == identity))
        if document is None:
            raise KeyError("hunt run not found")
        result: dict[str, Any] = registry.scrub_value(document)
        return result

    def hunt_history(self, since: datetime, *, device: str = "", source: str = "",
                     offset: int = 0, limit: int = 25) -> dict[str, Any]:
        criteria = [hunt_runs.c.started_at >= since]
        if device:
            criteria.append(hunt_runs.c.device == device)
        if source:
            criteria.append(hunt_runs.c.source == source)
        columns = [column for column in hunt_runs.c if column.name != "document"]
        with self.engine.connect() as connection:
            total = connection.scalar(select(func.count()).select_from(hunt_runs).where(*criteria))
            rows = connection.execute(select(*columns).where(*criteria)
                                      .order_by(hunt_runs.c.started_at.desc(), hunt_runs.c.id)
                                      .offset(offset).limit(limit))
            items = []
            for row in rows:
                item = dict(row._mapping)
                for name in ("started_at", "completed_at"):
                    if item[name] is not None:
                        item[name] = item[name].replace(tzinfo=UTC).isoformat()
                items.append(item)
        return {"items": items, "total": total or 0, "offset": offset, "limit": limit}

    def audit_since(self, device: str, since: datetime,
                    now: datetime | None = None) -> AuditTrail:
        """Successful configuration commands from the ns.log management audit trail
        (CLI/GUI/API CMD_EXECUTED) since ``since``, newest first. Events dated more than a
        few minutes in the future are ignored (forged or a wrong clock); those received
        since ``since`` are counted in the result, so a skewed clock is visible."""
        at = now or datetime.now(UTC)
        until = at + AUDIT_FUTURE_ALLOWANCE
        audit = (events.c.device == device, events.c.event_type.in_(AUDIT_EVENT_TYPES))
        future = select(func.count(), func.max(events.c.observed_at)).where(
            *audit, events.c.observed_at > until, events.c.received_at >= since)
        query = (
            select(events.c.document)
            .where(*audit, events.c.observed_at >= since, events.c.observed_at <= until)
            .order_by(events.c.observed_at.desc())
            .limit(AUDIT_SCAN_LIMIT)
            .execution_options(yield_per=AUDIT_RESULTS)
        )
        result: list[str] = []
        with self.engine.connect() as connection:
            ignored, latest = connection.execute(future).one()
            for doc in connection.scalars(query):
                if doc.get("source") != "nslog":
                    continue
                fields = doc["fields"]
                command = fields.get("Command", "")
                if (not fields.get("Status", "").startswith("Success")
                        or command.split(" ", 1)[0].lower() in {"show", "stat", "login", "logout"}
                        or not command):
                    continue
                result.append(
                    f"{fields.get('User', '?')}@{fields.get('Remote_ip', '?')}: "
                    f"{command}"
                )
                if len(result) >= AUDIT_RESULTS:
                    break
        if latest is not None and latest.tzinfo is None:
            latest = latest.replace(tzinfo=UTC)
        return AuditTrail(result, future_ignored=int(ignored or 0),
                          future_max=latest - at if latest is not None else None)

    def counts(self) -> dict[str, int]:
        with self.engine.connect() as connection:
            return {
                "events": int(connection.scalar(select(func.count()).select_from(events)) or 0),
                "findings": int(connection.scalar(select(func.count()).select_from(findings)) or 0),
                "pending_notifications": int(
                    connection.scalar(
                        select(func.count())
                        .select_from(outbox)
                        .where(outbox.c.delivered_at.is_(None))
                    )
                    or 0
                ),
            }

    def health_statistics(self) -> dict[str, Any]:
        result: dict[str, Any] = self.counts()
        with self.engine.connect() as connection:
            result["hunt_runs"] = connection.scalar(
                select(func.count()).select_from(hunt_runs)) or 0
            result["delivered_notifications"] = connection.scalar(
                select(func.count()).select_from(outbox).where(outbox.c.delivered_at.is_not(None))
            ) or 0
            result["retrying_notifications"] = connection.scalar(
                select(func.count()).select_from(outbox).where(
                    outbox.c.delivered_at.is_(None), outbox.c.attempts > 0)
            ) or 0
            for label, column in (("last_event_received", events.c.received_at),
                                  ("last_finding_stored", findings.c.stored_at),
                                  ("last_hunt_started", hunt_runs.c.started_at)):
                value = connection.scalar(select(func.max(column)))
                result[label] = value.replace(tzinfo=UTC).isoformat() if value else None
            result["database_bytes"] = (
                connection.scalar(select(func.pg_database_size(func.current_database())))
                if connection.dialect.name == "postgresql" else None
            )
        return result

    def prune(self, events_days: int, findings_days: int, now: datetime | None = None) -> None:
        at = now or datetime.now(UTC)
        with self.engine.begin() as connection:
            connection.execute(delete(hunt_runs).where(
                hunt_runs.c.started_at < at - timedelta(days=findings_days)))
            connection.execute(
                delete(events).where(events.c.received_at < at - timedelta(days=events_days))
            )
            old = select(findings.c.id).where(
                findings.c.stored_at < at - timedelta(days=findings_days),
                ~exists(
                    select(outbox.c.id).where(
                        outbox.c.finding_id == findings.c.id, outbox.c.delivered_at.is_(None)
                    )
                ),
            )
            old_ids = list(connection.scalars(old))
            if old_ids:
                connection.execute(delete(outbox).where(outbox.c.finding_id.in_(old_ids)))
                connection.execute(delete(findings).where(findings.c.id.in_(old_ids)))

    def close(self) -> None:
        self.engine.dispose()
