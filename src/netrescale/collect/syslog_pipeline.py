"""Live syslog parsing, detection, archival, and transactional indexing."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
import threading
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy.exc import InterfaceError, OperationalError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError

from netrescale.collect.syslog_tail import Cursor, LogBatch, SyslogTailer
from netrescale.config import Config, Device
from netrescale.detect.findings import (
    Finding,
    finding_document,
    finding_from_document,
    from_rule_hit,
    from_session_reuse,
)
from netrescale.detect.rules import ListMatcher, RuleEngine, load_rules
from netrescale.detect.sessions import SessionTracker
from netrescale.detect.severity import Severity
from netrescale.parse.nslog import LogEvent, parse_syslog
from netrescale.redact import registry
from netrescale.secrets.vault import atomic_write
from netrescale.store.archive import RawArchive
from netrescale.store.database import Database, IndexedEvent

log = logging.getLogger(__name__)

MAX_REPLAYS = 3  # failed replays of a pending batch before it is quarantined
MAX_QUARANTINED = 100  # quarantined batches kept per device; their raw lines stay archived
_TRANSIENT = (OSError, InterfaceError, PoolTimeoutError)  # never quarantine
# OperationalError SQLSTATEs from an outage, not the batch: connection, transaction rollback
# (deadlock, serialization), insufficient resources, lock timeout, shutdown, system I/O.
_OUTAGE_SQLSTATES = ("08", "40", "53", "55P03", "57P", "58")
SOURCE_CLASSES: dict[str, tuple[str, ...]] = {
    "ns.log": ("nslog",),
    "shell (bash.log/sh.log)": ("bashlog", "shlog"),
    "web access/error": ("httpaccess", "httpaccess-vpn", "httperror"),
    "auth.log": ("auth",),
    "notice.log": ("notice",),
}


@dataclass
class SourceHealth:
    lines: int = 0
    last_received: datetime | None = None


@dataclass(frozen=True, slots=True)
class SourceCoverage:
    source: str  # SOURCE_CLASSES key
    lines: int
    last_received: datetime | None


@dataclass
class FeedHealth:
    lines: int = 0
    parsed: int = 0
    raw_bytes: int = 0
    last_received: datetime | None = None
    last_error: str = ""
    line_errors: int = 0  # lines that failed parsing or rule evaluation and were skipped
    last_line_error: str = ""
    quarantined: int = 0  # pending batches set aside after MAX_REPLAYS failed replays
    last_quarantined: str = ""
    sources: dict[str, SourceHealth] = field(default_factory=dict)

    def record(self, source: str, lines: int, at: datetime | None) -> None:
        """Count lines from one source (bashlog, auth, ...) for per-source coverage."""
        entry = self.sources.setdefault(source, SourceHealth())
        entry.lines += lines
        if at is not None and (entry.last_received is None or at > entry.last_received):
            entry.last_received = at

    def source_coverage(self) -> list[SourceCoverage]:
        """Lines and the latest arrival per source class (SOURCE_CLASSES)."""
        out = []
        for name, members in SOURCE_CLASSES.items():
            seen = [self.sources[source] for source in members if source in self.sources]
            stamps = [entry.last_received for entry in seen if entry.last_received]
            out.append(SourceCoverage(name, sum(entry.lines for entry in seen),
                                      max(stamps, default=None)))
        return out

    def coverage(self) -> list[str]:
        """One line per source class, e.g. 'shell (bash.log/sh.log): never received'."""
        out = [f"{entry.source}: {entry.lines} line(s), last {entry.last_received.isoformat()}"
               if entry.lines and entry.last_received else f"{entry.source}: never received"
               for entry in self.source_coverage()]
        unknown = self.sources.get("unknown")
        if unknown and unknown.lines:
            out.append(f"unclassified: {unknown.lines} line(s)")
        return out


@dataclass
class _Journal:
    """A processed batch, written to pending/<device>.json before it is indexed."""

    batch: LogBatch
    records: list[IndexedEvent]
    alerts: list[Finding]
    lines: int
    parsed: int
    raw_bytes: int
    last_received: datetime
    sources: dict[str, tuple[int, datetime | None]] = field(default_factory=dict)
    line_errors: int = 0
    line_error: str = ""
    raw_ref: str | None = None
    attempts: int = 0

    def document(self) -> dict[str, Any]:
        return {"events": [asdict(record) for record in self.records],
                "findings": [finding_document(alert) for alert in self.alerts],
                "last_received": self.last_received.isoformat(),
                "lines": self.lines, "parsed": self.parsed, "raw_bytes": self.raw_bytes,
                "checkpoint": {"source_ip": self.batch.source_ip, "path": self.batch.path,
                               "start": self.batch.start, "cursor": asdict(self.batch.cursor)},
                "sources": {source: [count, at.isoformat() if at else None]
                            for source, (count, at) in self.sources.items()},
                "line_errors": self.line_errors, "line_error": self.line_error,
                "raw_ref": self.raw_ref, "attempts": self.attempts}

    @classmethod
    def load(cls, device: str, doc: dict[str, Any]) -> _Journal:
        records = []
        for record in doc["events"]:
            event = dict(record["event"])
            event["ts"] = datetime.fromisoformat(event["ts"]) if event["ts"] else None
            records.append(IndexedEvent(LogEvent(**event), record["raw_ref"],
                                        datetime.fromisoformat(record["received_at"]),
                                        record["identity"]))
        checkpoint = doc["checkpoint"]
        batch = LogBatch(device, str(checkpoint["source_ip"]), str(checkpoint["path"]),
                         int(checkpoint["start"]), Cursor(**checkpoint["cursor"]), ())
        sources = {str(source): (int(count), datetime.fromisoformat(at) if at else None)
                   for source, (count, at) in doc.get("sources", {}).items()}
        raw_ref = doc.get("raw_ref") or next(
            (str(record["raw_ref"]) for record in doc["events"]), None)
        return cls(batch, records, [finding_from_document(item) for item in doc["findings"]],
                   int(doc["lines"]), int(doc["parsed"]), int(doc["raw_bytes"]),
                   datetime.fromisoformat(doc["last_received"]), sources,
                   int(doc.get("line_errors", 0)), str(doc.get("line_error", "")),
                   raw_ref, int(doc.get("attempts", 0)))


def _line_error_finding(device: str, failures: dict[str, list[int]], raw_ref: str | None,
                        now: datetime) -> Finding:
    kinds = sorted(failures)
    count = sum(len(numbers) for numbers in failures.values())
    return Finding(
        dedup_key=f"log-parse-error|{device}|{','.join(kinds)}",
        rule_id="log-parse-error",
        title="Syslog lines could not be processed",
        severity=Severity.HIGH,
        category="health",
        device=device,
        summary=(f"{device}: {count} syslog line(s) failed parsing or rule evaluation "
                 f"({', '.join(kinds)}); they are archived but were not checked by the rules"),
        observed_at=now,
        evidence={"errors": {kind: numbers[:20] for kind, numbers in failures.items()},
                  "lines": count, "raw_ref": raw_ref},
    )


class SyslogPipeline:
    def __init__(self, cfg: Config, database: Database,
                 targets: Callable[[Finding], Sequence[str]]) -> None:
        self.cfg = cfg
        self.database = database
        self.targets = targets
        self._lock = threading.Lock()
        self.tailer = SyslogTailer(cfg.paths.log_dir / "syslog",
                                  cfg.paths.state_dir / "syslog-checkpoints.json",
                                  batch_lines=cfg.syslog.batch_lines,
                                  max_line_bytes=cfg.syslog.max_line_bytes)
        self.archive = RawArchive(cfg.paths.state_dir / "archive")
        lists = {}
        if cfg.syslog.admin_networks:
            lists["admin_networks"] = ListMatcher(cfg.syslog.admin_networks)
        if cfg.syslog.admin_users:
            lists["admin_users"] = ListMatcher(cfg.syslog.admin_users)
        self.engine = RuleEngine(load_rules(), lists)
        self.sessions = SessionTracker()
        self.health = {device.name: FeedHealth() for device in cfg.devices}

    @staticmethod
    def _received(line: str, address: str, fallback: datetime) -> datetime:
        parts = line.split(" ", 2)
        if len(parts) == 3 and parts[1] == address:
            try:
                stamp = datetime.fromisoformat(parts[0])
                if stamp.tzinfo is not None:
                    return min(stamp.astimezone(UTC), fallback)
            except (ValueError, OverflowError):
                pass
        return fallback

    def poll(self, device: Device) -> int:
        with self._lock:
            return self._poll(device)

    def wait_idle(self) -> None:
        with self._lock:
            pass

    def prune(self, now: datetime) -> None:
        with self._lock:
            raw_cutoff = now - timedelta(days=self.cfg.retention.raw_days)
            self.archive.prune(raw_cutoff.date())
            self.tailer.prune((now - timedelta(days=self.cfg.syslog.source_days)).date())
            for modified, path in self._quarantined():
                if modified < raw_cutoff.timestamp():
                    path.unlink(missing_ok=True)

    @property
    def quarantine_dir(self) -> Path:
        return self.cfg.paths.state_dir / "pending" / "quarantine"

    def _quarantined(self, device: str | None = None) -> list[tuple[float, Path]]:
        """(mtime, path) of quarantined batches, oldest first; all devices if device is None."""
        found = []
        if self.quarantine_dir.is_dir():
            for path in self.quarantine_dir.glob("*.json"):
                if device is not None and path.name.rsplit("-", 1)[0] != device:
                    continue
                try:
                    info = path.lstat()
                except FileNotFoundError:
                    continue
                if stat.S_ISREG(info.st_mode):
                    found.append((info.st_mtime, path))
        return sorted(found)

    def _transient(self, exc: BaseException) -> bool:
        """A database outage (keep the batch pending) rather than a batch that cannot be
        indexed. An OperationalError without a SQLSTATE is an outage only if the database
        no longer answers."""
        if isinstance(exc, _TRANSIENT):
            return True
        if not isinstance(exc, OperationalError):
            return False
        if exc.connection_invalidated:
            return True
        state = getattr(exc.orig, "sqlstate", None) or getattr(exc.orig, "pgcode", None)
        if state:
            return str(state).startswith(_OUTAGE_SQLSTATES)
        try:
            self.database.check()
        except Exception:  # noqa: BLE001 - any failure to answer means it is down
            return True
        return False

    def _ingest(self, journal: _Journal, now: datetime | None = None) -> None:
        self.database.ingest(journal.records,
                             [(alert, self.targets(alert)) for alert in journal.alerts], now)

    @staticmethod
    def _account(health: FeedHealth, journal: _Journal) -> None:
        health.lines += journal.lines
        health.parsed += journal.parsed
        health.raw_bytes += journal.raw_bytes
        if journal.lines:  # a reset notice alone is not evidence the feed is alive
            health.last_received = journal.last_received
        health.last_error = ""
        health.line_errors += journal.line_errors
        if journal.line_error:
            health.last_line_error = journal.line_error
        for source, (count, at) in journal.sources.items():
            health.record(source, count, at)

    def _replay(self, device: Device, pending: Path, health: FeedHealth) -> int:
        data = pending.read_bytes()
        try:
            doc = json.loads(data)
            journal = _Journal.load(device.name, doc)
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            # Unreadable journal: the tailer re-reads the batch from the last checkpoint.
            self._quarantine(device, pending, health, None, data, type(exc).__name__)
            return 0
        if journal.attempts >= MAX_REPLAYS:
            self._quarantine(device, pending, health, journal, data,
                             str(doc.get("last_error") or "unknown error"))
            return journal.lines
        doc["attempts"] = journal.attempts + 1
        atomic_write(pending, json.dumps(doc).encode())
        try:
            self._ingest(journal)
        except Exception as exc:
            if self._transient(exc):
                doc["attempts"] = journal.attempts  # a database outage is not a poison batch
            else:
                doc["last_error"] = type(exc).__name__
            atomic_write(pending, json.dumps(doc).encode())
            raise
        self.tailer.commit(journal.batch)
        pending.unlink()
        self._account(health, journal)
        return journal.lines

    def _quarantine(self, device: Device, pending: Path, health: FeedHealth,
                    journal: _Journal | None, data: bytes, error: str) -> None:
        """Set a pending batch aside so new logs keep flowing, and raise a CRITICAL finding.

        The batch's own findings are stored if they can be; its raw lines stay archived."""
        digest = hashlib.sha256(data).hexdigest()
        target = self.quarantine_dir / f"{device.name}-{digest[:16]}.json"
        if journal is None:
            key, lines, attempts, raw_ref = digest, 0, 0, None
            observed = datetime.fromtimestamp(pending.stat().st_mtime, UTC)
        else:
            key = f"{journal.batch.path}#{journal.batch.start}"
            lines, attempts, raw_ref = journal.lines, journal.attempts, journal.raw_ref
            observed = journal.last_received

        def finding(delivered: bool) -> Finding:
            return Finding(
                dedup_key=f"syslog-batch-quarantined|{device.name}|{key}",
                rule_id="syslog-batch-quarantined",
                title="Syslog batch quarantined after repeated indexing failures",
                severity=Severity.CRITICAL,
                category="health",
                device=device.name,
                summary=(f"{device.name}: a batch of {lines} syslog line(s) could not be "
                         f"indexed ({error}) and was set aside so monitoring continues; review "
                         "its lines in the raw archive"),
                observed_at=observed,
                evidence={"quarantine": f"pending/quarantine/{target.name}", "raw_ref": raw_ref,
                          "lines": lines, "attempts": attempts, "error": error,
                          "batch_rule_ids": sorted({alert.rule_id for alert in
                                                    (journal.alerts if journal else [])}),
                          "batch_findings_stored": delivered},
            )

        alerts = journal.alerts if journal else []
        try:
            self.database.ingest([], [(alert, self.targets(alert))
                                      for alert in [*alerts, finding(True)]])
        except Exception as exc:
            if self._transient(exc):
                raise
            # The batch's own findings may be what fails to store.
            self.database.ingest([], [(alert, self.targets(alert)) for alert in [finding(False)]])
        if journal is not None:
            self.tailer.commit(journal.batch)
        self.quarantine_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        pending.replace(target)
        os.utime(target)  # newest, so the cap below never drops it
        for _modified, old in self._quarantined(device.name)[:-MAX_QUARANTINED]:
            old.unlink(missing_ok=True)
        if journal is not None:
            self._account(health, journal)
        health.quarantined += 1
        health.last_quarantined = target.name
        log.error("%s: syslog batch quarantined to %s after %d attempt(s): %s",
                  device.name, target, attempts, error)

    def _process(self, device: Device, batch: LogBatch, health: FeedHealth,
                 now: datetime) -> _Journal:
        raw = b"".join(batch.lines)
        reference = self.archive.put(device.name, raw, now) if raw else None
        locator = reference.locator if reference else None
        alerts = list(batch.findings)
        indexed = []
        received = health.last_received
        parsed = 0
        sources: dict[str, tuple[int, datetime | None]] = {}
        failures: dict[str, list[int]] = {}
        for number, line in enumerate(batch.lines, 1):
            text = line.decode("latin-1")
            stamp = self._received(text, batch.source_ip, now)
            received = max(received, stamp) if received else stamp
            event: LogEvent | None = None
            try:
                event = parse_syslog(text, device.name, device.date_format, device.timezone)
                event.ts = event.ts or stamp
                hits = [from_rule_hit(hit) for hit in self.engine.evaluate(event)]
                hits += [from_session_reuse(hit) for hit in self.sessions.observe(event)]
            except Exception as exc:  # noqa: BLE001 - one bad line must not stop the feed
                failures.setdefault(type(exc).__name__, []).append(number)
                source = event.source if event else "unknown"
                sources[source] = (sources.get(source, (0, None))[0] + 1, stamp)
                continue
            sources[event.source] = (sources.get(event.source, (0, None))[0] + 1, stamp)
            parsed += int(event.event is not None or event.source not in ("nslog", "unknown"))
            if locator:
                hits = [replace(hit, evidence={**hit.evidence, "raw_ref": locator})
                        for hit in hits]
                high_volume = (event.event or "").startswith(("TCPCONNSTAT", "HTTPREQUEST", "ICA"))
                if hits or (event.event is not None and not high_volume):
                    indexed.append(IndexedEvent(event, locator, stamp))
            alerts.extend(hits)
        if failures:
            alerts.append(_line_error_finding(device.name, failures, locator, now))
            for kind, numbers in failures.items():
                log.warning("%s: %d syslog line(s) failed processing (%s) in %s",
                            device.name, len(numbers), kind, locator)
        return _Journal(batch, indexed, alerts, len(batch.lines), parsed, len(raw),
                        received or now, sources,
                        sum(len(numbers) for numbers in failures.values()),
                        ", ".join(sorted(failures)), locator)

    def _poll(self, device: Device) -> int:
        processed = 0
        health = self.health[device.name]
        pending = self.cfg.paths.state_dir / "pending" / f"{device.name}.json"
        if pending.exists():
            processed += self._replay(device, pending, health)
        for batch in self.tailer.batches(device):
            now = datetime.now(UTC)
            journal = self._process(device, batch, health, now)
            document = registry.scrub_value(journal.document())
            atomic_write(pending, json.dumps(document, default=str).encode())
            self._ingest(journal, now)
            self.tailer.commit(batch)
            pending.unlink()
            processed += journal.lines
            self._account(health, journal)
        return processed
