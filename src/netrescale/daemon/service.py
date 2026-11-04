"""netrescaled: the long-running service (one asyncio process).

Config polling, live syslog detection, durable notification delivery, exposure and health.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import contextvars
import hashlib
import json
import logging
import os
import random
import signal
from collections import Counter, OrderedDict, deque
from collections.abc import Collection, Iterator
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy.exc import InterfaceError, OperationalError, SQLAlchemyError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError

from netrescale.administration import Administration, appliance_failure
from netrescale.collect.config_poller import ConfigPoller
from netrescale.collect.features import detect_features
from netrescale.collect.fim import FimMonitor
from netrescale.collect.syslog_pipeline import SOURCE_CLASSES, FeedHealth, SyslogPipeline
from netrescale.config import Config, Device, DeviceMode, load_config
from netrescale.control import ControlError, ControlRequest, ControlServer
from netrescale.daemon import sdnotify
from netrescale.daemon.health import ResourceMonitor
from netrescale.detect.config_diff import diff_configs
from netrescale.detect.config_risk import load_risk_rules
from netrescale.detect.exposure import STALE_AFTER_DAYS, ExposureReport, assess, load_cve_data
from netrescale.detect.findings import (
    AuditStatus,
    Finding,
    from_config_diff,
    from_exposure,
    from_exposure_attention,
    from_exposure_lifecycle,
    from_stale_cve_data,
)
from netrescale.detect.severity import Severity
from netrescale.notify.sinks import Router, Sink, build_sinks
from netrescale.parse.version import parse_version
from netrescale.redact import registry
from netrescale.runtime import Runtime
from netrescale.secrets.base import CredentialError
from netrescale.secrets.resolver import CredentialBlocked, stale_entries
from netrescale.secrets.vault import atomic_write
from netrescale.store.database import Database, PendingDelivery, SinkBacklog
from netrescale.store.findings_log import FindingsLog
from netrescale.store.snapshots import FileSnapshotStore
from netrescale.transport.nitro import AuthRejected, NitroClient, NitroError
from netrescale.transport.tls import PinMismatch

log = logging.getLogger("netrescale.daemon")
UNREACHABLE_AFTER = 5  # consecutive failed polls before a health finding
AUDIT_FRESH_FOR = timedelta(minutes=2)  # older audit lines cannot attribute a config change
SINK_FAILING_AFTER = timedelta(minutes=15)  # undelivered this long: the sink is failing
SINK_CONCURRENCY = 2  # deliveries in flight per sink, so one sink cannot hold the others back
SINK_RETRY_AFTER = timedelta(seconds=30)  # after a failed send, the sink's rows are deferred
SEND_TIMEOUT = 45  # seconds per queued delivery
DIRECT_SEND_TIMEOUT = 30  # seconds per alert sent past the outbox
LIFECYCLE_REMINDER = timedelta(days=7)  # an unchanged end-of-maintenance/life train
READINESS_RETRY = (30.0, 300.0)  # first and maximum delay for transient setup failures
SPOOL_LIMIT = 1000  # daemon findings held in memory while the database is down
# Source classes (SOURCE_CLASSES keys) every device with syslog is expected to send.
EXPECTED_SOURCES = ("ns.log", "shell (bash.log/sh.log)", "web access/error")
_TRANSIENT = (OSError, OperationalError, InterfaceError, PoolTimeoutError)
_ACTOR: contextvars.ContextVar[str | None] = contextvars.ContextVar("netrescale_actor",
                                                                    default=None)


@contextlib.contextmanager
def instance_lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        import fcntl
    except ModuleNotFoundError:
        yield
        return

    descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("another netrescale daemon is already running") from exc
        yield
    finally:
        os.close(descriptor)


@dataclass
class DeviceHealth:
    failures: int = 0
    last_ok: datetime | None = None
    last_error: str = ""
    reported: bool = False
    attempts: int = 0
    successes: int = 0
    total_failures: int = 0
    last_attempt: datetime | None = None
    last_failure: datetime | None = None
    error_type: str = ""


@dataclass
class SinkHealth:
    failing: dict[str, datetime] = field(default_factory=dict)  # outbox row -> first failure
    # When the oldest notification that failed before this process started (or reloaded) was
    # queued, if queued since the sink's last delivery (Database.sink_backlog): the failure
    # episode outlives a restart.
    failed_before: datetime | None = None
    since: datetime | None = None  # start of the current failure episode
    last_error: str = ""
    last_failure: datetime | None = None
    last_success: datetime | None = None
    reported: bool = False  # notification-sink-failing emitted for this episode
    retry_at: datetime | None = None  # circuit breaker: rows are deferred unsent until then

    def _firsts(self) -> list[datetime]:
        firsts = list(dict(self.failing).values())
        return [*firsts, self.failed_before] if self.failed_before is not None else firsts

    def oldest(self) -> datetime | None:
        return min(self._firsts(), default=None)

    def episode(self) -> datetime | None:
        """First failure of a notification that has not failed before the latest successful
        delivery. A row that keeps failing while others are delivered (a rejected message) is
        stuck, not an outage: it neither holds an episode open nor masks a later outage."""
        firsts = self._firsts()
        if self.last_success is not None:
            firsts = [at for at in firsts if at >= self.last_success]
        return min(firsts, default=None)

    def is_failing(self, now: datetime) -> bool:
        """Nothing was delivered for SINK_FAILING_AFTER since a notification first failed."""
        start = self.episode()
        return start is not None and now - start >= SINK_FAILING_AFTER

    def deferring(self, now: datetime) -> bool:
        return self.retry_at is not None and now < self.retry_at

    def summary(self, now: datetime) -> dict[str, object]:
        oldest = self.oldest()
        return {"failing": self.is_failing(now), "undelivered_failures": len(self.failing),
                "oldest_failure": oldest.isoformat() if oldest else None,
                "failing_since": self.since.isoformat() if self.since else None,
                "last_error": self.last_error,
                "last_failure": self.last_failure.isoformat() if self.last_failure else None,
                "last_success": self.last_success.isoformat() if self.last_success else None,
                "alerted": self.reported}


def _transient(exc: BaseException) -> bool:
    return isinstance(exc, _TRANSIENT)


def _error_text(exc: BaseException) -> str:
    """Short scrubbed error text; never includes SQL statements or bound parameters."""
    if isinstance(exc, SQLAlchemyError):
        orig = str(getattr(exc, "orig", None) or "").strip()
        detail = orig.splitlines()[0] if orig else "database error"
    else:
        detail = str(exc)
    return registry.scrub(f"{type(exc).__name__}: {detail}")[:300]


def missing_sources(feed: FeedHealth) -> list[str]:
    """Expected syslog source classes with no line since the monitor started."""
    return [name for name in EXPECTED_SOURCES
            if not any(feed.sources[source].lines for source in SOURCE_CLASSES[name]
                       if source in feed.sources)]


def source_coverage(feed: FeedHealth) -> list[dict[str, object]]:
    """Per source class: lines, latest arrival and whether every device should send it."""
    return [{"source": entry.source, "lines": entry.lines,
             "last_received": entry.last_received.isoformat() if entry.last_received else None,
             "expected": entry.source in EXPECTED_SOURCES}
            for entry in feed.source_coverage()]


def removed_sinks(previous: Config, candidate: Config) -> list[str]:
    return [name for name in ("smtp", "siem", "webhook")
            if getattr(previous.notify, name) is not None
            and getattr(candidate.notify, name) is None]


# Settings that decide where a sink delivers; values are never echoed (webhook URLs hold tokens).
_SINK_DESTINATION = {"smtp": ("host", "port", "starttls", "sender", "recipients"),
                     "siem": ("host", "port", "transport", "ca_bundle"),
                     "webhook": ("url",)}
# Device settings that decide which appliance is polled and whose syslog is accepted.
_DEVICE_TARGET = ("nsip", "nitro_port", "spki_pin", "spki_pinning", "ca_bundle", "syslog_sources")


def redirected_sinks(previous: Config, candidate: Config) -> dict[str, list[str]]:
    """Sinks kept by name whose destination changed, with the changed setting names."""
    changed = {}
    for name, keys in _SINK_DESTINATION.items():
        old, new = getattr(previous.notify, name), getattr(candidate.notify, name)
        if old is None or new is None:
            continue
        if fields := [key for key in keys if getattr(old, key) != getattr(new, key)]:
            changed[name] = fields
    return changed


def _allowlist_change(label: str, before: list[str], after: list[str]) -> list[str]:
    """An allowlist suppresses alerts for what it lists; an empty one disables its rules."""
    if before and not after:
        return [f"cleared the {label} allowlist"]
    added = [value for value in after if value not in before]
    if before and added:
        shown = ", ".join(added[:5]) + (f" and {len(added) - 5} more" if len(added) > 5 else "")
        return [f"allowed more {label}s: {shown}"]
    return []


def coverage_reductions(previous: Config, candidate: Config) -> list[str]:
    """Settings changes that make the monitor see or report less, or report elsewhere."""
    changes = []
    kept = {device.name for device in candidate.devices}
    removed = [device.name for device in previous.devices if device.name not in kept]
    if removed:
        changes.append(f"removed device(s) {', '.join(removed)}")
    if previous.syslog.enabled and not candidate.syslog.enabled:
        changes.append("disabled syslog collection")
    if sinks := removed_sinks(previous, candidate):
        changes.append(f"removed notification sink(s) {', '.join(sinks)}")
    before = previous.defaults.intervals.syslog_silence_alert
    after = candidate.defaults.intervals.syslog_silence_alert
    if after > before:
        changes.append(f"raised the syslog silence alert from {before}s to {after}s")
    for name in _SINK_DESTINATION:
        old, new = getattr(previous.notify, name), getattr(candidate.notify, name)
        if (old is not None and new is not None
                and Severity.parse(new.min_severity) > Severity.parse(old.min_severity)):
            changes.append(f"raised the {name} minimum severity from {old.min_severity} "
                           f"to {new.min_severity}")
    changes += [f"changed the {name} sink destination ({', '.join(fields)})"
                for name, fields in redirected_sinks(previous, candidate).items()]
    changes += _allowlist_change("admin network", previous.syslog.admin_networks,
                                 candidate.syslog.admin_networks)
    changes += _allowlist_change("admin user", previous.syslog.admin_users,
                                 candidate.syslog.admin_users)
    if defaults := [key for key in ("nitro_port", "ca_bundle")
                    if getattr(previous.defaults, key) != getattr(candidate.defaults, key)]:
        changes.append(f"changed the device defaults ({', '.join(defaults)})")
    devices = {device.name: device for device in previous.devices}
    for device in candidate.devices:
        old_device = devices.get(device.name)
        if old_device is not None and (fields := [key for key in _DEVICE_TARGET
                                                  if getattr(old_device, key)
                                                  != getattr(device, key)]):
            changes.append(f"changed {device.name} {', '.join(fields)}")
    before = previous.defaults.intervals.config_probe
    after = candidate.defaults.intervals.config_probe
    if after > before:
        changes.append(f"raised the config probe interval from {before}s to {after}s")
    return changes + _fim_reductions(previous, candidate)


def _fim_reductions(previous: Config, candidate: Config) -> list[str]:
    changes = []
    kept = {device.name: device for device in candidate.devices}
    if off := [device.name for device in previous.devices if device.fim.enabled
               and device.name in kept and not kept[device.name].fim.enabled]:
        changes.append(f"disabled file-integrity monitoring on {', '.join(off)}")
    old, new = previous.defaults.fim, candidate.defaults.fim
    for key, label in (("webroot_interval", "web-root walk interval"),
                       ("rehash_interval", "re-hash interval")):
        if getattr(new, key) > getattr(old, key):
            changes.append(f"raised the file-integrity {label} from {getattr(old, key)}s to "
                           f"{getattr(new, key)}s")
    if limits := [key for key in ("max_entries", "max_depth", "walk_seconds", "max_hashes")
                  if getattr(new, key) < getattr(old, key)]:
        changes.append(f"lowered the file-integrity limits ({', '.join(limits)})")
    return changes


def exposure_findings(report: ExposureReport, *, lifecycle: bool = True) -> list[Finding]:
    """Everything the daemon reports for one exposure assessment."""
    stage = from_exposure_lifecycle(report) if lifecycle else None
    return [*from_exposure(report), *from_exposure_attention(report),
            *([stage] if stage else [])]


def lifecycle_state(state: dict[str, Any], report: ExposureReport,
                    at: datetime) -> tuple[bool, dict[str, Any]]:
    """Whether to report the train's lifecycle now (it changed, or LIFECYCLE_REMINDER passed
    since it was last reported), and the state to keep. Daily repeats of a condition that
    is not a compromise would train operators to ignore the channel."""
    current = {"train": report.version.train, "lifecycle": report.lifecycle_status}
    same = all(state.get(key) == value for key, value in current.items())
    try:
        reported = datetime.fromisoformat(state["reported_at"]) if same else None
    except (KeyError, TypeError, ValueError):
        reported = None
    due = reported is None or reported.tzinfo is None or at - reported >= LIFECYCLE_REMINDER
    stamp = at if due else reported
    return due, {**current, "reported_at": stamp.isoformat() if stamp else None}


def exposure_posture(report: ExposureReport, at: datetime) -> dict[str, object]:
    return {"assessed_at": at.isoformat(), "version": str(report.version),
            "train": report.version.train,
            "worst": str(report.worst), "lifecycle": report.lifecycle_status,
            "min_safe_build": str(report.min_safe_build) if report.min_safe_build else None,
            "actionable": [r.advisory.id for r in report.actionable],
            "needs_attention": [r.advisory.id for r in report.needs_attention],
            "warnings": list(report.warnings)}


@dataclass
class Service:
    rt: Runtime
    sinks: list[Sink] | None = None
    database: Database | None = None
    health: dict[str, DeviceHealth] = field(default_factory=dict)
    _stop: asyncio.Event = field(default_factory=asyncio.Event)

    def __post_init__(self) -> None:
        self.paused = False
        self.setup_error = ""
        self._running = False
        self._reload = asyncio.Event()
        self._reload_complete = asyncio.Event()
        self._replacement: Config | None = None
        self._administration: Administration | None = None
        self._resources = ResourceMonitor()
        self.db_error = ""
        self._spool: deque[tuple[Finding, tuple[str, ...]]] = deque(maxlen=SPOOL_LIMIT)
        self._logged: OrderedDict[str, None] = OrderedDict()
        control_state = self.rt.cfg.paths.state_dir / "monitor-control.json"
        if control_state.exists():
            self.paused = bool(json.loads(control_state.read_bytes()).get("paused"))
        self._audit_seen = self._load_audit_seen()
        self._configure()

    def _configure(self) -> None:
        cfg = self.rt.cfg
        self.store = FileSnapshotStore(cfg.paths.state_dir / "configs")
        self.findings_log = FindingsLog(cfg.paths.state_dir / "findings.jsonl")
        self.rules = load_risk_rules()
        self.cve_data = load_cve_data()
        smtp_ref = cfg.notify.smtp.credential if cfg.notify.smtp else None
        smtp_cred = (lambda: self.rt.resolver.resolve(smtp_ref)) if smtp_ref else None
        self.router = Router(self.sinks if self.sinks is not None
                             else build_sinks(cfg.notify, smtp_cred))
        self.health = {d.name: DeviceHealth() for d in cfg.devices}
        self.exposure_health = {d.name: DeviceHealth() for d in cfg.devices}
        self.fim_health = {d.name: DeviceHealth() for d in cfg.devices if d.fim.enabled}
        self.fim_monitors = {d.name: FimMonitor(d.name, self.store, cfg.defaults.fim)
                             for d in cfg.devices if d.fim.enabled}
        self.db = self.database or Database(cfg.database_url)
        if hasattr(self, "pipeline"):  # a reload: keep when ns.log last arrived
            self._remember_audit_feed(force=True)
        self.pipeline = SyslogPipeline(cfg, self.db, self.targets)
        self.started_at = datetime.now(UTC)
        self._quiet_feeds: set[str] = set()
        self.sink_health = {sink.name: SinkHealth() for sink in self.router.sinks}
        self._sink_backlog_read = False  # failures before this (re)start: see check_sinks
        self.exposure_posture: dict[str, dict[str, object]] = {}

    def _coverage_finding(self, action: str, changes: list[str]) -> Finding:
        actor = _ACTOR.get()
        at = datetime.now(UTC)
        return Finding(
            dedup_key=f"monitor-coverage-reduced|{action}|{at.isoformat()}",
            rule_id="monitor-coverage-reduced",
            title="Monitoring coverage reduced by an administrator",
            severity=Severity.HIGH, category="health", device=None,
            summary=f"{actor or 'An unidentified local administrator'}: {'; '.join(changes)}",
            observed_at=at, evidence={"actor": actor, "action": action, "changes": changes})

    async def pause_monitoring(self) -> dict[str, object]:
        if not self.paused:
            await self.record(self._coverage_finding("monitor.pause",
                                                     ["paused all appliance monitoring"]))
        self.paused = True
        await asyncio.to_thread(atomic_write, self.cfg.paths.state_dir / "monitor-control.json",
                                b'{"paused":true}')
        for device in self.cfg.devices:
            async with self.rt.device_lock(device.name):
                pass
        return {"paused": True}

    async def resume_monitoring(self) -> dict[str, object]:
        was_paused = self.paused
        self.paused = False
        await asyncio.to_thread(atomic_write, self.cfg.paths.state_dir / "monitor-control.json",
                                b'{"paused":false}')
        if was_paused:
            actor = _ACTOR.get()
            at = datetime.now(UTC)
            await self.record(Finding(
                f"monitor-resumed|{at.isoformat()}", "monitor-resumed",
                "Monitoring resumed by an administrator", Severity.INFO, "health", None,
                f"{actor or 'An unidentified local administrator'}: resumed appliance monitoring",
                observed_at=at, evidence={"actor": actor, "action": "monitor.resume"}))
        if self.setup_error and self._running:
            await self._request_reload(self.rt.cfg)
        return {"paused": False, "setup_error": self.setup_error}

    async def apply_settings(self) -> dict[str, object]:
        candidate = await asyncio.to_thread(load_config, self.rt.config_path)
        if candidate.paths != self.cfg.paths or candidate.admin_group != self.cfg.admin_group:
            raise ControlError("Host-managed paths changed; a host migration is required", 409)
        previous = self.cfg
        if reductions := coverage_reductions(previous, candidate):
            # Before activation: queued rows resolve the sink by name at delivery time, so a
            # removed or redirected sink gets this alert now, through its current settings.
            finding = self._coverage_finding("settings.apply", reductions)
            leaving = {*removed_sinks(previous, candidate), *redirected_sinks(previous, candidate)}
            await self._send_now(finding, leaving)
            await self.record(finding, exclude=leaving)
        dynamic = previous.model_copy(update={
            "retention": candidate.retention, "web": candidate.web,
            "max_credential_age_days": candidate.max_credential_age_days,
            "notify": previous.notify.model_copy(update={
                "daily_digest_hour_utc": candidate.notify.daily_digest_hour_utc}),
            "defaults": previous.defaults.model_copy(update={
                "intervals": previous.defaults.intervals.model_copy(update={
                    "syslog_silence_alert": candidate.defaults.intervals.syslog_silence_alert})}),
        })
        workers_reloaded = bool(self.setup_error) or candidate != dynamic
        if workers_reloaded:
            await self._request_reload(candidate)
        else:
            self.rt.cfg = candidate
            self.pipeline.cfg = candidate
        web_changed = candidate.web != previous.web
        database_changed = candidate.database_url != previous.database_url
        if candidate != previous:
            message = json.dumps({
                "at": datetime.now(UTC).isoformat(),
                "config": candidate.model_dump(mode="json"),
            }).encode()
            await asyncio.to_thread(
                atomic_write, self.cfg.paths.state_dir / "web-reload.json", message,
            )
        return {
            "applied": True, "paused": self.paused, "setup_error": self.setup_error,
            "web_reload": web_changed or database_changed,
            "workers_reloaded": workers_reloaded,
        }

    async def _request_reload(self, candidate: Config) -> None:
        if not self._running:
            self.rt.cfg = candidate
            self._configure()
            return
        self._reload_complete.clear()
        self._replacement = candidate
        self._reload.set()
        await asyncio.wait_for(self._reload_complete.wait(), timeout=120)

    async def administration_status(self) -> dict[str, object]:
        return {"administration": "available", "paused": self.paused,
                "setup_error": self.setup_error, "status": await asyncio.to_thread(self.status)}

    @property
    def cfg(self) -> Config:
        return self.rt.cfg

    async def _dispatch_control(self, request: ControlRequest) -> dict[str, Any]:
        """Run an administration request with its actor visible to the daemon callbacks."""
        assert self._administration is not None
        token = _ACTOR.set(request.actor)
        try:
            return await self._administration.execute(request)
        finally:
            _ACTOR.reset(token)

    def targets(self, finding: Finding, exclude: Collection[str] = ()) -> list[str]:
        return [sink.name for sink in self.router.sinks if sink.name not in exclude
                and (finding.severity >= sink.min_severity or finding.category == "digest")]

    async def _send_now(self, f: Finding, names: Collection[str]) -> set[str]:
        """Send ``f`` to the named sinks (within their min_severity) without the outbox;
        returns the sinks that accepted it."""
        wanted = set(self.targets(f)) & set(names)

        async def send(sink: Sink) -> str | None:
            try:
                async with asyncio.timeout(DIRECT_SEND_TIMEOUT):
                    await sink.send(f)
            except Exception as exc:  # noqa: BLE001 - reported, the caller falls back
                log.warning("%s: %s not sent: %s", sink.name, f.rule_id, _error_text(exc))
                return None
            return sink.name

        sent = await asyncio.gather(*(send(sink) for sink in self.router.sinks
                                      if sink.name in wanted))
        return {name for name in sent if name is not None}

    async def emit(self, f: Finding, *, exclude: Collection[str] = ()) -> None:
        """Write the finding to the local log first, then store and queue it. Database errors
        propagate so callers with their own retry (the config poller) keep the finding."""
        identity = f"{f.dedup_key}\0{f.observed_at.isoformat()}"
        if identity not in self._logged:
            log.warning("finding [%s] %s: %s", f.severity, f.rule_id, f.summary)
            try:
                await asyncio.to_thread(self.findings_log.append, f)
            except OSError as exc:
                log.error("local findings log not written: %s", exc)
            else:
                self._logged[identity] = None
                if len(self._logged) > 4 * SPOOL_LIMIT:
                    self._logged.popitem(last=False)
        await asyncio.to_thread(self.db.save_finding, f, self.targets(f, exclude))

    async def record(self, f: Finding, *, exclude: Collection[str] = ()) -> None:
        """emit() for daemon-generated findings: during a database outage the finding stays
        in the local log and is held in memory for the outbox instead of stopping the caller."""
        try:
            await self.emit(f, exclude=exclude)
        except SQLAlchemyError as exc:
            if _transient(exc):
                self._database_failed(exc)
                self._spool.append((f, tuple(exclude)))
            else:
                log.error("finding %s could not be stored: %s", f.rule_id, _error_text(exc))

    def _database_failed(self, exc: SQLAlchemyError) -> None:
        error = _error_text(exc)
        if error != self.db_error:
            log.error("database unavailable: %s", error)
        self.db_error = error

    async def _flush_spool(self) -> None:
        while self._spool:
            item = self._spool[0]
            finding, exclude = item
            try:
                await asyncio.to_thread(self.db.save_finding, finding,
                                        self.targets(finding, exclude))
            except SQLAlchemyError as exc:
                if _transient(exc):
                    raise
                log.error("finding %s could not be stored: %s", finding.rule_id,
                          _error_text(exc))
            if self._spool and self._spool[0] is item:
                self._spool.popleft()

    async def deliver_pending(self, now: datetime | None = None) -> int:
        """One outbox pass. Each sink has its own SINK_CONCURRENCY slots and a circuit
        breaker: after a failed send, its other rows are deferred unsent for SINK_RETRY_AFTER,
        so a sink that drops traffic costs one timeout per pass, not one per row. Within a
        sink, higher severities go first."""
        await self._flush_spool()
        await self.check_sinks(now)  # also before sending: a pass can take minutes
        deliveries = await asyncio.to_thread(self.db.pending, now)
        slots = {name: asyncio.Semaphore(SINK_CONCURRENCY)
                 for name in {delivery.sink for delivery in deliveries}}
        sinks = {sink.name: sink for sink in self.router.sinks}

        async def deliver(delivery: PendingDelivery) -> None:
            async with slots[delivery.sink]:
                at = now or datetime.now(UTC)
                sink = sinks.get(delivery.sink)
                health = self.sink_health.get(delivery.sink)
                if sink is not None and health is not None and health.deferring(at):
                    deferred = (f"deferred unsent: the {delivery.sink} sink failed at "
                                f"{health.last_failure or at:%Y-%m-%d %H:%M:%S} UTC")
                    self._track_delivery(delivery, deferred, at, attempted=False)
                    await asyncio.to_thread(self.db.delivery_result, delivery, deferred, now)
                    return
                error = None
                try:
                    if sink is None:
                        raise ValueError(f"notification sink {delivery.sink} "
                                         "is no longer configured")
                    async with asyncio.timeout(SEND_TIMEOUT):
                        await sink.send(delivery.finding)
                except Exception as exc:  # noqa: BLE001
                    error = f"{type(exc).__name__}: {exc}"
                    log.warning("%s: queued delivery failed: %s", delivery.sink, error)
                if sink is not None:
                    self._track_delivery(delivery, error, now or datetime.now(UTC))
                await asyncio.to_thread(self.db.delivery_result, delivery, error, now)

        ordered = sorted(deliveries, key=lambda delivery: delivery.finding.severity,
                         reverse=True)  # stable: oldest first within a severity
        results = await asyncio.gather(*(deliver(delivery) for delivery in ordered),
                                       return_exceptions=True)
        failure = next((result for result in results if isinstance(result, BaseException)),
                       None)
        if failure is not None:
            raise failure
        self.db_error = ""
        await self.check_sinks(now)
        return len(deliveries)

    def _track_delivery(self, delivery: PendingDelivery, error: str | None,
                        now: datetime, *, attempted: bool = True) -> None:
        health = self.sink_health.setdefault(delivery.sink, SinkHealth())
        if error is None:
            health.failing.pop(delivery.id, None)
            health.last_success = now
            health.retry_at = None
            health.failed_before = None  # older rows that fail again re-enter `failing`
        else:
            # A row that failed before a restart or reload counts from when it was queued.
            earlier = delivery.queued_at if delivery.attempts else None
            first = health.failing.setdefault(delivery.id, earlier or now)
            if attempted:
                health.last_error = registry.scrub(error)[:300]
                health.last_failure = now
                if health.last_success is None or first >= health.last_success:
                    health.retry_at = now + SINK_RETRY_AFTER  # not a known stuck row

    async def check_sinks(self, now: datetime | None = None) -> None:
        """Report a sink that delivered nothing for SINK_FAILING_AFTER since a notification
        first failed, through the other sinks (once per failure episode), and its recovery.
        An episode ends at the next successful delivery.

        Failures are tracked in memory; on the first check after a start or reload, the
        outbox backlog adds the ones from before it, so a restart does not reset the clock."""
        at = now or datetime.now(UTC)
        backlog: dict[str, SinkBacklog] | None = None
        if not self._sink_backlog_read:
            backlog = await asyncio.to_thread(self.db.sink_backlog, at)
            for name, health in self.sink_health.items():
                if (entry := backlog.get(name)) is not None:
                    health.failed_before = entry.failing_since
                    health.last_success = health.last_success or entry.last_delivered
                    health.last_error = health.last_error or registry.scrub(
                        entry.last_error or "")[:300]
            self._sink_backlog_read = True
        for name, health in list(self.sink_health.items()):
            start = health.episode()
            if health.since is not None and start != health.since:
                if health.reported:
                    await self.record(Finding(
                        f"notification-sink-recovered|{name}|{health.since.isoformat()}",
                        "notification-sink-recovered", "Notification sink recovered",
                        Severity.INFO, "health", None,
                        f"The {name} sink is delivering again (failing since "
                        f"{health.since:%Y-%m-%d %H:%M} UTC)",
                        evidence={"sink": name, "failing_since": health.since.isoformat()}))
                health.since, health.reported = None, False
            if start is None:
                continue
            health.since = start
            if health.reported or not health.is_failing(at):
                continue
            health.reported = True
            oldest = health.oldest() or start
            if backlog is None:
                backlog = await asyncio.to_thread(self.db.sink_backlog, at)
            entry = backlog.get(name)
            undelivered = entry.count if entry is not None else len(health.failing)
            alert = Finding(
                dedup_key=f"notification-sink-failing|{name}|{start.isoformat()}",
                rule_id="notification-sink-failing", title="Notification sink is failing",
                severity=Severity.HIGH, category="health", device=None,
                summary=(f"{undelivered} notification(s) for the {name} sink are "
                         f"undelivered, failing since {start:%Y-%m-%d %H:%M} UTC: "
                         f"{health.last_error}"),
                evidence={"sink": name, "failing_since": start.isoformat(),
                          "oldest_failure": oldest.isoformat(), "undelivered": undelivered,
                          "undelivered_failures": len(health.failing),
                          "max_attempts": entry.max_attempts if entry is not None else None,
                          "last_error": health.last_error})
            # Straight to the working sinks: their queues may hold older rows. Sinks that
            # do not take it now get it through the outbox.
            working = [other for other, state in self.sink_health.items()
                       if other != name and not state.deferring(at)]
            sent = await self._send_now(alert, working)
            await self.record(alert, exclude={name, *sent})

    async def notification_loop(self) -> None:
        delay = 5.0
        while not self._stop.is_set():
            try:
                count = await self.deliver_pending()
                wait, delay = (0.1 if count else 5.0), 5.0
            except SQLAlchemyError as exc:  # outbox unavailable: queued rows stay pending
                self._database_failed(exc)
                wait, delay = delay, min(delay * 2, 60.0)
            if not await self._sleep(wait):
                break

    async def syslog_loop(self) -> None:
        backoff = 0.0
        while not self._stop.is_set():
            processed = 0
            transient = False
            for device in self.cfg.devices:
                if self.paused:
                    break
                try:
                    processed += await asyncio.to_thread(self.pipeline.poll, device)
                except Exception as exc:  # noqa: BLE001 - one feed must not stop the others
                    # The pending batch is kept; repeated non-transient failures quarantine
                    # it inside the pipeline (with its own CRITICAL finding).
                    outage = isinstance(exc, SQLAlchemyError) and _transient(exc)
                    transient = transient or outage
                    await self._syslog_error(device, exc, outage=outage)
            await self.check_syslog_health()
            await asyncio.to_thread(self._remember_audit_feed)
            backoff = min(max(backoff * 2, self.cfg.syslog.poll_seconds), 60) if transient else 0
            wait = backoff or (0.1 if processed else self.cfg.syslog.poll_seconds)
            if not await self._sleep(wait):
                break

    async def _syslog_error(self, device: Device, exc: Exception, *, outage: bool) -> None:
        if outage and isinstance(exc, SQLAlchemyError):
            self._database_failed(exc)
        elif not isinstance(exc, OSError | ValueError | SQLAlchemyError):
            log.error("%s: unexpected syslog pipeline error", device.name, exc_info=exc)
        feed = self.pipeline.health[device.name]
        error = _error_text(exc)
        if error != feed.last_error:
            await self.record(Finding(
                f"syslog-error|{device.name}|{error}", "syslog-ingestion-error",
                "Syslog ingestion is blocked", Severity.HIGH, "health", device.name,
                f"{device.name}: {error}"))
        feed.last_error = error

    async def check_syslog_health(self, now: datetime | None = None) -> None:
        at = now or datetime.now(UTC)
        threshold = timedelta(seconds=self.cfg.defaults.intervals.syslog_silence_alert)
        for device in self.cfg.devices:
            feed = self.pipeline.health[device.name]
            quiet = at - (feed.last_received or self.started_at) >= threshold
            if quiet and self.health[device.name].last_ok is not None:
                if device.name not in self._quiet_feeds:
                    await self.record(Finding(
                        f"syslog-silent|{device.name}", "syslog-silent", "Syslog feed is silent",
                        Severity.HIGH, "health", device.name,
                        f"{device.name}: NITRO is reachable but no recent syslog was received",
                        evidence={"last_received": feed.last_received.isoformat()
                                  if feed.last_received else None}))
                    self._quiet_feeds.add(device.name)
            elif not quiet:
                self._quiet_feeds.discard(device.name)

    def status(self, now: datetime | None = None) -> dict[str, object]:
        now = now or datetime.now(UTC)
        warnings = []
        if self.setup_error:
            warnings.append(self.setup_error)
        if self.paused:
            warnings.append("Monitoring is paused by an administrator")
        if not self.router.sinks:
            warnings.append("No notification sinks configured")
        if self.cfg.syslog.enabled and self.pipeline.engine.disabled:
            warnings.append("Some detection rules are disabled; configure syslog allowlists")
        if self.db_error:
            warnings.append(f"Database unavailable ({self.db_error}); findings are kept in the "
                            "local findings log and retried")
        sink_health = dict(self.sink_health)
        for name, sink in sink_health.items():
            oldest = sink.oldest()
            if oldest is not None and sink.is_failing(now):
                warnings.append(f"Notification sink {name} has undelivered findings since "
                                f"{oldest:%Y-%m-%d %H:%M} UTC: {sink.last_error}")
        # This runs in a worker thread while pipeline.poll adds sources in another: copy
        # each sources dict (atomic) before iterating it.
        feeds = {name: replace(feed, sources=dict(feed.sources))
                 for name, feed in self.pipeline.health.items()}
        for name, feed in feeds.items():
            if feed.quarantined:
                warnings.append(f"{name}: {feed.quarantined} syslog batch(es) could not be "
                                f"indexed and were quarantined (latest {feed.last_quarantined})")
        unhealthy = any(health.failures or health.last_ok is None
                        for health in self.health.values())
        unhealthy = unhealthy or bool(self._quiet_feeds) or any(
            feed.last_error for feed in feeds.values())
        unhealthy = unhealthy or any(health.failures for health in self.exposure_health.values())
        fim = {name: monitor.status for name, monitor in self.fim_monitors.items()}
        for name, summary in fim.items():
            if summary.get("coverage_gaps"):
                warnings.append(f"{name}: file-integrity coverage unknown for "
                                f"{len(summary['coverage_gaps'])} path(s)")
        unhealthy = unhealthy or any(health.failures or health.last_ok is None
                                     for health in self.fim_health.values())
        resources = self._resources.snapshot(self.cfg.paths.state_dir, self.cfg.paths.log_dir)
        disk = resources["filesystems"].get("state", {})
        syslog = self.cfg.syslog.enabled
        return {"state": ("paused" if self.paused else
                  "idle" if not self.cfg.devices and not self.setup_error else
                  "degraded" if unhealthy or warnings else "healthy"),
            "paused": self.paused, "setup_error": self.setup_error,
                "updated_at": now.isoformat(), "started_at": self.started_at.isoformat(),
                "pid": os.getpid(), "warnings": warnings,
                "devices": {name: {"nitro": asdict(health),
                                   "syslog": {**asdict(feed), "silent": name in self._quiet_feeds,
                                              "coverage": feed.coverage(),
                                              "source_coverage": source_coverage(feed),
                                              "missing_sources": (missing_sources(feed)
                                                                  if syslog else [])},
                                   "exposure": {**asdict(self.exposure_health[name]),
                                                "posture": self.exposure_posture.get(name)},
                                   "fim": ({"enabled": True, **asdict(self.fim_health[name]),
                                            **fim[name]} if name in fim
                                           else {"enabled": False})}
                            for name, health in self.health.items()
                            for feed in [feeds[name]]},
                "advisory_data": {"data_version": self.cve_data.data_version.isoformat(),
                                  "age_days": self.cve_data.age_days(),
                                  "stale": self.cve_data.is_stale(),
                                  "stale_after_days": STALE_AFTER_DAYS},
                "notifications": {name: sink.summary(now)
                                  for name, sink in sink_health.items()},
                "disabled_rules": self.pipeline.engine.disabled,
                "syslog_enabled": self.cfg.syslog.enabled,
                "disk_free_bytes": disk.get("free_bytes"),
                "disk_total_bytes": disk.get("total_bytes"), "resources": resources,
                "archive_heads": {device.name: self.pipeline.archive.head(device.name)
                                  for device in self.cfg.devices}}

    async def status_loop(self) -> None:
        while not self._stop.is_set():
            status = await asyncio.to_thread(self.status)
            data = json.dumps(registry.scrub_value(status), default=str, indent=2).encode()
            await asyncio.to_thread(atomic_write, self.cfg.paths.state_dir / "status.json", data)
            if not await self._sleep(10):
                break

    # ---- loops --------------------------------------------------------------------------

    def _nslog_seen(self, device: str) -> datetime | None:
        """When an ns.log line from ``device`` last arrived, also before a reload or restart."""
        feed = self.pipeline.health.get(device)
        audit = feed.sources.get("nslog") if feed else None
        stamps = [at for at in (audit.last_received if audit else None,
                                self._audit_seen.get(device)) if at is not None]
        return max(stamps, default=None)

    def _load_audit_seen(self) -> dict[str, datetime]:
        path = self.cfg.paths.state_dir / "audit-feed.json"
        try:
            document = json.loads(path.read_bytes())
            seen = {str(name): datetime.fromisoformat(stamp) for name, stamp in document.items()}
        except FileNotFoundError:
            return {}
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            log.warning("ignoring unreadable %s: %s", path.name, type(exc).__name__)
            return {}
        return {name: at for name, at in seen.items() if at.tzinfo is not None}

    def _remember_audit_feed(self, *, force: bool = False) -> None:
        """Persist when ns.log last arrived per device (at most every minute unless forced).
        Without it, a reload or restart after ns.log forwarding was cut would read as 'never
        observed' and stop the audit-feed-unavailable escalation for good."""
        seen = {device.name: at for device in self.cfg.devices
                if (at := self._nslog_seen(device.name)) is not None}
        step = timedelta(0) if force else AUDIT_FRESH_FOR / 2
        if seen == self._audit_seen or not any(
                name not in self._audit_seen or at - self._audit_seen[name] >= step
                for name, at in seen.items()):
            return
        self._audit_seen = seen
        try:
            atomic_write(self.cfg.paths.state_dir / "audit-feed.json", json.dumps(
                {name: at.isoformat() for name, at in seen.items()}).encode())
        except OSError as exc:
            log.error("audit feed state not written: %s", exc)

    def audit_status(self, device: str,
                     now: datetime | None = None) -> tuple[AuditStatus | None, datetime | None]:
        """Whether the ns.log audit trail can attribute a config change on ``device``, and
        when an ns.log line last arrived. (None, None) when ns.log has never been received
        from the device: the feed's normal state is unknown, so nothing is escalated."""
        if not self.cfg.syslog.enabled:
            return AuditStatus.DISABLED, None
        feed = self.pipeline.health.get(device)
        seen = self._nslog_seen(device)
        if feed is None or seen is None:
            return None, None
        if feed.last_error or (now or datetime.now(UTC)) - seen > AUDIT_FRESH_FOR:
            return AuditStatus.UNAVAILABLE, seen
        return AuditStatus.AVAILABLE, seen

    def attribution(self, device: str, since: datetime) -> list[str] | None:
        """ConfigPoller's AttributionSource. The poller asks only while config_audit_status
        reports the audit feed available."""
        now = datetime.now(UTC)
        return self.db.audit_since(device, max(since, now - timedelta(minutes=5)))

    async def config_audit_status(self, device: str, client: NitroClient
                                  ) -> tuple[AuditStatus | None, datetime | None]:
        """ConfigPoller's AuditStatusSource: audit_status, except that an unavailable feed on
        an HA secondary is not escalated, since HA-synced changes carry no audit trail there."""
        status, since = self.audit_status(device)
        if (status is AuditStatus.UNAVAILABLE and self.cfg.pair_of(device)
                and await self._ha_secondary(device, client)):
            return None, None
        return status, since

    async def _ha_secondary(self, device: str, client: NitroClient) -> bool:
        """Whether NITRO (read-only `show ha node`) reports this node as the HA secondary.
        The role is `hacurmasterstate` (`state` is node health). Any failure counts as
        primary, so the change is escalated and still reported."""
        try:
            nodes = await client.ha_nodes()
        except Exception as exc:  # noqa: BLE001 - e.g. CredentialBlocked on a re-login
            log.info("%s: HA role unknown (%s); treating the node as primary", device,
                     type(exc).__name__)
            return False
        local = next((node for node in nodes if str(node.get("id", "")) == "0"), {})
        role = str(local.get("hacurmasterstate") or "").replace(" ", "").lower()
        return role in {"secondary", "staysecondary"}

    async def check_ha(self, now: datetime | None = None) -> None:
        if self.paused:
            return
        at = now or datetime.now(UTC)
        for pair in self.cfg.ha_pairs:
            if any(self.health[name].last_ok is None or self.health[name].failures
                   for name in pair.nodes):
                continue
            first = self.store.latest(pair.nodes[0], "running")
            second = self.store.latest(pair.nodes[1], "running")
            if first is None or second is None:
                continue
            diff = await asyncio.to_thread(
                diff_configs, self.store.content(first.sha256), self.store.content(second.sha256),
                self.rules, for_peer_compare=True)
            key = "ha-" + pair.name
            state = self.store.get_state(key)
            if diff.empty:
                if state:
                    await asyncio.to_thread(self.store.set_state, key, {})
                continue
            identity = hashlib.sha256(diff.render().encode()).hexdigest()
            if state.get("identity") != identity:
                state = {"identity": identity, "since": at.isoformat()}
            elif (not state.get("reported") and at - datetime.fromisoformat(state["since"])
                  >= timedelta(seconds=pair.sync_grace_seconds)):
                finding = from_config_diff(pair.name, diff, kind="peer", attribution=None,
                                           snapshot_id=identity[:12])
                await self.record(finding)
                state["reported"] = True
            await asyncio.to_thread(self.store.set_state, key, state)

    async def ha_loop(self) -> None:
        while not self._stop.is_set():
            await self.check_ha()
            if not await self._sleep(self.cfg.defaults.intervals.config_probe):
                break

    async def _sleep(self, seconds: float) -> bool:
        """Sleep unless stopping; returns False when the service is shutting down."""
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._stop.wait(), timeout=seconds)
        return not self._stop.is_set()

    async def config_loop(self, d: Device) -> None:
        poller = ConfigPoller(d.name, self.store, self.rules,
                              full_refresh=timedelta(seconds=self.cfg.defaults.intervals
                                                     .config_full),
                              attribution=self.attribution,
                              audit_status=self.config_audit_status)
        interval = self.cfg.defaults.intervals.config_probe
        await self._sleep(random.uniform(0, min(interval, 30)))  # noqa: S311 - jitter only
        # One long-lived NITRO session per device: logging in on every poll would flood the
        # audit log. The client re-logs in by itself when the session expires.
        client: NitroClient | None = None
        try:
            while not self._stop.is_set():
                try:
                    async with self.rt.device_lock(d.name):
                        if self.paused:
                            await _close_quietly(client)
                            client = None
                        else:
                            self.health[d.name].attempts += 1
                            self.health[d.name].last_attempt = datetime.now(UTC)
                            if client is None:
                                client = self.rt.nitro_client(d)
                            for f in await poller.tick(client):
                                await self.emit(f)
                            await asyncio.to_thread(poller.acknowledge)
                            self._ok(d)
                except (OperationalError, InterfaceError, PoolTimeoutError) as exc:
                    # Database outage, not an appliance failure: the poller keeps its findings
                    # pending and re-emits them on the next tick.
                    self._database_failed(exc)
                except Exception as exc:  # noqa: BLE001 - classified below; loop must survive
                    await _close_quietly(client)
                    client = None
                    await self._handle_poll_error(d, exc)
                if not await self._sleep(interval):
                    break
        finally:
            await _close_quietly(client)

    async def fim_loop(self, d: Device) -> None:
        """File-integrity monitoring (collect/fim.py) for one opted-in device: Tier A on every
        config probe, Tier B web-root walks when due. Like config_loop it keeps one long-lived
        NITRO session (here for the FIM account) and holds the device lock while it uses it,
        so pause_monitoring() waits for an in-flight walk."""
        monitor = self.fim_monitors[d.name]
        fim = self.cfg.defaults.fim
        interval = self.cfg.defaults.intervals.config_probe
        await self._sleep(random.uniform(0, min(interval, 30)))  # noqa: S311 - jitter only
        client: NitroClient | None = None
        try:
            while not self._stop.is_set():
                try:
                    async with self.rt.device_lock(d.name):
                        if self.paused:
                            await _close_quietly(client)
                            client = None
                        else:
                            health = self.fim_health[d.name]
                            health.attempts += 1
                            health.last_attempt = datetime.now(UTC)
                            if client is None:
                                client = self.rt.nitro_client(d, credential=self.cfg.fim_ref(d))
                            # Bounded so a slow appliance cannot hold the device lock. Tier B
                            # has its own shorter timeout inside tick(); this one covers Tier A.
                            async with asyncio.timeout(3 * fim.walk_seconds + 300):
                                findings = await monitor.tick(client)
                            for f in findings:
                                await self.emit(f)
                            await asyncio.to_thread(monitor.acknowledge)
                            self._fim_ok(d)
                except (OperationalError, InterfaceError, PoolTimeoutError) as exc:
                    self._database_failed(exc)  # findings stay pending in the FIM state
                except Exception as exc:  # noqa: BLE001 - classified below; loop must survive
                    await _close_quietly(client)
                    client = None
                    await self._fim_failed(d, exc)
                if not await self._sleep(interval):
                    break
        finally:
            await _close_quietly(client)

    def _fim_ok(self, d: Device) -> None:
        health = self.fim_health[d.name]
        health.last_ok = datetime.now(UTC)
        health.successes += 1
        health.failures = 0
        health.last_error = ""
        health.error_type = ""
        health.reported = False

    async def _fim_failed(self, d: Device, exc: Exception) -> None:
        """A FIM pass that failed as a whole (not a refused path: that is a coverage gap).
        A rejected or missing FIM credential is reported at once; other errors after
        UNREACHABLE_AFTER consecutive failures."""
        health = self.fim_health[d.name]
        health.failures += 1
        health.total_failures += 1
        health.last_failure = datetime.now(UTC)
        health.error_type = type(exc).__name__
        blocked = isinstance(exc, CredentialError | AuthRejected | PinMismatch)
        if isinstance(exc, httpx.TransportError):
            error = f"{type(exc).__name__}: {appliance_failure(exc)}"
        elif isinstance(exc, NitroError | OSError | CredentialError | TimeoutError | PinMismatch):
            error = f"{type(exc).__name__}: {exc}"
        else:
            log.error("%s: unexpected error in file-integrity loop", d.name, exc_info=exc)
            error = "internal error (see journal)"
        health.last_error = registry.scrub(error)
        log.warning("%s: file-integrity pass failed (%d): %s", d.name, health.failures, error)
        if (blocked or health.failures >= UNREACHABLE_AFTER) and not health.reported:
            health.reported = True
            await self.record(Finding(
                dedup_key=f"fim-unavailable|{d.name}|{error[:60]}", rule_id="fim-unavailable",
                title="File-integrity monitoring is not running for this device",
                severity=Severity.HIGH if blocked else Severity.MEDIUM, category="health",
                device=d.name,
                summary=(f"{d.name}: {health.last_error}. Boot hooks, crontabs, SSH keys and "
                         "web roots are not being checked."),
                evidence={"failures": health.failures, "account": self.cfg.fim_ref(d),
                          "last_ok": health.last_ok.isoformat() if health.last_ok else None}))

    async def _handle_poll_error(self, d: Device, exc: Exception) -> None:
        self.health[d.name].error_type = type(exc).__name__
        if isinstance(exc, CredentialBlocked | AuthRejected):
            await self._fail(d, str(exc), severity=Severity.HIGH, now=True)
        elif isinstance(exc, PinMismatch):
            await self._fail(d, f"TLS key changed: {exc}", severity=Severity.CRITICAL,
                             now=True)
        elif isinstance(exc, httpx.TransportError):
            await self._fail(d, f"{type(exc).__name__}: {appliance_failure(exc)}")
        elif isinstance(exc, NitroError | OSError | CredentialError | TimeoutError):
            await self._fail(d, f"{type(exc).__name__}: {exc}")
        else:
            log.error("%s: unexpected error in config loop", d.name, exc_info=exc)
            await self._fail(d, "internal error (see journal)")

    def _ok(self, d: Device) -> None:
        h = self.health[d.name]
        if h.reported:
            log.info("%s: reachable again", d.name)
        h.last_ok = datetime.now(UTC)
        h.successes += 1
        h.failures = 0
        h.last_error = ""
        h.error_type = ""
        h.reported = False

    async def _fail(self, d: Device, error: str, *, severity: Severity = Severity.MEDIUM,
                    now: bool = False) -> None:
        h = self.health[d.name]
        h.failures += 1
        h.total_failures += 1
        h.last_failure = datetime.now(UTC)
        h.last_error = registry.scrub(error)
        log.warning("%s: poll failed (%d): %s", d.name, h.failures, error)
        if (now or h.failures >= UNREACHABLE_AFTER) and not h.reported:
            h.reported = True
            await self.record(Finding(
                dedup_key=f"health|{d.name}|{error[:60]}",
                rule_id="health-device-unreachable" if not now else "health-device-blocked",
                title="netrescale cannot monitor this device",
                severity=severity, category="health", device=d.name,
                summary=f"{d.name}: {error}",
                evidence={"failures": h.failures,
                          "last_ok": h.last_ok.isoformat() if h.last_ok else None}))

    async def exposure_loop(self) -> None:
        await self._sleep(60)
        while not self._stop.is_set():
            # Once per run (daily); the outbox repeats it at most every 6 hours.
            stale = None if self.paused else from_stale_cve_data(self.cve_data)
            if stale is not None:
                await self.record(stale)
            for d in self.cfg.devices:
                health = self.exposure_health[d.name]
                try:
                    async with self.rt.device_lock(d.name):
                        if self.paused:
                            continue
                        health.attempts += 1
                        health.last_attempt = datetime.now(UTC)
                        async with self.rt.nitro_client(d) as c:
                            v = parse_version(await c.version_string(), d.firmware_variant)
                            report = assess(d.name, v, await detect_features(c), self.cve_data)
                        due, lifecycle = await self._lifecycle_due(report)
                        for f in exposure_findings(report, lifecycle=due):
                            await self.record(f)
                        await asyncio.to_thread(self.store.set_state,
                                                f"_exposure-{d.name}", lifecycle)
                        health.last_ok = datetime.now(UTC)
                        self.exposure_posture[d.name] = exposure_posture(report, health.last_ok)
                        health.successes += 1
                        health.failures = 0
                        health.last_error = ""
                        health.error_type = ""
                except (NitroError, OSError, CredentialError, ValueError,
                    httpx.TransportError, SQLAlchemyError) as exc:
                    health.failures += 1
                    health.total_failures += 1
                    health.last_failure = datetime.now(UTC)
                    health.error_type = type(exc).__name__
                    health.last_error = (registry.scrub(str(appliance_failure(exc)))
                                         if isinstance(exc, httpx.TransportError) else
                                         _error_text(exc) if isinstance(exc, SQLAlchemyError)
                                         else registry.scrub(str(exc)))
                    log.info("%s: exposure check skipped: %s", d.name, exc)
            if not await self._sleep(24 * 3600):
                break

    async def _lifecycle_due(self, report: ExposureReport) -> tuple[bool, dict[str, Any]]:
        try:  # "_" cannot start a device name, so this key never collides with poller state
            state = await asyncio.to_thread(self.store.get_state, f"_exposure-{report.device}")
        except (OSError, ValueError) as exc:
            log.warning("%s: lifecycle state unreadable: %s", report.device, exc)
            state = {}
        return lifecycle_state(state if isinstance(state, dict) else {}, report,
                               datetime.now(UTC))

    async def housekeeping_loop(self) -> None:
        last_digest: datetime | None = None
        last_retention: datetime | None = None
        while not self._stop.is_set():
            now = datetime.now(UTC)
            if last_retention is None or last_retention.date() != now.date():
                try:
                    await asyncio.to_thread(self.db.prune, self.cfg.retention.events_days,
                                            self.cfg.retention.findings_days, now)
                    await asyncio.to_thread(self.pipeline.prune, now)
                    last_retention = now
                except SQLAlchemyError as exc:  # retried on the next pass
                    self._database_failed(exc)
            try:
                vault = self.rt.provider.vault
                for m in stale_entries(vault, self.cfg.max_credential_age_days):
                    await self.record(Finding(
                        dedup_key=f"cred-age|{m.name}|{m.updated.date()}",
                        rule_id="credential-age", title="Credential due for rotation",
                        severity=Severity.LOW, category="health", device=None,
                        summary=f"local:{m.name} last changed {m.updated:%Y-%m-%d}; rotate "
                                f"with `netrescale cred rotate {m.name}`"))
            except CredentialError as exc:
                log.error("vault check failed: %s", exc)
            hour = self.cfg.notify.daily_digest_hour_utc
            if now.hour == hour and (last_digest is None or last_digest.date() != now.date()):
                await self.record(await asyncio.to_thread(self.digest, now))
                last_digest = now
            if not await self._sleep(600):
                break

    def digest(self, now: datetime) -> Finding:
        since = now - timedelta(days=1)
        try:
            counts = Counter(doc["severity"] for doc in
                             self.db.recent_findings(since, limit=100000)
                             if doc.get("category") != "digest")
            counted = True
        except SQLAlchemyError as exc:
            self._database_failed(exc)
            counts, counted = Counter(), False
        stale = [n for n, h in self.health.items()
                 if h.last_ok is None or now - h.last_ok > timedelta(hours=1)]
        feeds = {d.name: self.pipeline.health[d.name] for d in self.cfg.devices
                 if d.name in self.pipeline.health}
        syslog = self.cfg.syslog.enabled
        missing = {name: gaps for name, feed in feeds.items()
                   if syslog and (gaps := missing_sources(feed))}
        quarantined = {name: feed.quarantined for name, feed in feeds.items() if feed.quarantined}
        line_errors = {name: feed.line_errors for name, feed in feeds.items() if feed.line_errors}
        failing = sorted(name for name, sink in self.sink_health.items() if sink.is_failing(now))
        fim_stale = [name for name, health in self.fim_health.items()
                     if health.last_ok is None or now - health.last_ok > timedelta(hours=1)]
        fim_gaps = {name: len(monitor.status["coverage_gaps"])
                    for name, monitor in self.fim_monitors.items()
                    if monitor.status.get("coverage_gaps")}
        parts = ["Last 24h: " + ((", ".join(f"{n} {s}" for s, n in sorted(counts.items()))
                                  or "no findings") if counted else
                                 "finding counts unavailable (database error)")]
        if not self.cfg.devices:
            parts.append("No devices configured")
        else:
            if stale:
                parts.append(f"NOT MONITORED: {', '.join(stale)}")
            if missing:
                parts.append("LOG SOURCES NEVER RECEIVED since monitor start: " + "; ".join(
                    f"{name} ({', '.join(gaps)})" for name, gaps in missing.items()))
            if quarantined:
                parts.append("SYSLOG BATCHES QUARANTINED: " + ", ".join(
                    f"{name} ({count})" for name, count in quarantined.items()))
            if not stale:
                parts.append(f"NITRO polling OK for all {len(self.health)} device(s)"
                             if missing or quarantined else
                             f"All {len(self.health)} device(s) polled OK")
        if fim_stale:
            parts.append(f"FILE INTEGRITY NOT CHECKED: {', '.join(fim_stale)}")
        if fim_gaps:
            parts.append("FILE INTEGRITY COVERAGE UNKNOWN: " + ", ".join(
                f"{name} ({count} path(s))" for name, count in fim_gaps.items()))
        if failing:
            parts.append(f"NOTIFICATION SINK FAILING: {', '.join(failing)}")
        attention = bool(stale or missing or quarantined or failing or not counted
                         or fim_stale or fim_gaps)
        return Finding(dedup_key=f"digest|{now.date()}", rule_id="daily-digest",
                       title="netrescale daily digest",
                       severity=Severity.MEDIUM if attention else Severity.INFO,
                       category="digest", device=None, summary=". ".join(parts) + ".",
                       evidence={"counts": dict(counts), "unmonitored": stale,
                                 "missing_sources": missing,
                                 "log_coverage": ({name: feed.coverage()
                                                   for name, feed in feeds.items()}
                                                  if syslog else {}),
                                 "coverage_since": self.started_at.isoformat(),
                                 "quarantined_batches": quarantined, "line_errors": line_errors,
                                 "failing_sinks": failing,
                                 "fim_unchecked": fim_stale, "fim_coverage_gaps": fim_gaps,
                                 "archive_heads": {
                                     device.name: self.pipeline.archive.head(device.name)
                                     for device in self.cfg.devices}})

    async def watchdog_loop(self) -> None:
        interval = sdnotify.watchdog_interval()
        if interval is None:
            return
        while await self._sleep(interval):
            sdnotify.notify("WATCHDOG=1")

    # ---- lifecycle ----------------------------------------------------------------------

    def stop(self) -> None:
        self._stop.set()

    async def _readiness(self) -> None:
        if any(device.mode is DeviceMode.ACTIVE for device in self.cfg.devices):
            raise ValueError("SSH collection is not available in this release; use mode: observe")
        if self.cfg.notify.siem and self.cfg.notify.siem.forward_events:
            raise ValueError("SIEM raw-event forwarding is not available; "
                             "use forward_events: false")
        if self.rt.nitro_transport is None:
            for device in self.cfg.devices:
                target = self.rt.nitro_target(device)
                if not target.spki_pinning or not target.spki_pin:
                    continue
                try:
                    valid = len(base64.b64decode(target.spki_pin, validate=True)) == 32
                except (ValueError, binascii.Error):
                    valid = False
                if not valid:
                    raise ValueError(f"{device.name}: configure a valid SPKI pin before starting")
        _ = self.rt.provider.vault
        await asyncio.to_thread(self.db.check)

    async def run(self) -> None:
        with instance_lock(self.cfg.paths.state_dir / "daemon.lock"):
            await self._run()

    async def _run(self) -> None:
        self._administration = Administration(self.rt, self.db, {
            "settings.apply": self.apply_settings, "monitor.pause": self.pause_monitoring,
            "monitor.resume": self.resume_monitoring,
            "platform.status": self.administration_status})
        control = ControlServer(self.cfg.paths.control_socket, self._dispatch_control)
        await control.start()
        self._running = True
        retry_delay = READINESS_RETRY[0]
        try:
            while not self._stop.is_set():
                retry_after: float | None = None
                try:
                    await self._readiness()
                    self.setup_error = ""
                    retry_delay = READINESS_RETRY[0]
                except Exception as exc:  # noqa: BLE001
                    if _transient(exc):  # e.g. PostgreSQL restarting: retry, don't wait for admin
                        retry_after, retry_delay = retry_delay, min(retry_delay * 2,
                                                                    READINESS_RETRY[1])
                        self.setup_error = (f"Monitoring setup is incomplete: "
                                            f"{type(exc).__name__}; retrying in "
                                            f"{retry_after:.0f}s")
                    else:
                        self.setup_error = (
                            registry.scrub(str(exc))
                            if isinstance(exc, ValueError | CredentialError)
                            else f"Monitoring setup is incomplete: {type(exc).__name__}")
                    log.error("%s", self.setup_error)
                tasks = [asyncio.create_task(self.status_loop(), name="status")]
                if not self.setup_error:
                    tasks += [asyncio.create_task(self.config_loop(device),
                                                 name=f"config:{device.name}")
                              for device in self.cfg.devices]
                    tasks += [asyncio.create_task(self.fim_loop(device),
                                                 name=f"fim:{device.name}")
                              for device in self.cfg.devices if device.fim.enabled]
                    tasks += [asyncio.create_task(self.exposure_loop(), name="exposure"),
                              asyncio.create_task(self.housekeeping_loop(), name="housekeeping"),
                              asyncio.create_task(self.notification_loop(), name="notifications")]
                    if self.cfg.syslog.enabled:
                        tasks.append(asyncio.create_task(self.syslog_loop(), name="syslog"))
                    if self.cfg.ha_pairs:
                        tasks.append(asyncio.create_task(self.ha_loop(), name="ha"))
                if sdnotify.watchdog_interval() is not None:
                    tasks.append(asyncio.create_task(self.watchdog_loop(), name="watchdog"))
                stopping = asyncio.create_task(self._stop.wait(), name="stop")
                reloading = asyncio.create_task(self._reload.wait(), name="reload")
                control_tasks: list[asyncio.Task[Any]] = [stopping, reloading]
                if retry_after is not None:
                    control_tasks.append(asyncio.create_task(asyncio.sleep(retry_after),
                                                             name="readiness-retry"))
                self._reload_complete.set()
                sdnotify.notify("READY=1\nSTATUS=" + (self.setup_error or
                                 f"monitoring {len(self.cfg.devices)} device(s)"))
                try:
                    done, _pending = await asyncio.wait([*control_tasks, *tasks],
                                                        return_when=asyncio.FIRST_COMPLETED)
                    if not any(task in done for task in control_tasks):
                        failed = next(task for task in tasks if task in done)
                        cause = None if failed.cancelled() else failed.exception()
                        message = f"monitoring task {failed.get_name()} stopped"
                        raise RuntimeError(message) from cause
                finally:
                    for task in [*control_tasks, *tasks]:
                        task.cancel()
                    await asyncio.gather(*control_tasks, *tasks, return_exceptions=True)
                    await asyncio.to_thread(self.pipeline.wait_idle)
                if self._stop.is_set():
                    break
                if not self._reload.is_set():
                    continue  # readiness retry: same configuration, check again
                for sink in self.router.sinks:
                    aclose = getattr(sink, "aclose", None)
                    if aclose is not None:
                        await aclose()
                if self.database is None:
                    await asyncio.to_thread(self.db.close)
                self.rt.cfg = self._replacement or self.rt.cfg
                self._replacement = None
                self._reload.clear()
                self._configure()
                self._administration.database = self.db
        finally:
            self._running = False
            self._stop.set()
            sdnotify.notify("STOPPING=1")
            await control.close()
            for sink in self.router.sinks:
                aclose = getattr(sink, "aclose", None)
                if aclose is not None:
                    await aclose()
            await asyncio.to_thread(self.db.close)


async def _close_quietly(client: NitroClient | None) -> None:
    if client is not None:
        with contextlib.suppress(Exception):
            await client.aclose()


def run_service(rt: Runtime) -> None:
    async def main() -> None:
        svc = Service(rt)
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, svc.stop)
        await svc.run()

    asyncio.run(main())
