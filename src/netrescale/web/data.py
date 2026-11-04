"""Bounded read models for the browser; appliance credentials are never loaded here."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from difflib import unified_diff
from typing import Any, Literal
from urllib.parse import urlsplit

from sqlalchemy import Text, cast, func, select
from sqlalchemy.exc import SQLAlchemyError

from netrescale.config import Config
from netrescale.detect.severity import Severity
from netrescale.parse.nsconf import redact_config
from netrescale.redact import registry
from netrescale.store.database import Database, events, findings, outbox
from netrescale.store.snapshots import FileSnapshotStore


class WebData:
    def __init__(self, cfg: Config, database: Database, *, preview: bool = False) -> None:
        self.cfg = cfg
        self.database = database
        self.preview = preview

    def status(self) -> dict[str, Any]:
        try:
            document: dict[str, Any] = json.loads(
                (self.cfg.paths.state_dir / "status.json").read_bytes()
            )
            updated = datetime.fromisoformat(document["updated_at"])
            if self.preview:
                elapsed = datetime.now(UTC) - updated
                document["updated_at"] = datetime.now(UTC).isoformat()
                for health in document.get("devices", {}).values():
                    for kind, key in (("nitro", "last_ok"), ("syslog", "last_received")):
                        value = health.get(kind, {}).get(key)
                        if value:
                            health[kind][key] = (
                                datetime.fromisoformat(value) + elapsed
                            ).isoformat()
                return document
            if datetime.now(UTC) - updated > timedelta(seconds=60):
                document["state"] = "stale"
            result: dict[str, Any] = registry.scrub_value(document)
            return result
        except FileNotFoundError:
            return {
                "state": "not-running",
                "devices": {},
                "warnings": ["No daemon status available"],
            }
        except (OSError, ValueError, KeyError, TypeError):
            return {
                "state": "unavailable",
                "devices": {},
                "warnings": ["Daemon status unavailable"],
            }

    def devices(self) -> list[dict[str, Any]]:
        status = self.status()
        result = []
        for device in self.cfg.devices:
            health = status.get("devices", {}).get(device.name, {})
            nitro = health.get("nitro", {})
            feed = health.get("syslog", {})
            reachable = bool(nitro.get("last_ok")) and not nitro.get("failures")
            current = status["state"] not in {"stale", "not-running", "unavailable", "paused"}
            pair = self.cfg.pair_of(device.name)
            result.append(
                {
                    "name": device.name,
                    "address": device.nsip,
                    "mode": str(device.mode),
                    "pair": pair.name if pair else None,
                    "state": "online" if reachable and current else "unmonitored",
                    "pinned": device.spki_pinning and bool(device.spki_pin),
                    "nitro": nitro,
                    "syslog": feed,
                    "posture": health.get("exposure", {}).get("posture"),
                }
            )
        return result

    def overview(self) -> dict[str, Any]:
        status = self.status()
        severity = {str(level): 0 for level in Severity}
        try:
            counts = self.database.counts()
            with self.database.engine.connect() as connection:
                query = (
                    select(findings.c.severity, func.count())
                    .where(findings.c.observed_at >= datetime.now(UTC) - timedelta(days=1))
                    .group_by(findings.c.severity)
                )
                for level, count in connection.execute(query):
                    severity[str(Severity(level))] = count
            database: dict[str, Any] = {"available": True, **counts}
        except SQLAlchemyError:
            database = {"available": False, "error": "PostgreSQL is unavailable or uninitialized"}
        return {
            "status": status,
            "database": database,
            "devices": self.devices(),
            "severity": severity,
            "generated_at": datetime.now(UTC).isoformat(),
        }

    def _recent_actions(self, access: Literal["admin", "operator", "none"]) -> dict[str, Any]:
        if access == "none" or self.preview:
            return {"available": False, "items": []}
        path = self.cfg.paths.state_dir / "administration.jsonl"
        try:
            with path.open("rb") as stream:
                size = stream.seek(0, os.SEEK_END)
                stream.seek(max(0, size - 512 * 1024))
                if size > 512 * 1024:
                    stream.readline()
                lines = stream.read(512 * 1024).splitlines()
        except FileNotFoundError:
            return {"available": True, "items": []}
        except OSError:
            return {"available": False, "items": [], "error": "Action diagnostics are unreadable"}
        items = []
        seen = set()
        for line in reversed(lines):
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if not isinstance(entry, dict):
                continue
            action = str(entry.get("action", ""))
            if access != "admin" and not (action.startswith("device.") or action == "logs.fetch"):
                continue
            identity = entry.get("request_id")
            if identity and identity in seen:
                continue
            if identity:
                seen.add(identity)
            keys = ["at", "action", "target", "outcome", "error", "error_type", "status",
                    "duration_ms", "request_id"]
            if access == "admin":
                keys.append("actor")
            items.append({key: entry.get(key) for key in keys})
            if len(items) == 100:
                break
        return {"available": True, "items": registry.scrub_value(items)}

    def health(self, *, action_access: Literal["admin", "operator", "none"] = "none"
               ) -> dict[str, Any]:
        status = self.status()
        devices = self.devices()
        for device in devices:
            cfg = self.cfg.device(device["name"])
            device["exposure"] = status.get("devices", {}).get(device["name"], {}).get(
                "exposure", {})
            device["tls_verification"] = "SPKI" if cfg.spki_pinning and cfg.spki_pin else "CA"
            device["nitro_port"] = cfg.nitro_port or self.cfg.defaults.nitro_port
            device["syslog_enabled"] = self.cfg.syslog.enabled
        try:
            database = {"available": True, **self.database.health_statistics()}
            delivery = self.delivery()
            findings = self.search("findings", days=30, minimum="info", device="",
                                   category="health", query="", offset=0, limit=50)
        except SQLAlchemyError:
            database = {"available": False,
                        "error": "PostgreSQL is unreachable or its schema is not initialized"}
            delivery = {"sinks": []}
            findings = {"items": []}
        return {
            "status": status, "resources": status.get("resources"), "devices": devices,
            "database": database, "delivery": delivery, "findings": findings,
            "actions": self._recent_actions(action_access),
            "intervals": self.cfg.defaults.intervals.model_dump(),
            "generated_at": datetime.now(UTC).isoformat(),
        }

    def search(
        self,
        kind: Literal["findings", "events"],
        *,
        days: int,
        minimum: str,
        device: str,
        category: str,
        query: str,
        offset: int,
        limit: int,
    ) -> dict[str, Any]:
        table = findings if kind == "findings" else events
        criteria = [table.c.observed_at >= datetime.now(UTC) - timedelta(days=days)]
        if kind == "findings":
            criteria.append(findings.c.severity >= int(Severity.parse(minimum)))
        if device:
            self.cfg.device(device)
            criteria.append(table.c.document["device"].as_string() == device)
        if category and kind == "findings":
            criteria.append(table.c.document["category"].as_string() == category)
        if query:
            criteria.append(cast(table.c.document, Text).icontains(query, autoescape=True))
        with self.database.engine.connect() as connection:
            total = connection.scalar(select(func.count()).select_from(table).where(*criteria))
            rows = connection.execute(
                select(table.c.id, table.c.document)
                .where(*criteria)
                .order_by(table.c.observed_at.desc(), table.c.id)
                .offset(offset)
                .limit(limit)
            )
            documents = [{**row.document, "id": row.id} for row in rows]
        return {
            "items": registry.scrub_value(documents),
            "total": total,
            "offset": offset,
            "limit": limit,
        }

    def configurations(self, device: str, kind: str, index: int | None,
                       compare_index: int | None = None) -> dict[str, Any]:
        self.cfg.device(device)
        if not (self.cfg.paths.state_dir / "configs").exists():
            if index is not None:
                raise KeyError("snapshot not found")
            return {"device": device, "kind": kind, "items": []}
        store = FileSnapshotStore(self.cfg.paths.state_dir / "configs")
        history = store.history(device, kind)
        items = [
            {"index": number, "at": snapshot.at.isoformat(), "sha256": snapshot.sha256}
            for number, snapshot in enumerate(history)
        ][-200:]
        result: dict[str, Any] = {"device": device, "kind": kind, "items": list(reversed(items))}
        if index is not None:
            if not 0 <= index < len(history):
                raise KeyError("snapshot not found")
            text = store.content(history[index].sha256)
            result["content"] = registry.scrub(redact_config(text))
            baseline = compare_index if compare_index is not None else index - 1
            if baseline >= 0:
                if baseline >= len(history):
                    raise KeyError("comparison snapshot not found")
                previous = registry.scrub(redact_config(store.content(history[baseline].sha256)))
                result["comparison"] = {"index": baseline, "at": history[baseline].at.isoformat()}
            else:
                previous = ""
                result["comparison"] = None
            lines = list(unified_diff(
                previous.splitlines(), result["content"].splitlines(),
                fromfile=f"{device}/{kind}/{baseline}" if baseline >= 0 else "empty baseline",
                tofile=f"{device}/{kind}/{index}", lineterm="",
            ))
            result["diff"] = "\n".join(lines)
            result["changes"] = {
                "added": sum(line.startswith("+") and not line.startswith("+++") for line in lines),
                "removed": sum(line.startswith("-") and not line.startswith("---")
                               for line in lines),
            }
        return result

    def delivery(self) -> dict[str, Any]:
        """Configured sinks with their outbox backlog (Database.sink_backlog) and the
        daemon's view of their health (status.json "notifications"; None without it)."""
        result = []
        backlog = self.database.sink_backlog()
        daemon = self.status().get("notifications") or {}
        with self.database.engine.connect() as connection:
            for name in ("smtp", "siem", "webhook"):
                config = getattr(self.cfg.notify, name)
                if config is None:
                    continue
                queued = backlog.get(name)
                last = connection.scalar(
                    select(func.max(outbox.c.delivered_at)).where(outbox.c.sink == name)
                )
                if last is not None and last.tzinfo is None:
                    last = last.replace(tzinfo=UTC)
                health = daemon.get(name) if isinstance(daemon, dict) else None
                destination = urlsplit(config.url).hostname if name == "webhook" else config.host
                result.append(
                    {
                        "name": name,
                        "destination": destination,
                        "min_severity": config.min_severity,
                        "pending": queued.count if queued else 0,
                        "oldest_undelivered": queued.oldest_queued.isoformat() if queued else None,
                        "max_attempts": queued.max_attempts if queued else 0,
                        "last_delivered": last.isoformat() if last else None,
                        "error": queued.last_error if queued else None,
                        "health": {key: health.get(key) for key in (
                            "failing", "failing_since", "alerted", "last_failure")}
                        if isinstance(health, dict) else None,
                    }
                )
        return {"sinks": result, "digest_hour": self.cfg.notify.daily_digest_hour_utc}
