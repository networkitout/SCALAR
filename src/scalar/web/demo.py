"""Isolated, explicitly labeled sample data for UI evaluation without appliances."""

from __future__ import annotations

import json
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi import FastAPI
from sqlalchemy import create_engine

from scalar.config import Config
from scalar.control import ControlError
from scalar.detect.findings import Finding
from scalar.detect.rules import load_rules
from scalar.detect.severity import Severity
from scalar.parse.nslog import parse_line
from scalar.store.database import Database, IndexedEvent
from scalar.store.snapshots import FileSnapshotStore
from scalar.web.app import create_app


def preview_app() -> FastAPI:
    temporary = tempfile.TemporaryDirectory(prefix="scalar-ui-preview-")
    root = Path(temporary.name)
    names = ["adc-lon-01", "adc-lon-02", "gw-nyc-01", "gw-nyc-02"]
    cfg = Config.model_validate(
        {
            "paths": {"state_dir": str(root), "vault": str(root / "unused-vault")},
            "devices": [
                {
                    "name": name,
                    "nsip": f"192.0.2.{10 + number}",
                    "spki_pin": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                }
                for number, name in enumerate(names)
            ],
            "ha_pairs": [
                {"name": "london-adc", "nodes": names[:2]},
                {"name": "new-york-gateway", "nodes": names[2:]},
            ],
            "syslog": {
                "admin_networks": ["198.51.100.0/24"],
                "admin_users": ["ops.admin", "sc_nitro"],
            },
            "notify": {
                "smtp": {
                    "host": "smtp.example.invalid",
                    "sender": "monitor@example.invalid",
                    "recipients": ["operations@example.invalid"],
                },
                "siem": {"host": "cribl.example.invalid"},
                "webhook": {"url": "https://hooks.example.invalid/sample"},
            },
        }
    )
    database = Database(create_engine(f"sqlite:///{root / 'preview.db'}"))
    database.initialize()
    now = datetime.now(UTC)
    samples = [
        (
            "config-saved-tamper",
            "Saved configuration changed outside the normal save path",
            Severity.CRITICAL,
            "config_change",
        ),
        (
            "mgmt-from-unexpected-ip",
            "Management activity from an unexpected address",
            Severity.HIGH,
            "log_rule",
        ),
        (
            "exposure-CVE-2025-5777",
            "Firmware build potentially exposed to CitrixBleed 2",
            Severity.HIGH,
            "exposure",
        ),
        ("config-peer", "HA peers have diverging configuration", Severity.MEDIUM, "config_change"),
        ("config-running", "Running configuration updated", Severity.LOW, "config_change"),
        ("credential-age", "Monitoring credential is due for rotation", Severity.LOW, "health"),
        (
            "session-reuse",
            "Gateway session observed from a second IP",
            Severity.HIGH,
            "session_reuse",
        ),
        ("config-saved", "Saved configuration updated", Severity.INFO, "config_change"),
    ]
    for number in range(34):
        rule, title, severity, category = samples[number % len(samples)]
        device = names[number % len(names)]
        observed = now - timedelta(minutes=number * 17 + 4)
        database.save_finding(
            Finding(
                f"preview-{number}",
                rule,
                title,
                severity,
                category,
                device,
                f"{title} on {device}. Sample record for the preview workspace.",
                observed,
                evidence={
                    "sample": True,
                    "source": "nslog",
                    "remote_ip": "198.51.100.42",
                    "command": "set lb vserver storefront -state ENABLED",
                },
                cve=("CVE-2025-5777",) if category == "exposure" else (),
            ),
            ["smtp", "siem", "webhook"] if number == 0 else [],
            now,
        )
        event = parse_line(
            "nslog",
            f"{observed:%Y/%m/%d:%H:%M:%S} GMT {device} 0-PPE-0 : "
            f"default GUI CMD_EXECUTED {1000 + number} 0 : User ops.admin "
            '- Remote_ip 198.51.100.42 - Command "show ns config" - Status "Success"',
            device,
        )
        database.ingest([IndexedEvent(event, "preview-only", observed)], [])
    for delivery in database.pending(now):
        database.delivery_result(
            delivery, "Connection to SMTP relay timed out" if delivery.sink == "smtp" else None, now
        )
    snapshots = FileSnapshotStore(root / "configs")
    for name in names:
        config = f"set ns hostName {name}\nadd lb vserver storefront HTTP 192.0.2.80 80\n"
        snapshots.put(name, "running", config, at=now - timedelta(days=2))
        snapshots.put(
            name,
            "running",
            config + "set lb vserver storefront -state ENABLED\n",
            at=now - timedelta(hours=3),
        )
        snapshots.put(
            name,
            "running",
            config + "set lb vserver storefront -state DISABLED\n",
            at=now - timedelta(minutes=12),
        )
        snapshots.put(name, "saved", config, at=now - timedelta(days=2))
    def coverage(number: int) -> list[dict[str, object]]:
        shell = 0 if number == 3 else 310  # one device never sent shell logs
        sources = [("ns.log", True, 9400), ("shell (bash.log/sh.log)", True, shell),
                   ("web access/error", True, 2600), ("auth.log", False, 120),
                   ("notice.log", False, 0)]
        return [{"source": source, "expected": expected, "lines": lines + number * 40 * bool(lines),
                 "last_received": (now - timedelta(minutes=2)).isoformat() if lines else None}
                for source, expected, lines in sources]

    def posture(number: int) -> dict[str, object]:
        train, build = ("14.1", "73.46") if number < 2 else ("13.1", "64.23")
        vulnerable = number >= 2
        return {"assessed_at": (now - timedelta(hours=5)).isoformat(),
                "version": f"{train} {build}", "train": train,
                "worst": "vulnerable" if vulnerable else "fixed",
                "lifecycle": "end_of_maintenance" if train == "13.1" else "supported",
                "min_safe_build": "64.29" if train == "13.1" else "73.46",
                "actionable": ["CVE-2026-107406"] if vulnerable else [],
                "needs_attention": [], "warnings": []}

    status = {
        "state": "healthy",
        "updated_at": now.isoformat(),
        "started_at": (now - timedelta(days=12)).isoformat(),
        "warnings": [],
        "devices": {
            name: {
                "nitro": {
                    "last_ok": (now - timedelta(seconds=20)).isoformat(),
                    "failures": 0,
                    "last_error": "",
                },
                "syslog": {
                    "last_received": (now - timedelta(seconds=15)).isoformat(),
                    "lines": 12460 + number * 2958,
                    "last_error": "",
                    "source_coverage": coverage(number),
                    "missing_sources": ["shell (bash.log/sh.log)"] if number == 3 else [],
                },
                "exposure": {"last_ok": (now - timedelta(hours=5)).isoformat(),
                             "posture": posture(number)},
            }
            for number, name in enumerate(names)
        },
        "notifications": {
            "smtp": {"failing": True, "failing_since": (now - timedelta(minutes=40)).isoformat(),
                     "alerted": True, "last_failure": now.isoformat()},
            "siem": {"failing": False, "failing_since": None, "alerted": False,
                     "last_failure": None},
            "webhook": {"failing": False, "failing_since": None, "alerted": False,
                        "last_failure": None},
        },
    }
    (root / "status.json").write_text(json.dumps(status))

    class PreviewControl:
        async def call(
            self, actor: str, action: str, parameters: dict[str, object] | None = None
        ) -> dict[str, object]:
            if action == "settings.get":
                return {
                    "document": cfg.model_dump(mode="json"),
                    "revision": "preview",
                    "pending_apply": False,
                    "schema": Config.model_json_schema(),
                    "host_managed": ["paths", "admin_group"],
                }
            if action == "users.list":
                return {
                    "items": [
                        {"name": "preview-admin", "role": "admin", "enabled": True},
                        {"name": "preview-operator", "role": "operator", "enabled": True},
                    ]
                }
            if action == "credentials.list":
                return {
                    "items": [
                        {
                            "name": "sc_nitro",
                            "username": "sc_nitro",
                            "has_ssh_key": False,
                            "updated": now.isoformat(),
                            "users": names,
                        }
                    ],
                    "blocked": [],
                }
            if action == "vault.status":
                return {"entries": 1, "key_id": "preview-only", "backup_available": False}
            if action == "platform.status":
                return {"administration": "preview", "paused": False, "setup_error": ""}
            if action == "audit.list":
                return {"items": []}
            if action == "rules.list":
                return {
                    "items": [
                        {
                            "id": rule.id,
                            "title": rule.title,
                            "severity": str(rule.severity),
                            "sources": sorted(rule.sources),
                        }
                        for rule in load_rules()
                    ]
                }
            raise ControlError("Actions are disabled in the preview", 409)

    app = create_app(cfg, database, demo=True, control=PreviewControl())
    app.state.preview_directory = temporary
    app.state.preview_database = database
    return app
