"""Disposable full-stack administration workspace, with no real appliance connections."""

from __future__ import annotations

import asyncio
import tempfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml
from fastapi import FastAPI
from sqlalchemy import create_engine

from netrescale.config import Config
from netrescale.daemon.service import Service
from netrescale.detect.findings import Finding
from netrescale.detect.severity import Severity
from netrescale.runtime import Runtime
from netrescale.secrets.base import Credential
from netrescale.secrets.vault import Vault, generate_key
from netrescale.store.database import Database
from netrescale.store.snapshots import FileSnapshotStore
from netrescale.web.app import create_app
from netrescale.web.auth import set_password, update_user
from tests.emulator.nitro import FakeNitro

TEST_PASSWORD = "administration-browser-test-only"


class TestSink:
    name = "webhook"
    min_severity = Severity.INFO

    async def send(self, finding: Finding) -> None:
        return


def create_test_app() -> FastAPI:
    workspace = tempfile.TemporaryDirectory(prefix="nr-admin-")
    root = Path(workspace.name)
    cfg = Config.model_validate(
        {
            "paths": {
                "state_dir": str(root),
                "vault": str(root / "vault"),
                "log_dir": str(root / "logs"),
                "control_socket": str(root / "c.sock"),
            },
            "devices": [{"name": "test-gateway", "nsip": "192.0.2.10", "spki_pin": "test-pin"}],
            "web": {"allowed_hosts": ["127.0.0.1", "localhost", "testserver"]},
            "notify": {"webhook": {"url": "https://example.invalid/test-only"}},
        }
    )
    config_path = root / "config.yaml"
    config_path.write_text(yaml.safe_dump(cfg.model_dump(mode="json")))
    key = generate_key()
    Vault.create(cfg.paths.vault, key).set(
        "nr_nitro", Credential("nr_nitro", "nitro-password"), actor="test"
    )
    set_password(root / "web-users.json", "test-admin", TEST_PASSWORD)
    update_user(root / "web-users.json", "test-viewer", password=TEST_PASSWORD, role="viewer")
    fake = FakeNitro(
        running="set ns hostName test-gateway\n", saved="set ns hostName test-gateway\n",
        files={
            "/var/log/ns.log": (
                b'2026/10/06:10:00:00 GMT test-gateway 0-PPE-0 : default AAA Message 1 0 : '
                b'"Authentication is rejected for \x89\x01\xfe"\n'),
            "/var/log/httperror.log": b"[Oct 06 10:01:00 2026] access to /vpn/unapproved.php\n",
            "/var/log/notice.log": b"Oct 6 10:00:00 test-gateway system: service started\n",
        },
    )
    snapshots = FileSnapshotStore(root / "configs")
    for number, hostname in enumerate(("previous-gateway", "intermediate-gateway")):
        snapshots.put("test-gateway", "running", f"set ns hostName {hostname}\n",
                      at=datetime.now(UTC) - timedelta(hours=2 - number))
    runtime = Runtime(
        cfg, lambda: key, nitro_transport=lambda device: fake.transport(), config_path=config_path
    )
    database = Database(create_engine(f"sqlite:///{root / 'test.db'}"))
    database.initialize()
    service = Service(runtime, sinks=[TestSink()], database=database)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        task = asyncio.create_task(service.run())
        await asyncio.wait_for(service._reload_complete.wait(), timeout=10)
        try:
            yield
        finally:
            service.stop()
            await task
            workspace.cleanup()

    app = create_app(cfg, database)
    app.router.lifespan_context = lifespan
    app.state.test_service = service
    app.state.test_appliance = fake
    return app
