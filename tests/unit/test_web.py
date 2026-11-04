import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError

from scalar.config import Config
from scalar.detect.findings import Finding
from scalar.detect.severity import Severity
from scalar.store.database import Database
from scalar.store.snapshots import FileSnapshotStore
from scalar.web.app import COOKIE, create_app
from scalar.web.auth import (
    AuthenticationError,
    AuthStore,
    LoginThrottled,
    load_accounts,
    set_password,
    update_user,
)

requires_peercred = pytest.mark.skipif(
    not hasattr(__import__("socket"), "SO_PEERCRED"), reason="needs Linux SO_PEERCRED")

PASSWORD = "a-long-test-only-password"


def test_http_setup_preserves_config_and_limits_network_permissions(tmp_path: Path) -> None:
    import yaml

    from scalar.config import load_config
    from scalar.web.server import configure_http

    path = tmp_path / "config.yaml"
    cfg = Config.model_validate({"devices": [{"name": "gateway", "nsip": "192.0.2.10",
                                             "spki_pin": "unchanged-pin"}]})
    path.write_text(yaml.safe_dump(cfg.model_dump(mode="json")))
    original = path.read_bytes()
    dropin = tmp_path / "service.d" / "20-http-access.conf"
    origin = configure_http(path, "192.0.2.50", ["198.51.100.5/32"], dropin_path=dropin)
    updated = load_config(path)
    assert origin == "http://192.0.2.50:8080"
    assert updated.web.allow_http and updated.web.host == "192.0.2.50"
    assert "192.0.2.50" in updated.web.allowed_hosts
    assert updated.devices == cfg.devices
    assert updated.paths == cfg.paths
    assert path.with_name("config.yaml.bak").read_bytes() == original
    assert "IPAddressAllow=198.51.100.5/32" in dropin.read_text()
    assert "IPAddressDeny" not in dropin.read_text()
    configure_http(path, "192.0.2.50", ["203.0.113.0/24"], dropin_path=dropin)
    assert "198.51.100.5" not in dropin.read_text()
    assert "IPAddressAllow=203.0.113.0/24" in dropin.read_text()


@pytest.mark.parametrize("host,networks", [
    ("0.0.0.0", ["192.0.2.0/24"]), ("192.0.2.50", []),
    ("192.0.2.50", ["192.0.2.0/24\nIPAddressDeny="]),
])
def test_invalid_http_setup_does_not_write_files(tmp_path: Path, host: str,
                                                networks: list[str]) -> None:
    from scalar.web.server import configure_http

    path = tmp_path / "config.yaml"
    path.write_text("{}\n")
    dropin = tmp_path / "service.d" / "http.conf"
    with pytest.raises(ValueError):
        configure_http(path, host, networks, dropin_path=dropin)
    assert path.read_text() == "{}\n"
    assert not dropin.exists()


def test_http_setup_does_not_overwrite_an_unmanaged_dropin(tmp_path: Path) -> None:
    from scalar.web.server import configure_http

    path = tmp_path / "config.yaml"
    path.write_text("{}\n")
    dropin = tmp_path / "http.conf"
    dropin.write_text("[Service]\nMemoryMax=1G\n")
    with pytest.raises(ValueError, match="unmanaged"):
        configure_http(path, "192.0.2.50", ["198.51.100.0/24"], dropin_path=dropin)
    assert path.read_text() == "{}\n"
    assert dropin.read_text() == "[Service]\nMemoryMax=1G\n"


@pytest.mark.parametrize("settings", [
    {"host": "0.0.0.0"},
    {"public_url": "http://testserver"},
    {"host": "192.0.2.10", "public_url": "http://192.0.2.10:8080"},
])
def test_network_http_requires_explicit_opt_in(settings: dict[str, str]) -> None:
    with pytest.raises(ValueError, match="HTTP"):
        Config.model_validate({"web": settings})


@pytest.mark.parametrize("public_url", [None, "http://testserver"])
def test_opt_in_http_allows_login_without_redirect_and_preserves_csrf(web, public_url) -> None:  # type: ignore[no-untyped-def]
    _client, cfg, database = web
    document = cfg.model_dump(mode="json")
    document["web"].update(host="192.0.2.10", allow_http=True, public_url=public_url)
    config = Config.model_validate(document)
    with TestClient(create_app(config, database), follow_redirects=False) as client:
        response = client.get("/api/auth")
        assert response.status_code == 200
        assert "strict-transport-security" not in response.headers
        response = client.post("/api/login", json={"username": "admin", "password": PASSWORD},
                               headers={"origin": "http://testserver"})
        assert response.status_code == 200
        assert "Secure" not in response.headers["set-cookie"]
        assert "HttpOnly" in response.headers["set-cookie"]
        assert "SameSite=strict" in response.headers["set-cookie"]
        assert client.get("/api/session").status_code == 200
        assert client.post("/api/delivery/test", json={}).status_code == 403
        assert client.post("/api/delivery/test", json={}, headers={
            "x-csrf-token": response.json()["csrf"], "origin": "http://attacker.test"}).status_code == 403
        assert client.get("/api/auth", headers={"host": "attacker.test"}).status_code == 400


def test_http_opt_in_does_not_downgrade_an_https_public_url(web) -> None:  # type: ignore[no-untyped-def]
    _client, cfg, database = web
    document = cfg.model_dump(mode="json")
    document["web"].update(allow_http=True, public_url="https://testserver")
    with TestClient(create_app(Config.model_validate(document), database),
                    base_url="https://testserver") as client:
        response = client.post("/api/login", json={"username": "admin", "password": PASSWORD})
        assert response.status_code == 200
        assert "Secure" in response.headers["set-cookie"]
        assert "strict-transport-security" in response.headers


def test_user_roles_disable_and_last_administrator(tmp_path: Path) -> None:
    path = tmp_path / "users.json"
    set_password(path, "admin", PASSWORD)
    update_user(path, "observer", password=PASSWORD, role="viewer", create_only=True)
    store = AuthStore(path)
    token, session = store.login("observer", PASSWORD, "local")
    assert session.role == "viewer"
    update_user(path, "observer", role="operator")
    assert store.session(token) is None
    update_user(path, "observer", enabled=False)
    with pytest.raises(AuthenticationError, match="invalid username"):
        store.login("observer", PASSWORD, "local")
    for change in ({"remove": True}, {"enabled": False}, {"role": "viewer"}):
        with pytest.raises(AuthenticationError, match="administrator"):
            update_user(path, "admin", **change)
    assert load_accounts(path)["admin"].role == "admin"


def test_legacy_web_accounts_migrate_without_password_reset(tmp_path: Path) -> None:
    path = tmp_path / "users.json"
    set_password(path, "existing", PASSWORD)
    encoded = load_accounts(path)["existing"].password_hash
    path.write_text(json.dumps({"version": 1, "users": {"existing": encoded}}))
    assert AuthStore(path).login("existing", PASSWORD, "local")[1].role == "admin"
    update_user(path, "new-user", password=PASSWORD, role="viewer")
    assert json.loads(path.read_bytes())["version"] == 2
    assert load_accounts(path)["existing"].password_hash == encoded


def test_legacy_upgrade_does_not_promote_every_operator(tmp_path: Path) -> None:
    path = tmp_path / "users.json"
    set_password(path, "admin", PASSWORD)
    encoded = load_accounts(path)["admin"].password_hash
    path.write_text(json.dumps({"version": 1, "users": {"other": encoded, "admin": encoded}}))
    users = load_accounts(path)
    assert users["admin"].role == "admin"
    assert users["other"].role == "operator"


def test_web_password_is_hashed_and_sessions_are_revocable(tmp_path: Path) -> None:
    path = tmp_path / "users.json"
    set_password(path, "admin", PASSWORD)
    assert PASSWORD not in path.read_text()
    assert "$argon2id$" in path.read_text()
    store = AuthStore(path)
    token, session = store.login("admin", PASSWORD, "127.0.0.1")
    assert store.session(token) == session
    store.logout(token)
    assert store.session(token) is None


def test_password_reset_invalidates_existing_sessions(tmp_path: Path) -> None:
    path = tmp_path / "users.json"
    set_password(path, "admin", PASSWORD)
    store = AuthStore(path)
    token, _session = store.login("admin", PASSWORD, "127.0.0.1")
    set_password(path, "admin", "a-different-test-password")
    assert store.session(token) is None


def test_no_default_web_credentials_and_login_throttling(tmp_path: Path) -> None:
    store = AuthStore(tmp_path / "users.json")
    for _ in range(5):
        with pytest.raises(AuthenticationError, match="invalid username or password"):
            store.login("admin", "admin", "127.0.0.1")
    with pytest.raises(LoginThrottled):
        store.login("admin", "admin", "127.0.0.1")


@pytest.mark.parametrize("session_seconds", [-1, 3600])
def test_session_expiration_and_restart(tmp_path: Path, session_seconds: int) -> None:
    path = tmp_path / "users.json"
    set_password(path, "admin", PASSWORD)
    store = AuthStore(path, session_seconds=session_seconds)
    token, session = store.login("admin", PASSWORD, "127.0.0.1")
    assert store.session(token) == (session if session_seconds > 0 else None)
    assert AuthStore(path).session(token) is None


def test_settings_reload_preserves_browser_session(web) -> None:  # type: ignore[no-untyped-def]
    _client, cfg, database = web
    auth = AuthStore(cfg.paths.state_dir / "web-users.json")
    with TestClient(create_app(cfg, database, auth_store=auth)) as client:
        response = client.post("/api/login", json={"username": "admin", "password": PASSWORD})
        assert response.status_code == 200
        csrf = response.json()["csrf"]
        original = client.get("/api/session").json()
        cookies = dict(client.cookies)
        saved_session = auth.session(cookies[COOKIE])
        assert saved_session is not None

    document = cfg.model_dump(mode="json")
    document["devices"].append({"name": "second-gateway", "nsip": "192.0.2.11"})
    with TestClient(create_app(Config.model_validate(document), database,
                               auth_store=auth)) as reloaded:
        reloaded.cookies.update(cookies)
        response = reloaded.get("/api/session")
        assert response.status_code == 200
        assert response.json() == original
        assert auth.session(cookies[COOKIE]) is saved_session
        assert reloaded.post("/api/logout", json={}).status_code == 403
        assert reloaded.post("/api/logout", json={},
                             headers={"x-csrf-token": csrf}).status_code == 200
        assert reloaded.get("/api/session").status_code == 401


@pytest.mark.parametrize("change,preserve_session", [
    ("unchanged", True), ("devices", True), ("published", True), ("session_hours", False),
    ("allowed_hosts", False), ("state_dir", False),
])
def test_server_settings_reload_session_policy(web, monkeypatch: pytest.MonkeyPatch,
                                               change: str, preserve_session: bool) -> None:  # type: ignore[no-untyped-def]
    import asyncio

    import uvicorn
    import yaml

    from scalar.web import server as web_server

    _client, cfg, database = web
    config_path = cfg.paths.state_dir / "config.yaml"
    document = cfg.model_dump(mode="json")
    config_path.write_text(yaml.safe_dump(document))
    if change in ("devices", "published"):
        document["devices"].append({"name": "second-gateway", "nsip": "192.0.2.11"})
    elif change == "session_hours":
        document["web"]["session_hours"] = 1
    elif change == "allowed_hosts":
        document["web"]["allowed_hosts"].append("localhost")
    elif change == "state_dir":
        document["paths"]["state_dir"] = str(cfg.paths.state_dir / "moved")

    stores: list[AuthStore] = []
    refreshed = []
    token = ""
    original_sleep = asyncio.sleep

    async def yield_control(_delay: float) -> None:
        await original_sleep(0)

    def make_app(candidate: Config, *, auth_store: AuthStore | None = None) -> FastAPI:
        assert auth_store is not None
        stores.append(auth_store)
        app = create_app(candidate, database, auth_store=auth_store)
        original = app.state.refresh_config

        def refresh(config: Config) -> bool:
            accepted: bool = original(config)
            if accepted:
                refreshed.append(config)
            return accepted

        app.state.refresh_config = refresh
        return app

    class ReloadingServer:
        def __init__(self, config: uvicorn.Config) -> None:
            self.should_exit = False

        async def serve(self) -> None:
            nonlocal token
            if len(stores) != 1:
                return
            token, _session = stores[0].login("admin", PASSWORD, "local")
            config_path.write_text(yaml.safe_dump(document))
            (cfg.paths.state_dir / "web-reload.json").write_text(json.dumps({"config": document}))
            if change == "published":
                staged = {**document, "web": {**document["web"], "session_hours": 2}}
                config_path.write_text(yaml.safe_dump(staged))
            while not self.should_exit and not refreshed:
                await original_sleep(0)

    monkeypatch.setattr(web_server, "create_app", make_app)
    monkeypatch.setattr(web_server.uvicorn, "Server", ReloadingServer)
    monkeypatch.setattr(web_server.asyncio, "sleep", yield_control)
    web_server.serve(config_path)

    assert len(stores) == (1 if preserve_session else 2)
    assert (stores[0] is stores[-1]) is preserve_session
    assert (stores[-1].session(token) is not None) is preserve_session
    assert stores[-1].session_seconds == document["web"]["session_hours"] * 3600
    if preserve_session:
        assert refreshed == [Config.model_validate(document)]


def test_web_configuration_refresh_is_live_and_preserves_security(web) -> None:  # type: ignore[no-untyped-def]
    client, cfg, _database = web
    sign_in(client)
    session = client.get("/api/session").json()
    document = cfg.model_dump(mode="json")
    document["devices"].append({"name": "second-gateway", "nsip": "192.0.2.11"})
    document["retention"]["findings_days"] = 180
    assert client.app.state.refresh_config(Config.model_validate(document))
    assert len(client.get("/api/devices").json()["items"]) == 2
    assert client.get("/api/settings").json()["retention"]["findings_days"] == 180
    assert client.get("/api/session").json() == session
    document["web"]["allowed_hosts"] = ["other.example"]
    assert not client.app.state.refresh_config(Config.model_validate(document))
    assert client.get("/api/session").status_code == 200
    assert client.get("/api/auth", headers={"host": "other.example"}).status_code == 400


def test_inflight_request_keeps_its_configuration_snapshot(web, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    from scalar.web.data import WebData

    client, cfg, _database = web
    sign_in(client)
    entered, release = Event(), Event()
    original = WebData.devices

    def delayed(self):  # type: ignore[no-untyped-def]
        entered.set()
        assert release.wait(5)
        return original(self)

    monkeypatch.setattr(WebData, "devices", delayed)
    with ThreadPoolExecutor(max_workers=1) as executor:
        request = executor.submit(client.get, "/api/devices")
        try:
            assert entered.wait(5)
            assert client.app.state.refresh_config(cfg.model_copy(update={"devices": []}))
        finally:
            release.set()
        assert len(request.result(timeout=5).json()["items"]) == 1
    assert client.get("/api/devices").json()["items"] == []


@pytest.mark.parametrize("name,password", [("../admin", PASSWORD), ("admin", "short")])
def test_invalid_web_account_is_rejected(tmp_path: Path, name: str, password: str) -> None:
    with pytest.raises(AuthenticationError):
        set_password(tmp_path / "users.json", name, password)


@pytest.fixture
def web(tmp_path: Path):  # type: ignore[no-untyped-def]
    cfg = Config.model_validate(
        {
            "paths": {"state_dir": str(tmp_path)},
            "devices": [{"name": "gateway", "nsip": "192.0.2.10"}],
            "web": {"allowed_hosts": ["testserver"]},
            "notify": {"webhook": {"url": "https://example.test/private-token"}},
        }
    )
    database = Database(create_engine(f"sqlite:///{tmp_path / 'web.db'}"))
    database.initialize()
    set_password(tmp_path / "web-users.json", "admin", PASSWORD)
    with TestClient(create_app(cfg, database)) as client:
        yield client, cfg, database


def sign_in(client: TestClient) -> dict[str, str]:
    result = client.post("/api/login", json={"username": "admin", "password": PASSWORD})
    assert result.status_code == 200, result.text
    assert "HttpOnly" in result.headers["set-cookie"]
    assert "SameSite=strict" in result.headers["set-cookie"]
    return {"x-csrf-token": result.json()["csrf"]}


@pytest.mark.parametrize(
    "endpoint",
    [
        "/api/overview",
        "/api/devices",
        "/api/health",
        "/api/records/findings",
        "/api/configurations/gateway",
        "/api/delivery",
        "/api/settings",
    ],
)
def test_monitoring_data_requires_authentication(web, endpoint: str) -> None:  # type: ignore[no-untyped-def]
    client, _cfg, _database = web
    assert client.get(endpoint).status_code == 401


def test_authenticated_filters_and_pagination(web) -> None:  # type: ignore[no-untyped-def]
    client, _cfg, database = web
    for number in range(3):
        database.save_finding(
            Finding(
                str(number),
                "rule",
                "Title",
                Severity.HIGH,
                "log_rule",
                "gateway",
                f"Event {number}",
            ),
            [],
        )
    sign_in(client)
    result = client.get("/api/records/findings?device=gateway&minimum=high&limit=2").json()
    assert result["total"] == 3 and len(result["items"]) == 2
    assert len(client.get("/api/records/findings?offset=2&limit=2").json()["items"]) == 1
    assert client.get("/api/records/findings?query=Event%201").json()["total"] == 1
    assert client.get("/api/records/findings?limit=100000").status_code == 422


def test_csrf_origin_and_logout_revocation(web) -> None:  # type: ignore[no-untyped-def]
    client, _cfg, database = web
    assert (
        client.post(
            "/api/login",
            json={"username": "admin", "password": PASSWORD},
            headers={"origin": "https://attacker.test"},
        ).status_code
        == 403
    )
    headers = sign_in(client)
    old_cookie = client.cookies.get("scalar_session")
    assert client.post("/api/delivery/test", json={}).status_code == 403
    assert client.post("/api/delivery/test", json={}, headers=headers).status_code == 200
    assert database.counts()["pending_notifications"] == 1
    assert client.post("/api/logout", json={}, headers=headers).status_code == 200
    client.cookies.set("scalar_session", old_cookie)
    assert client.get("/api/session").status_code == 401


def test_configuration_redaction_and_destination_secrets(web) -> None:  # type: ignore[no-untyped-def]
    client, cfg, _database = web
    store = FileSnapshotStore(cfg.paths.state_dir / "configs")
    store.put("gateway", "running", "add system user admin super-secret-password\n")
    sign_in(client)
    response = client.get("/api/configurations/gateway?index=0")
    assert response.status_code == 200
    assert "super-secret-password" not in response.text
    assert "private-token" not in client.get("/api/delivery").text
    assert client.get("/api/configurations/unknown").status_code == 404


def test_configuration_unified_diff_and_selected_baseline(web) -> None:  # type: ignore[no-untyped-def]
    client, cfg, _database = web
    store = FileSnapshotStore(cfg.paths.state_dir / "configs")
    for name in ("original", "middle", "latest"):
        store.put("gateway", "running", f"set ns hostName {name}\nadd system user admin secret-{name}\n")
    sign_in(client)
    current = client.get("/api/configurations/gateway?index=2").json()
    assert current["comparison"]["index"] == 1
    assert "-set ns hostName middle" in current["diff"]
    assert "+set ns hostName latest" in current["diff"]
    assert "@@" in current["diff"]
    assert current["changes"] == {"added": 2, "removed": 2}
    selected = client.get("/api/configurations/gateway?index=2&compare_index=0").json()
    assert "-set ns hostName original" in selected["diff"]
    assert "middle" not in selected["diff"]
    assert "secret-original" not in json.dumps(selected)
    assert "secret-latest" not in json.dumps(selected)
    baseline = client.get("/api/configurations/gateway?index=0").json()
    assert baseline["comparison"] is None
    assert baseline["changes"] == {"added": 2, "removed": 0}
    same = client.get("/api/configurations/gateway?index=2&compare_index=2").json()
    assert same["diff"] == ""
    assert same["changes"] == {"added": 0, "removed": 0}
    assert client.get("/api/configurations/gateway?index=2&compare_index=100").status_code == 404
    assert client.get("/api/configurations/gateway?index=2&compare_index=-1").status_code == 422
    assert client.get("/api/configurations/gateway?compare_index=0").status_code == 422


def test_health_details_include_diagnostics_and_statistics(web) -> None:  # type: ignore[no-untyped-def]
    from scalar.redact import registry

    client, cfg, _database = web
    registry.register("private-health-secret")
    (cfg.paths.state_dir / "status.json").write_text(json.dumps({
        "state": "degraded", "updated_at": datetime.now(UTC).isoformat(),
        "resources": {"cpu_count": 4, "process": {"pid": 42}},
        "devices": {"gateway": {"nitro": {"failures": 2, "last_error": "TLS pin mismatch"},
                                  "exposure": {"last_error": "Check failed"}}},
    }))
    (cfg.paths.state_dir / "administration.jsonl").write_text("\n".join(json.dumps(entry) for entry in [
        {"request_id": "same", "action": "device.probe", "outcome": "requested"},
        {"request_id": "same", "action": "device.probe", "outcome": "failed", "status": 502,
         "error": "TLS failed private-health-secret", "error_type": "PinMismatch"},
    ]) + "\ninvalid partial JSON")
    sign_in(client)
    result = client.get("/api/health")
    assert result.status_code == 200
    health = result.json()
    assert health["devices"][0]["nitro"]["failures"] == 2
    assert health["devices"][0]["exposure"]["last_error"] == "Check failed"
    assert health["resources"]["cpu_count"] == 4
    assert health["database"]["hunt_runs"] == 0
    assert len(health["actions"]["items"]) == 1
    assert health["actions"]["items"][0]["error_type"] == "PinMismatch"
    assert "private-health-secret" not in result.text


def test_exposure_coverage_and_sink_health_reach_the_browser(web) -> None:  # type: ignore[no-untyped-def]
    from scalar.redact import registry

    client, cfg, database = web
    registry.register("private-relay-secret")
    now = datetime.now(UTC)
    posture = {"assessed_at": now.isoformat(), "version": "13.1 64.23", "train": "13.1",
               "worst": "vulnerable", "lifecycle": "end_of_maintenance",
               "min_safe_build": "64.29", "actionable": ["CVE-2026-107406"],
               "needs_attention": [], "warnings": []}
    coverage = [{"source": "ns.log", "lines": 4, "last_received": now.isoformat(),
                 "expected": True},
                {"source": "shell (bash.log/sh.log)", "lines": 0, "last_received": None,
                 "expected": True}]
    (cfg.paths.state_dir / "status.json").write_text(json.dumps({
        "state": "degraded", "updated_at": now.isoformat(),
        "devices": {"gateway": {
            "nitro": {}, "exposure": {"posture": posture},
            "syslog": {"source_coverage": coverage,
                       "missing_sources": ["shell (bash.log/sh.log)"]}}},
        "notifications": {"webhook": {"failing": True, "failing_since": now.isoformat(),
                                      "alerted": True, "last_failure": now.isoformat(),
                                      "last_error": "not exposed to the browser"}},
    }))
    queued = now - timedelta(minutes=30)
    database.save_finding(Finding("w", "r", "t", Severity.HIGH, "health", None, "s"),
                          ["webhook"], now=queued)
    for delivery in database.pending(now):
        database.delivery_result(delivery, "relay refused private-relay-secret", now)
    sign_in(client)
    assert client.get("/api/devices").json()["items"][0]["posture"] == posture
    health = client.get("/api/health").json()
    device = health["devices"][0]
    assert device["exposure"]["posture"]["min_safe_build"] == "64.29"
    assert device["syslog"]["source_coverage"] == coverage
    sink = client.get("/api/delivery").json()["sinks"][0]
    assert health["delivery"]["sinks"] == [sink]
    assert sink["pending"] == 1 and sink["max_attempts"] == 1
    assert sink["oldest_undelivered"] == queued.isoformat()
    assert sink["health"] == {"failing": True, "failing_since": now.isoformat(),
                              "alerted": True, "last_failure": now.isoformat()}
    assert sink["error"] == "relay refused ***REDACTED***"
    script = client.get("/static/app.js").text
    for label in ("Minimum safe build", "Exposure posture", "Log source coverage",
                  "Never received", "Failing since (UTC)", "Oldest queued (UTC)"):
        assert label in script
    assert "innerHTML" not in script and "insertAdjacentHTML" not in script


@pytest.mark.parametrize("role,count", [("viewer", 0), ("operator", 1), ("admin", 2)])
def test_health_respects_action_diagnostic_permissions(web, role: str, count: int) -> None:  # type: ignore[no-untyped-def]
    client, cfg, _database = web
    update_user(cfg.paths.state_dir / "web-users.json", "health-user", password=PASSWORD, role=role)
    (cfg.paths.state_dir / "administration.jsonl").write_text("\n".join(json.dumps(entry) for entry in [
        {"action": "users.save", "actor": "admin", "outcome": "failed"},
        {"action": "device.probe", "actor": "admin", "outcome": "failed"},
    ]))
    client.post("/api/login", json={"username": "health-user", "password": PASSWORD})
    result = client.get("/api/health").json()
    assert len(result["actions"]["items"]) == count
    if role == "operator":
        assert "actor" not in result["actions"]["items"][0]


def test_stale_status_is_not_healthy(web) -> None:  # type: ignore[no-untyped-def]
    client, cfg, _database = web
    (cfg.paths.state_dir / "status.json").write_text(
        json.dumps(
            {
                "state": "healthy",
                "updated_at": (datetime.now(UTC) - timedelta(minutes=2)).isoformat(),
                "devices": {"gateway": {"nitro": {"last_ok": datetime.now(UTC).isoformat()}}},
            }
        )
    )
    sign_in(client)
    result = client.get("/api/overview").json()
    assert result["status"]["state"] == "stale"
    assert result["devices"][0]["state"] == "unmonitored"


def test_disabled_spki_is_not_reported_as_an_active_pin(web) -> None:  # type: ignore[no-untyped-def]
    _client, cfg, database = web
    device = cfg.devices[0].model_copy(update={"spki_pin": "retained-pin", "spki_pinning": False})
    updated = cfg.model_copy(update={"devices": [device]})
    with TestClient(create_app(updated, database)) as client:
        sign_in(client)
        assert client.get("/api/devices").json()["items"][0]["pinned"] is False
    assert device.spki_pin == "retained-pin"


def test_host_and_transport_safety(web) -> None:  # type: ignore[no-untyped-def]
    client, _cfg, _database = web
    assert client.get("/api/auth", headers={"host": "attacker.test"}).status_code == 400
    with pytest.raises(ValueError, match="HTTPS"):
        Config.model_validate({"web": {"host": "0.0.0.0"}})
    assert client.get("/api/auth").headers["x-frame-options"] == "DENY"


def test_packaged_ui_and_preview_are_isolated() -> None:
    from scalar.web.demo import preview_app

    app = preview_app()
    with TestClient(app, base_url="http://localhost") as client:
        assert client.get("/").status_code == 200
        assert client.get("/static/style.css").status_code == 200
        assert client.get("/static/theme.js").status_code == 200
        assert client.get("/static/lucide.min.js").status_code == 200
        assert client.get("/static/plex-regular.woff2").status_code == 200
        assert client.get("/api/session").json()["demo"] is True
        assert len(client.get("/api/devices").json()["items"]) == 4
        assert (
            client.post(
                "/api/delivery/test", json={}, headers={"x-csrf-token": "preview"}
            ).status_code
            == 409
        )
    app.state.preview_database.close()
    app.state.preview_directory.cleanup()


def test_packaged_ui_has_secure_forensic_finding_presentation(web) -> None:  # type: ignore[no-untyped-def]
    client, _cfg, database = web
    database.save_finding(
        Finding(
            "forensic",
            "config-running",
            "Configuration changed",
            Severity.HIGH,
            "config_change",
            "gateway",
            "A management user was added.",
            evidence={
                "new_users": ["breakglass"],
                "why_it_matters": "The account can administer the appliance.",
                "remediation": ["Validate the change ticket", "Disable if unauthorized"],
                "attribution": [],
                "unattributed": True,
                "diff": "+ add system user breakglass [REDACTED]",
            },
            cve=("CVE-2025-5777",),
        ),
        [],
    )
    sign_in(client)
    item = client.get("/api/records/findings").json()["items"][0]
    assert item["evidence"]["new_users"] == ["breakglass"]
    assert item["evidence"]["attribution"] == []
    assert item["cve"] == ["CVE-2025-5777"]

    script = client.get("/static/app.js")
    assert script.status_code == 200
    for label in (
        "WHAT HAPPENED",
        "Affected or new users",
        "Why it matters",
        "Remediation",
        "Attribution",
        "Evidence",
    ):
        assert label in script.text
    assert "innerHTML" not in script.text
    assert "default-src 'self'" in client.get("/").headers["content-security-policy"]
    admin_script = client.get("/static/admin.js").text
    assert "Apply saved settings" not in admin_script
    assert 'call("settings.apply")' not in admin_script


def test_https_cookies_and_http_redirect(web) -> None:  # type: ignore[no-untyped-def]
    _client, cfg, database = web
    config = cfg.model_copy(update={"web": cfg.web.model_copy(
        update={"public_url": "https://testserver"})})
    app = create_app(config, database)
    with TestClient(app, base_url="https://testserver") as client:
        response = client.post("/api/login", json={"username": "admin", "password": PASSWORD})
        assert response.status_code == 200
        assert "Secure" in response.headers["set-cookie"]
        assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    with TestClient(app, base_url="http://testserver", follow_redirects=False) as client:
        response = client.get("/")
        assert response.status_code == 307
        assert response.headers["location"] == "https://testserver/"


def test_login_validation_does_not_echo_passwords(web) -> None:  # type: ignore[no-untyped-def]
    client, _cfg, _database = web
    password = "sensitive-test-value-" * 30
    response = client.post("/api/login", json={"username": "admin", "password": password})
    assert response.status_code == 422
    assert "sensitive-test-value" not in response.text
    response = client.post("/api/login", json={"username": "admin", "password": "x" * 9000})
    assert response.status_code == 413


def test_password_reset_revokes_browser_session(web) -> None:  # type: ignore[no-untyped-def]
    client, cfg, _database = web
    sign_in(client)
    assert client.get("/api/session").status_code == 200
    set_password(cfg.paths.state_dir / "web-users.json", "admin", "a-new-test-only-password")
    assert client.get("/api/session").status_code == 401


def test_database_outage_is_explicit_and_does_not_leak_details(web,
                                                             monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    client, _cfg, database = web
    sign_in(client)

    def unavailable() -> None:
        raise SQLAlchemyError("private database connection details")

    monkeypatch.setattr(database, "counts", unavailable)
    response = client.get("/api/overview")
    assert response.status_code == 200
    assert response.json()["database"]["available"] is False
    assert "private database" not in response.text


@pytest.mark.parametrize("role,action,expected", [
    ("viewer", "users.list", 403), ("viewer", "monitor.pause", 403),
    ("operator", "settings.save", 403), ("operator", "device.probe", 200),
    ("admin", "users.list", 200), ("admin", "shell", 403),
    ("viewer", "logs.list", 403), ("viewer", "logs.fetch", 403),
    ("viewer", "logs.read", 403), ("viewer", "logs.hunt", 403),
    ("operator", "logs.fetch", 200), ("operator", "logs.hunt", 200),
    ("viewer", "hunts.list", 403), ("viewer", "hunts.get", 403),
    ("operator", "hunts.list", 200), ("operator", "hunts.get", 200),
    ("operator", "rules.save", 403), ("operator", "rules.delete", 403),
    ("operator", "rules.enabled", 403), ("admin", "rules.save", 200),
])
def test_admin_api_enforces_roles_before_daemon_call(web, role: str, action: str,
                                                    expected: int) -> None:  # type: ignore[no-untyped-def]
    _client, cfg, database = web
    update_user(cfg.paths.state_dir / "web-users.json", "test-user", password=PASSWORD, role=role)
    calls = []

    class Control:
        async def call(self, actor, action, parameters=None):  # type: ignore[no-untyped-def]
            calls.append((actor, action))
            return {"ok": True}

    with TestClient(create_app(cfg, database, control=Control())) as client:
        result = client.post("/api/login", json={"username": "test-user", "password": PASSWORD})
        headers = {"x-csrf-token": result.json()["csrf"]}
        assert client.get("/api/session").json()["role"] == role
        response = client.post("/api/admin/action", json={"action": action}, headers=headers)
        assert response.status_code == expected, response.text
        assert calls == ([("test-user", action)] if expected == 200 else [])


def test_administration_requires_recent_authentication(web,
                                                       monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    import time
    from types import SimpleNamespace

    from scalar.web import app as app_module

    client, _cfg, _database = web
    headers = sign_in(client)
    monkeypatch.setattr(app_module, "time", SimpleNamespace(monotonic=lambda: time.monotonic() + 601))
    response = client.post("/api/admin/action", json={"action": "monitor.pause"}, headers=headers)
    assert response.status_code == 428
    monkeypatch.setattr(app_module, "time", time)
    assert client.post("/api/reauth", json={"password": "wrong-password"}, headers=headers).status_code == 403
    assert client.post("/api/reauth", json={"password": PASSWORD}, headers=headers).status_code == 200


@requires_peercred
def test_full_stack_web_daemon_administration_roundtrip() -> None:
    from tests.emulator.admin import TEST_PASSWORD, create_test_app

    app = create_test_app()
    with TestClient(app) as client:
        result = client.post("/api/login", json={"username": "test-admin", "password": TEST_PASSWORD})
        headers = {"x-csrf-token": result.json()["csrf"]}

        def action(name: str, parameters=None):  # type: ignore[no-untyped-def]
            response = client.post("/api/admin/action", json={"action": name,
                                    "parameters": parameters or {}}, headers=headers)
            assert response.status_code == 200, response.text
            return response.json()

        assert action("users.list")["items"]
        assert 'href="#detection"' in client.get("/").text
        logs = action("logs.fetch", {"device": "test-gateway", "sources": ["nslog"]})
        assert len(logs["captures"]) == 1
        hunt = action("logs.hunt", {"device": "test-gateway", "source": "nslog"})
        assert hunt["findings"]
        assert hunt["capture"]["path"] == "/var/log/ns.log"
        history = action("hunts.list")
        assert history["total"] == 1
        saved_hunt = action("hunts.get", {"id": hunt["run"]["id"]})
        assert saved_hunt["result"]["findings"] == hunt["findings"]
        templates = action("rules.templates")
        assert len(templates["items"]) == 17
        rules = action("rules.list")
        added = action("rules.save", {"text": templates["items"][0]["yaml"],
                          "revision": rules["revision"]})
        assert added["tested"] >= 2
        scripted = action("tools.hunt", {"text": "pitboss NSPPE-00;id; unexpectedly died"})
        assert "custom-ctx-log-poisoning" in {finding["rule_id"] for finding in scripted["findings"]}
        assert action("hunts.list")["total"] == 2
        action("users.save", {"name": "new-viewer", "role": "viewer", "password": TEST_PASSWORD,
                              "create": True})
        action("credentials.save", {"name": "spare", "username": "monitor", "password": TEST_PASSWORD})
        credentials = action("credentials.list")
        assert TEST_PASSWORD not in json.dumps(credentials)
        assert all("password" not in item for item in credentials["items"])
        settings = action("settings.get")
        settings["document"]["max_credential_age_days"] = 75
        settings["document"]["devices"][0]["spki_pinning"] = False
        saved = action("settings.save", {"document": settings["document"],
                         "revision": settings["revision"]})
        assert saved["applied"] and not saved["pending_apply"]
        assert not saved["web_reload"]
        assert app.state.test_service.cfg.max_credential_age_days == 75
        assert not app.state.test_service.cfg.devices[0].spki_pinning
        assert app.state.test_service.cfg.devices[0].spki_pin == "test-pin"
        assert action("monitor.pause")["paused"]
        assert action("device.probe", {"device": "test-gateway"})["version"]
        assert not action("monitor.resume")["paused"]
        action("credentials.delete", {"name": "spare"})
        action("users.delete", {"name": "new-viewer"})
        assert action("audit.list")["items"]


def test_account_throttle_holds_across_source_addresses(tmp_path: Path) -> None:
    path = tmp_path / "users.json"
    set_password(path, "admin", PASSWORD)
    store = AuthStore(path)
    for number in range(10):
        with pytest.raises(AuthenticationError):
            store.login("admin", "wrong-password", f"192.0.2.{number}")
    with pytest.raises(LoginThrottled):
        store.login("admin", PASSWORD, "192.0.2.200")


def test_user_file_changes_apply_despite_caching(tmp_path: Path) -> None:
    path = tmp_path / "users.json"
    set_password(path, "admin", PASSWORD)
    store = AuthStore(path)
    token, _session = store.login("admin", PASSWORD, "192.0.2.1")
    assert store.session(token) is not None
    update_user(path, "second", password=PASSWORD, role="viewer")
    update_user(path, "admin", password=PASSWORD + "-new")
    assert store.session(token) is None  # password change invalidates the cached session


def test_unauthenticated_status_hides_version(web) -> None:  # type: ignore[no-untyped-def]
    client, _cfg, _database = web
    assert "version" not in client.get("/api/auth").json()
