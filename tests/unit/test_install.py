import os
import stat
import subprocess
import sys
from configparser import ConfigParser
from pathlib import Path

import pytest

from netrescale import __version__

INSTALLER = Path(__file__).parents[2] / "deploy" / "install.sh"


def test_appliance_egress_is_limited_to_configured_management_addresses(tmp_path: Path) -> None:
    from netrescale.appliance import allow_appliance_network
    from netrescale.config import Config, Device

    cfg = Config(devices=[Device(name="one", nsip="192.0.2.10", syslog_sources=["198.51.100.4"]),
                          Device(name="two", nsip="2001:db8::10")])
    path = tmp_path / "service.d" / "30-appliance-egress.conf"
    addresses = allow_appliance_network(cfg, path)
    assert addresses == ["192.0.2.10/32", "2001:db8::10/128"]
    assert "IPAddressAllow=192.0.2.10/32" in path.read_text()
    assert "IPAddressAllow=2001:db8::10/128" in path.read_text()
    assert "198.51.100.4" not in path.read_text()
    assert "IPAddressDeny" not in path.read_text()
    allow_appliance_network(cfg.model_copy(update={"devices": cfg.devices[:1]}), path)
    assert "2001:db8" not in path.read_text()


def test_appliance_egress_preserves_unmanaged_files_and_rejects_empty_inventory(tmp_path: Path) -> None:
    from netrescale.appliance import allow_appliance_network
    from netrescale.config import Config, Device

    path = tmp_path / "custom.conf"
    path.write_text("[Service]\nMemoryMax=1G\n")
    with pytest.raises(ValueError, match="unmanaged"):
        allow_appliance_network(Config(devices=[Device(name="one", nsip="192.0.2.10")]), path)
    assert path.read_text() == "[Service]\nMemoryMax=1G\n"
    with pytest.raises(ValueError, match="no device"):
        allow_appliance_network(Config(), tmp_path / "empty.conf")
    assert not (tmp_path / "empty.conf").exists()


@pytest.mark.parametrize("address", ["fe80::1%eth0", "fe80::1%eth0\nIPAddressDeny="])
def test_appliance_egress_rejects_scoped_addresses(tmp_path: Path, address: str) -> None:
    from netrescale.appliance import allow_appliance_network
    from netrescale.config import Config, Device

    path = tmp_path / "egress.conf"
    with pytest.raises(ValueError):
        allow_appliance_network(Config(devices=[Device(name="device", nsip=address)]), path)
    assert not path.exists()


@pytest.mark.linux
def test_installer_syntax() -> None:
    subprocess.run(["bash", "-n", str(INSTALLER)], check=True)


@pytest.mark.linux
@pytest.mark.parametrize("same_directory", [True, False])
def test_installer_readme_copy(tmp_path: Path, same_directory: bool) -> None:
    source = tmp_path / "source"
    source.mkdir()
    destination = source if same_directory else tmp_path / "target"
    destination.mkdir(exist_ok=True)
    (source / "README.md").write_text("release documentation\n")
    script = INSTALLER.read_text()
    start = script.index('if [[ ! "$SRC_DIR/README.md" -ef "$PREFIX/README.md" ]]')
    block = script[start:script.index("\nfi", start) + 3]
    subprocess.run(["bash", "-eu", "-c", block], check=True,
                   env={**os.environ, "SRC_DIR": str(source), "PREFIX": str(destination)})
    assert (destination / "README.md").read_text() == "release documentation\n"


def test_web_unit_has_no_vault_credential_and_is_local_only() -> None:
    config = ConfigParser(interpolation=None)
    config.read(INSTALLER.parent / "netrescale-web.service")
    service = config["Service"]
    assert service["User"] == "netrescale"
    assert service["IPAddressDeny"] == "any"
    assert service["IPAddressAllow"] == "localhost"
    assert "LoadCredentialEncrypted" not in service
    assert "/var/lib/netrescale/vault" in service["InaccessiblePaths"]
    assert service["ExecStart"].endswith("web serve")


def test_only_monitoring_unit_can_write_application_settings() -> None:
    monitor = ConfigParser(interpolation=None, strict=False)
    monitor.read(INSTALLER.parent / "netrescale.service")
    assert monitor["Service"]["ReadWritePaths"] == "/etc/netrescale"
    web = ConfigParser(interpolation=None)
    web.read(INSTALLER.parent / "netrescale-web.service")
    assert "/etc/netrescale" in web["Service"]["ReadOnlyPaths"]
    assert "ReadWritePaths" not in web["Service"]


@pytest.mark.linux
def test_installer_repairs_application_access_without_exposing_state(tmp_path: Path) -> None:
    prefix = tmp_path / "application"
    executable = prefix / "venv" / "bin" / "netrescale"
    module = prefix / "venv" / "lib" / "module.py"
    executable.parent.mkdir(parents=True)
    module.parent.mkdir()
    executable.write_text("#!/bin/sh\nexit 0\n")
    module.write_text("VERSION = 'test'\n")
    for directory in (prefix, prefix / "venv", executable.parent, module.parent):
        directory.chmod(0o750)
    executable.chmod(0o750)
    module.chmod(0o640)
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    vault = state / "vault"
    vault.write_text("private test data")
    vault.chmod(0o600)

    script = INSTALLER.read_text()
    start = script.index('chmod 0755 "$PREFIX"')
    block = script[start:script.index('\nif [[ ! "$SRC_DIR/README.md"', start)]
    subprocess.run(["bash", "-eu"], input=block, text=True, check=True,
                   env={**os.environ, "PREFIX": str(prefix)})

    assert stat.S_IMODE(prefix.stat().st_mode) == 0o755
    assert stat.S_IMODE(executable.stat().st_mode) == 0o755
    assert stat.S_IMODE(module.stat().st_mode) == 0o644
    assert stat.S_IMODE(state.stat().st_mode) == 0o700
    assert stat.S_IMODE(vault.stat().st_mode) == 0o600


@pytest.mark.linux
@pytest.mark.parametrize("installed_version,web_available,success", [
    (__version__, "yes", True), ("outdated", "yes", False), (__version__, "no", False),
])
def test_installer_verifies_installed_web_cli(tmp_path: Path, installed_version: str,
                                             web_available: str, success: bool) -> None:
    (tmp_path / "venv").symlink_to(Path(sys.executable).parent.parent, target_is_directory=True)
    script = INSTALLER.read_text()
    start = script.index("verify_installation() {")
    block = script[start:script.index("\n}\n", start) + 3] + "\nverify_installation\n"
    helpers = """
die() { printf '%s\\n' "$*" >&2; exit 1; }
runuser() {
    [[ "$1" == "-u" && "$2" == "netrescale" && "$3" == "--" ]] || return 1
    case "${*: -1}" in
        version) printf '%s\\n' "$TEST_VERSION" ;;
        --help) [[ "$TEST_WEB" == "yes" ]] ;;
        validate) return 0 ;;
        "SELECT 1") printf '1\\n' ;;
        *) return 1 ;;
    esac
}
systemd-analyze() { return 0; }
"""
    config_dir = tmp_path / "etc" / "netrescale"
    systemd_dir = tmp_path / "etc" / "systemd" / "system"
    config_dir.mkdir(parents=True)
    systemd_dir.mkdir(parents=True)
    (config_dir / "config.yaml").write_text("devices: []\n")
    (systemd_dir / "netrescale.service").write_text("[Service]\n")
    (systemd_dir / "netrescale-web.service").write_text("[Service]\n")
    block = block.replace("/etc/netrescale", str(config_dir))
    block = block.replace("/etc/systemd/system", str(systemd_dir))
    result = subprocess.run(["bash", "-eu"], input=helpers + block, text=True,
                            capture_output=True, check=False,
                            env={**os.environ, "PREFIX": str(tmp_path),
                                 "SRC_DIR": str(INSTALLER.parent.parent),
                                 "TEST_VERSION": installed_version, "TEST_WEB": web_available})
    assert (result.returncode == 0) is success, result.stderr
    if success:
        assert "CLI, config, units, and database verified" in result.stdout
    else:
        assert "installed CLI version" in result.stderr or "web commands are unavailable" in result.stderr


def test_installer_verify_only_is_read_only_and_documented() -> None:
    script = INSTALLER.read_text()
    case_start = script.index('case "${1:-}" in')
    case_block = script[case_start:script.index("\nesac", case_start)]
    assert "--verify-only)" in case_block
    assert "verify_installation" in case_block
    assert "exit 0" in case_block
    assert case_block.index("verify_installation") < case_block.index("exit 0")
    assert "apt-get" not in case_block
