from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from netrescale.collect.config_poller import ConfigPoller
from netrescale.detect.config_risk import load_risk_rules
from netrescale.detect.findings import AuditStatus
from netrescale.detect.severity import Severity
from netrescale.secrets.base import Credential
from netrescale.store.snapshots import FileSnapshotStore
from netrescale.transport.nitro import NitroClient, NitroTarget
from tests.emulator.nitro import FakeNitro

BASE = ("#NS14.1 Build 73.37\n# Last modified by `save config`, Mon Oct  5 10:00:00 2026\n"
        "set ns hostName ns-gw-01\nadd lb vserver web HTTP 10.0.1.10 80\n")
T0 = datetime(2026, 10, 5, 10, 0, tzinfo=UTC)


@pytest.fixture
def fake() -> FakeNitro:
    return FakeNitro(running=BASE, saved=BASE)


@pytest.fixture
def poller(tmp_path: Path) -> ConfigPoller:
    return ConfigPoller("ns-gw-01", FileSnapshotStore(tmp_path / "configs"), load_risk_rules())


def client(fake: FakeNitro) -> NitroClient:
    return NitroClient(NitroTarget("ns-gw-01", "x", spki_pin="p"),
                       lambda: Credential("nr_nitro", "nitro-password"),
                       transport=fake.transport())


async def tick(poller: ConfigPoller, fake: FakeNitro, at: datetime):  # type: ignore[no-untyped-def]
    async with client(fake) as c:
        findings = await poller.tick(c, now=at)
        poller.acknowledge()
        return findings


def change(fake: FakeNitro, running: str | None = None, saved: str | None = None,
           change_time: str = "Mon Oct  5 10:05:00 2026", save_time: str | None = None) -> None:
    if running is not None:
        fake.running = running
        fake.lastconfigchangedtime = change_time
    if saved is not None:
        fake.saved = saved
    if save_time is not None:
        fake.lastconfigsavetime = save_time


async def test_first_tick_is_baseline_only(poller: ConfigPoller, fake: FakeNitro) -> None:
    assert await tick(poller, fake, T0) == []
    assert poller.store.latest("ns-gw-01", "running") is not None


async def test_unchanged_probe_skips_full_fetch(poller: ConfigPoller, fake: FakeNitro) -> None:
    await tick(poller, fake, T0)
    fake.requests.clear()
    assert await tick(poller, fake, T0 + timedelta(minutes=1)) == []
    paths = {r.url.path for r in fake.requests}
    assert "/nitro/v1/config/nsrunningconfig" not in paths


async def test_running_change_then_save(poller: ConfigPoller, fake: FakeNitro) -> None:
    await tick(poller, fake, T0)
    evil = BASE + "add system user backdoor 0123456789abcdef0123 -encrypted\n"
    change(fake, running=evil)
    found = await tick(poller, fake, T0 + timedelta(minutes=1))
    kinds = {f.rule_id: f for f in found}
    assert {"config-running", "config-drift", "suspicious-management-user",
            "management-user-added"} <= set(kinds)
    assert kinds["config-running"].severity is Severity.CRITICAL
    assert "0123456789abcdef0123" not in kinds["config-running"].evidence["diff"]

    # the drift is reported once, not every tick
    fake.lastconfigchangedtime = "Mon Oct  5 10:06:00 2026"
    assert await tick(poller, fake, T0 + timedelta(minutes=2)) == []

    # admin saves -> saved changes, drift clears, no tamper alert
    change(fake, saved=evil, save_time="Mon Oct  5 10:07:00 2026")
    found = await tick(poller, fake, T0 + timedelta(minutes=3))
    ids = {f.rule_id for f in found}
    assert {"config-saved", "suspicious-management-user", "management-user-added"} <= ids


async def test_running_change_emits_forensic_findings(poller: ConfigPoller,
                                                      fake: FakeNitro) -> None:
    await tick(poller, fake, T0)
    evil = BASE + (
        "add system user backdoor 0123456789abcdef0123 -encrypted\n"
        "bind system user backdoor superuser 0\n"
        "set audit syslogParams -logLevel NONE\n"
    )
    change(fake, running=evil)
    found = await tick(poller, fake, T0 + timedelta(minutes=1))
    ids = {f.rule_id for f in found}
    assert {"config-running", "config-drift", "suspicious-management-user",
            "management-user-added", "management-superuser-grant",
            "audit-logging-disabled"} <= ids
    forensic = [f for f in found if f.rule_id in {
        "suspicious-management-user",
        "management-user-added",
        "management-superuser-grant",
        "audit-logging-disabled",
    }]
    assert forensic
    assert all(f.category == "config_change" for f in forensic)
    assert all("0123456789abcdef0123" not in "\n".join(str(v) for v in f.evidence["evidence"]) for f in forensic)


async def test_saved_config_tamper_emits_forensic_findings(poller: ConfigPoller,
                                                           fake: FakeNitro) -> None:
    await tick(poller, fake, T0)
    evil_saved = BASE + (
        "add system user backdoor 0123456789abcdef0123 -encrypted\n"
        "bind system user backdoor superuser 0\n"
        "set audit syslogParams -logLevel NONE\n"
    )
    fake.saved = evil_saved
    found = await tick(poller, fake, T0 + timedelta(hours=7))
    ids = {f.rule_id for f in found}
    assert {"config-saved-tamper", "suspicious-management-user",
            "management-user-added", "management-superuser-grant",
            "audit-logging-disabled"} <= ids
    forensic = [f for f in found if f.rule_id in {
        "suspicious-management-user",
        "management-user-added",
        "management-superuser-grant",
        "audit-logging-disabled",
    }]
    assert forensic
    assert all(f.dedup_key.startswith("config-forensics|") for f in forensic)
    assert all("0123456789abcdef0123" not in "\n".join(str(v) for v in f.evidence["evidence"]) for f in forensic)


async def test_comment_only_change_is_ignored(poller: ConfigPoller, fake: FakeNitro) -> None:
    await tick(poller, fake, T0)
    change(fake, saved=BASE.replace("10:00:00", "11:11:11"), save_time="later")
    assert await tick(poller, fake, T0 + timedelta(minutes=1)) == []


async def test_saved_config_edited_on_disk_is_tamper(poller: ConfigPoller,
                                                     fake: FakeNitro) -> None:
    await tick(poller, fake, T0)
    # attacker appends to ns.conf; no running change, no `save config`
    fake.saved = BASE + "add system user persist 0123456789abcdef0123 -encrypted\n"
    found = await tick(poller, fake, T0 + timedelta(hours=7))  # full refresh due
    ids = {f.rule_id: f for f in found}
    assert "config-saved-tamper" in ids
    assert ids["config-saved-tamper"].severity is Severity.CRITICAL


async def test_save_then_modify_within_one_poll_is_not_tamper(poller: ConfigPoller,
                                                             fake: FakeNitro) -> None:
    await tick(poller, fake, T0)
    a = BASE.replace("10.0.1.10 80", "10.0.1.10 8080")
    b = BASE.replace("10.0.1.10 80", "10.0.1.10 8081")
    change(fake, running=b, saved=a, save_time="Mon Oct  5 10:04:00 2026")
    found = await tick(poller, fake, T0 + timedelta(minutes=1))
    assert "config-saved-tamper" not in {f.rule_id for f in found}
    assert {"config-running", "config-saved", "config-drift"} <= {f.rule_id for f in found}


async def test_attribution_unavailable_vs_empty(tmp_path: Path, fake: FakeNitro) -> None:
    rules = load_risk_rules()
    p = ConfigPoller("ns-gw-01", FileSnapshotStore(tmp_path / "c"), rules,
                     attribution=lambda d, since: [])
    await tick(p, fake, T0)
    change(fake, running=BASE + "add lb vserver web2 HTTP 10.0.1.11 80\n")
    found = {f.rule_id: f for f in await tick(p, fake, T0 + timedelta(minutes=1))}
    assert found["config-running"].severity is Severity.HIGH  # low change, unattributed
    assert found["config-running"].evidence["unattributed"] is True


class AuditLog:
    """AttributionSource and AuditStatusSource double that records its calls."""

    def __init__(self, status: AuditStatus | None, since: datetime | None = None,
                 who: list[str] | None = None) -> None:
        self.result = (status, since)
        self.who = who if who is not None else []
        self.status_calls: list[str] = []
        self.attribution_calls: list[datetime] = []

    async def status(self, device: str, client: NitroClient) -> tuple[AuditStatus | None,
                                                                       datetime | None]:
        assert isinstance(client, NitroClient)
        self.status_calls.append(device)
        return self.result

    def attribution(self, device: str, since: datetime) -> list[str]:
        self.attribution_calls.append(since)
        return self.who


def audited(tmp_path: Path, audit: AuditLog) -> ConfigPoller:
    return ConfigPoller("ns-gw-01", FileSnapshotStore(tmp_path / "c"), load_risk_rules(),
                        attribution=audit.attribution, audit_status=audit.status)


async def test_unavailable_audit_feed_escalates_running_and_saved_changes(
        tmp_path: Path, fake: FakeNitro) -> None:
    seen = T0 - timedelta(minutes=30)
    audit = AuditLog(AuditStatus.UNAVAILABLE, seen)
    p = audited(tmp_path, audit)
    await tick(p, fake, T0)
    new = BASE + "add lb vserver web2 HTTP 10.0.1.11 80\n"
    change(fake, running=new, saved=new, save_time="Mon Oct  5 10:06:00 2026")
    found = {f.rule_id: f for f in await tick(p, fake, T0 + timedelta(minutes=1))}
    assert audit.status_calls == ["ns-gw-01"]  # once per tick, for both changes
    assert audit.attribution_calls == []  # an unavailable feed is not queried
    for kind in ("config-running", "config-saved"):
        f = found[kind]
        assert f.severity is Severity.HIGH and f.evidence["unattributed"] is False
        assert f.evidence["attribution_status"] == "unavailable"
        assert f.evidence["audit_unavailable_since"] == seen.isoformat()
        assert f"audit feed unavailable since {seen.isoformat()}" in f.summary


@pytest.mark.parametrize(("status", "who", "severity", "unattributed"), [
    (AuditStatus.AVAILABLE, ["admin1@10.0.0.5: add lb vserver web2"], Severity.LOW, False),
    (AuditStatus.AVAILABLE, [], Severity.HIGH, True),
    (AuditStatus.DISABLED, None, Severity.LOW, False),
    (None, None, Severity.LOW, False),
])
async def test_attribution_is_looked_up_only_while_the_audit_feed_is_available(
        tmp_path: Path, fake: FakeNitro, status: AuditStatus | None, who: list[str] | None,
        severity: Severity, unattributed: bool) -> None:
    audit = AuditLog(status, who=who)
    p = audited(tmp_path, audit)
    await tick(p, fake, T0)
    change(fake, running=BASE + "add lb vserver web2 HTTP 10.0.1.11 80\n")
    found = {f.rule_id: f for f in await tick(p, fake, T0 + timedelta(minutes=1))}
    f = found["config-running"]
    assert f.severity is severity and f.evidence["unattributed"] is unattributed
    assert f.evidence["attribution_status"] == (str(status) if status else None)
    assert f.evidence["attribution"] == (who if status is AuditStatus.AVAILABLE else None)
    assert audit.attribution_calls == ([T0] if status is AuditStatus.AVAILABLE else [])
    assert found["config-drift"].evidence["attribution_status"] is None  # not attributable


async def test_audit_status_is_not_consulted_without_a_change(tmp_path: Path,
                                                              fake: FakeNitro) -> None:
    audit = AuditLog(AuditStatus.UNAVAILABLE, T0)
    p = audited(tmp_path, audit)
    change(fake, running=BASE + "add lb vserver web2 HTTP 10.0.1.11 80\n")
    found = await tick(p, fake, T0)  # baseline, with unsaved changes
    assert [f.rule_id for f in found] == ["config-drift"]
    change(fake, running=fake.running.replace("10:00:00", "10:09:00"), change_time="t2")
    assert await tick(p, fake, T0 + timedelta(minutes=1)) == []  # comment-only
    assert await tick(p, fake, T0 + timedelta(hours=7)) == []  # full refresh, no change
    assert audit.status_calls == [] and audit.attribution_calls == []


async def test_pending_findings_keep_their_audit_status_after_a_restart(
        tmp_path: Path, fake: FakeNitro) -> None:
    p = audited(tmp_path, AuditLog(AuditStatus.UNAVAILABLE, T0))
    await tick(p, fake, T0)
    change(fake, running=BASE + "add lb vserver web2 HTTP 10.0.1.11 80\n")
    async with client(fake) as nitro:
        findings = await p.tick(nitro, now=T0 + timedelta(minutes=1))  # never acknowledged
    later = AuditLog(None)
    restarted = audited(tmp_path, later)
    async with client(fake) as nitro:
        assert await restarted.tick(nitro, now=T0 + timedelta(minutes=2)) == findings
    escalated = next(f for f in findings if f.rule_id == "config-running")
    assert escalated.severity is Severity.HIGH
    assert later.status_calls == []


async def test_snapshot_history_is_kept(poller: ConfigPoller, fake: FakeNitro) -> None:
    await tick(poller, fake, T0)
    for i in range(3):
        change(fake, running=BASE + f"add route 10.{i}.0.0 255.255.0.0 10.0.0.1\n",
               change_time=f"t{i}")
        await tick(poller, fake, T0 + timedelta(minutes=i + 1))
    hist = poller.store.history("ns-gw-01", "running")
    assert len(hist) == 4
    assert "10.2.0.0" in poller.store.content(hist[-1].sha256)


async def test_unacknowledged_alerts_survive_restart(poller: ConfigPoller, fake: FakeNitro) -> None:
    await tick(poller, fake, T0)
    change(fake, running=BASE + "add system user backdoor secret -encrypted\n")
    async with client(fake) as nitro:
        findings = await poller.tick(nitro, now=T0 + timedelta(minutes=1))
    restarted = ConfigPoller(poller.device, poller.store, poller.rules)
    async with client(fake) as nitro:
        assert await restarted.tick(nitro, now=T0 + timedelta(minutes=2)) == findings
    restarted.acknowledge()
    assert await tick(restarted, fake, T0 + timedelta(minutes=3)) == []


async def test_crash_after_snapshot_write_preserves_change(poller: ConfigPoller, fake: FakeNitro,
                                                           monkeypatch: pytest.MonkeyPatch) -> None:
    await tick(poller, fake, T0)
    change(fake, running=BASE + "add system user backdoor secret -encrypted\n")
    original = poller.store.set_state

    def fail_after_snapshots(device, state):  # type: ignore[no-untyped-def]
        if "inflight" not in state and state.get("pending_findings"):
            raise OSError("simulated interrupted write")
        original(device, state)

    monkeypatch.setattr(poller.store, "set_state", fail_after_snapshots)
    with pytest.raises(OSError, match="interrupted"):
        await tick(poller, fake, T0 + timedelta(minutes=1))
    monkeypatch.setattr(poller.store, "set_state", original)
    restarted = ConfigPoller(poller.device, poller.store, poller.rules)
    found = await tick(restarted, fake, T0 + timedelta(minutes=2))
    assert "config-running" in {finding.rule_id for finding in found}
