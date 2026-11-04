from datetime import UTC, date, datetime, timedelta

import pytest

from netrescale.detect.config_diff import diff_configs
from netrescale.detect.config_risk import load_risk_rules
from netrescale.detect.exposure import (
    Advisory,
    CveData,
    DeviceFeatures,
    ExposureReport,
    Status,
    assess,
)
from netrescale.detect.findings import (
    AuditStatus,
    AuditTrail,
    from_config_diff,
    from_exposure,
    from_exposure_attention,
    from_exposure_lifecycle,
    from_rule_hit,
    from_stale_cve_data,
)
from netrescale.detect.rules import RuleEngine, load_rules
from netrescale.detect.severity import Severity
from netrescale.parse.nslog import parse_line
from netrescale.parse.version import Build, parse_version

RULES = load_risk_rules()
LOW_CHANGE = diff_configs("set ns hostName a\n", "set ns hostName a\nadd lb vserver v HTTP\n",
                          RULES)
CRITICAL_CHANGE = diff_configs("set ns hostName a\n",
                               "set ns hostName a\nadd system user evil x\n", RULES)
SINCE = datetime(2026, 10, 5, 9, 58, tzinfo=UTC)


def test_feed_unavailable_escalates_running_and_saved_changes() -> None:
    assert LOW_CHANGE.max_severity < Severity.HIGH
    for kind in ("running", "saved"):
        f = from_config_diff("ns1", LOW_CHANGE, kind=kind, attribution=None, snapshot_id="s1",
                             attribution_status=AuditStatus.UNAVAILABLE,
                             audit_unavailable_since=SINCE)
        assert f.severity is Severity.HIGH
        assert "audit feed unavailable since 2026-10-05T09:58:00+00:00" in f.summary
        assert f.evidence["attribution_status"] == "unavailable"
        assert f.evidence["audit_unavailable_since"] == SINCE.isoformat()
        assert f.evidence["audit_feed"] == "audit feed unavailable since 2026-10-05T09:58:00+00:00"
        assert f.evidence["unattributed"] is False


def test_feed_unavailable_without_timestamp_and_with_plain_string() -> None:
    f = from_config_diff("ns1", LOW_CHANGE, kind="running", attribution=[], snapshot_id="s1",
                         attribution_status="unavailable")
    assert f.severity is Severity.HIGH
    assert "audit feed unavailable" in f.summary and "unattributed" not in f.summary
    assert f.evidence["audit_unavailable_since"] is None


def test_feed_unavailable_never_lowers_or_touches_other_kinds() -> None:
    f = from_config_diff("ns1", CRITICAL_CHANGE, kind="running", attribution=None,
                         snapshot_id="s1", attribution_status="unavailable",
                         audit_unavailable_since=SINCE)
    assert f.severity is Severity.CRITICAL
    for kind in ("drift", "peer"):
        g = from_config_diff("ns1", LOW_CHANGE, kind=kind, attribution=None, snapshot_id="s1",
                             attribution_status="unavailable", audit_unavailable_since=SINCE)
        assert g.severity is LOW_CHANGE.max_severity
        assert "audit feed" not in g.summary


def test_attributed_change_is_not_escalated_even_if_feed_flagged() -> None:
    f = from_config_diff("ns1", LOW_CHANGE, kind="running", attribution=["admin1@10.0.0.5"],
                         snapshot_id="s1", attribution_status="unavailable",
                         audit_unavailable_since=SINCE)
    assert f.severity is LOW_CHANGE.max_severity and "admin1@10.0.0.5" in f.summary


@pytest.mark.parametrize("status", [None, "disabled", "available"])
def test_disabled_or_absent_status_keeps_existing_behavior(status: str | None) -> None:
    f = from_config_diff("ns1", LOW_CHANGE, kind="running", attribution=None, snapshot_id="s1",
                         attribution_status=status)
    assert f.severity is LOW_CHANGE.max_severity
    assert f.summary == f"NetScaler running configuration changed on ns1: {LOW_CHANGE.summarize()}"
    assert f.evidence["attribution_status"] == status
    assert "audit_feed" not in f.evidence
    g = from_config_diff("ns1", LOW_CHANGE, kind="running", attribution=[], snapshot_id="s1",
                         attribution_status=status)
    assert g.severity is Severity.HIGH and g.evidence["unattributed"] is True


def test_future_dated_audit_events_are_reported_without_attributing() -> None:
    skewed = AuditTrail([], future_ignored=3, future_max=timedelta(minutes=17, seconds=40))
    f = from_config_diff("ns1", LOW_CHANGE, kind="running", attribution=skewed,
                         snapshot_id="s1")
    assert f.severity is Severity.HIGH and f.evidence["unattributed"] is True
    note = "3 audit events ignored: dated up to 17 min in the future"
    assert note in f.summary and note in f.evidence["audit_clock_skew"]
    attributed = AuditTrail(["admin1@10.0.0.5: add lb vserver v HTTP"], future_ignored=1,
                            future_max=timedelta(hours=2))
    g = from_config_diff("ns1", LOW_CHANGE, kind="running", attribution=attributed,
                         snapshot_id="s1")
    assert g.severity is LOW_CHANGE.max_severity and "clock skew" not in g.summary
    assert "120 min" in g.evidence["audit_clock_skew"]
    for plain in ([], AuditTrail([])):
        h = from_config_diff("ns1", LOW_CHANGE, kind="running", attribution=plain,
                             snapshot_id="s1")
        assert "audit_clock_skew" not in h.evidence and "future" not in h.summary


def test_unknown_attribution_status_is_rejected() -> None:
    with pytest.raises(ValueError):
        from_config_diff("ns1", LOW_CHANGE, kind="running", attribution=None, snapshot_id="s1",
                         attribution_status="lagging")


def test_rule_hit_finding_carries_evidence_dedup_key() -> None:
    rule = next(r for r in load_rules() if r.id == "mgmt-high-risk-command")
    line = ("2026/10/05:10:00:01 GMT ns1 0-PPE-0 : default GUI CMD_EXECUTED 1 0 : User a - "
            'Remote_ip 10.0.0.5 - Command "add system user x ****" - Status "Success"')
    hit = RuleEngine([rule]).evaluate(parse_line("nslog", line, "ns1"))[0]
    f = from_rule_hit(hit)
    assert f.dedup_key == hit.dedup_key
    assert f.dedup_key.startswith("mgmt-high-risk-command|ns1|") and len(f.dedup_key) > 30


def _advisory(cve: str, *, exploited: bool, fixed: dict[str, str] | None = None,
              not_affected: frozenset[str] = frozenset(),
              requires: tuple[str, ...] = ()) -> Advisory:
    return Advisory(id=cve, title=f"{cve} title", bulletin="CTX000001", exploited=exploited,
                    severity="critical", requires=requires, requires_mode="all",
                    fixed={t: Build.parse(b) for t, b in (fixed or {}).items()},
                    not_affected=not_affected, unfixed=frozenset(),
                    post_patch_actions=("kill icaconnection -all",), verified=False)


DATA = CveData(
    data_version=date(2026, 9, 1),
    lifecycle={"13.1": {"train": "13.1", "status": "end_of_maintenance", "note": "EoM soon"},
               "12.1": {"train": "12.1", "status": "end_of_life"},
               "14.1": {"train": "14.1", "status": "supported"}},
    advisories=(
        _advisory("CVE-2099-0001", exploited=True, fixed={"14.1": "60.10", "13.1": "59.5"},
                  requires=("gateway_or_aaa",)),
        _advisory("CVE-2099-0002", exploited=True, fixed={"14.1": "66.1"}),
        _advisory("CVE-2099-0003", exploited=False, fixed={"14.1": "70.1"}),
        _advisory("CVE-2099-0004", exploited=False, not_affected=frozenset({"14.1"})),
    ),
)


def _report(raw: str, today: date = date(2026, 9, 2)) -> ExposureReport:
    return assess("ns1", parse_version(raw), DeviceFeatures(), DATA, today)


def test_needs_attention_lists_exploited_unknowns() -> None:
    report = _report("NetScaler NS13.1: Build 50.1.nc")
    assert not report.train_unknown
    assert [r.advisory.id for r in report.needs_attention] == ["CVE-2099-0002"]
    findings = from_exposure_attention(report)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity is Severity.HIGH and f.category == "exposure"
    assert f.title == "Cannot determine exposure to CVE-2099-0002 (train 13.1 not in advisory data)"
    assert f.dedup_key == "exposure-unknown|ns1|CVE-2099-0002|50.1"
    assert f.cve == ("CVE-2099-0002",)
    assert f.evidence["data_version"] == "2026-09-01"
    assert f.evidence["exploited"] is True and f.evidence["verified"] is False
    assert f.evidence["bulletin"] == "CTX000001"
    assert f.evidence["min_safe_build"] == "59.5"
    assert _report("NetScaler NS14.1: Build 70.1.nc").needs_attention == []


def test_all_unknown_train_needs_attention_once_per_device() -> None:
    report = _report("NetScaler NS15.1: Build 10.1.nc")
    assert report.train_unknown and report.worst is Status.UNKNOWN
    assert len(report.needs_attention) == 4
    findings = from_exposure_attention(report)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity is Severity.HIGH
    assert f.title == "Cannot determine exposure (train 15.1 not in advisory data)"
    assert f.dedup_key == "exposure-unknown|ns1|15.1|10.1"
    assert f.cve == ("CVE-2099-0001", "CVE-2099-0002")
    assert f.evidence["advisories"] == [f"CVE-2099-000{i}" for i in range(1, 5)]
    assert f.evidence["min_safe_build"] is None


def test_from_exposure_keeps_behavior_and_adds_context() -> None:
    report = _report("NetScaler NS14.1: Build 60.1.nc")
    findings = {f.cve[0]: f for f in from_exposure(report)}
    assert set(findings) == {"CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"}
    f = findings["CVE-2099-0001"]
    assert f.dedup_key == "exposure|ns1|CVE-2099-0001|60.1"
    assert f.severity is Severity.HIGH  # possibly exposed: feature gates unknown
    assert f.title.startswith("Possibly exposed to CVE-2099-0001")
    assert f.summary == "ns1 runs 14.1 60.1; fixed in 14.1-60.10"
    ev = f.evidence
    assert ev["data_version"] == "2026-09-01" and ev["min_safe_build"] == "70.1"
    assert ev["verified"] is False and ev["verified_data"] is False
    assert ev["bulletin"] == "CTX000001" and ev["exploited"] is True
    assert ev["post_patch_actions"] == ["kill icaconnection -all"]


def test_stale_cve_data_health_finding() -> None:
    assert from_stale_cve_data(DATA, date(2026, 9, 20)) is None
    f = from_stale_cve_data(DATA, date(2026, 10, 13))
    assert f is not None
    assert f.dedup_key == "exposure-data-stale|2026-09-01"
    assert f.category == "health" and f.device is None
    assert f.severity is Severity.MEDIUM
    assert f.evidence["data_version"] == "2026-09-01" and f.evidence["age_days"] == 42
    assert "42 days old" in f.summary


def test_lifecycle_findings_per_device() -> None:
    eom = from_exposure_lifecycle(_report("NetScaler NS13.1: Build 59.5.nc"))
    assert eom is not None
    assert eom.dedup_key == "exposure-lifecycle|ns1|13.1|end_of_maintenance"
    assert eom.severity is Severity.MEDIUM and eom.category == "exposure"
    assert "EoM soon" in eom.summary
    eol = from_exposure_lifecycle(_report("NetScaler NS12.1: Build 65.1.nc"))
    assert eol is not None and eol.severity is Severity.HIGH
    assert eol.dedup_key == "exposure-lifecycle|ns1|12.1|end_of_life"
    assert from_exposure_lifecycle(_report("NetScaler NS14.1: Build 70.1.nc")) is None
    assert from_exposure_lifecycle(_report("NetScaler NS15.1: Build 1.1.nc")) is None
