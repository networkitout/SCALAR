"""The Finding: the single alertable unit every detector produces."""

from __future__ import annotations

import enum
import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Any

from scalar.detect.config_diff import ConfigDiff
from scalar.detect.config_forensics import ConfigForensicReport, ForensicCheck
from scalar.detect.exposure import (
    STALE_AFTER_DAYS,
    AdvisoryResult,
    CveData,
    ExposureReport,
    Status,
)
from scalar.detect.rules import RuleHit
from scalar.detect.sessions import SessionReuse
from scalar.detect.severity import Severity
from scalar.redact import registry


@dataclass(frozen=True, slots=True)
class Finding:
    dedup_key: str
    rule_id: str
    title: str
    severity: Severity
    category: str  # config_change | log_rule | session_reuse | exposure | sweep | health
    device: str | None
    summary: str
    observed_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    evidence: dict[str, Any] = field(default_factory=dict)
    cve: tuple[str, ...] = ()
    mitre: tuple[str, ...] = ()
    references: tuple[str, ...] = ()


def finding_document(finding: Finding) -> dict[str, Any]:
    doc = asdict(finding)
    doc["severity"] = str(finding.severity)
    doc["observed_at"] = finding.observed_at.isoformat()
    result: dict[str, Any] = json.loads(json.dumps(registry.scrub_value(doc), default=str))
    return result


def finding_from_document(doc: dict[str, Any]) -> Finding:
    values = {**doc, "severity": Severity.parse(doc["severity"]),
              "observed_at": datetime.fromisoformat(doc["observed_at"])}
    for key in ("cve", "mitre", "references"):
        values[key] = tuple(values.get(key, []))
    values.pop("deliveries", None)
    return Finding(**values)


def from_rule_hit(hit: RuleHit) -> Finding:
    ev = hit.event
    evidence: dict[str, Any] = {"source": ev.source, "line": ev.raw, "fields": dict(ev.fields)}
    if hit.count > 1:
        evidence["count"] = hit.count
        evidence["group"] = list(hit.group)
    return Finding(
        dedup_key=hit.dedup_key,
        rule_id=hit.rule.id,
        title=hit.rule.title,
        severity=hit.rule.severity,
        category="log_rule",
        device=ev.device,
        summary=f"{hit.rule.title} on {ev.device}"
                + (f" ({hit.count} events)" if hit.count > 1 else ""),
        observed_at=ev.ts or datetime.now(UTC),
        evidence=evidence,
        cve=hit.rule.cve,
        mitre=hit.rule.mitre,
        references=hit.rule.references,
    )


def from_session_reuse(r: SessionReuse) -> Finding:
    return Finding(
        dedup_key=r.dedup_key,
        rule_id="session-reuse",
        title="Gateway session reused from a second IP address",
        severity=Severity.HIGH,
        category="session_reuse",
        device=r.device,
        summary=(f"Session {r.session_id} (user {r.user or '?'}) established from "
                 f"{r.original_ip} was used from {r.new_ip}"),
        observed_at=r.seen_at,
        evidence={"session_id": r.session_id, "user": r.user, "original_ip": r.original_ip,
                  "new_ip": r.new_ip, "first_seen": r.first_seen.isoformat()},
        cve=("CVE-2023-4966", "CVE-2025-5777"),
        mitre=("T1550.004",),
    )


class AuditStatus(enum.StrEnum):
    """State of the audit-log source behind a config-change attribution."""

    AVAILABLE = "available"  # checked; an empty attribution means nobody made the change
    DISABLED = "disabled"  # no audit source configured; no escalation
    UNAVAILABLE = "unavailable"  # syslog expected, but the feed is silent, errored or lagging


class AuditTrail(list[str]):
    """Attribution entries from the audit log (Database.audit_since), plus the management
    events it ignored because they are dated in the future (clock skew or forgery)."""

    def __init__(self, entries: Iterable[str] = (), *, future_ignored: int = 0,
                 future_max: timedelta | None = None) -> None:
        super().__init__(entries)
        self.future_ignored = future_ignored
        self.future_max = future_max

    @property
    def skew_note(self) -> str:
        if not self.future_ignored:
            return ""
        minutes = int((self.future_max or timedelta()).total_seconds() // 60)
        return (f"{self.future_ignored} audit events ignored: dated up to {minutes} min in "
                "the future (appliance clock skew or forged timestamps?)")


def from_config_diff(device: str, diff: ConfigDiff, *, kind: str,
                     attribution: list[str] | None, snapshot_id: str,
                     attribution_status: str | None = None,
                     audit_unavailable_since: datetime | None = None) -> Finding:
    """``attribution`` None means no audit-log source is available (no escalation);
    an empty list means the audit log was checked and nobody made this change.
    ``attribution_status`` "unavailable" (see AuditStatus) means the audit feed should exist
    but cannot be trusted: running/saved changes without attribution become at least HIGH."""
    status = AuditStatus(attribution_status) if attribution_status is not None else None
    counts = diff.counts()
    title = {"running": "NetScaler running configuration changed",
             "saved": "NetScaler saved configuration (ns.conf) changed",
             "drift": "Unsaved changes: running config differs from ns.conf",
             "peer": "HA peers have diverging configuration"}[kind]
    attributable = kind in ("running", "saved")
    feed_down = attributable and status is AuditStatus.UNAVAILABLE and not attribution
    unattributed = attributable and attribution == [] and not feed_down
    severity = diff.max_severity
    if (unattributed or feed_down) and severity < Severity.HIGH:
        severity = Severity.HIGH
    since = audit_unavailable_since.isoformat() if audit_unavailable_since else None
    feed_note = (f"audit feed unavailable since {since}" if since else
                 "audit feed unavailable (no audit data received)")
    skew = attribution.skew_note if isinstance(attribution, AuditTrail) else ""
    summary = (f"{title} on {device}: {diff.summarize()}" +
               (f"; by {', '.join(attribution)}" if attribution else
                ("; NO matching audit-log entry (unattributed)" if unattributed else
                 (f"; {feed_note}, so the change cannot be attributed" if feed_down else ""))))
    if skew and attributable and not attribution:
        summary += f"; {skew}"
    evidence: dict[str, Any] = {
        "diff": diff.render(limit=200), "counts": counts,
        "attribution": list(attribution) if attribution is not None else None,
        "unattributed": unattributed,
        "attribution_status": str(status) if status else None,
        "rules": sorted({rid for c in diff.changes for rid in c.rule_ids}),
    }
    if feed_down:
        evidence["audit_feed"] = feed_note
        evidence["audit_unavailable_since"] = since
    if skew:
        evidence["audit_clock_skew"] = skew
    return Finding(
        dedup_key=f"config-{kind}|{device}|{snapshot_id}",
        rule_id=f"config-{kind}",
        title=title,
        severity=severity,
        category="config_change",
        device=device,
        summary=summary,
        evidence=evidence,
    )


def from_forensic_check(check: ForensicCheck, *, device: str | None = None,
                       observed_at: datetime | None = None) -> Finding:
    return Finding(
        dedup_key=check.dedup_key,
        rule_id=check.id,
        title=check.title,
        severity=check.severity,
        category="config_change",
        device=device,
        summary=check.summary,
        observed_at=observed_at or datetime.now(UTC),
        evidence={
            "evidence": list(check.evidence),
            "remediation": check.remediation,
            "cves": list(check.cves),
            "mitre": list(check.mitre),
            "references": list(check.references),
        },
        cve=check.cves,
        mitre=check.mitre,
        references=check.references,
    )


def from_forensic_report(report: ConfigForensicReport,
                        *, observed_at: datetime | None = None) -> list[Finding]:
    return [from_forensic_check(check, device=report.device, observed_at=observed_at)
            for check in report.checks]


def _report_context(report: ExposureReport) -> dict[str, Any]:
    return {"data_version": report.data_version.isoformat() if report.data_version else None,
            "min_safe_build": str(report.min_safe_build) if report.min_safe_build else None}


def _advisory_evidence(report: ExposureReport, r: AdvisoryResult) -> dict[str, Any]:
    a = r.advisory
    return {"version": str(report.version), "status": str(r.status),
            "gate": r.gate_detail, "bulletin": a.bulletin,
            "exploited": a.exploited, "verified_data": a.verified, "verified": a.verified,
            "post_patch_actions": list(a.post_patch_actions), **_report_context(report)}


def from_exposure(report: ExposureReport) -> list[Finding]:
    out = []
    for r in report.actionable:
        a = r.advisory
        possibly = r.status is Status.POSSIBLY_EXPOSED
        out.append(Finding(
            dedup_key=f"exposure|{report.device}|{a.id}|{report.version.build}",
            rule_id=f"exposure-{a.id}",
            title=f"{'Possibly exposed' if possibly else 'Vulnerable'} to {a.id}: {a.title}",
            severity=Severity.parse(a.severity) if not possibly else Severity.HIGH,
            category="exposure",
            device=report.device,
            summary=(f"{report.device} runs {report.version}; fixed in "
                     f"{report.version.train}-{r.fixed_in}" if r.fixed_in else
                     f"{report.device} runs {report.version}; no fix on this train"),
            evidence=_advisory_evidence(report, r),
            cve=(a.id,),
        ))
    return out


def from_exposure_attention(report: ExposureReport) -> list[Finding]:
    """HIGH findings for exposure that cannot be determined (ExposureReport.needs_attention):
    one per device when no advisory covers the train, else one per exploited advisory."""
    pending = report.needs_attention
    v = report.version
    if not pending:
        return []
    if report.train_unknown:
        exploited = tuple(r.advisory.id for r in pending if r.advisory.exploited)
        return [Finding(
            dedup_key=f"exposure-unknown|{report.device}|{v.train}|{v.build}",
            rule_id="exposure-unknown-train",
            title=f"Cannot determine exposure (train {v.train} not in advisory data)",
            severity=Severity.HIGH,
            category="exposure",
            device=report.device,
            summary=(f"{report.device} runs {v}; no advisory in the CVE table covers train "
                     f"{v.train}, so exposure to {len(pending)} advisories "
                     f"({len(exploited)} exploited) is unknown"),
            evidence={"version": str(v), "status": str(Status.UNKNOWN), "train": v.train,
                      "advisories": [r.advisory.id for r in pending],
                      "exploited_advisories": list(exploited), **_report_context(report),
                      "remediation": "Check the Citrix security bulletins for this release, "
                                     "update the CVE table, and set 'firmware_variant' on "
                                     "the device if the train was detected wrongly."},
            cve=exploited,
        )]
    return [Finding(
        dedup_key=f"exposure-unknown|{report.device}|{r.advisory.id}|{v.build}",
        rule_id=f"exposure-unknown-{r.advisory.id}",
        title=f"Cannot determine exposure to {r.advisory.id} (train {v.train} not in "
              "advisory data)",
        severity=Severity.HIGH,
        category="exposure",
        device=report.device,
        summary=(f"{report.device} runs {v}; {r.advisory.id} ({r.advisory.title}) is "
                 f"exploited, but the advisory data has no entry for train {v.train}"),
        evidence={**_advisory_evidence(report, r),
                  "remediation": f"Check bulletin {r.advisory.bulletin or r.advisory.id} "
                                 f"for train {v.train} and treat the device as exposed "
                                 "until it is confirmed fixed."},
        cve=(r.advisory.id,),
    ) for r in pending]


def from_stale_cve_data(data: CveData, today: date | None = None) -> Finding | None:
    """Health finding once the bundled advisory data is older than STALE_AFTER_DAYS."""
    if not data.is_stale(today):
        return None
    age = data.age_days(today)
    version = data.data_version.isoformat()
    return Finding(
        dedup_key=f"exposure-data-stale|{version}",
        rule_id="exposure-data-stale",
        title="Advisory data for exposure checks is out of date",
        severity=Severity.MEDIUM,
        category="health",
        device=None,
        summary=(f"The CVE table is {age} days old (data_version {version}); advisories "
                 "published since then are not checked"),
        evidence={"data_version": version, "age_days": age,
                  "stale_after_days": STALE_AFTER_DAYS,
                  "remediation": "Update scalar's advisory data and check the Citrix "
                                 "security bulletins for newer advisories."},
    )


_LIFECYCLE = {"end_of_maintenance": (Severity.MEDIUM, "end of maintenance"),
              "end_of_life": (Severity.HIGH, "end of life")}


def from_exposure_lifecycle(report: ExposureReport) -> Finding | None:
    """Per-device finding while the firmware train is at end of maintenance or life."""
    entry = _LIFECYCLE.get(report.lifecycle_status)
    if entry is None:
        return None
    severity, label = entry
    v = report.version
    note = f" ({report.lifecycle_note})" if report.lifecycle_note else ""
    return Finding(
        dedup_key=f"exposure-lifecycle|{report.device}|{v.train}|{report.lifecycle_status}",
        rule_id="exposure-lifecycle",
        title=f"Firmware train {v.train} is at {label}",
        severity=severity,
        category="exposure",
        device=report.device,
        summary=f"{report.device} runs {v}; {v.train} is at {label}{note}",
        evidence={"version": str(v), "train": v.train, "lifecycle": report.lifecycle_status,
                  "note": report.lifecycle_note, **_report_context(report),
                  "remediation": "Plan an upgrade to a supported release train."},
    )
