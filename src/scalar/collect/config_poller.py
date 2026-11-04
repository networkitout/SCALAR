"""Watch one device's configuration and turn every change into a finding.

Each tick:
1. Cheap probe: NITRO ``nsconfig`` (lastconfigchangedtime, lastconfigsavetime, configchanged).
2. If those moved, or a full refresh is due, fetch the running and saved configs.
3. Compare the redacted, comment-free form with the previous snapshot. Comment-only changes
   (like the "Last modified" header) are not changes.
4. Findings:
   * running config changed          -> config-running (severity from the risk rules)
   * saved config changed            -> config-saved
   * saved has lines running lacks   -> config-saved-tamper (critical: ns.conf edited on disk,
                                        persists across reboot, never seen in running)
   * running != saved                -> config-drift (unsaved changes), once per drift state
The first tick only records a baseline. Running/saved changes carry their attribution and the
audit feed's status (from_config_diff), looked up only when such a change is found.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from scalar.detect.config_diff import ConfigDiff, diff_lines
from scalar.detect.config_forensics import analyze_config
from scalar.detect.config_risk import RiskRules
from scalar.detect.findings import (
    AuditStatus,
    Finding,
    finding_document,
    finding_from_document,
    from_config_diff,
    from_forensic_report,
)
from scalar.detect.severity import Severity
from scalar.parse.nsconf import config_lines
from scalar.store.snapshots import Snapshot, SnapshotStore
from scalar.transport.nitro import NitroClient

log = logging.getLogger(__name__)

# (device, since) -> "user@ip: command" strings from the audit log, or None when the log
# pipeline isn't available (then changes are not escalated as unattributed).
AttributionSource = Callable[[str, datetime], list[str] | None]
# (device, client) -> the audit feed's status for this device and when its audit log last
# arrived, or (None, None) when unknown (no escalation). See from_config_diff.
AuditStatusSource = Callable[[str, NitroClient],
                             Awaitable[tuple[AuditStatus | None, datetime | None]]]


@dataclass(frozen=True, slots=True)
class _Audit:
    """What the audit log says about one tick's running/saved changes."""

    attribution: list[str] | None = None
    status: AuditStatus | None = None
    unavailable_since: datetime | None = None


def _norm(text: str) -> tuple[list[str], str]:
    lines = config_lines(text)
    return lines, hashlib.sha256("\n".join(sorted(lines)).encode("utf-8", "replace")).hexdigest()


@dataclass
class ConfigPoller:
    device: str
    store: SnapshotStore
    rules: RiskRules
    full_refresh: timedelta = timedelta(hours=6)
    attribution: AttributionSource | None = None
    # With an audit_status source, attribution is looked up only while the feed is available.
    audit_status: AuditStatusSource | None = None

    async def tick(self, client: NitroClient, now: datetime | None = None) -> list[Finding]:
        now = now or datetime.now(UTC)
        state = self.store.get_state(self.device)
        if state.get("pending_findings"):
            return [finding_from_document(doc) for doc in state["pending_findings"]]
        inflight = state.get("inflight")
        if inflight is None:
            probe = await client.config_state()
            marker = {key: str(probe.get(key)) for key in
                      ("lastconfigchangedtime", "lastconfigsavetime", "configchanged")}
            last_full = state.get("last_full")
            due = last_full is None or now - datetime.fromisoformat(last_full) >= self.full_refresh
            if not due and marker == state.get("marker"):
                return []
            inflight = {"running": await client.running_config(),
                        "saved": await client.saved_config(), "marker": marker,
                        "at": now.isoformat(), "previous": {}}
            for kind in ("running", "saved"):
                previous = self.store.latest(self.device, kind)
                inflight["previous"][kind] = ({"sha256": previous.sha256,
                                                "at": previous.at.isoformat(),
                                                "meta": previous.meta} if previous else None)
            state["inflight"] = inflight
            self.store.set_state(self.device, state)
        previous_snapshots = []
        for kind in ("running", "saved"):
            document = inflight["previous"][kind]
            previous_snapshots.append(Snapshot(
                self.device, kind, document["sha256"], datetime.fromisoformat(document["at"]),
                document["meta"]) if document else None)
        observed = datetime.fromisoformat(inflight["at"])
        findings = await self._evaluate(inflight["running"], inflight["saved"],
                                        inflight["marker"], state, observed,
                                        (previous_snapshots[0], previous_snapshots[1]), client)
        state.update(marker=inflight["marker"], last_full=observed.isoformat(),
                     pending_findings=[finding_document(finding) for finding in findings])
        state.pop("inflight", None)
        self.store.set_state(self.device, state)
        return findings

    def acknowledge(self) -> None:
        state = self.store.get_state(self.device)
        if "pending_findings" in state:
            state.pop("pending_findings")
            self.store.set_state(self.device, state)

    async def _audit(self, client: NitroClient | None, since: datetime) -> _Audit:
        status, unavailable_since = (await self.audit_status(self.device, client)
                                     if self.audit_status and client else (None, None))
        who = None
        if self.attribution and (self.audit_status is None or status is AuditStatus.AVAILABLE):
            who = await asyncio.to_thread(self.attribution, self.device, since)
        return _Audit(who, status, unavailable_since)

    def _change(self, diff: ConfigDiff, kind: str, snapshot: Snapshot, audit: _Audit) -> Finding:
        return from_config_diff(self.device, diff, kind=kind, attribution=audit.attribution,
                                snapshot_id=snapshot.sha256[:12], attribution_status=audit.status,
                                audit_unavailable_since=audit.unavailable_since)

    async def _evaluate(self, running: str, saved: str, marker: dict[str, str],
                        state: dict[str, Any], now: datetime,
                        previous: tuple[Snapshot | None, Snapshot | None] | None = None,
                        client: NitroClient | None = None) -> list[Finding]:
        r_lines, r_norm = _norm(running)
        s_lines, s_norm = _norm(saved)
        prev_r, prev_s = previous if previous is not None else (
            self.store.latest(self.device, "running"), self.store.latest(self.device, "saved"))
        findings: list[Finding] = []

        r_changed = prev_r is None or prev_r.meta.get("norm") != r_norm
        s_changed = prev_s is None or prev_s.meta.get("norm") != s_norm
        snap_r = (self.store.put(self.device, "running", running, {"norm": r_norm, **marker},
                                 now)[0] if r_changed else prev_r)
        snap_s = (self.store.put(self.device, "saved", saved, {"norm": s_norm, **marker},
                                 now)[0] if s_changed else prev_s)
        assert snap_r is not None and snap_s is not None

        prev_r_text = self.store.content(prev_r.sha256) if prev_r is not None else None
        prev_s_text = self.store.content(prev_s.sha256) if prev_s is not None else None

        if prev_r is None or prev_s is None:
            log.info("%s: baseline recorded (%d running lines)", self.device, len(r_lines))
        else:
            audit: _Audit | None = None  # looked up once, for the first running/saved change
            if r_changed:
                old = config_lines(prev_r_text or "")
                diff = diff_lines(old, r_lines, self.rules)
                if not diff.empty:
                    audit = audit or await self._audit(client, prev_r.at)
                    findings.append(self._change(diff, "running", snap_r, audit))
                findings.extend(from_forensic_report(
                    analyze_config(running, previous_text=prev_r_text, device=self.device),
                ))
            if s_changed:
                old = config_lines(prev_s_text or "")
                diff = diff_lines(old, s_lines, self.rules)
                if not diff.empty:
                    audit = audit or await self._audit(client, prev_r.at)
                    findings.append(self._change(diff, "saved", snap_s, audit))
                findings.extend(from_forensic_report(
                    analyze_config(saved, previous_text=prev_s_text, device=self.device),
                ))
                findings += self._tamper_check(r_lines, s_lines, snap_s.sha256[:12], marker,
                                               prev_s.meta)

        drift_id = f"{r_norm[:12]}-{s_norm[:12]}"
        if r_norm != s_norm:
            if state.get("drift_reported") != drift_id:
                diff = diff_lines(s_lines, r_lines, self.rules)
                if not diff.empty:
                    findings.append(from_config_diff(self.device, diff, kind="drift",
                                                     attribution=None, snapshot_id=drift_id))
                state["drift_reported"] = drift_id
        else:
            state.pop("drift_reported", None)
        return findings

    def _tamper_check(self, r_lines: list[str], s_lines: list[str], snap_id: str,
                      marker: dict[str, str], prev_meta: dict[str, Any]) -> list[Finding]:
        """A normal `save config` writes the running config, so after a save every saved
        line exists in running. Saved-only lines mean ns.conf was edited outside the CLI."""
        extra = sorted(set(s_lines) - set(r_lines))
        save_time_moved = prev_meta.get("lastconfigsavetime") != marker["lastconfigsavetime"]
        appliance_says_saved = marker["configchanged"].lower() in ("false", "0")
        # Save-then-modify within one poll interval also leaves saved-only lines, but then
        # the save time moved and the appliance reports unsaved changes. Only flag when the
        # appliance's own state contradicts the file.
        if not extra or (save_time_moved and not appliance_says_saved):
            return []
        diff = diff_lines(r_lines, s_lines, self.rules)
        f = from_config_diff(self.device, diff, kind="saved", attribution=None,
                             snapshot_id=snap_id)
        return [Finding(
            dedup_key=f"config-saved-tamper|{self.device}|{snap_id}",
            rule_id="config-saved-tamper",
            title="Saved config (ns.conf) contains lines that are not in the running config",
            severity=Severity.CRITICAL,
            category="config_change",
            device=self.device,
            summary=(f"{len(extra)} line(s) in ns.conf on {self.device} are not in the "
                     "running config"
                     + ("" if save_time_moved else " and the last-save time did not change")
                     + ". They will be applied at the next reboot. Check for persistence."),
            evidence={**f.evidence, "save_time_moved": save_time_moved},
            mitre=("T1037", "T1554"),
        )]
