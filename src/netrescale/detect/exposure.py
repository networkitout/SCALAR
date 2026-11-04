"""Compare a device's firmware build and features against the bundled CVE table."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import date
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from netrescale.parse.version import Build, NsVersion

STALE_AFTER_DAYS = 30


class Status(enum.StrEnum):
    VULNERABLE = "vulnerable"
    POSSIBLY_EXPOSED = "possibly_exposed"  # vulnerable build, feature gate unknown
    VULNERABLE_NOT_EXPOSED = "vulnerable_not_exposed"  # vulnerable build, feature not in use
    FIXED = "fixed"
    NOT_AFFECTED = "not_affected"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class DeviceFeatures:
    """Config conditions that gate exploitability. None means 'not determined'."""

    gateway_or_aaa: bool | None = None
    saml_idp: bool | None = None
    saml: bool | None = None
    ipv6_lb: bool | None = None
    hdx_content_routing: bool | None = None

    def get(self, name: str) -> bool | None:
        if not hasattr(self, name):
            raise KeyError(f"unknown feature gate {name!r}")
        value: bool | None = getattr(self, name)
        return value


@dataclass(frozen=True, slots=True)
class Advisory:
    id: str
    title: str
    bulletin: str
    exploited: bool
    severity: str
    requires: tuple[str, ...]
    requires_mode: str  # "all" | "any"
    fixed: dict[str, Build]
    not_affected: frozenset[str]
    unfixed: frozenset[str]
    post_patch_actions: tuple[str, ...]
    verified: bool


@dataclass(frozen=True, slots=True)
class CveData:
    data_version: date
    lifecycle: dict[str, dict[str, Any]]
    advisories: tuple[Advisory, ...]

    def min_safe_build(self, train: str) -> Build | None:
        builds = [a.fixed[train] for a in self.advisories if train in a.fixed]
        return max(builds) if builds else None

    def age_days(self, today: date | None = None) -> int:
        return ((today or date.today()) - self.data_version).days

    def is_stale(self, today: date | None = None) -> bool:
        return self.age_days(today) > STALE_AFTER_DAYS


@dataclass(frozen=True, slots=True)
class AdvisoryResult:
    advisory: Advisory
    status: Status
    fixed_in: Build | None
    gate_detail: str = ""


@dataclass(slots=True)
class ExposureReport:
    device: str
    version: NsVersion
    lifecycle_status: str
    results: list[AdvisoryResult] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    data_version: date | None = None
    min_safe_build: Build | None = None  # highest first-fixed build on this train
    lifecycle_note: str = ""

    @property
    def actionable(self) -> list[AdvisoryResult]:
        return [r for r in self.results
                if r.status in (Status.VULNERABLE, Status.POSSIBLY_EXPOSED)]

    @property
    def train_unknown(self) -> bool:
        """No advisory covers this train, so nothing about its exposure is known."""
        return bool(self.results) and all(r.status is Status.UNKNOWN for r in self.results)

    @property
    def needs_attention(self) -> list[AdvisoryResult]:
        """UNKNOWN results that must not read as 'not exposed': every UNKNOWN when the
        whole train is unknown, otherwise those for exploited advisories."""
        unknown = [r for r in self.results if r.status is Status.UNKNOWN]
        return unknown if self.train_unknown else [r for r in unknown if r.advisory.exploited]

    @property
    def worst(self) -> Status:
        order = [Status.VULNERABLE, Status.POSSIBLY_EXPOSED, Status.UNKNOWN,
                 Status.VULNERABLE_NOT_EXPOSED, Status.FIXED, Status.NOT_AFFECTED]
        present = {r.status for r in self.results}
        return next((s for s in order if s in present), Status.NOT_AFFECTED)


def load_cve_data(path: Path | None = None) -> CveData:
    if path is None:
        text = resources.files("netrescale.data").joinpath("cve_builds.yaml").read_text("utf-8")
    else:
        text = path.read_text("utf-8")
    doc = yaml.safe_load(text)
    advisories = []
    for a in doc["advisories"]:
        mode = a.get("requires_mode", "all")
        if mode not in ("all", "any"):
            raise ValueError(f"{a['id']}: requires_mode must be 'all' or 'any'")
        adv = Advisory(
            id=a["id"],
            title=a["title"],
            bulletin=a.get("bulletin", ""),
            exploited=bool(a.get("exploited", False)),
            severity=a.get("severity", "high"),
            requires=tuple(a.get("requires", [])),
            requires_mode=mode,
            fixed={str(t): Build.parse(str(b)) for t, b in (a.get("fixed") or {}).items()},
            not_affected=frozenset(a.get("not_affected", [])),
            unfixed=frozenset(a.get("unfixed", [])),
            post_patch_actions=tuple(a.get("post_patch_actions", [])),
            verified=bool(a.get("verified", False)),
        )
        overlap = (set(adv.fixed) & adv.not_affected) | (set(adv.fixed) & adv.unfixed) | (
            adv.not_affected & adv.unfixed)
        if overlap:
            raise ValueError(f"{adv.id}: train(s) {sorted(overlap)} listed in conflicting sets")
        for gate in adv.requires:
            DeviceFeatures().get(gate)  # validates gate names
        advisories.append(adv)
    return CveData(
        data_version=date.fromisoformat(str(doc["data_version"])),
        lifecycle={str(e["train"]): e for e in doc.get("lifecycle", [])},
        advisories=tuple(advisories),
    )


def _gate(adv: Advisory, features: DeviceFeatures) -> tuple[bool | None, str]:
    if not adv.requires:
        return True, ""
    values = {g: features.get(g) for g in adv.requires}
    detail = ", ".join(f"{g}={'?' if v is None else v}" for g, v in values.items())
    vals = list(values.values())
    if adv.requires_mode == "any":
        if any(v is True for v in vals):
            return True, detail
        if all(v is False for v in vals):
            return False, detail
        return None, detail
    if all(v is True for v in vals):
        return True, detail
    if any(v is False for v in vals):
        return False, detail
    return None, detail


def assess_advisory(adv: Advisory, version: NsVersion, features: DeviceFeatures) -> AdvisoryResult:
    train = version.train
    if train in adv.not_affected:
        return AdvisoryResult(adv, Status.NOT_AFFECTED, None)
    fixed_in = adv.fixed.get(train)
    if fixed_in is not None:
        vulnerable = version.build < fixed_in
    elif train in adv.unfixed:
        vulnerable = True
    else:
        return AdvisoryResult(adv, Status.UNKNOWN, None, f"train {train} not in advisory data")
    if not vulnerable:
        return AdvisoryResult(adv, Status.FIXED, fixed_in)
    exposed, detail = _gate(adv, features)
    status = {True: Status.VULNERABLE, False: Status.VULNERABLE_NOT_EXPOSED,
              None: Status.POSSIBLY_EXPOSED}[exposed]
    return AdvisoryResult(adv, status, fixed_in, detail)


def assess(device: str, version: NsVersion, features: DeviceFeatures, data: CveData,
           today: date | None = None) -> ExposureReport:
    today = today or date.today()
    life = data.lifecycle.get(version.train, {})
    report = ExposureReport(device, version, str(life.get("status", "unknown")),
                            data_version=data.data_version,
                            min_safe_build=data.min_safe_build(version.train),
                            lifecycle_note=str(life.get("note") or ""))
    if report.lifecycle_status in ("end_of_life", "end_of_maintenance"):
        report.warnings.append(
            f"{version.train} is {report.lifecycle_status.replace('_', ' ')}"
            + (f" ({life['note']})" if life.get("note") else ""))
    if version.variant_inferred:
        report.warnings.append(
            f"variant '{version.variant}' inferred from build {version.build}; set "
            "'firmware_variant' on the device if this is wrong")
    age = data.age_days(today)
    if data.is_stale(today):
        report.warnings.append(
            f"CVE data is {age} days old (data_version {data.data_version}); "
            "check Citrix security bulletins for newer advisories")
    report.results = [assess_advisory(a, version, features) for a in data.advisories]
    return report
