"""Parse NetScaler firmware version strings (NITRO ``nsversion`` / CLI ``show version``).

Examples:
    NetScaler NS14.1: Build 43.56.nc, Date: Jun 10 2025, 11:21:31   (64-bit)
    Citrix ADC NS13.0: Build 47.24.nc, Date: ...
    NetScaler NS13.1-FIPS: Build 37.241.nc, ...      (variant marker, if present)

The 13.1 FIPS and NDcPP builds share one 37.x branch. Their version strings may not carry a
marker, so 13.1-37.<minor >= 100> is treated as that train. (The only regular 13.1 build on
37.x was 37.38, which predates every fix in the CVE table, so the heuristic can't hide a
vulnerability.) A per-device override can set the variant explicitly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering

_VERSION_RE = re.compile(
    r"NS(?P<release>\d+\.\d+)"
    r"(?:[-_ ](?P<variant>FIPS|NDcPP|NDCPP))?"
    r"\s*:\s*Build\s+(?P<major>\d+)\.(?P<minor>\d+)",
    re.IGNORECASE,
)

FIPS_BRANCH = {"13.1": 37}
FIPS_MIN_MINOR = 100


class VersionParseError(ValueError):
    pass


@total_ordering
@dataclass(frozen=True, slots=True)
class Build:
    major: int
    minor: int

    @classmethod
    def parse(cls, s: str) -> Build:
        try:
            major, minor = s.strip().split(".", 1)
            return cls(int(major), int(minor))
        except ValueError as exc:
            raise VersionParseError(f"invalid build {s!r}; expected '<major>.<minor>'") from exc

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Build):
            return NotImplemented
        return (self.major, self.minor) < (other.major, other.minor)

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}"


@dataclass(frozen=True, slots=True)
class NsVersion:
    release: str  # e.g. "14.1"
    build: Build
    variant: str | None  # None | "fips" | "ndcpp"
    variant_inferred: bool = False
    raw: str = ""

    @property
    def train(self) -> str:
        """Key into the CVE table: '14.1', '13.1-fips', ..."""
        return f"{self.release}-{self.variant}" if self.variant else self.release

    def __str__(self) -> str:
        return f"{self.train} {self.build}"


def parse_version(raw: str, variant_override: str | None = None) -> NsVersion:
    m = _VERSION_RE.search(raw)
    if not m:
        raise VersionParseError(f"unrecognised NetScaler version string: {raw!r}")
    release = m["release"]
    build = Build(int(m["major"]), int(m["minor"]))
    inferred = False
    if variant_override:
        variant: str | None = variant_override.lower()
    elif m["variant"]:
        variant = m["variant"].lower()
    elif FIPS_BRANCH.get(release) == build.major and build.minor >= FIPS_MIN_MINOR:
        variant, inferred = "fips", True
    else:
        variant = None
    if variant not in (None, "fips", "ndcpp"):
        raise VersionParseError(f"unknown variant {variant!r}")
    return NsVersion(release, build, variant, inferred, raw.strip())
