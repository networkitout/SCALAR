"""Risk rules for config changes (data/config_risk.yaml)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

import yaml

from scalar.detect.severity import Severity
from scalar.parse.nsconf import Command

OPS = frozenset({"added", "removed", "modified"})


@dataclass(frozen=True, slots=True)
class RiskRule:
    id: str
    severity: Severity
    reason: str
    verbs: frozenset[str] = frozenset()
    objects: frozenset[str] = frozenset()
    object_prefixes: tuple[str, ...] = ()
    options: frozenset[str] = frozenset()
    line_regex: re.Pattern[str] | None = None
    ops: frozenset[str] = frozenset()
    tests: tuple[str, ...] = ()

    def matches(self, cmd: Command, op: str) -> bool:
        if self.ops and op not in self.ops:
            return False
        if self.verbs and cmd.verb not in self.verbs:
            return False
        if self.objects or self.object_prefixes:
            in_objects = cmd.object in self.objects
            in_prefix = any(cmd.object.startswith(p) for p in self.object_prefixes)
            if not (in_objects or in_prefix):
                return False
        if self.options and not any(o in cmd.options for o in self.options):
            return False
        return not (self.line_regex and not self.line_regex.search(cmd.raw))


@dataclass(frozen=True, slots=True)
class RiskRules:
    default: Severity
    rules: tuple[RiskRule, ...]

    def classify(self, cmd: Command, op: str) -> list[RiskRule]:
        return [r for r in self.rules if r.matches(cmd, op)]


def load_risk_rules(path: Path | None = None) -> RiskRules:
    if path is None:
        text = resources.files("scalar.data").joinpath("config_risk.yaml").read_text("utf-8")
    else:
        text = path.read_text("utf-8")
    doc = yaml.safe_load(text)
    rules = []
    seen: set[str] = set()
    for r in doc["rules"]:
        rid = r["id"]
        if rid in seen:
            raise ValueError(f"duplicate config risk rule id {rid!r}")
        seen.add(rid)
        ops = frozenset(r.get("ops", []))
        if ops - OPS:
            raise ValueError(f"{rid}: invalid ops {sorted(ops - OPS)}")
        rules.append(RiskRule(
            id=rid,
            severity=Severity.parse(r["severity"]),
            reason=r["reason"],
            verbs=frozenset(v.lower() for v in r.get("verbs", [])),
            objects=frozenset(o.lower() for o in r.get("objects", [])),
            object_prefixes=tuple(p.lower() for p in r.get("object_prefixes", [])),
            options=frozenset(o.lower() for o in r.get("options", [])),
            line_regex=re.compile(r["line_regex"], re.IGNORECASE) if r.get("line_regex") else None,
            ops=ops,
            tests=tuple(r.get("tests", [])),
        ))
    return RiskRules(Severity.parse(doc.get("default_severity", "low")), tuple(rules))
