"""Data-driven posture and forensic indicators for NetScaler configurations."""

from __future__ import annotations

import enum
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from scalar.detect.exposure import load_cve_data
from scalar.detect.severity import Severity
from scalar.parse.nsconf import Command, iter_commands, parse_many, unquote

SCHEMA_VERSION = 1


class IndicatorKind(enum.StrEnum):
    FEATURE = "feature"
    WEAKNESS = "weakness"
    FORENSIC_OBSERVABLE = "forensic_observable"


@dataclass(frozen=True, slots=True)
class CommandMatcher:
    verbs: frozenset[str] = frozenset()
    objects: frozenset[str] = frozenset()
    object_prefixes: tuple[str, ...] = ()
    option_values: tuple[tuple[str, frozenset[str]], ...] = ()
    line_regex: re.Pattern[str] | None = None

    def matches(self, command: Command) -> bool:
        if self.verbs and command.verb not in self.verbs:
            return False
        if self.objects or self.object_prefixes:
            exact = command.object in self.objects
            prefixed = any(command.object.startswith(prefix) for prefix in self.object_prefixes)
            if not (exact or prefixed):
                return False
        for option, accepted in self.option_values:
            values = command.option(option)
            if values is None or not any(unquote(value).lower() in accepted for value in values):
                return False
        return self.line_regex is None or self.line_regex.search(command.raw) is not None


@dataclass(frozen=True, slots=True)
class IndicatorRule:
    id: str
    kind: IndicatorKind
    severity: Severity
    title: str
    rationale: str
    remediation: str
    cves: tuple[str, ...]
    references: tuple[str, ...]
    match_any: tuple[CommandMatcher, ...]


@dataclass(frozen=True, slots=True)
class ConfigIntelligence:
    data_version: date
    rules: tuple[IndicatorRule, ...]


@dataclass(frozen=True, slots=True)
class ConfigIndicator:
    id: str
    kind: IndicatorKind
    severity: Severity
    title: str
    rationale: str
    remediation: str
    cves: tuple[str, ...]
    references: tuple[str, ...]
    evidence: tuple[str, ...]


def _string_list(value: object, field: str, rule_id: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{rule_id}: {field} must be a list of non-empty strings")
    return tuple(value)


def _load_matcher(raw: object, rule_id: str) -> CommandMatcher:
    if not isinstance(raw, dict):
        raise ValueError(f"{rule_id}: every match_any entry must be a mapping")
    allowed = {"verbs", "objects", "object_prefixes", "option_values", "line_regex"}
    unknown = set(raw) - allowed
    if unknown:
        raise ValueError(f"{rule_id}: unknown matcher fields {sorted(unknown)}")

    option_values_raw = raw.get("option_values") or {}
    if not isinstance(option_values_raw, dict):
        raise ValueError(f"{rule_id}: option_values must be a mapping")
    option_values: list[tuple[str, frozenset[str]]] = []
    for option, values in option_values_raw.items():
        if not isinstance(option, str):
            raise ValueError(f"{rule_id}: option_values keys must be strings")
        accepted = _string_list(values, f"option_values.{option}", rule_id)
        if not accepted:
            raise ValueError(f"{rule_id}: option_values.{option} cannot be empty")
        option_values.append((option.lower(), frozenset(value.lower() for value in accepted)))

    regex_raw = raw.get("line_regex")
    if regex_raw is not None and not isinstance(regex_raw, str):
        raise ValueError(f"{rule_id}: line_regex must be a string")
    matcher = CommandMatcher(
        verbs=frozenset(
            value.lower() for value in _string_list(raw.get("verbs"), "verbs", rule_id)
        ),
        objects=frozenset(
            value.lower() for value in _string_list(raw.get("objects"), "objects", rule_id)
        ),
        object_prefixes=tuple(
            value.lower()
            for value in _string_list(raw.get("object_prefixes"), "object_prefixes", rule_id)
        ),
        option_values=tuple(option_values),
        line_regex=re.compile(regex_raw, re.IGNORECASE) if regex_raw is not None else None,
    )
    if not any((
        matcher.verbs,
        matcher.objects,
        matcher.object_prefixes,
        matcher.option_values,
        matcher.line_regex,
    )):
        raise ValueError(f"{rule_id}: matcher cannot be empty")
    return matcher


def _matches(rule: IndicatorRule, command: Command) -> bool:
    return any(matcher.matches(command) for matcher in rule.match_any)


def load_config_intelligence(path: Path | None = None) -> ConfigIntelligence:
    """Load and validate packaged config posture intelligence."""
    if path is None:
        text = (
            resources.files("scalar.data")
            .joinpath("config_intelligence.yaml")
            .read_text("utf-8")
        )
    else:
        text = path.read_text("utf-8")
    doc: Any = yaml.safe_load(text)
    if not isinstance(doc, dict):
        raise ValueError("config intelligence document must be a mapping")
    if doc.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"unsupported config intelligence schema {doc.get('schema_version')!r}")

    known_cves = {advisory.id for advisory in load_cve_data().advisories}
    rules: list[IndicatorRule] = []
    seen: set[str] = set()
    raw_rules = doc.get("indicators")
    if not isinstance(raw_rules, list):
        raise ValueError("indicators must be a list")
    for raw in raw_rules:
        if not isinstance(raw, dict):
            raise ValueError("every indicator must be a mapping")
        rule_id = raw.get("id")
        if not isinstance(rule_id, str) or not re.fullmatch(r"[a-z][a-z0-9-]*", rule_id):
            raise ValueError(f"invalid indicator id {rule_id!r}")
        if rule_id in seen:
            raise ValueError(f"duplicate config intelligence indicator id {rule_id!r}")
        seen.add(rule_id)
        try:
            kind = IndicatorKind(raw["kind"])
            severity = Severity.parse(raw["severity"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"{rule_id}: invalid kind or severity") from exc
        cves = _string_list(raw.get("cves"), "cves", rule_id)
        unknown_cves = set(cves) - known_cves
        if unknown_cves:
            raise ValueError(f"{rule_id}: CVEs absent from cve_builds.yaml: {sorted(unknown_cves)}")
        references = _string_list(raw.get("references"), "references", rule_id)
        if not references or any(not ref.startswith("https://") for ref in references):
            raise ValueError(f"{rule_id}: references must contain HTTPS URLs")
        matchers_raw = raw.get("match_any")
        if not isinstance(matchers_raw, list) or not matchers_raw:
            raise ValueError(f"{rule_id}: match_any must be a non-empty list")
        rule = IndicatorRule(
            id=rule_id,
            kind=kind,
            severity=severity,
            title=str(raw.get("title") or ""),
            rationale=str(raw.get("rationale") or ""),
            remediation=str(raw.get("remediation") or ""),
            cves=cves,
            references=references,
            match_any=tuple(_load_matcher(item, rule_id) for item in matchers_raw),
        )
        if not rule.title or not rule.rationale or not rule.remediation:
            raise ValueError(f"{rule_id}: title, rationale, and remediation are required")
        for sample in _string_list(raw.get("positive_tests"), "positive_tests", rule_id):
            commands = list(iter_commands(sample))
            if not commands or not any(_matches(rule, command) for command in commands):
                raise ValueError(f"{rule_id}: positive test does not match: {sample!r}")
        for sample in _string_list(raw.get("negative_tests"), "negative_tests", rule_id):
            if any(_matches(rule, command) for command in iter_commands(sample)):
                raise ValueError(f"{rule_id}: negative test unexpectedly matches: {sample!r}")
        rules.append(rule)
    return ConfigIntelligence(date.fromisoformat(str(doc["data_version"])), tuple(rules))


def _commands(value: str | Iterable[str | Command]) -> list[Command]:
    if isinstance(value, str):
        return list(iter_commands(value))
    materialized = list(value)
    if all(isinstance(item, Command) for item in materialized):
        return [item for item in materialized if isinstance(item, Command)]
    if all(isinstance(item, str) for item in materialized):
        return parse_many(item for item in materialized if isinstance(item, str))
    raise TypeError("commands_or_lines must contain only Command objects or only strings")


def assess_config_indicators(
    commands_or_lines: str | Iterable[str | Command],
    intelligence: ConfigIntelligence | None = None,
) -> list[ConfigIndicator]:
    """Return deduplicated config indicators; matches are evidence, not proof of exploitation."""
    commands = _commands(commands_or_lines)
    data = intelligence or load_config_intelligence()
    indicators: list[ConfigIndicator] = []
    for rule in data.rules:
        evidence = tuple(dict.fromkeys(
            command.raw for command in commands if _matches(rule, command)
        ))
        if evidence:
            indicators.append(ConfigIndicator(
                id=rule.id,
                kind=rule.kind,
                severity=rule.severity,
                title=rule.title,
                rationale=rule.rationale,
                remediation=rule.remediation,
                cves=rule.cves,
                references=rule.references,
                evidence=evidence,
            ))
    return indicators
