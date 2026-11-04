"""YAML log-detection rules, evaluated on the parsed event stream.

Rule file schema (data/rules/*.yaml, a list of rules):
    id, title, severity, sources: [nslog|bashlog|...], event_types: ["SSLVPN LOGIN", ...]
    match:                      # every condition given must hold
      message_regex: str        # on the message (text after " : "); raw line if unparsed
      raw_regex: str            # on the whole line
      fields: {Field: regex}    # extracted fields must exist and match
      fields_differ: [A, B]     # both IP fields exist and differ
      not_in_list: {Field: list_name}   # IP fields check CIDRs; others exact match
    threshold: {count: int, window_seconds: int, group_by: [Field, ...]}
    dedup_by: [Field, ...]      # optional, rules without a threshold; see LogRule.dedup_fields
    cve: [...]; mitre: [...]; references: [...]
    tests: {positive: [{source, line}], negative: [{source, line}]}   # required
Rules are indexed by event_type (or source when they don't specify one), so each line is
only checked against relevant rules.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections import defaultdict, deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from netrescale.detect.severity import Severity
from netrescale.parse.nslog import INJECTION_FIELD, LogEvent
from netrescale.redact import registry

_IP_FIELDS = frozenset({"Client_ip", "Remote_ip", "Source", "Destination", "ClientIP",
                        "Nat_ip", "Vserver"})
# Who did it and from where; the Command is added after these.
DEFAULT_DEDUP_FIELDS = ("User", "Client_ip", "Remote_ip", "ClientIP", "Source")
SHELL_SOURCES = frozenset({"bashlog", "shlog"})
# Fields the parsers can produce (nslog key/value fields, shell Tty, derived fields).
KNOWN_FIELDS = frozenset({
    "User", "Client_ip", "SessionId", "Remote_ip", "Command", "Status", "Source",
    "Destination", "Vserver", "Nat_ip", "Context", "Browser_type", "Groups",
    "Failure_reason", "ClientIP", "Rejected_user", INJECTION_FIELD, "Tty",
})
GROUP_VALUE_MAX = 64  # longer threshold group values are hashed in the dedup key


class RuleError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Threshold:
    count: int
    window: timedelta
    group_by: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class LogRule:
    id: str
    title: str
    severity: Severity
    sources: frozenset[str]
    event_types: frozenset[str]  # "FEATURE EVENT", e.g. "SSLVPN TCPCONNSTAT"
    events: frozenset[str]  # event name under any feature, e.g. "CMD_EXECUTED"
    message_regex: re.Pattern[str] | None
    raw_regex: re.Pattern[str] | None
    fields: tuple[tuple[str, re.Pattern[str]], ...]
    fields_differ: tuple[str, str] | None
    not_in_list: tuple[tuple[str, str], ...]
    threshold: Threshold | None
    cve: tuple[str, ...]
    mitre: tuple[str, ...]
    references: tuple[str, ...]
    tests_positive: tuple[tuple[str, str], ...]
    tests_negative: tuple[tuple[str, str], ...]
    dedup_by: tuple[str, ...] | None = None  # None: see dedup_fields; (): rule|device

    @property
    def dedup_fields(self) -> tuple[str, ...]:
        """Fields that separate notifications of this rule (RuleHit.dedup_key). Default:
        actor and Command for shell and Command-matching rules, the allowlisted or compared
        fields for not_in_list/fields_differ rules, and none (one key per rule and device)
        for message/raw matches, which unauthenticated senders can vary at will."""
        if self.dedup_by is not None:
            return self.dedup_by
        if (self.sources and self.sources <= SHELL_SOURCES) or any(
                name == "Command" for name, _ in self.fields):
            return (*DEFAULT_DEDUP_FIELDS, "Command")
        return tuple(dict.fromkeys([name for name, _ in self.not_in_list]
                                   + list(self.fields_differ or ())))

    def matches(self, ev: LogEvent, lists: Mapping[str, ListMatcher]) -> bool:
        if self.sources and ev.source not in self.sources:
            return False
        if self.event_types and ev.event_type not in self.event_types:
            return False
        if self.events and ev.event not in self.events:
            return False
        if self.raw_regex and not self.raw_regex.search(ev.raw):
            return False
        if self.message_regex and not self.message_regex.search(ev.message or ev.raw):
            return False
        for name, rx in self.fields:
            v = ev.fields.get(name)
            if v is None or not rx.search(v):
                return False
        if self.fields_differ:
            a, b = (ev.ip_field(f) for f in self.fields_differ)
            if a is None or b is None or a == b:
                return False
        for name, list_name in self.not_in_list:
            matcher = lists.get(list_name)
            if matcher is None:
                raise RuleError(f"rule {self.id}: list {list_name!r} is not configured")
            v = ev.ip_field(name) if name in _IP_FIELDS else ev.fields.get(name)
            if v is None or matcher.contains(v):
                return False
        return True


class ListMatcher:
    """A named allowlist: CIDRs/IPs and/or exact strings."""

    def __init__(self, items: Iterable[str]) -> None:
        self.networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.values: set[str] = set()
        for item in items:
            try:
                self.networks.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                self.values.add(item)

    def contains(self, value: str) -> bool:
        if value in self.values:
            return True
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return False
        return any(ip in n for n in self.networks)


@dataclass(frozen=True, slots=True)
class RuleHit:
    rule: LogRule
    event: LogEvent
    group: tuple[str, ...]
    count: int

    @property
    def dedup_key(self) -> str:
        """Threshold rules: rule|device|group. Others: rule|device, plus a digest of the
        rule's dedup_fields when it has any, so a different actor or command is not muted by
        an earlier hit."""
        if self.rule.threshold is not None:
            return "|".join((self.rule.id, self.event.device, *map(_bounded, self.group)))
        fields = self.rule.dedup_fields
        if not fields:
            return f"{self.rule.id}|{self.event.device}"
        return "|".join((self.rule.id, self.event.device, evidence_digest(self.event, fields)))


def _digest(text: str) -> str:
    material = registry.scrub(text)  # never hash a known secret
    return hashlib.sha256(material.encode("utf-8", "backslashreplace")).hexdigest()


def _bounded(value: str) -> str:
    """Attacker-supplied values are unbounded; the stored dedup key is indexed."""
    return value if len(value) <= GROUP_VALUE_MAX else "sha256:" + _digest(value)[:16]


def _dedup_value(ev: LogEvent, name: str) -> str:
    value = ev.fields.get(name, "")
    if name in _IP_FIELDS:
        return ev.ip_field(name) or value
    return " ".join(value.split()) if name == "Command" else value


def evidence_digest(ev: LogEvent, fields: tuple[str, ...]) -> str:
    """Short stable digest of an event's values for ``fields`` (IP fields normalized,
    Command whitespace-normalized)."""
    return _digest("\0".join(f"{name}={_dedup_value(ev, name)}" for name in fields))[:12]


def _compile(rx: str | None, rule_id: str) -> re.Pattern[str] | None:
    if rx is None:
        return None
    try:
        return re.compile(rx)
    except re.error as exc:
        raise RuleError(f"rule {rule_id}: bad regex {rx!r}: {exc}") from exc


def _vectors(raw: Any, rule_id: str, kind: str) -> tuple[tuple[str, str], ...]:
    out = []
    for item in raw or []:
        if not isinstance(item, dict) or "line" not in item:
            raise RuleError(f"rule {rule_id}: {kind} test vectors need 'source' and 'line'")
        out.append((str(item.get("source", "nslog")), str(item["line"])))
    return tuple(out)


def parse_rule(doc: dict[str, Any]) -> LogRule:
    rid = doc.get("id")
    if not rid:
        raise RuleError(f"rule without id: {doc!r}")
    match = doc.get("match") or {}
    unknown = set(match) - {"message_regex", "raw_regex", "fields", "fields_differ",
                            "not_in_list"}
    if unknown:
        raise RuleError(f"rule {rid}: unknown match keys {sorted(unknown)}")
    th = doc.get("threshold")
    differ = match.get("fields_differ")
    if differ is not None and len(differ) != 2:
        raise RuleError(f"rule {rid}: fields_differ needs exactly two fields")
    dedup_by = doc.get("dedup_by")
    if dedup_by is not None:
        if (not isinstance(dedup_by, list | tuple)
                or not all(isinstance(f, str) and f for f in dedup_by)):
            raise RuleError(f"rule {rid}: dedup_by must be a list of field names")
        unknown_fields = sorted(set(dedup_by) - KNOWN_FIELDS)
        if unknown_fields:
            raise RuleError(f"rule {rid}: dedup_by names fields the parser never extracts: "
                            f"{unknown_fields}; known: {sorted(KNOWN_FIELDS)}")
        if th:
            raise RuleError(f"rule {rid}: dedup_by does not apply to threshold rules; "
                            "use threshold.group_by")
    rule = LogRule(
        id=rid,
        title=doc["title"],
        severity=Severity.parse(doc["severity"]),
        sources=frozenset(doc.get("sources", [])),
        event_types=frozenset(doc.get("event_types", [])),
        events=frozenset(doc.get("events", [])),
        message_regex=_compile(match.get("message_regex"), rid),
        raw_regex=_compile(match.get("raw_regex"), rid),
        fields=tuple((k, re.compile(v)) for k, v in (match.get("fields") or {}).items()),
        fields_differ=(differ[0], differ[1]) if differ else None,
        not_in_list=tuple((match.get("not_in_list") or {}).items()),
        threshold=Threshold(int(th["count"]), timedelta(seconds=int(th["window_seconds"])),
                            tuple(th.get("group_by", []))) if th else None,
        cve=tuple(doc.get("cve", [])),
        mitre=tuple(doc.get("mitre", [])),
        references=tuple(doc.get("references", [])),
        tests_positive=_vectors((doc.get("tests") or {}).get("positive"), rid, "positive"),
        tests_negative=_vectors((doc.get("tests") or {}).get("negative"), rid, "negative"),
        dedup_by=tuple(dedup_by) if dedup_by is not None else None,
    )
    if not rule.tests_positive or not rule.tests_negative:
        raise RuleError(f"rule {rid}: positive and negative test vectors are required")
    return rule


def load_rule_documents(paths: Iterable[Path] | None = None) -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    if paths is None:
        pkg = resources.files("netrescale.data").joinpath("rules")
        for entry in sorted(pkg.iterdir(), key=lambda p: p.name):
            if entry.name.endswith(".yaml"):
                docs.extend(yaml.safe_load(entry.read_text("utf-8")) or [])
    else:
        for p in paths:
            docs.extend(yaml.safe_load(p.read_text("utf-8")) or [])
    return docs


def load_rules(paths: Iterable[Path] | None = None) -> list[LogRule]:
    rules = [parse_rule(document) for document in load_rule_documents(paths)]
    ids = [r.id for r in rules]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise RuleError(f"duplicate rule ids: {sorted(dupes)}")
    return rules


@dataclass
class RuleEngine:
    rules: list[LogRule]
    lists: dict[str, ListMatcher] = field(default_factory=dict)
    disabled: dict[str, str] = field(init=False, default_factory=dict)  # rule id -> reason
    _by_event: dict[str | None, list[LogRule]] = field(init=False, default_factory=dict)
    _windows: dict[tuple[str, str, tuple[str, ...]], deque[datetime]] = field(
        init=False, default_factory=lambda: defaultdict(deque))

    def __post_init__(self) -> None:
        index: dict[str | None, list[LogRule]] = defaultdict(list)
        for r in self.rules:
            missing = [ln for _, ln in r.not_in_list if ln not in self.lists]
            if missing:
                self.disabled[r.id] = f"allowlist(s) not configured: {', '.join(missing)}"
                continue
            # Index on the event name; event_types are re-checked exactly in matches().
            keys: set[str | None] = {et.split(" ", 1)[-1] for et in r.event_types}
            keys |= set(r.events)
            for k in keys or {None}:
                index[k].append(r)
        self._by_event = dict(index)

    @property
    def active_rules(self) -> list[LogRule]:
        return [r for r in self.rules if r.id not in self.disabled]

    def candidates(self, ev: LogEvent) -> list[LogRule]:
        specific = self._by_event.get(ev.event, []) if ev.event else []
        return specific + self._by_event.get(None, [])

    def evaluate(self, ev: LogEvent) -> list[RuleHit]:
        hits = []
        for rule in self.candidates(ev):
            if not rule.matches(ev, self.lists):
                continue
            if rule.threshold is None:
                hits.append(RuleHit(rule, ev, (), 1))
                continue
            group = tuple(ev.fields.get(g, "") for g in rule.threshold.group_by)
            key = (rule.id, ev.device, group)
            now = ev.ts or datetime.now(UTC)
            window = self._windows[key]
            window.append(now)
            while window and now - window[0] > rule.threshold.window:
                window.popleft()
            if len(window) >= rule.threshold.count:
                hits.append(RuleHit(rule, ev, group, len(window)))
                window.clear()  # fire once per burst; the next burst starts fresh
        return hits
