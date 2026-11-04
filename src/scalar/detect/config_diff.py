"""Diff two NetScaler configs and score each change.

Configs are compared as multisets of redacted command lines, so pure reordering is not a
change. A removed ``add``/``set`` line and an added line with the same (verb, object, name)
are reported as one ``modified`` change. Bind lines are never paired: a different binding
is a different fact.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field

from scalar.detect.config_risk import RiskRules
from scalar.detect.severity import Severity
from scalar.parse.nsconf import Command, config_lines, parse_command

_PAIRABLE_VERBS = frozenset({"add", "set"})


@dataclass(frozen=True, slots=True)
class LineChange:
    op: str  # added | removed | modified
    before: str | None
    after: str | None
    verb: str
    object: str
    name: str | None
    severity: Severity
    rule_ids: tuple[str, ...]
    reasons: tuple[str, ...]

    def render(self) -> str:
        if self.op == "modified":
            return f"~ {self.before}\n  -> {self.after}"
        sign = "+" if self.op == "added" else "-"
        return f"{sign} {self.after if self.op == 'added' else self.before}"


_CATEGORY_RULES: tuple[tuple[str, frozenset[str]], ...] = (
    ("new/changed management users", frozenset({"mgmt-user"})),
    ("privileged policy grants", frozenset({"mgmt-group-or-policy", "mgmt-user-binding"})),
    ("suspicious rewrite/script-injection activity",
     frozenset({"page-injection", "rewrite-responder", "ns-extension"})),
    ("audit logging tampering", frozenset({"logging-tamper", "logging-disabled"})),
)


@dataclass(slots=True)
class ConfigDiff:
    changes: list[LineChange] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not self.changes

    @property
    def max_severity(self) -> Severity:
        return max((c.severity for c in self.changes), default=Severity.INFO)

    def by_severity(self) -> list[LineChange]:
        return sorted(self.changes, key=lambda c: (-c.severity, c.object, c.name or ""))

    def counts(self) -> dict[str, int]:
        return dict(Counter(c.op for c in self.changes))

    def summarize(self) -> str:
        if self.empty:
            return "no suspicious configuration shifts detected"

        parts: list[str] = []
        seen_examples: set[str] = set()
        for title, rule_ids in _CATEGORY_RULES:
            matches = [c for c in self.changes if set(c.rule_ids) & rule_ids]
            if not matches:
                continue
            examples: list[str] = []
            for change in matches:
                label = (change.name or change.object
                         or (change.after or change.before or "config change"))
                if label not in seen_examples:
                    examples.append(label)
                    seen_examples.add(label)
                if len(examples) >= 3:
                    break
            parts.append(f"{title}: {', '.join(examples)}")

        remaining = sum(1 for change in self.changes if not any(set(change.rule_ids) & rule_ids
                                                             for _, rule_ids in _CATEGORY_RULES))
        if remaining:
            parts.append(f"other notable changes: {remaining}")

        if parts:
            return "; ".join(parts)
        return f"{len(self.changes)} configuration change(s) detected"

    def render(self, limit: int | None = None) -> str:
        items = self.by_severity()
        shown = items if limit is None else items[:limit]
        out = [f"[{c.severity}] {c.render()}" for c in shown]
        if limit is not None and len(items) > limit:
            out.append(f"... {len(items) - limit} more change(s)")
        return "\n".join(out)


def _score(rules: RiskRules, op: str, cmds: list[Command]) -> tuple[Severity, tuple[str, ...],
                                                                    tuple[str, ...]]:
    matched = {}
    for cmd in cmds:
        for r in rules.classify(cmd, op):
            matched[r.id] = r
    if not matched:
        return rules.default, (), ("configuration change",)
    ordered = sorted(matched.values(), key=lambda r: -r.severity)
    return ordered[0].severity, tuple(r.id for r in ordered), tuple(r.reason for r in ordered)


def diff_lines(old: list[str], new: list[str], rules: RiskRules) -> ConfigDiff:
    removed = list((Counter(old) - Counter(new)).elements())
    added = list((Counter(new) - Counter(old)).elements())

    removed_by_key: dict[tuple[str, str, str | None], list[Command]] = defaultdict(list)
    for line in removed:
        cmd = parse_command(line)
        if cmd is not None:
            removed_by_key[cmd.key].append(cmd)

    result = ConfigDiff()
    for line in added:
        cmd = parse_command(line)
        if cmd is None:
            continue
        prior = removed_by_key.get(cmd.key) if cmd.verb in _PAIRABLE_VERBS else None
        if prior:
            before = prior.pop(0)
            sev, ids, reasons = _score(rules, "modified", [before, cmd])
            result.changes.append(LineChange("modified", before.raw, cmd.raw, cmd.verb,
                                             cmd.object, cmd.name, sev, ids, reasons))
        else:
            sev, ids, reasons = _score(rules, "added", [cmd])
            result.changes.append(LineChange("added", None, cmd.raw, cmd.verb, cmd.object,
                                             cmd.name, sev, ids, reasons))
    for cmds in removed_by_key.values():
        for cmd in cmds:
            sev, ids, reasons = _score(rules, "removed", [cmd])
            result.changes.append(LineChange("removed", cmd.raw, None, cmd.verb, cmd.object,
                                             cmd.name, sev, ids, reasons))
    return result


def diff_configs(old_text: str, new_text: str, rules: RiskRules, *,
                 for_peer_compare: bool = False) -> ConfigDiff:
    """Diff two raw config texts. Both sides are redacted before comparison."""
    return diff_lines(config_lines(old_text, for_peer_compare=for_peer_compare),
                      config_lines(new_text, for_peer_compare=for_peer_compare), rules)
