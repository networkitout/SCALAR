import re
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from hypothesis import given, settings
from hypothesis import strategies as st

from netrescale.detect.rules import (
    ListMatcher,
    LogRule,
    RuleEngine,
    RuleError,
    load_rules,
    parse_rule,
)
from netrescale.detect.sessions import SessionTracker
from netrescale.parse.nslog import LogEvent, parse_line, parse_nslog

RULES = load_rules()
LISTS = {
    "admin_networks": ListMatcher(["10.0.0.0/8"]),
    "admin_users": ListMatcher(["admin1", "nsroot", "nr_nitro"]),
}

NS = "Oct  5 10:00:01 <local0.info> 10.0.0.10 2026/10/05:10:00:01 GMT ns-gw-01 0-PPE-0 : "


def _fire(rule: LogRule, source: str, line: str) -> bool:
    engine = RuleEngine([rule], LISTS)
    n = rule.threshold.count if rule.threshold else 1
    hits = []
    for _ in range(n):
        ev = parse_line(source, line, "ns-gw-01")
        hits += [h for h in engine.evaluate(ev) if h.rule.id == rule.id]
    return bool(hits)


@pytest.mark.parametrize(
    ("rule", "source", "line"),
    [pytest.param(r, s, ln, id=f"{r.id}+{i}") for r in RULES
     for i, (s, ln) in enumerate(r.tests_positive)],
)
def test_positive_vectors(rule: LogRule, source: str, line: str) -> None:
    assert _fire(rule, source, line), f"{rule.id} should fire on: {line}"


@pytest.mark.parametrize(
    ("rule", "source", "line"),
    [pytest.param(r, s, ln, id=f"{r.id}-{i}") for r in RULES
     for i, (s, ln) in enumerate(r.tests_negative)],
)
def test_negative_vectors(rule: LogRule, source: str, line: str) -> None:
    assert not _fire(rule, source, line), f"{rule.id} must not fire on: {line}"


# The quadratic form cve-2026-88771-injected-command used before; its linear replacement
# must match exactly the same lines.
QUADRATIC_88771 = re.compile(r"(?i)(login|authentication|rejected|fail).*NSPPE;\s*\S")
KIB_256 = 256 * 1024


def _injected_command_rule() -> LogRule:
    return next(r for r in RULES if r.id == "cve-2026-88771-injected-command")


@pytest.mark.parametrize("text", [
    "fail" * (KIB_256 // 4),
    "LoGiN x" * (KIB_256 // 7),
    "failNSPPE" * (KIB_256 // 9),
    "rejected " * (KIB_256 // 18) + "NSPPE;" + " " * (KIB_256 // 2),
    ("authentication NSPPE" + "\n") * (KIB_256 // 21),
    "x" * KIB_256,
], ids=["keywords", "mixed-case", "partial-marker", "trailing-space", "many-lines", "no-keyword"])
def test_injected_command_rule_is_linear_on_long_lines(text: str) -> None:
    rule = _injected_command_rule()
    assert rule.raw_regex is not None
    line = NS + "default AAATM LOGIN_FAILED 7001 0 : User " + text
    assert len(line) >= KIB_256
    started = time.perf_counter()
    assert not rule.raw_regex.search(line)
    assert not RuleEngine([rule], LISTS).evaluate(parse_line("nslog", line, "ns-gw-01"))
    assert time.perf_counter() - started < 1  # the quadratic form took ~25 s


_FRAGMENTS = st.sampled_from([
    "login", "LOGIN", "authentication", "Rejected", "fail", "FaIl", "NSPPE;", "nsppe;",
    "NSPPE", ";", " ", "\t", "\n", "\r", "\x0b", "\x85", "\xa0", "x", "-", "\u212a", "K",
])


@settings(max_examples=2000, deadline=None)
@given(st.lists(st.one_of(_FRAGMENTS, st.text(max_size=3)), max_size=16).map("".join))
def test_injected_command_rule_matches_the_quadratic_form(text: str) -> None:
    rule = _injected_command_rule()
    assert rule.raw_regex is not None
    assert bool(rule.raw_regex.search(text)) == bool(QUADRATIC_88771.search(text))


def test_rules_require_vectors() -> None:
    with pytest.raises(RuleError, match="test vectors"):
        parse_rule({"id": "x", "title": "t", "severity": "low", "match": {"raw_regex": "a"}})


def test_unknown_match_key_rejected() -> None:
    with pytest.raises(RuleError, match="unknown match keys"):
        parse_rule({"id": "x", "title": "t", "severity": "low", "match": {"regex": "a"}})


SHELL = "Oct  5 10:00:01 <local7.notice> ns-gw-01 bash[1]: {user} on /dev/pts/0 shell_command=\"{cmd}\""
CMD = NS + ('default GUI CMD_EXECUTED {seq} 0 : User {user} - Remote_ip {ip} - '
            'Command "{cmd}" - Status "Success"')


def _keys(rule: LogRule, source: str, lines: list[str]) -> list[str]:
    engine = RuleEngine([rule], LISTS)
    return [h.dedup_key for ln in lines for h in engine.evaluate(parse_line(source, ln, "ns-gw-01"))]


def test_dedup_key_distinguishes_evidence() -> None:
    rule = next(r for r in RULES if r.id == "shell-tmp-exec")
    benign, attacker, again = _keys(rule, "bashlog", [
        SHELL.format(user="nsroot", cmd="cat /var/tmp/report.log"),
        SHELL.format(user="nsroot", cmd="chmod +x /var/tmp/the"),
        SHELL.format(user="nsroot", cmd="cat  /var/tmp/report.log "),
    ])
    assert benign.startswith("shell-tmp-exec|ns-gw-01|")
    assert benign != attacker and benign == again  # whitespace is normalized
    rule = next(r for r in RULES if r.id == "mgmt-high-risk-command")
    keys = _keys(rule, "nslog", [
        CMD.format(seq=1, user="admin1", ip="10.20.0.5", cmd="add system user ops ****"),
        CMD.format(seq=2, user="admin1", ip="10.20.0.5", cmd="add system user ops ****"),
        CMD.format(seq=3, user="admin1", ip="203.0.113.9", cmd="add system user ops ****"),
        CMD.format(seq=4, user="admin1", ip="10.20.0.5", cmd="bind system user x superuser 0"),
    ])
    assert keys[0] == keys[1] and len(set(keys)) == 3


def test_message_rules_default_to_one_key_per_device() -> None:
    rule = parse_rule({**custom_rule(), "sources": ["notice"],
                       "match": {"raw_regex": "missed too many heartbeats"}})
    assert rule.dedup_fields == ()
    line = "Oct  5 10:00:0{s} <local0.err> ns-gw-01 pitboss: PPE {n} missed too many heartbeats"
    keys = _keys(rule, "notice", [line.format(s=1, n=1), line.format(s=7, n=2),
                                  line.format(s=1, n=1) + "; core dumped"])
    assert set(keys) == {"custom-test|ns-gw-01"}


def test_unauthenticated_floods_share_one_key() -> None:
    """Garbage usernames are attacker-chosen; one key per rule and device, whatever the bytes."""
    rule = next(r for r in RULES if r.id == "cve-2025-5777-garbage-username")
    lines = [NS + f'default AAA Message {4521 + i} 0 : "Authentication is rejected for '
             f'{chr(0x80 + i)}{chr(0xC0 + i)}AB{i}"' for i in range(30)]
    assert set(_keys(rule, "nslog", lines)) == {"cve-2025-5777-garbage-username|ns-gw-01"}


def test_allowlist_rules_key_on_the_listed_field() -> None:
    """One GUI session from an unexpected address is one key; a second address is another."""
    rule = next(r for r in RULES if r.id == "mgmt-from-unexpected-ip")
    assert rule.dedup_fields == ("Remote_ip",)
    session = [CMD.format(seq=i, user="admin1", ip="198.51.100.7",
                          cmd=f"show lb vserver vs-{i}") for i in range(50)]
    keys = _keys(rule, "nslog", [*session, CMD.format(seq=99, user="admin1",
                                                      ip="198.51.100.8", cmd="show ns ip")])
    assert len(set(keys[:50])) == 1 and keys[50] != keys[0]
    users = next(r for r in RULES if r.id == "mgmt-unknown-admin-user")
    assert users.dedup_fields == ("User",)
    assert next(r for r in RULES if r.id == "session-ip-mismatch").dedup_fields == (
        "Client_ip", "Source")


def test_dedup_by_selects_key_fields() -> None:
    lines = [CMD.format(seq=1, user="a", ip="198.51.100.1", cmd="show ns ip"),
             CMD.format(seq=2, user="b", ip="198.51.100.1", cmd="add ns ip 1.2.3.4"),
             CMD.format(seq=3, user="a", ip="198.51.100.2:443", cmd="show ns ip")]
    base = {**custom_rule(), "events": ["CMD_EXECUTED"], "match": {"fields": {"User": "."}}}
    by_ip = _keys(parse_rule({**base, "dedup_by": ["Remote_ip"]}), "nslog", lines)
    assert by_ip[0] == by_ip[1] != by_ip[2]
    assert set(_keys(parse_rule(base), "nslog", lines)) == {"custom-test|ns-gw-01"}
    by_command = {**base, "match": {"fields": {"Command": "."}}}
    assert len(set(_keys(parse_rule(by_command), "nslog", lines))) == 3
    assert set(_keys(parse_rule({**by_command, "dedup_by": []}), "nslog", lines)) == {
        "custom-test|ns-gw-01"}


def test_threshold_rules_keep_group_dedup_key() -> None:
    rule = next(r for r in RULES if r.id == "mgmt-login-bruteforce")
    line = CMD.format(seq=1, user="nsroot", ip="198.51.100.7", cmd="login nsroot").replace(
        "Success", "ERROR: Invalid username or password")
    assert _keys(rule, "nslog", [line] * 5) == ["mgmt-login-bruteforce|ns-gw-01|198.51.100.7"]


def test_threshold_group_values_are_bounded_in_dedup_key() -> None:
    rule = next(r for r in RULES if r.id == "mgmt-login-bruteforce")
    long_a, long_b = "a" * 5000, "a" * 4999 + "b"
    keys = [_keys(rule, "nslog", [CMD.format(seq=1, user="nsroot", ip=ip, cmd="login nsroot")
                                  .replace("Success", "ERROR: Invalid username")] * 5)[0]
            for ip in (long_a, long_a, long_b)]
    assert keys[0] == keys[1] != keys[2]
    assert all(len(key) < 100 for key in keys)
    assert keys[0].startswith("mgmt-login-bruteforce|ns-gw-01|sha256:")


@pytest.mark.parametrize("dedup_by", ["User", [""], [1], ["Remote_IP"], ["User", "Clientip"],
                                      ["Group(s)"], ["message"]])
def test_invalid_dedup_by_rejected(dedup_by: object) -> None:
    with pytest.raises(RuleError, match="dedup_by"):
        parse_rule({**custom_rule(), "dedup_by": dedup_by})


def test_known_fields_cover_every_parser_field() -> None:
    from netrescale.detect.rules import KNOWN_FIELDS
    from netrescale.parse import nslog

    parsed = {nslog._FIELD_NAMES.get(key, key) for key in nslog._FIELD_KEYS}
    assert parsed | {"Rejected_user", nslog.INJECTION_FIELD, "Tty"} == KNOWN_FIELDS
    shell = parse_line("bashlog", SHELL.format(user="nsroot", cmd="id"), "ns-gw-01")
    assert set(shell.fields) <= KNOWN_FIELDS
    assert parse_rule({**custom_rule(), "dedup_by": sorted(KNOWN_FIELDS)}).dedup_by


def test_dedup_by_rejected_with_threshold() -> None:
    with pytest.raises(RuleError, match="dedup_by"):
        parse_rule({**custom_rule(), "dedup_by": ["User"],
                    "threshold": {"count": 2, "window_seconds": 60}})


def test_dedup_digest_does_not_hash_registered_secrets() -> None:
    from netrescale.redact import registry

    rule = next(r for r in RULES if r.id == "shell-tmp-exec")
    first = SHELL.format(user="nsroot", cmd="/tmp/x -p dedup-secret-one")
    second = SHELL.format(user="nsroot", cmd="/tmp/x -p dedup-secret-two")
    assert len(set(_keys(rule, "bashlog", [first, second]))) == 2
    registry.register("dedup-secret-one")
    registry.register("dedup-secret-two")
    try:
        assert len(set(_keys(rule, "bashlog", [first, second]))) == 1
    finally:
        registry.forget("dedup-secret-one")
        registry.forget("dedup-secret-two")


def custom_rule() -> dict:
    return {"id": "custom-test", "title": "Custom test", "severity": "medium",
            "sources": ["nslog"], "match": {"raw_regex": "suspicious-marker"},
            "tests": {"positive": [{"source": "nslog", "line": "suspicious-marker"}],
                      "negative": [{"source": "nslog", "line": "ordinary entry"}]}}


async def test_custom_rules_are_validated_and_retained(tmp_path: Path) -> None:
    from netrescale.detect.hunt_rules import HuntRuleStore, run_worker

    path = tmp_path / "hunt-rules.json"
    store = HuntRuleStore(path)
    checked = await run_worker({"mode": "validate", "text": yaml.safe_dump(custom_rule())})
    assert checked["tested"] == 2
    revision = store.save(checked["documents"], "", "admin")
    assert path.stat().st_mode & 0o777 == 0o600
    reopened = HuntRuleStore(path)
    assert reopened.read()[0] == revision
    assert any(document["id"] == "custom-test" for document in reopened.active())
    result = await run_worker({"mode": "scan", "text": "suspicious-marker", "source": "nslog",
                               "device": "gateway", "rules": reopened.active()})
    assert "custom-test" in {finding["rule_id"] for finding in result["findings"]}
    with pytest.raises(RuleError, match="changed"):
        reopened.save(checked["documents"], "", "other-admin")
    checked["documents"][0]["enabled"] = False
    revision = reopened.save(checked["documents"], revision, "admin")
    assert all(document["id"] != "custom-test" for document in reopened.active())
    reopened.delete("custom-test", revision)
    assert reopened.read()[1]["rules"] == {}


async def test_custom_rule_dedup_by_is_validated_and_kept() -> None:
    from netrescale.detect.hunt_rules import run_worker

    checked = await run_worker({"mode": "validate", "text": yaml.safe_dump(
        {**custom_rule(), "dedup_by": ["User", "Client_ip"]})})
    assert checked["documents"][0]["dedup_by"] == ["User", "Client_ip"]
    assert parse_rule(checked["documents"][0]).dedup_by == ("User", "Client_ip")
    plain = await run_worker({"mode": "validate", "text": yaml.safe_dump(custom_rule())})
    assert "dedup_by" not in plain["documents"][0]


@pytest.mark.parametrize("change", [
    {"id": "bundled-rule"}, {"sources": ["shell"]}, {"command": "arbitrary command"},
    {"match": {}}, {"match": {"raw_regex": "("}}, {"match": {"raw_regex": "ordinary"}},
    {"tests": {"positive": [], "negative": []}}, {"dedup_by": "User"},
    {"dedup_by": ["Remote_IP"]},
    {"dedup_by": ["User"], "threshold": {"count": 1, "window_seconds": 60}},
])
async def test_custom_rule_invalid_definitions_are_rejected(change: dict) -> None:
    from netrescale.detect.hunt_rules import run_worker

    with pytest.raises(RuleError):
        await run_worker({"mode": "validate", "text": yaml.safe_dump({**custom_rule(), **change})})


async def test_custom_regex_cannot_stall_the_daemon() -> None:
    from netrescale.detect.hunt_rules import run_worker

    document = custom_rule()
    document["match"]["raw_regex"] = "(a+)+$"
    with pytest.raises(RuleError, match="time limit"):
        await run_worker({"mode": "scan", "text": "a" * 5000 + "!", "source": "nslog",
                          "device": "test", "rules": [document]}, timeout=2)
    good = await run_worker({"mode": "validate", "text": yaml.safe_dump(custom_rule())})
    assert good["tested"] == 2


async def test_script_templates_pass_all_vectors_and_are_opt_in(tmp_path: Path) -> None:
    from netrescale.detect.hunt_rules import HuntRuleStore, run_worker, templates

    pack = templates()
    assert len(pack["items"]) == 17
    assert "Thomas Poppelgaard" in pack["source"]["provenance"]
    assert "not independently verified" in pack["source"]["provenance"]
    checked = await run_worker({"mode": "validate", "text": yaml.safe_dump(pack["items"])})
    assert checked["tested"] >= 34
    store = HuntRuleStore(tmp_path / "hunt-rules.json")
    template_ids = {rule["id"] for rule in pack["items"]}
    assert not template_ids.intersection(rule["id"] for rule in store.active())
    store.save(checked["documents"], "", "admin")
    assert template_ids.issubset(rule["id"] for rule in store.active())


def test_rule_with_missing_list_is_disabled_not_fatal() -> None:
    engine = RuleEngine(RULES, {})
    assert "mgmt-from-unexpected-ip" in engine.disabled
    assert all(r.id not in engine.disabled for r in engine.active_rules)


def test_parse_cmd_executed_fields() -> None:
    ev = parse_nslog(NS + 'default GUI CMD_EXECUTED 812 0 : User admin1 - Remote_ip 10.20.0.5 '
                     '- Command "add ns ip 1.2.3.4 \\"x\\"" - Status "Success"', "ns-gw-01")
    assert ev.event_type == "GUI CMD_EXECUTED"
    assert ev.partition == "default"
    assert ev.seq == 812
    assert ev.ts == datetime(2026, 10, 5, 10, 0, 1, tzinfo=UTC)
    assert ev.fields["User"] == "admin1"
    assert ev.fields["Remote_ip"] == "10.20.0.5"
    assert ev.fields["Command"] == 'add ns ip 1.2.3.4 \\"x\\"'
    assert ev.fields["Status"] == "Success"


def test_parse_without_partition_and_mmddyyyy() -> None:
    ev = parse_nslog("10/05/2026:10:00:01 GMT ns 0-PPE-0 : SSLVPN LOGIN 5 0 : Context a@1.2.3.4 - "
                     "SessionId: 9- User a - Client_ip 1.2.3.4", "d", "MMDDYYYY")
    assert (ev.partition, ev.feature, ev.event) == (None, "SSLVPN", "LOGIN")
    assert ev.fields["SessionId"] == "9"
    assert ev.ts == datetime(2026, 10, 5, 10, 0, 1, tzinfo=UTC)


def test_unparseable_line_is_kept_raw() -> None:
    ev = parse_nslog("garbage line", "d")
    assert ev.event_type is None and ev.raw == "garbage line"


def test_threshold_window_and_reset() -> None:
    rule = next(r for r in RULES if r.id == "mgmt-login-bruteforce")
    engine = RuleEngine([rule], LISTS)
    line = NS + ('default API CMD_EXECUTED 1 0 : User nsroot - Remote_ip 198.51.100.7 - '
                 'Command "login nsroot" - Status "ERROR: Invalid username or password"')
    t0 = datetime(2026, 10, 5, tzinfo=UTC)
    fired = []
    for i in range(12):
        ev = parse_nslog(line, "ns-gw-01")
        ev.ts = t0 + timedelta(seconds=10 * i)
        fired.append(bool(engine.evaluate(ev)))
    assert fired == [False] * 4 + [True] + [False] * 4 + [True] + [False] * 2
    # spaced-out failures never reach the threshold
    engine2 = RuleEngine([rule], LISTS)
    for i in range(10):
        ev = parse_nslog(line, "ns-gw-01")
        ev.ts = t0 + timedelta(minutes=2 * i)
        assert not engine2.evaluate(ev)


def test_session_reuse_detected_once_per_new_ip() -> None:
    tracker = SessionTracker()
    base = NS + "default SSLVPN {ev} 1 0 : Context j@{c} - SessionId: 77- User j - Client_ip {c}"
    login = parse_nslog(base.format(ev="LOGIN", c="192.0.2.10"), "ns-gw-01")
    assert tracker.observe(login) == []
    hijack = parse_nslog(base.format(ev="TCPCONNSTAT", c="192.0.2.10") +
                         " - Source 203.0.113.66:5151 - Destination 10.1.1.1:2598", "ns-gw-01")
    found = tracker.observe(hijack)
    assert len(found) == 1 and found[0].new_ip == "203.0.113.66"
    assert found[0].original_ip == "192.0.2.10"
    assert tracker.observe(hijack) == []  # reported once
    # the same session id after a reboot is a different session, tracked separately
    assert tracker.observe(login, boot_id="boot2") == []
    assert len(tracker) == 2


def test_session_tracker_evicts_idle() -> None:
    tracker = SessionTracker(idle_ttl=timedelta(hours=1))
    for i in range(3):
        ev = LogEvent("nslog", "d", "", fields={"SessionId": str(i), "Client_ip": "1.1.1.1"},
                      ts=datetime(2026, 1, 1, i, tzinfo=UTC))
        tracker.observe(ev)
    assert len(tracker) == 2
