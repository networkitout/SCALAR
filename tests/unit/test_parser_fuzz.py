"""Appliance output is untrusted: parsers must never raise or hang on arbitrary input."""

import time

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from scalar.parse.nslog import extract_fields, parse_line, parse_syslog

FUZZ = settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
SEEDS = [
    "Oct  5 10:00:01 <local0.info> ns-gw-01 10/05/2026:10:00:01 GMT ns-gw-01 0-PPE-0 : default "
    "SSLVPN HTTPREQUEST 1 : Context u@1.2.3.4 - SessionId: 1 - User u",
    "Oct  5 10:00:01 <local7.notice> ns-gw-01 sh[99]: nobody on ? shell_command=\"id\"",
]


@FUZZ
@given(st.text(max_size=4000))
def test_arbitrary_text_never_raises(line: str) -> None:
    for source in ("nslog", "bashlog", "shlog", "httpaccess", "other"):
        parse_line(source, line, "dev")
    parse_syslog(line, "dev")
    extract_fields(line)


@FUZZ
@given(st.sampled_from(SEEDS), st.text(max_size=300), st.integers(0, 150))
def test_mutated_valid_lines_never_raise(seed: str, junk: str, cut: int) -> None:
    line = seed[:cut] + junk + seed[cut:]
    parse_syslog(line, "dev")
    parse_line("nslog", line, "dev")


def test_pathological_quoting_is_bounded() -> None:
    started = time.monotonic()
    for line in ('a="' * 20000, "x=" + '\\"' * 50000, " " * 100000 + "k=v", "<" * 100000):
        parse_syslog(line, "dev")
        extract_fields(line)
    assert time.monotonic() - started < 5
