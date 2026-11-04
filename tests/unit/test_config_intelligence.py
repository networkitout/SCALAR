from pathlib import Path

import pytest
import yaml

from netrescale.detect.config_intelligence import (
    IndicatorKind,
    assess_config_indicators,
    load_config_intelligence,
)
from netrescale.detect.severity import Severity
from netrescale.parse.nsconf import parse_many


def _by_id(config: str) -> dict[str, object]:
    return {indicator.id: indicator for indicator in assess_config_indicators(config)}


def test_packaged_data_loads_and_has_stable_unique_ids() -> None:
    data = load_config_intelligence()
    assert data.rules
    assert len({rule.id for rule in data.rules}) == len(data.rules)
    assert all(rule.references for rule in data.rules)


def test_feature_indicators_map_to_packaged_cves_without_claiming_exploitation() -> None:
    indicators = assess_config_indicators(
        "\n".join((
            "add vpn vserver gateway SSL 192.0.2.10 443",
            "add authentication samlIdPProfile local-idp -samlSPCertName sp",
            "add server app-v6 2001:db8::10",
            "add cr vserver hdx-cr HDX 192.0.2.40 443",
        ))
    )
    by_id = {indicator.id: indicator for indicator in indicators}
    assert {
        "gateway-or-aaa-configured",
        "saml-configured",
        "saml-idp-configured",
        "ipv6-load-balancing-configured",
        "hdx-content-routing-configured",
    } <= set(by_id)
    assert by_id["gateway-or-aaa-configured"].kind is IndicatorKind.FEATURE
    assert "CVE-2025-5777" in by_id["gateway-or-aaa-configured"].cves
    assert all("does not" in item.rationale.lower() or "not proof" in item.rationale.lower()
               for item in by_id.values())


def test_feature_indicators_cite_current_advisories() -> None:
    rules = {rule.id: rule for rule in load_config_intelligence().rules}
    assert {"CVE-2026-8452", "CVE-2026-19490"} <= set(rules["gateway-or-aaa-configured"].cves)
    assert {"CVE-2026-19490", "CVE-2026-88779", "CVE-2026-107406"} <= set(
        rules["saml-configured"].cves)
    assert "CVE-2026-8452" not in rules["saml-configured"].cves  # gated on Gateway/AAA
    assert {"CVE-2026-3055", "CVE-2026-8451"} <= set(rules["saml-idp-configured"].cves)


def test_dbs_ipv6_server_is_an_ipv6_endpoint() -> None:
    hit = _by_id("add server dbs-v6 app.example.com -IPv6Address YES")
    assert "ipv6-load-balancing-configured" in hit
    assert "ipv6-load-balancing-configured" not in _by_id(
        "add server dbs-v4 app.example.com -IPv6Address NO")
    assert "ipv6-load-balancing-configured" in _by_id(
        "add server dbs-aaaa app.example.com -queryType AAAA")
    assert "ipv6-load-balancing-configured" not in _by_id(
        "add server dbs-a app.example.com -queryType A")


def test_posture_and_observable_matches_are_specific() -> None:
    config = "\n".join((
        "set ns ip 192.0.2.5 -gui ENABLED",
        "set ssl profile legacy -tls1 ENABLED",
        "set audit syslogParams -logLevel NONE",
        'add rewrite action inject insert_before q{"<script src=/x.js></script>"}',
        "add ssl certKey staged -cert /var/tmp/staged.pem -key /var/tmp/staged.key",
        "import ns extension https://updates.example/ext.lua ext",
    ))
    by_id = _by_id(config)
    assert by_id.keys() >= {
        "insecure-management-gui",
        "legacy-tls-enabled",
        "audit-loglevel-none",
        "gateway-page-script-injection",
        "certificate-from-transient-path",
        "remote-ns-extension-import",
    }
    script = by_id["gateway-page-script-injection"]
    assert script.severity is Severity.CRITICAL  # type: ignore[union-attr]
    assert script.evidence == (  # type: ignore[union-attr]
        'add rewrite action inject insert_before q{"<script src=/x.js></script>"}',
    )


def test_benign_near_matches_do_not_raise_false_positives() -> None:
    config = "\n".join((
        "add lb vserver web HTTP 192.0.2.20 80",
        "add authentication ldapAction corp -serverIP 192.0.2.30",
        "set ns ip 192.0.2.5 -gui SECUREONLY",
        "set ssl profile modern -tls1 DISABLED -tls12 ENABLED -tls13 ENABLED",
        "set audit syslogParams -logLevel ALL",
        'add responder action maintenance respondwith q{"Service unavailable"}',
        "add ssl certKey gateway -cert /nsconfig/ssl/gateway.pem -key /nsconfig/ssl/gateway.key",
        "import ns extension /nsconfig/extensions/approved.lua approved",
    ))
    assert assess_config_indicators(config) == []


def test_accepts_lines_or_parsed_commands_and_deduplicates_evidence() -> None:
    lines = [
        "add vpn vserver gateway SSL 192.0.2.10 443",
        "add vpn vserver gateway SSL 192.0.2.10 443",
    ]
    from_lines = assess_config_indicators(lines)
    from_commands = assess_config_indicators(parse_many(lines))
    assert from_lines == from_commands
    assert from_lines[0].evidence == (lines[0],)


def test_rejects_mixed_input_types() -> None:
    command = parse_many(["add vpn vserver gateway SSL 192.0.2.10 443"])[0]
    with pytest.raises(TypeError, match="only Command objects or only strings"):
        assess_config_indicators([command, "add server app 192.0.2.10"])


def test_schema_rejects_unknown_cve_reference(tmp_path: Path) -> None:
    path = tmp_path / "intel.yaml"
    path.write_text(yaml.safe_dump({
        "schema_version": 1,
        "data_version": "2026-10-05",
        "indicators": [{
            "id": "bad-cve",
            "kind": "feature",
            "severity": "info",
            "title": "Bad CVE",
            "rationale": "Test only.",
            "remediation": "Test only.",
            "cves": ["CVE-2099-9999"],
            "references": ["https://example.invalid/advisory"],
            "match_any": [{"objects": ["vpn vserver"]}],
        }],
    }), encoding="utf-8")
    with pytest.raises(ValueError, match=r"absent from cve_builds\.yaml"):
        load_config_intelligence(path)


def test_schema_rejects_positive_test_that_does_not_match(tmp_path: Path) -> None:
    path = tmp_path / "intel.yaml"
    path.write_text(yaml.safe_dump({
        "schema_version": 1,
        "data_version": "2026-10-05",
        "indicators": [{
            "id": "self-test",
            "kind": "weakness",
            "severity": "medium",
            "title": "Self test",
            "rationale": "Test only.",
            "remediation": "Test only.",
            "cves": [],
            "references": ["https://example.invalid/advisory"],
            "match_any": [{"objects": ["vpn vserver"]}],
            "positive_tests": ["add lb vserver web HTTP 192.0.2.10 80"],
        }],
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="positive test does not match"):
        load_config_intelligence(path)
