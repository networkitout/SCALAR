from datetime import date
from typing import Any

import pytest

from scalar.collect.features import detect_features
from scalar.detect.exposure import (
    AdvisoryResult,
    DeviceFeatures,
    ExposureReport,
    Status,
    assess,
    load_cve_data,
)
from scalar.detect.severity import Severity
from scalar.parse.version import Build, VersionParseError, parse_version
from scalar.secrets.base import Credential
from scalar.transport.nitro import NitroClient, NitroTarget
from tests.emulator.nitro import FakeNitro

DATA = load_cve_data()
TODAY = DATA.data_version
GW = DeviceFeatures(gateway_or_aaa=True, saml_idp=False, saml=False, ipv6_lb=False,
                    hdx_content_routing=False)
LB_ONLY = DeviceFeatures(gateway_or_aaa=False, saml_idp=False, saml=False, ipv6_lb=False,
                         hdx_content_routing=False)
SAML_SP = DeviceFeatures(gateway_or_aaa=False, saml_idp=False, saml=True, ipv6_lb=False,
                         hdx_content_routing=False)
SAML_IDP = DeviceFeatures(gateway_or_aaa=False, saml_idp=True, saml=True, ipv6_lb=False,
                          hdx_content_routing=False)


@pytest.mark.parametrize(
    ("raw", "train", "build"),
    [
        ("NetScaler NS14.1: Build 43.56.nc, Date: Jun 10 2025, 11:21:31   (64-bit)", "14.1",
         "43.56"),
        ("Citrix ADC NS13.0: Build 47.24.nc, Date: Jan 20 2020, 06:53:44", "13.0", "47.24"),
        ("NetScaler NS13.1: Build 58.32.nc, Date: ...", "13.1", "58.32"),
        ("NetScaler NS13.1-FIPS: Build 37.241.nc", "13.1-fips", "37.241"),
        ("NetScaler NS13.1: Build 37.235.nc", "13.1-fips", "37.235"),  # inferred
        ("NetScaler NS13.1: Build 37.38.nc", "13.1", "37.38"),  # old regular 37.x build
    ],
)
def test_parse_version(raw: str, train: str, build: str) -> None:
    v = parse_version(raw)
    assert v.train == train
    assert v.build == Build.parse(build)


def test_variant_override_and_inference_flag() -> None:
    v = parse_version("NetScaler NS13.1: Build 37.235.nc", variant_override="ndcpp")
    assert v.train == "13.1-ndcpp" and not v.variant_inferred
    assert parse_version("NetScaler NS13.1: Build 37.235.nc").variant_inferred


def test_parse_garbage() -> None:
    with pytest.raises(VersionParseError):
        parse_version("not a version")


def test_build_ordering() -> None:
    assert Build.parse("59.9") < Build.parse("59.19") < Build.parse("60.1")


def by_id(report: ExposureReport) -> dict[str, AdvisoryResult]:
    return {r.advisory.id: r for r in report.results}


def test_88771_fixed_14_1_without_saml_is_clean() -> None:
    r = assess("ns1", parse_version("NetScaler NS14.1: Build 73.37.nc"), GW, DATA, TODAY)
    assert r.actionable == []
    assert by_id(r)["CVE-2023-3519"].status is Status.NOT_AFFECTED
    assert by_id(r)["CVE-2025-5777"].status is Status.FIXED
    assert by_id(r)["CVE-2026-88779"].status is Status.VULNERABLE_NOT_EXPOSED
    assert by_id(r)["CVE-2026-107406"].status is Status.VULNERABLE_NOT_EXPOSED


@pytest.mark.parametrize("features", [SAML_SP, SAML_IDP], ids=["saml-sp", "saml-idp"])
def test_88771_fixed_14_1_with_saml_is_actionable(features: DeviceFeatures) -> None:
    r = assess("ns1", parse_version("NetScaler NS14.1: Build 73.37.nc"), features, DATA, TODAY)
    res = by_id(r)
    assert res["CVE-2026-88771"].status is Status.FIXED
    assert res["CVE-2026-88779"].status is Status.VULNERABLE
    assert res["CVE-2026-107406"].status is Status.VULNERABLE
    assert res["CVE-2026-107406"].fixed_in == Build.parse("73.46")
    assert r.worst is Status.VULNERABLE


@pytest.mark.parametrize(
    ("raw", "override"),
    [
        ("NetScaler NS13.1: Build 64.23.nc", None),
        ("NetScaler NS13.1-FIPS: Build 37.279.nc", None),
        ("NetScaler NS13.1: Build 37.279.nc", "ndcpp"),
        ("NetScaler NS14.1-FIPS: Build 73.37.nc", None),
    ],
)
def test_88771_fixed_other_trains_with_saml_idp_are_actionable(raw: str,
                                                               override: str | None) -> None:
    r = assess("ns1", parse_version(raw, override), SAML_IDP, DATA, TODAY)
    ids = {x.advisory.id for x in r.actionable}
    assert {"CVE-2026-88779", "CVE-2026-107406"} <= ids
    assert "CVE-2026-88771" not in ids


@pytest.mark.parametrize(
    ("raw", "override"),
    [
        ("NetScaler NS14.1: Build 73.46.nc", None),
        ("NetScaler NS13.1: Build 64.29.nc", None),
        ("NetScaler NS13.1-FIPS: Build 37.283.nc", None),
        ("NetScaler NS13.1: Build 37.283.nc", "ndcpp"),
        ("NetScaler NS14.1-FIPS: Build 73.46.nc", None),
        ("NetScaler NS14.1: Build 73.46.nc", "fips"),
    ],
)
@pytest.mark.parametrize("features", [GW, SAML_IDP], ids=["gateway", "saml-idp"])
def test_latest_fixed_builds_are_clean(raw: str, override: str | None,
                                       features: DeviceFeatures) -> None:
    r = assess("ns1", parse_version(raw, override), features, DATA, TODAY)
    assert [x.advisory.id for x in r.actionable] == []
    assert [x.advisory.id for x in r.needs_attention] == []
    assert r.worst in (Status.FIXED, Status.NOT_AFFECTED, Status.VULNERABLE_NOT_EXPOSED)


@pytest.mark.parametrize("build", ["66.68", "72.61", "73.46"])
def test_14_1_fips_builds_have_no_unknown_advisories(build: str) -> None:
    # 66.68 is the earliest 14.1-FIPS build, above every 14.1 fix the older bulletins name.
    r = assess("f", parse_version(f"NetScaler NS14.1-FIPS: Build {build}.nc"), GW, DATA, TODAY)
    assert [x.advisory.id for x in r.results if x.status is Status.UNKNOWN] == []
    assert r.needs_attention == []
    res = by_id(r)
    for cve in ("CVE-2023-4966", "CVE-2025-5777", "CVE-2025-6543", "CVE-2025-7775",
                "CVE-2026-3055"):
        assert res[cve].status is Status.FIXED, cve


def test_ldap_only_gateway_is_vulnerable_to_8452() -> None:
    r = assess("gw", parse_version("NetScaler NS14.1: Build 72.50.nc"), GW, DATA, TODAY)
    res = by_id(r)
    assert res["CVE-2026-8452"].status is Status.VULNERABLE
    assert res["CVE-2026-8452"].advisory.requires == ("gateway_or_aaa",)
    assert res["CVE-2026-8451"].status is Status.VULNERABLE_NOT_EXPOSED  # SAML IdP only
    fips = assess("gw", parse_version("NetScaler NS14.1-FIPS: Build 72.50.nc"), GW, DATA,
                  TODAY)
    assert by_id(fips)["CVE-2026-8452"].status is Status.VULNERABLE


def test_19490_gate_is_gateway_or_saml_superset() -> None:
    v = parse_version("NetScaler NS13.1: Build 63.20.nc")
    assert by_id(assess("x", v, SAML_SP, DATA, TODAY))["CVE-2026-19490"].status is (
        Status.VULNERABLE)
    assert by_id(assess("x", v, GW, DATA, TODAY))["CVE-2026-19490"].status is Status.VULNERABLE
    assert by_id(assess("x", v, LB_ONLY, DATA, TODAY))["CVE-2026-19490"].status is (
        Status.VULNERABLE_NOT_EXPOSED)
    fixed = parse_version("NetScaler NS13.1: Build 63.21.nc")
    assert by_id(assess("x", fixed, SAML_SP, DATA, TODAY))["CVE-2026-19490"].status is (
        Status.FIXED)


def test_3055_14_1_uses_conservative_66_59_fix() -> None:
    r = assess("idp", parse_version("NetScaler NS14.1: Build 66.54.nc"), SAML_IDP, DATA, TODAY)
    assert by_id(r)["CVE-2026-3055"].status is Status.VULNERABLE
    r = assess("idp", parse_version("NetScaler NS14.1: Build 66.59.nc"), SAML_IDP, DATA, TODAY)
    assert by_id(r)["CVE-2026-3055"].status is Status.FIXED


def test_12_1_fips_and_ndcpp_entries() -> None:
    ndcpp = parse_version("NetScaler NS12.1: Build 55.329.nc", "ndcpp")
    assert by_id(assess("x", ndcpp, GW, DATA, TODAY))["CVE-2025-7775"].status is (
        Status.VULNERABLE)
    fips = parse_version("NetScaler NS12.1: Build 55.329.nc", "fips")
    assert by_id(assess("x", fips, GW, DATA, TODAY))["CVE-2025-6543"].status is (
        Status.NOT_AFFECTED)


def test_historical_kev_entries() -> None:
    res = by_id(assess("x", parse_version("NetScaler NS13.1: Build 51.14.nc"), GW, DATA,
                       TODAY))
    assert res["CVE-2023-6548"].status is Status.VULNERABLE  # management interface, no gate
    assert res["CVE-2023-6549"].status is Status.VULNERABLE
    assert res["CVE-2022-27518"].status is Status.NOT_AFFECTED
    old = by_id(assess("x", parse_version("Citrix ADC NS13.0: Build 58.30.nc"), SAML_SP, DATA,
                       TODAY))
    assert old["CVE-2022-27518"].status is Status.VULNERABLE
    fips = by_id(assess("x", parse_version("NetScaler NS14.1-FIPS: Build 73.46.nc"), GW, DATA,
                        TODAY))
    for cve in ("CVE-2022-27518", "CVE-2023-6548", "CVE-2023-6549"):
        assert fips[cve].status is not Status.UNKNOWN, cve


def test_citrixbleed2_era_build_is_vulnerable() -> None:
    r = assess("ns1", parse_version("NetScaler NS14.1: Build 43.50.nc"), GW, DATA, TODAY)
    ids = {x.advisory.id for x in r.actionable}
    assert {"CVE-2025-5777", "CVE-2025-6543", "CVE-2025-7775", "CVE-2026-88771"} <= ids
    assert "CVE-2023-4966" not in ids  # fixed at 8.50
    assert r.worst is Status.VULNERABLE


def test_gate_false_marks_not_exposed_but_default_config_cve_still_hits() -> None:
    lb_only = DeviceFeatures(gateway_or_aaa=False, saml_idp=False, saml=False, ipv6_lb=False,
                             hdx_content_routing=False)
    r = assess("lb1", parse_version("NetScaler NS14.1: Build 43.50.nc"), lb_only, DATA, TODAY)
    res = by_id(r)
    assert res["CVE-2025-5777"].status is Status.VULNERABLE_NOT_EXPOSED
    assert res["CVE-2026-88771"].status is Status.VULNERABLE  # no gate


def test_unknown_features_are_possibly_exposed_not_dropped() -> None:
    r = assess("x", parse_version("NetScaler NS14.1: Build 43.50.nc"), DeviceFeatures(), DATA,
               TODAY)
    assert by_id(r)["CVE-2025-5777"].status is Status.POSSIBLY_EXPOSED


def test_any_mode_gate() -> None:
    ipv6 = DeviceFeatures(gateway_or_aaa=False, ipv6_lb=True, hdx_content_routing=False)
    r = assess("x", parse_version("NetScaler NS14.1: Build 47.46.nc"), ipv6, DATA, TODAY)
    assert by_id(r)["CVE-2025-7775"].status is Status.VULNERABLE


def test_eol_train_warns_and_unfixed_is_vulnerable() -> None:
    r = assess("old", parse_version("Citrix ADC NS13.0: Build 92.21.nc"), GW, DATA, TODAY)
    assert any("end of life" in w for w in r.warnings)
    assert by_id(r)["CVE-2025-5777"].status is Status.VULNERABLE
    assert by_id(r)["CVE-2023-4966"].status is Status.FIXED


def test_fips_train_uses_fips_builds() -> None:
    r = assess("f", parse_version("NetScaler NS13.1: Build 37.241.nc"), GW, DATA, TODAY)
    res = by_id(r)
    assert res["CVE-2025-7775"].status is Status.FIXED
    assert res["CVE-2026-88771"].status is Status.VULNERABLE


def test_unlisted_train_is_unknown() -> None:
    r = assess("f", parse_version("NetScaler NS15.1: Build 10.1.nc"), GW, DATA, TODAY)
    assert by_id(r)["CVE-2025-5777"].status is Status.UNKNOWN
    assert r.train_unknown and len(r.needs_attention) == len(DATA.advisories)
    # CTX693420 lists 12.1-FIPS but not 12.1-NDcPP; the gap must surface, not read as fixed.
    nd = assess("f", parse_version("NetScaler NS12.1: Build 55.330.nc", "ndcpp"), GW, DATA,
                TODAY)
    assert by_id(nd)["CVE-2025-5777"].status is Status.UNKNOWN
    assert "CVE-2025-5777" in {x.advisory.id for x in nd.needs_attention}


def test_stale_data_warning() -> None:
    r = assess("x", parse_version("NetScaler NS14.1: Build 73.37.nc"), GW, DATA,
               date(2027, 1, 1))
    assert any("days old" in w for w in r.warnings)


def test_min_safe_build() -> None:
    assert DATA.min_safe_build("14.1") == Build.parse("73.46")
    assert DATA.min_safe_build("14.1-fips") == Build.parse("73.46")
    assert DATA.min_safe_build("13.1") == Build.parse("64.29")
    assert DATA.min_safe_build("13.1-fips") == Build.parse("37.283")
    assert DATA.min_safe_build("13.1-ndcpp") == Build.parse("37.283")


def test_packaged_data_is_consistent() -> None:
    ids = [a.id for a in DATA.advisories]
    assert len(ids) == len(set(ids))
    assert DATA.data_version >= date(2026, 10, 13)
    for a in DATA.advisories:
        assert a.bulletin.startswith("CTX"), a.id
        Severity.parse(a.severity)
        # 13.1 FIPS and NDcPP share one build branch; listing only one leaves the other UNKNOWN.
        fips = "13.1-fips" in a.fixed or "13.1-fips" in a.not_affected | a.unfixed
        ndcpp = "13.1-ndcpp" in a.fixed or "13.1-ndcpp" in a.not_affected | a.unfixed
        assert fips == ndcpp, a.id
        if "13.1-fips" in a.fixed:
            assert a.fixed["13.1-fips"] == a.fixed["13.1-ndcpp"], a.id
    assert DATA.lifecycle["13.1"].get("verified") is True


def test_every_advisory_covers_every_live_train() -> None:
    # A live train missing from an advisory yields UNKNOWN, which the daemon alerts on daily.
    live = {t for t, e in DATA.lifecycle.items() if e.get("status") != "end_of_life"}
    assert {"13.1", "13.1-fips", "13.1-ndcpp", "14.1", "14.1-fips"} <= live
    for a in DATA.advisories:
        listed = set(a.fixed) | a.not_affected | a.unfixed
        assert live <= listed, (a.id, sorted(live - listed))


async def _features(servers: list[dict[str, Any]]) -> tuple[DeviceFeatures, FakeNitro]:
    fake = FakeNitro(resources={"server": servers, "service": [{"name": "s1",
                                                                "ipaddress": "192.0.2.20"}]})
    target = NitroTarget("ns1", "ns1.example", spki_pin="unused-with-mock-transport")
    async with NitroClient(target, lambda: Credential("sc_nitro", "nitro-password"),
                           transport=fake.transport()) as c:
        return await detect_features(c), fake


@pytest.mark.parametrize("flag", ["YES", "yes"])
async def test_dbs_ipv6_server_sets_ipv6_lb(flag: str) -> None:
    feats, fake = await _features([{"name": "dbs-v6", "domain": "app.example.com",
                                    "ipaddress": "0.0.0.0", "ipv6address": flag}])
    assert feats.ipv6_lb is True
    get = next(r for r in fake.requests if r.url.path == "/nitro/v1/config/server"
               and "count" not in r.url.params)
    assert set(get.url.params["attrs"].split(",")) == {"name", "ipaddress", "domain",
                                                      "ipv6address", "querytype"}
    r = assess("lb", parse_version("NetScaler NS14.1: Build 47.40.nc"), feats, DATA, TODAY)
    assert by_id(r)["CVE-2025-7775"].status is Status.VULNERABLE


@pytest.mark.parametrize("qtype", ["AAAA", "aaaa"])
async def test_dbs_aaaa_querytype_server_sets_ipv6_lb(qtype: str) -> None:
    feats, _ = await _features([{"name": "dbs-aaaa", "domain": "app.example.com",
                                 "ipaddress": "0.0.0.0", "ipv6address": "NO",
                                 "querytype": qtype}])
    assert feats.ipv6_lb is True


async def test_ipv4_and_dbs_ipv4_servers_are_not_ipv6() -> None:
    feats, _ = await _features([
        {"name": "web", "ipaddress": "192.0.2.10", "ipv6address": "NO"},
        {"name": "dbs-v4", "domain": "app.example.com", "ipaddress": "0.0.0.0",
         "ipv6address": "NO", "querytype": "A"},
        {"name": "dbs-srv", "domain": "_http._tcp.example.com", "ipaddress": "0.0.0.0",
         "ipv6address": "NO", "querytype": "SRV"},
    ])
    assert feats.ipv6_lb is False
    feats, _ = await _features([{"name": "v6", "ipaddress": "2001:db8::10"}])
    assert feats.ipv6_lb is True


def test_design_exposure_table_matches_the_advisory_data() -> None:
    import re
    from pathlib import Path

    design = (Path(__file__).parents[2] / "docs" / "design.md").read_text("utf-8")
    rows = [[cell.strip().split(" ")[0] for cell in line.strip("|").split("|")[:5]]
            + [line.strip("|").split("|")[5].strip()]
            for line in design.splitlines() if re.match(r"\| \d{4}-\d+", line)]
    gates = {"Gateway/AAA": ("gateway_or_aaa",), "SAML IdP": ("saml_idp",),
             "SAML SP or IdP": ("saml",), "Gateway/AAA or SAML": ("gateway_or_aaa", "saml"),
             "Gateway/AAA, IPv6 LB, HDX CR": ("gateway_or_aaa", "ipv6_lb", "hdx_content_routing"),
             "default config / DTLS": ()}
    advisories = {a.id: a for a in DATA.advisories}
    assert {"2026-8451", "2026-8452", "2026-19490", "2026-88779",
            "2026-107406"} <= {row[0] for row in rows}
    for cve, bulletin, build_14, build_13, build_fips, gate in rows:
        advisory = advisories[f"CVE-{cve.split('/')[0]}"]
        assert bulletin == advisory.bulletin, cve
        assert gates[gate] == advisory.requires, cve
        for train, build in (("14.1", build_14), ("13.1", build_13), ("13.1-fips", build_fips)):
            if build == "n/a":
                assert train in advisory.not_affected, (cve, train)
            else:
                assert str(advisory.fixed[train]) == build, (cve, train)
    safe = re.search(r"Minimum safe builds.*\*\*14\.1-(\S+)\*\*, \*\*13\.1-(\S+)\*\*, "
                     r"\*\*13\.1-FIPS/NDcPP (\S+)\*\*", design)
    assert safe is not None
    assert safe.groups() == tuple(str(DATA.min_safe_build(train))
                                  for train in ("14.1", "13.1", "13.1-fips"))
