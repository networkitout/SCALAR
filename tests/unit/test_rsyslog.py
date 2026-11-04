from pathlib import Path

from scalar.config import load_config
from scalar.rsyslog import nftables_conf, rsyslog_conf, syslog_sources

EXAMPLE = Path(__file__).parents[2] / "deploy" / "config.example.yaml"


def test_rsyslog_routes_only_inventory_sources_by_sender_ip() -> None:
    cfg = load_config(EXAMPLE)
    conf = rsyslog_conf(cfg)
    assert syslog_sources(cfg) == ["10.0.0.10", "10.0.0.11"]
    assert '$fromhost-ip == "10.0.0.10" or $fromhost-ip == "10.0.0.11"' in conf
    assert "%fromhost-ip%" in conf and "%hostname%" not in conf  # never trust message hostname
    assert "quarantine.log" in conf
    assert 'queue.saveOnShutdown="on"' in conf
    assert conf.count("{") == conf.count("}")


def test_nftables_allows_only_inventory() -> None:
    nft = nftables_conf(load_config(EXAMPLE))
    assert "elements = { 10.0.0.10, 10.0.0.11 }" in nft
    assert "tcp dport 514 drop" in nft and "udp dport 514 drop" in nft
