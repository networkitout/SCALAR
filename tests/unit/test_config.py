from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from scalar.config import Config, DeviceMode, load_config
from scalar.detect.config_diff import diff_configs
from scalar.detect.config_risk import load_risk_rules
from scalar.runtime import Runtime

EXAMPLE = Path(__file__).parents[2] / "deploy" / "config.example.yaml"


def test_example_config_is_valid() -> None:
    cfg = load_config(EXAMPLE)
    assert [d.name for d in cfg.devices] == ["ns-gw-01", "ns-gw-02"]
    assert cfg.pair_of("ns-gw-01") is not None
    assert cfg.nitro_ref(cfg.device("ns-gw-01")) == "local:sc_nitro"
    assert cfg.credential_users() == {"local:sc_nitro": ["ns-gw-01", "ns-gw-02"]}


def base() -> dict:  # type: ignore[type-arg]
    return yaml.safe_load(EXAMPLE.read_text())


@pytest.mark.parametrize(
    ("mutate", "msg"),
    [
        (lambda d: d["devices"].append(dict(d["devices"][0])), "duplicate device"),
        (lambda d: d["devices"][0].update(nsip="not-an-ip"), "nsip"),
        (lambda d: d["devices"][0].update(mode="active"), "ssh_hostkey"),
        (lambda d: d["devices"][0].update(nitro_credential="sc_nitro"), "credential ref"),
        (lambda d: d["ha_pairs"][0].update(nodes=["ns-gw-01", "nope"]), "unknown device"),
        (lambda d: d["notify"]["webhook"].update(url="http://insecure"), "url"),
        (lambda d: d.update(surprise=1), "surprise"),
    ],
)
def test_invalid_configs(mutate, msg: str) -> None:  # type: ignore[no-untyped-def]
    doc = base()
    mutate(doc)
    with pytest.raises(ValidationError, match=msg):
        Config.model_validate(doc)


def test_active_device_counts_sweep_credential() -> None:
    doc = base()
    doc["devices"][0].update(mode="active", ssh_hostkey="ssh-ed25519 AAAAC3Nza")
    cfg = Config.model_validate(doc)
    assert cfg.device("ns-gw-01").mode is DeviceMode.ACTIVE
    assert cfg.credential_users()["local:sc_sweep"] == ["ns-gw-01"]


def test_spki_pinning_is_default_and_can_be_disabled_without_losing_the_pin() -> None:
    document = base()
    cfg = Config.model_validate(document)
    assert cfg.devices[0].spki_pinning
    original_pin = cfg.devices[0].spki_pin
    document["devices"][0]["spki_pinning"] = False
    cfg = Config.model_validate(document)
    assert not cfg.devices[0].spki_pinning
    assert cfg.devices[0].spki_pin == original_pin
    target = Runtime(cfg, lambda: b"").nitro_target(cfg.devices[0])
    assert not target.spki_pinning and target.spki_pin == original_pin
    assert not Config.model_validate(cfg.model_dump()).devices[0].spki_pinning


def test_diff_summary_highlights_new_users_and_policy_changes() -> None:
    old = "set ns hostName a\n"
    new = (
        "set ns hostName a\n"
        "add system user backdoor 0123456789abcdef0123 -encrypted -hashmethod SHA512\n"
        "bind system user backdoor superuser 100\n"
    )
    diff = diff_configs(old, new, load_risk_rules())
    summary = diff.summarize()
    assert "new/changed management users" in summary
    assert "privileged policy grants" in summary
    assert "backdoor" in summary


def test_fim_is_opt_in_per_device_with_bounded_intervals() -> None:
    doc = base()
    cfg = Config.model_validate(doc)
    assert not any(device.fim.enabled for device in cfg.devices)
    assert cfg.defaults.fim.webroot_interval == 600
    doc["devices"][0]["fim"] = {"enabled": True}
    cfg = Config.model_validate(doc)
    assert cfg.fim_ref(cfg.device("ns-gw-01")) == "local:sc_fim"
    assert cfg.credential_users()["local:sc_fim"] == ["ns-gw-01"]
    doc["devices"][0]["fim"] = {"enabled": True, "credential": "local:sc_nitro"}
    cfg = Config.model_validate(doc)
    assert cfg.credential_users() == {"local:sc_nitro": ["ns-gw-01", "ns-gw-02"]}


@pytest.mark.parametrize("fim", [
    {"webroot_interval": 60}, {"webroot_interval": 3600}, {"rehash_interval": 10},
    {"max_depth": 0}, {"credential": "sc_fim"}, {"surprise": 1},
])
def test_invalid_fim_settings(fim: dict) -> None:  # type: ignore[type-arg]
    doc = base()
    doc["defaults"]["fim"] = fim
    with pytest.raises(ValidationError):
        Config.model_validate(doc)


def test_smtp_credential_requires_starttls() -> None:
    from scalar.config import SmtpSink

    base = {"host": "smtp.example.internal", "sender": "a@example.com",
            "recipients": ["b@example.com"]}
    SmtpSink(**base, credential="local:smtp_relay")
    SmtpSink(**base, starttls=False)
    with pytest.raises(ValidationError, match="requires starttls"):
        SmtpSink(**base, credential="local:smtp_relay", starttls=False)
