import asyncio
import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from scalar.config import SiemSink, WebhookSink
from scalar.detect.config_diff import diff_configs
from scalar.detect.config_risk import load_risk_rules
from scalar.detect.findings import Finding, from_config_diff
from scalar.detect.severity import Severity
from scalar.notify import formats
from scalar.notify.sinks import (
    OutboundSecretLeak,
    Router,
    SiemNotifier,
    WebhookNotifier,
    guard_outbound,
)
from scalar.redact import registry

T = datetime(2026, 10, 5, 10, 0, 1, tzinfo=UTC)


def finding(sev: Severity = Severity.HIGH, key: str = "k1", **kw: object) -> Finding:
    base = dict(dedup_key=key, rule_id="mgmt-high-risk-command",
                title="High-risk | management=command", severity=sev, category="log_rule",
                device="ns-gw-01", summary="line1\nline2 a=b \\ c", observed_at=T,
                evidence={"line": "x"}, cve=("CVE-2025-5777",), mitre=("T1098",))
    base.update(kw)
    return Finding(**base)  # type: ignore[arg-type]


def test_ecs_shape() -> None:
    doc = formats.to_ecs(finding())
    assert doc["@timestamp"] == "2026-10-05T10:00:01+00:00"
    assert doc["event"]["kind"] == "alert" and doc["event"]["severity"] == 75
    assert doc["vulnerability"]["id"] == ["CVE-2025-5777"]
    assert doc["threat"]["technique"]["id"] == ["T1098"]
    assert doc["host"]["name"] == "ns-gw-01"


def test_cef_escaping() -> None:
    cef = formats.to_cef(finding())
    header, ext = cef.rsplit("|", 1)
    assert header.startswith("CEF:0|scalar|scalar|")
    assert "High-risk \\| management=command" in header  # | escaped in header, = left alone
    assert "msg=line1\\nline2 a\\=b \\\\ c" in ext
    assert "\n" not in cef
    assert "|8|" in cef  # high -> 8


def test_rfc5424_and_octet_framing() -> None:
    msg = formats.rfc5424("hello\nworld", Severity.CRITICAL, hostname="h",
                          timestamp="2026-10-05T10:00:01.000Z")
    assert msg == b"<162>1 2026-10-05T10:00:01.000Z h scalar - FINDING - hello\nworld"
    framed = formats.octet_frame(msg)
    n, _, rest = framed.partition(b" ")
    assert int(n) == len(rest) == len(msg)


def test_outbound_guard_blocks_registered_secrets() -> None:
    registry.register("Sup3r-Secret-Value")
    with pytest.raises(OutboundSecretLeak):
        guard_outbound("oops Sup3r-Secret-Value leaked")
    guard_outbound("clean payload")


def test_config_diff_finding_unattributed_is_escalated() -> None:
    rules = load_risk_rules()
    d = diff_configs("set ns hostName a\n", "set ns hostName a\nadd lb vserver v HTTP\n", rules)
    f = from_config_diff("ns1", d, kind="running", attribution=[], snapshot_id="s1")
    assert f.severity is Severity.HIGH  # LOW change, but nobody we can attribute it to
    assert "unattributed" in f.summary
    f2 = from_config_diff("ns1", d, kind="running", attribution=["admin1@10.20.0.5"],
                          snapshot_id="s1")
    assert f2.severity is Severity.LOW and "admin1@10.20.0.5" in f2.summary


class FakeSink:
    def __init__(self, name: str, min_sev: Severity, fail: bool = False) -> None:
        self.name = name
        self.min_severity = min_sev
        self.sent: list[Finding] = []
        self.fail = fail

    async def send(self, f: Finding) -> None:
        if self.fail:
            raise ConnectionError("down")
        self.sent.append(f)


async def test_router_severity_dedup_and_isolation() -> None:
    email, siem, broken = (FakeSink("email", Severity.HIGH), FakeSink("siem", Severity.INFO),
                           FakeSink("hook", Severity.INFO, fail=True))
    r = Router([email, siem, broken], suppress_for=timedelta(hours=1))
    res = await r.dispatch(finding(Severity.MEDIUM), now=T)
    assert [x.sink for x in res if x.ok] == ["siem"]
    assert [x.sink for x in res if not x.ok] == ["hook"]
    await r.dispatch(finding(Severity.MEDIUM), now=T + timedelta(minutes=5))
    assert len(siem.sent) == 1  # suppressed duplicate
    await r.dispatch(finding(Severity.MEDIUM), now=T + timedelta(hours=2))
    assert len(siem.sent) == 2
    await r.dispatch(finding(Severity.CRITICAL, key="k2"), now=T)
    assert [f.dedup_key for f in email.sent] == ["k2"]


async def test_webhook_slack_and_generic() -> None:
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200)

    t = httpx.MockTransport(handler)
    await WebhookNotifier(WebhookSink(url="https://hooks.example/x", format="slack"),
                          transport=t).send(finding())
    await WebhookNotifier(WebhookSink(url="https://hooks.example/y"), transport=t).send(finding())
    assert "text" in json.loads(seen[0].content)
    assert json.loads(seen[1].content)["event"]["id"] == "k1"


async def test_siem_tcp_delivery_and_reconnect() -> None:
    received: list[bytes] = []

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        received.append(await reader.read(65536))
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        sink = SiemNotifier(SiemSink(host="127.0.0.1", port=port, transport="tcp"))
        await sink.send(finding())
        await asyncio.sleep(0.1)
        await sink.send(finding(key="k2"))  # server closed the first connection
        await asyncio.sleep(0.2)
        await sink.aclose()
        payloads = b"".join(received)
        assert payloads.count(b"scalar - FINDING - ") >= 1
        n, _, rest = received[0].partition(b" ")
        assert int(n) == len(rest)
        body = rest.split(b" - FINDING - ", 1)[1]
        assert json.loads(body)["event"]["id"] == "k1"
    finally:
        server.close()


def _finding(title: str = "t", summary: str = "s") -> Finding:
    return Finding("k", "rule", title, Severity.HIGH, "log_rule", "dev", summary)


def test_slack_text_cannot_trigger_mentions_or_links() -> None:
    finding = _finding(summary="user <!channel> <https://evil.example|click> & <@U123>")
    text = formats.slack_payload(finding)["text"]
    assert "<" not in text and ">" not in text
    assert "&lt;!channel&gt;" in text and "&amp;" in text


def test_email_subject_stays_a_single_header_line() -> None:
    subject = formats.email_subject(_finding(title="a\r\nBcc: evil@example.com"))
    assert "\n" not in subject and "\r" not in subject
