"""Notification sinks and the router that fans findings out to them.

Every payload is checked against the secret registry right before it leaves the process.
A payload containing a known secret is refused, not scrubbed: that case is a bug to fix.
"""

from __future__ import annotations

import asyncio
import json
import logging
import smtplib
import ssl
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from typing import Protocol

import httpx

from netrescale.config import Notify, SiemSink, SmtpSink, WebhookSink
from netrescale.detect.findings import Finding
from netrescale.detect.severity import Severity
from netrescale.notify import formats
from netrescale.redact import SecretRegistry, registry
from netrescale.secrets.base import Credential

log = logging.getLogger(__name__)


class OutboundSecretLeak(RuntimeError):
    pass


def guard_outbound(payload: str | bytes, reg: SecretRegistry = registry) -> None:
    text = payload.decode("utf-8", "replace") if isinstance(payload, bytes) else payload
    if reg.contains_secret(text):
        raise OutboundSecretLeak("refusing to send a notification that contains a secret")


class Sink(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def min_severity(self) -> Severity: ...

    async def send(self, f: Finding) -> None: ...


@dataclass
class SmtpNotifier:
    cfg: SmtpSink
    credential: Callable[[], Credential] | None = None
    name: str = "smtp"

    @property
    def min_severity(self) -> Severity:
        return Severity.parse(self.cfg.min_severity)

    def _build(self, f: Finding) -> EmailMessage:
        msg = EmailMessage()
        msg["Subject"] = formats.email_subject(f)
        msg["From"] = self.cfg.sender
        msg["To"] = ", ".join(self.cfg.recipients)
        msg.set_content(formats.email_body(f))
        return msg

    def _send_sync(self, msg: EmailMessage) -> None:
        with smtplib.SMTP(self.cfg.host, self.cfg.port, timeout=30) as smtp:
            if self.cfg.starttls:
                smtp.starttls(context=ssl.create_default_context())
            if self.credential is not None:
                cred = self.credential()
                smtp.login(cred.username, cred.reveal_password())
            smtp.send_message(msg)

    async def send(self, f: Finding) -> None:
        msg = self._build(f)
        guard_outbound(msg.as_string())
        await asyncio.to_thread(self._send_sync, msg)


@dataclass
class WebhookNotifier:
    cfg: WebhookSink
    transport: httpx.AsyncBaseTransport | None = None
    name: str = "webhook"

    @property
    def min_severity(self) -> Severity:
        return Severity.parse(self.cfg.min_severity)

    async def send(self, f: Finding) -> None:
        body = formats.slack_payload(f) if self.cfg.format == "slack" else formats.to_ecs(f)
        data = json.dumps(body, default=str)
        guard_outbound(data)
        async with httpx.AsyncClient(transport=self.transport, timeout=20,
                                     follow_redirects=False) as client:
            resp = await client.post(self.cfg.url, content=data,
                                     headers={"Content-Type": "application/json"})
            resp.raise_for_status()


@dataclass
class SiemNotifier:
    """RFC 5424 over TCP or TLS with RFC 6587 octet counting (Cribl syslog source)."""

    cfg: SiemSink
    name: str = "siem"
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _writer: asyncio.StreamWriter | None = None

    @property
    def min_severity(self) -> Severity:
        return Severity.parse(self.cfg.min_severity)

    def render(self, f: Finding) -> bytes:
        body = formats.to_json(f) if self.cfg.format == "json" else formats.to_cef(f)
        return formats.octet_frame(formats.rfc5424(body, f.severity))

    async def _connect(self) -> asyncio.StreamWriter:
        ctx = None
        if self.cfg.transport == "tls":
            ctx = ssl.create_default_context(cafile=self.cfg.ca_bundle)
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(self.cfg.host, self.cfg.port, ssl=ctx), timeout=15)
        return writer

    async def send_raw(self, frame: bytes) -> None:
        guard_outbound(frame)
        async with self._lock:
            for attempt in (1, 2):
                try:
                    if self._writer is None or self._writer.is_closing():
                        self._writer = await self._connect()
                    self._writer.write(frame)
                    await asyncio.wait_for(self._writer.drain(), timeout=15)
                    return
                except (OSError, TimeoutError):
                    self._writer = None
                    if attempt == 2:
                        raise

    async def send(self, f: Finding) -> None:
        await self.send_raw(self.render(f))

    async def aclose(self) -> None:
        if self._writer is not None:
            self._writer.close()
            self._writer = None


@dataclass
class DeliveryResult:
    sink: str
    ok: bool
    error: str | None = None


@dataclass
class Router:
    """Severity routing plus in-memory dedup. The persistent outbox (with retries across
    restarts) wraps this in the daemon."""

    sinks: list[Sink]
    suppress_for: timedelta = timedelta(hours=6)
    _last_sent: dict[tuple[str, str], datetime] = field(default_factory=dict)

    async def dispatch(self, f: Finding, now: datetime | None = None) -> list[DeliveryResult]:
        now = now or datetime.now(UTC)
        results = []
        for sink in self.sinks:
            # The daily digest goes everywhere: silence must never look like "all fine".
            if f.severity < sink.min_severity and f.category != "digest":
                continue
            key = (sink.name, f.dedup_key)
            last = self._last_sent.get(key)
            if last is not None and now - last < self.suppress_for:
                continue
            try:
                await sink.send(f)
            except OutboundSecretLeak as exc:
                log.error("%s: %s (finding %s)", sink.name, exc, f.dedup_key)
                results.append(DeliveryResult(sink.name, False, str(exc)))
                continue
            except Exception as exc:  # noqa: BLE001 - one sink failing must not stop others
                log.warning("%s: delivery failed for %s: %s", sink.name, f.dedup_key, exc)
                results.append(DeliveryResult(sink.name, False, str(exc)))
                continue
            self._last_sent[key] = now
            results.append(DeliveryResult(sink.name, True))
        return results


def build_sinks(cfg: Notify, smtp_credential: Callable[[], Credential] | None = None) -> list[Sink]:
    sinks: list[Sink] = []
    if cfg.smtp:
        sinks.append(SmtpNotifier(cfg.smtp, smtp_credential))
    if cfg.siem:
        sinks.append(SiemNotifier(cfg.siem))
    if cfg.webhook:
        sinks.append(WebhookNotifier(cfg.webhook))
    return sinks
