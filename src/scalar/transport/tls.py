"""TLS public-key (SPKI) pinning for NetScaler management interfaces.

NetScaler management certificates are often self-signed, so CA validation alone is not
enough. A pinned connection checks the SHA-256 of the server's SubjectPublicKeyInfo right
after the TLS handshake, before any HTTP bytes (including NITRO login credentials) are sent.
Key pinning (rather than pinning the certificate) survives re-issuing a cert with the same key.
"""

from __future__ import annotations

import base64
import hashlib
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpcore
import httpx
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class PinMismatch(ssl.SSLError):
    """The server presented a key that does not match the pinned SPKI hash."""

    def __init__(self, host: str, expected: str, actual: str) -> None:
        super().__init__(f"TLS key for {host} does not match the pin "
                         f"(expected sha256/{expected}, got sha256/{actual})")
        self.host = host
        self.expected = expected
        self.actual = actual


def spki_sha256(der_cert: bytes) -> str:
    cert = x509.load_der_x509_certificate(der_cert)
    spki = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(hashlib.sha256(spki).digest()).decode()


@dataclass(frozen=True, slots=True)
class PeerCertInfo:
    spki_sha256: str
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    self_signed: bool


def describe_cert(der_cert: bytes) -> PeerCertInfo:
    cert = x509.load_der_x509_certificate(der_cert)
    return PeerCertInfo(
        spki_sha256=spki_sha256(der_cert),
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        self_signed=cert.subject == cert.issuer,
    )


def fetch_peer_cert(host: str, port: int = 443, timeout: float = 10.0) -> PeerCertInfo:
    """Read the server certificate without validating it, for trust-on-first-use pinning.

    Sends no HTTP request and no credentials; the caller must show the result to an admin
    and get explicit confirmation before storing the pin.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # inspection only; nothing is sent
    with socket.create_connection((host, port), timeout=timeout) as sock, \
            ctx.wrap_socket(sock, server_hostname=host) as tls:
        der = tls.getpeercert(binary_form=True)
    if not der:
        raise ssl.SSLError(f"{host}:{port} presented no certificate")
    return describe_cert(der)


def make_ssl_context(*, pin: str | None, ca_bundle: str | None) -> ssl.SSLContext:
    """Pinned connections skip chain checks (the pin replaces them); otherwise use CAs."""
    if pin and not ca_bundle:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # the SPKI pin is verified right after the handshake
    else:
        ctx = ssl.create_default_context(cafile=ca_bundle)
        # Python 3.13 enables VERIFY_X509_STRICT by default, which rejects many appliance certs.
        ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


class _PinningStream(httpcore.AsyncNetworkStream):
    def __init__(self, inner: httpcore.AsyncNetworkStream, host: str, pin: str) -> None:
        self._inner = inner
        self._host = host
        self._pin = pin

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return await self._inner.read(max_bytes, timeout)

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        await self._inner.write(buffer, timeout)

    async def aclose(self) -> None:
        await self._inner.aclose()

    def get_extra_info(self, info: str) -> Any:
        return self._inner.get_extra_info(info)

    async def start_tls(self, ssl_context: ssl.SSLContext, server_hostname: str | None = None,
                        timeout: float | None = None) -> httpcore.AsyncNetworkStream:
        tls = await self._inner.start_tls(ssl_context, server_hostname, timeout)
        ssl_obj = tls.get_extra_info("ssl_object")
        der = ssl_obj.getpeercert(binary_form=True) if ssl_obj is not None else None
        actual = spki_sha256(der) if der else "<none>"
        if actual != self._pin:
            await tls.aclose()
            raise PinMismatch(self._host, self._pin, actual)
        return tls


class _PinningBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, host: str, pin: str) -> None:
        self._inner = httpcore.AnyIOBackend()
        self._host = host
        self._pin = pin

    async def connect_tcp(self, host: str, port: int, timeout: float | None = None,
                          local_address: str | None = None,
                          socket_options: Any = None) -> httpcore.AsyncNetworkStream:
        stream = await self._inner.connect_tcp(host, port, timeout, local_address,
                                               socket_options)
        return _PinningStream(stream, self._host, self._pin)

    async def connect_unix_socket(self, path: str, timeout: float | None = None,
                                  socket_options: Any = None) -> httpcore.AsyncNetworkStream:
        raise RuntimeError("unix sockets are not used for NetScaler connections")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class PinnedTransport(httpx.AsyncHTTPTransport):
    """httpx transport whose every new TLS connection must match ``pin``."""

    def __init__(self, host: str, pin: str, ssl_context: ssl.SSLContext,
                 max_connections: int = 2) -> None:
        super().__init__(verify=ssl_context, trust_env=False)
        if not hasattr(self, "_pool"):  # guards against httpx internals changing
            raise RuntimeError("unsupported httpx version: transport has no _pool")
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl_context,
            max_connections=max_connections,
            max_keepalive_connections=max_connections,
            keepalive_expiry=30.0,
            network_backend=_PinningBackend(host, pin),
        )
