import asyncio
import contextlib
import datetime as dt
import ipaddress
import ssl
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from scalar.secrets.base import Credential
from scalar.secrets.resolver import CredentialBlocked, CredentialRef, LockoutGuard
from scalar.transport.nitro import (
    AuthRejected,
    NitroClient,
    NitroError,
    NitroTarget,
    PermissionDenied,
    ReadOnlyViolation,
)
from scalar.transport.tls import PinMismatch, describe_cert, spki_sha256
from tests.emulator.nitro import FakeNitro

TARGET = NitroTarget("ns1", "ns1.example", spki_pin="unused-with-mock-transport")


def client(fake: FakeNitro, pw: str = "nitro-password", **kw: object) -> NitroClient:
    return NitroClient(TARGET, lambda: Credential("sc_nitro", pw), transport=fake.transport(),
                       **kw)  # type: ignore[arg-type]


async def test_reads_version_and_configs() -> None:
    fake = FakeNitro(running="set ns hostName a\nadd route 0.0.0.0 0.0.0.0 1.1.1.1\n")
    async with client(fake) as c:
        assert "NS14.1" in await c.version_string()
        assert "add route" in await c.running_config()
        assert (await c.config_state())["configchanged"] is True
    assert fake.sessions == set()  # logged out on close
    assert fake.login_attempts == 1  # one session reused for every request


async def test_password_never_in_url_or_headers() -> None:
    fake = FakeNitro()
    async with client(fake) as c:
        await c.version_string()
    for req in fake.requests:
        assert "nitro-password" not in str(req.url)
        assert "nitro-password" not in str(req.headers)


async def test_session_expiry_relogs_once() -> None:
    fake = FakeNitro()
    async with client(fake) as c:
        await c.version_string()
        fake.expire_sessions()
        await c.version_string()
    assert fake.login_attempts == 2


async def test_bad_password_trips_lockout_guard_and_is_not_retried() -> None:
    fake = FakeNitro()
    guard = LockoutGuard()
    ref = CredentialRef.parse("local:sc_nitro")
    c = client(fake, pw="wrong", on_auth_rejected=lambda: guard.record_rejection("ns1", ref))
    with pytest.raises(AuthRejected):
        await c.version_string()
    await c.aclose()
    assert fake.login_attempts == 1
    with pytest.raises(CredentialBlocked):
        guard.check("ns1", ref)


async def test_cmdpolicy_denial_is_permission_denied() -> None:
    fake = FakeNitro(denied={"nsrunningconfig"})
    async with client(fake) as c:
        with pytest.raises(PermissionDenied):
            await c.running_config()


async def test_count_and_attrs() -> None:
    fake = FakeNitro(resources={"vpnvserver": [{"name": "gw1"}, {"name": "gw2"}]})
    async with client(fake) as c:
        assert await c.count("vpnvserver") == 2
        assert await c.count("authenticationvserver") == 0


async def test_log_file_download_uses_read_only_session() -> None:
    content = b"event with non-ASCII bytes: \x89\xfe\n"
    fake = FakeNitro(files={"/var/log/ns.log": content})
    async with client(fake) as nitro:
        assert await nitro.system_file("ns.log", "/var/log") == content
        fake.expire_sessions()
        assert await nitro.system_file("ns.log", "/var/log") == content
    assert fake.login_attempts == 2
    assert all(request.method == "GET" or request.url.path.rsplit("/", 1)[-1]
               in {"login", "logout"} for request in fake.requests)
    downloads = [request for request in fake.requests if request.url.path.endswith("systemfile")]
    assert all(request.url.params["args"] == "filename:ns.log,filelocation:/var/log"
               for request in downloads)
    assert all(request.url.query == b"args=filename:ns.log,filelocation:%2Fvar%2Flog"
               for request in downloads)


async def test_systemfile_rejects_encoded_argument_separators() -> None:
    fake = FakeNitro(files={"/var/log/ns.log": b"log entry\n"})
    async with client(fake) as nitro:
        with pytest.raises(NitroError, match="Invalid args in query parameters"):
            await nitro._get("/nitro/v1/config/systemfile",
                             {"args": "filename:ns.log,filelocation:/var/log"})


async def test_systemfile_encodes_argument_values_exactly_once() -> None:
    filename = "ns +%2F&.log"
    location = "/var/log/archive +%2F&"
    fake = FakeNitro(files={f"{location}/{filename}": b"log entry\n"})
    async with client(fake) as nitro:
        assert await nitro.system_file(filename, location) == b"log entry\n"
    downloads = [request for request in fake.requests if request.url.path.endswith("systemfile")]
    assert len(downloads) == 1
    assert downloads[0].url.query == (
        b"args=filename:ns%20%2B%252F%26.log,"
        b"filelocation:%2Fvar%2Flog%2Farchive%20%2B%252F%26"
    )
    assert set(downloads[0].url.params) == {"args"}


@pytest.mark.parametrize("filename,location", [
    ("../ns.log", "/var/log"), ("ns.log,filename:other", "/var/log"),
    ("ns.log", "/var/log,filename:other"), ("ns.log", "var/log"),
])
async def test_systemfile_argument_injection_is_rejected(filename: str, location: str) -> None:
    fake = FakeNitro()
    async with client(fake) as nitro:
        with pytest.raises(ValueError):
            await nitro.system_file(filename, location)
    assert not fake.requests


@pytest.mark.parametrize("size", [5, 100000])
async def test_log_file_download_is_bounded(size: int) -> None:
    fake = FakeNitro(files={"/var/log/ns.log": b"x" * size})
    async with client(fake) as nitro:
        with pytest.raises(NitroError, match="transfer limit"):
            await nitro.system_file("ns.log", "/var/log", max_bytes=4)


@pytest.mark.parametrize("content,filename", [("not base64", "ns.log"), ("", "other.log")])
async def test_log_download_rejects_bad_content(content: str, filename: str) -> None:
    fake = FakeNitro(resources={"systemfile": [{"filename": filename, "filelocation": "/var/log",
                                              "filecontent": content}]})
    async with client(fake) as nitro:
        with pytest.raises(NitroError):
            await nitro.system_file("ns.log", "/var/log")


async def test_log_file_download_respects_permissions_and_lockout() -> None:
    fake = FakeNitro(denied={"systemfile"})
    async with client(fake) as nitro:
        with pytest.raises(PermissionDenied):
            await nitro.system_file("ns.log", "/var/log")
    async with client(fake, pw="wrong") as nitro:
        with pytest.raises(AuthRejected):
            await nitro.system_file("ns.log", "/var/log")
    assert fake.login_attempts == 2


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH"])
async def test_read_only_guard_blocks_writes(method: str) -> None:
    fake = FakeNitro()
    c = client(fake)
    with pytest.raises(ReadOnlyViolation):
        await c._http.request(method, "/nitro/v1/config/lbvserver",
                              json={"lbvserver": {"name": "x"}})
    with pytest.raises(ReadOnlyViolation):
        await c._http.get("/menu/neo")
    await c.aclose()
    assert all(r.url.path != "/nitro/v1/config/lbvserver" for r in fake.requests)


def test_target_requires_pin_or_ca() -> None:
    with pytest.raises(ValueError, match="never disabled"):
        NitroTarget("x", "x")


# ---- real-socket TLS pinning -------------------------------------------------------------


def _self_signed(tmp: Path, *, address: str | None = None) -> tuple[Path, Path, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ns-server-certificate")])
    now = dt.datetime.now(dt.UTC)
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - dt.timedelta(days=1))
               .not_valid_after(now + dt.timedelta(days=30)))
    if address is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(address))]),
            critical=False)
    cert = builder.sign(key, hashes.SHA256())
    cert_path, key_path = tmp / "c.pem", tmp / "k.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return cert_path, key_path, cert.public_bytes(serialization.Encoding.DER)


async def _read_request(reader: asyncio.StreamReader) -> bytes:
    """Read headers plus the declared body; httpx may send them in separate TLS records."""
    head = await reader.readuntil(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1])
    return head + (await reader.readexactly(length) if length else b"")


async def _serve(cert: Path, key: Path, received: list[bytes]) -> tuple[asyncio.Server, int]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            data = await asyncio.wait_for(_read_request(reader), timeout=2)
        except (TimeoutError, ConnectionError, ssl.SSLError):
            data = b""
        received.append(data)
        if data:
            body = b'{"errorcode":0,"message":"Done","nsversion":{"version":"NS14.1: Build 1.1"}}'
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                         b"Set-Cookie: NITRO_AUTH_TOKEN=t\r\n"
                         b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
            await writer.drain()
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=ctx)
    return server, server.sockets[0].getsockname()[1]


async def test_pin_match_and_mismatch_on_real_tls(tmp_path: Path) -> None:
    cert, key, der = _self_signed(tmp_path)
    good_pin = spki_sha256(der)
    assert describe_cert(der).self_signed
    received: list[bytes] = []
    server, port = await _serve(cert, key, received)
    try:
        ok = NitroClient(NitroTarget("lab", "127.0.0.1", port, spki_pin=good_pin),
                         lambda: Credential("sc_nitro", "pin-test-password"))
        await ok.login()  # completes the handshake and sends the login
        await ok._http.aclose()
        assert any(b"pin-test-password" in r for r in received)

        received.clear()
        bad = NitroClient(NitroTarget("lab", "127.0.0.1", port, spki_pin="AAAA" + good_pin[4:]),
                          lambda: Credential("sc_nitro", "pin-test-password"))
        with pytest.raises(PinMismatch):
            await bad.login()
        await bad._http.aclose()
        await asyncio.sleep(0.1)
        assert all(b"pin-test-password" not in r for r in received)  # nothing leaked
        assert isinstance(PinMismatch("h", "a", "b"), ssl.SSLError)
    finally:
        # Server.wait_closed() can stall on Windows after a peer reset; don't wait forever.
        server.close()
        if hasattr(server, "abort_clients"):
            server.abort_clients()
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(server.wait_closed(), 2)


@pytest.mark.parametrize("trust", ["bundle", "system", "untrusted", "wrong-address"])
async def test_spki_disabled_still_validates_ca_and_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, trust: str,
) -> None:
    address = "192.0.2.10" if trust == "wrong-address" else "127.0.0.1"
    cert, key, _der = _self_signed(tmp_path, address=address)
    if trust == "system":
        monkeypatch.setenv("SSL_CERT_FILE", str(cert))
    received: list[bytes] = []
    server, port = await _serve(cert, key, received)
    target = NitroTarget("lab", "127.0.0.1", port, spki_pin="retained-unused-fingerprint",
                         ca_bundle=str(cert) if trust in {"bundle", "wrong-address"} else None,
                         spki_pinning=False)
    try:
        async with NitroClient(target, lambda: Credential("sc_nitro", "ca-test-password")) as nitro:
            if trust in {"bundle", "system"}:
                await nitro.login()
                assert any(b"ca-test-password" in request for request in received)
            else:
                with pytest.raises(httpx.ConnectError, match="certificate verify failed"):
                    await nitro.login()
                assert all(b"ca-test-password" not in request for request in received)
    finally:
        server.close()
        if hasattr(server, "abort_clients"):
            server.abort_clients()
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(server.wait_closed(), 2)
