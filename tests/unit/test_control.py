import asyncio
import json
import os
from pathlib import Path

import pytest

from netrescale.control import ControlClient, ControlError, ControlRequest, ControlServer

requires_peercred = pytest.mark.skipif(
    not hasattr(__import__("socket"), "SO_PEERCRED"), reason="needs Linux SO_PEERCRED")


@requires_peercred
@pytest.mark.linux
async def test_local_control_roundtrip_and_error(tmp_path: Path) -> None:
    async def dispatch(request: ControlRequest) -> dict[str, str]:
        if request.action != "status":
            raise ControlError("operation not allowed", 403)
        return {"actor": request.actor}

    server = ControlServer(tmp_path / "c.sock", dispatch)
    await server.start()
    try:
        client = ControlClient(server.path)
        assert await client.call("admin", "status") == {"actor": "admin"}
        with pytest.raises(ControlError, match="not allowed"):
            await client.call("admin", "shell")
        assert server.path.stat().st_mode & 0o777 == 0o600
    finally:
        await server.close()
    assert not server.path.exists()


@requires_peercred
@pytest.mark.linux
async def test_control_rejects_wrong_peer_and_invalid_fields(tmp_path: Path) -> None:
    seen = []

    async def dispatch(request: ControlRequest) -> dict[str, bool]:
        seen.append(request)
        return {"ok": True}

    server = ControlServer(tmp_path / "c.sock", dispatch, allowed_uid=os.getuid() + 1)
    await server.start()
    try:
        with pytest.raises(ControlError, match="not authorized"):
            await ControlClient(server.path).call("admin", "status")
        assert seen == []
        server.allowed_uid = os.getuid()
        reader, writer = await asyncio.open_unix_connection(server.path)
        writer.write(b'{"actor":"admin","action":"status","command":"rm"}\n')
        await writer.drain()
        assert json.loads(await reader.readline())["status"] == 400
        writer.close()
        await writer.wait_closed()
        assert seen == []
    finally:
        await server.close()


@pytest.mark.linux
async def test_control_preserves_unexpected_existing_file(tmp_path: Path) -> None:
    async def dispatch(request: ControlRequest) -> dict[str, bool]:
        return {"ok": True}

    path = tmp_path / "c.sock"
    path.write_text("do not overwrite")
    with pytest.raises(ControlError, match="refusing"):
        await ControlServer(path, dispatch).start()
    assert path.read_text() == "do not overwrite"


def test_peer_identity_fails_closed() -> None:
    from netrescale.control import peer_uid

    class Broken:
        def getsockopt(self, *_args: object) -> bytes:
            raise OSError("no credentials")

    with pytest.raises(ControlError) as missing:
        peer_uid(None)
    assert missing.value.status == 403
    with pytest.raises(ControlError):
        peer_uid(Broken())
