"""Peer-authenticated, bounded local RPC between the web process and the daemon."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import socket
import stat
import struct
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

MAX_REQUEST = 4 * 1024 * 1024
MAX_RESPONSE = 8 * 1024 * 1024
CONTROL_TIMEOUT = 180


class ControlError(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


class ControlRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    actor: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    action: str = Field(pattern=r"^[a-z][a-z.]{0,63}$")
    parameters: dict[str, Any] = Field(default_factory=dict)


def _local_uid() -> int:
    if hasattr(os, "getuid"):
        with contextlib.suppress(AttributeError, OSError, TypeError):
            return int(os.getuid())
    return 0


def peer_uid(connection: Any) -> int:
    """Return the connected peer's uid, or refuse: an unknown peer is never trusted."""
    if connection is None or not hasattr(socket, "SO_PEERCRED"):
        raise ControlError("local peer identity unavailable", 403)
    try:
        credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        _pid, uid, _gid = struct.unpack("3i", credentials)
        return int(uid)
    except (AttributeError, OSError, ValueError, TypeError, struct.error):
        raise ControlError("local peer identity unavailable", 403) from None


def _loopback_port(path: Path) -> int:
    digest = hashlib.sha256(str(path).encode("utf-8")).hexdigest()
    return 20000 + int(digest[:4], 16) % 20000


class ControlClient:
    def __init__(self, path: Path) -> None:
        self.path = path

    async def call(
        self, actor: str, action: str, parameters: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        raw = (
            ControlRequest(actor=actor, action=action, parameters=parameters or {})
            .model_dump_json()
            .encode()
            + b"\n"
        )
        if len(raw) > MAX_REQUEST:
            raise ControlError("administration request is too large", 413)
        try:
            async with asyncio.timeout(CONTROL_TIMEOUT + 5):
                if os.name == "nt" or not hasattr(socket, "AF_UNIX"):
                    reader, writer = await asyncio.open_connection(
                        "127.0.0.1", _loopback_port(self.path), limit=MAX_RESPONSE
                    )
                else:
                    reader, writer = await asyncio.open_unix_connection(
                        self.path, limit=MAX_RESPONSE
                    )
                try:
                    owner = (peer_uid(writer.get_extra_info("socket"))
                             if hasattr(os, "getuid") else None)
                    if owner is not None and owner not in (os.getuid(), 0):
                        raise ControlError("unexpected daemon socket owner", 403)
                    writer.write(raw)
                    await writer.drain()
                    line = await reader.readline()
                    response = json.loads(line)
                finally:
                    writer.close()
                    with contextlib.suppress(OSError):
                        await writer.wait_closed()
        except (OSError, TimeoutError) as exc:
            raise ControlError(
                "Administration daemon is unavailable. Check the monitoring service.", 503
            ) from exc
        except (ValueError, KeyError) as exc:
            raise ControlError("Invalid response from administration daemon", 502) from exc
        if not response.get("ok"):
            raise ControlError(
                response.get("error", "Administration request failed"), response.get("status", 400)
            )
        result: dict[str, Any] = response["result"]
        return result


class ControlServer:
    def __init__(
        self,
        path: Path,
        dispatch: Callable[[ControlRequest], Awaitable[dict[str, Any]]],
        allowed_uid: int | None = None,
    ) -> None:
        self.path = path
        self.dispatch = dispatch
        self.allowed_uid = _local_uid() if allowed_uid is None else allowed_uid
        self.server: asyncio.AbstractServer | None = None
        self._requests: set[asyncio.Task[Any]] = set()
        self._slots = asyncio.Semaphore(4)

    async def start(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        if os.name == "nt" or not hasattr(socket, "AF_UNIX"):
            port = _loopback_port(self.path)
            self.server = await asyncio.start_server(
                self._handle, "127.0.0.1", port, limit=MAX_REQUEST, backlog=16
            )
            self._port = port
            return
        if self.path.exists() or self.path.is_symlink():
            existing = self.path.lstat()
            if not stat.S_ISSOCK(existing.st_mode) or existing.st_uid != _local_uid():
                raise ControlError("refusing to replace unexpected control path", 409)
            try:
                _reader, writer = await asyncio.open_unix_connection(self.path)
            except ConnectionRefusedError:
                self.path.unlink()
            else:
                writer.close()
                await writer.wait_closed()
                raise ControlError("another administration server is running", 409)
        self.server = await asyncio.start_unix_server(
            self._handle, self.path, limit=MAX_REQUEST, backlog=16
        )
        self.path.chmod(0o600)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task:
            self._requests.add(task)
        try:
            if peer_uid(writer.get_extra_info("socket")) not in (0, self.allowed_uid):
                raise ControlError("local peer not authorized", 403)
            if self._slots.locked():
                raise ControlError("administration service is busy", 429)
            async with self._slots, asyncio.timeout(CONTROL_TIMEOUT):
                async with asyncio.timeout(5):
                    line = await reader.readline()
                if not line.endswith(b"\n") or len(line) > MAX_REQUEST:
                    raise ControlError("invalid administration request size", 413)
                request = ControlRequest.model_validate_json(line)
                result = await self.dispatch(request)
                response = {"ok": True, "result": result}
        except ControlError as exc:
            response = {"ok": False, "error": str(exc), "status": exc.status}
        except (ValueError, ValidationError):
            response = {"ok": False, "error": "invalid administration request", "status": 400}
        except TimeoutError:
            response = {"ok": False, "error": "administration operation timed out", "status": 504}
        except asyncio.CancelledError:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
            if task:
                self._requests.discard(task)
            raise
        except Exception:  # noqa: BLE001
            response = {"ok": False, "error": "administration operation failed", "status": 500}
        try:
            raw = json.dumps(response, default=str).encode() + b"\n"
            if len(raw) > MAX_RESPONSE:
                raw = b'{"ok":false,"error":"result too large; narrow the query","status":413}\n'
            writer.write(raw)
            await writer.drain()
        except (OSError, ConnectionError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
            if task:
                self._requests.discard(task)

    async def close(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        for task in self._requests:
            task.cancel()
        await asyncio.gather(*self._requests, return_exceptions=True)
        if self.server and self.path.exists():
            self.path.unlink()
