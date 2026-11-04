"""Run the web service and reload only after the daemon applies new settings."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import logging
from collections.abc import Callable
from pathlib import Path

import uvicorn
import yaml

from netrescale.config import Config, load_config
from netrescale.secrets.vault import atomic_write
from netrescale.web.app import create_app
from netrescale.web.auth import AuthStore

HTTP_ACCESS_DROPIN = Path("/etc/systemd/system/netrescale-web.service.d/20-http-access.conf")
HTTP_ACCESS_MARKER = "# Managed by netrescale web allow-http.\n"
log = logging.getLogger(__name__)


def configure_http(config_path: Path, host: str, networks: list[str], *, port: int | None = None,
                   dropin_path: Path = HTTP_ACCESS_DROPIN) -> str:
    address = ipaddress.IPv4Address(host)
    if address.is_unspecified or address.is_loopback or address.is_multicast or address.is_reserved:
        raise ValueError("choose the server's specific network IPv4 address")
    if not networks:
        raise ValueError("at least one allowed client address or network is required")
    permitted = sorted({str(ipaddress.ip_network(network, strict=False)) for network in networks})
    if dropin_path.exists() and not dropin_path.read_text().startswith(HTTP_ACCESS_MARKER):
        raise ValueError("refusing to overwrite an unmanaged HTTP access drop-in")
    document = load_config(config_path).model_dump(mode="json")
    web = document["web"]
    port = web["port"] if port is None else port
    origin = f"http://{address}:{port}"
    web.update(host=str(address), port=port, public_url=origin, allow_http=True)
    web["allowed_hosts"] = list(dict.fromkeys([*web["allowed_hosts"], str(address)]))
    candidate = Config.model_validate(document)
    dropin = HTTP_ACCESS_MARKER + "[Service]\n" + "".join(
        f"IPAddressAllow={network}\n" for network in permitted)
    dropin_path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    atomic_write(dropin_path, dropin.encode(), backup=True, mode=0o644)
    atomic_write(config_path, yaml.safe_dump(candidate.model_dump(mode="json"),
                                            sort_keys=False).encode(), backup=True, mode=0o640)
    return origin


def _stamp(path: Path) -> tuple[int, int]:
    try:
        metadata = path.stat()
        return metadata.st_mtime_ns, metadata.st_ino
    except FileNotFoundError:
        return 0, 0


def serve(config_path: Path) -> None:
    async def run() -> None:
        previous: Config | None = None
        auth_store: AuthStore | None = None
        replacement: Config | None = None
        while True:
            cfg = replacement or load_config(config_path)
            replacement = None
            if (previous is None or cfg.web != previous.web
                    or cfg.paths.state_dir != previous.paths.state_dir):
                auth_store = AuthStore(
                    cfg.paths.state_dir / "web-users.json",
                    session_seconds=cfg.web.session_hours * 3600,
                )
            previous = cfg
            marker = cfg.paths.state_dir / "web-reload.json"
            initial = _stamp(marker)
            app = create_app(cfg, auth_store=auth_store)
            server = uvicorn.Server(
                uvicorn.Config(
                    app,
                    host=cfg.web.host,
                    port=cfg.web.port,
                    access_log=False,
                    proxy_headers=True,
                    forwarded_allow_ips="127.0.0.1,::1",
                )
            )
            reload_requested = False

            async def watch(server: uvicorn.Server, marker: Path, initial: tuple[int, int],
                            refresh: Callable[[Config], bool]) -> None:
                nonlocal reload_requested, replacement
                while not server.should_exit:
                    await asyncio.sleep(1)
                    changed = _stamp(marker)
                    if changed != initial:
                        try:
                            message = json.loads(marker.read_bytes())
                            candidate = (Config.model_validate(message["config"])
                                         if "config" in message else load_config(config_path))
                        except (OSError, ValueError, TypeError) as exc:
                            log.warning("Web settings refresh failed: %s", type(exc).__name__)
                            initial = changed
                            continue
                        if refresh(candidate):
                            initial = changed
                            continue
                        replacement = candidate
                        await asyncio.sleep(2)
                        reload_requested = True
                        server.should_exit = True
                        return

            watcher = asyncio.create_task(watch(server, marker, initial, app.state.refresh_config))
            try:
                await server.serve()
            finally:
                watcher.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await watcher
            if not reload_requested:
                return

    asyncio.run(run())
