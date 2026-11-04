"""Minimal sd_notify(3) client (no libsystemd dependency)."""

from __future__ import annotations

import os
import socket


def notify(state: str) -> bool:
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return False
    if addr.startswith("@"):
        addr = "\0" + addr[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
        s.connect(addr)
        s.sendall(state.encode())
    return True


def watchdog_interval() -> float | None:
    """Half the WatchdogSec configured on the unit, in seconds."""
    usec = os.environ.get("WATCHDOG_USEC")
    if not usec or os.environ.get("WATCHDOG_PID", str(os.getpid())) != str(os.getpid()):
        return None
    return int(usec) / 2_000_000
