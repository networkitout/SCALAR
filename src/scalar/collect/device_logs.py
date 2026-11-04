"""Bounded, private log captures retrieved through read-only NITRO requests."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from scalar.secrets.vault import atomic_write

LogSource = Literal[
    "nslog", "bashlog", "shlog", "httperror", "httpaccess", "httpaccess-vpn", "notice", "auth"
]
LOG_FILES: dict[LogSource, str] = {
    "nslog": "/var/log/ns.log",
    "bashlog": "/var/log/bash.log",
    "shlog": "/var/log/sh.log",
    "httperror": "/var/log/httperror.log",
    "httpaccess": "/var/log/httpaccess.log",
    "httpaccess-vpn": "/var/log/httpaccess-vpn.log",
    "notice": "/var/log/notice.log",
    "auth": "/var/log/auth.log",
}
MAX_CAPTURE_BYTES = 1024 * 1024
MAX_CAPTURE_LINES = 10000


class DeviceLogStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    def _path(self, device: str, source: LogSource) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}", device) or source not in LOG_FILES:
            raise ValueError("invalid device or log source")
        return self.root / device / f"{source}.json"

    def read(self, device: str, source: LogSource) -> dict[str, Any] | None:
        path = self._path(device, source)
        if not path.exists():
            return None
        if path.stat().st_size > 6 * MAX_CAPTURE_BYTES + 65536:
            raise ValueError("log capture exceeds its size limit")
        document: dict[str, Any] = json.loads(path.read_bytes())
        raw = document["text"].encode("latin-1")
        if hashlib.sha256(raw).hexdigest() != document["sha256"]:
            raise ValueError("log capture integrity check failed")
        return document

    def put(self, device: str, source: LogSource, content: bytes) -> dict[str, Any]:
        retained = content[-MAX_CAPTURE_BYTES:]
        truncated = len(content) > MAX_CAPTURE_BYTES
        if truncated:
            boundary = retained.find(b"\n")
            retained = retained[boundary + 1:] if boundary >= 0 else b""
        lines = retained.splitlines(keepends=True)
        truncated = truncated or len(lines) > MAX_CAPTURE_LINES
        retained = b"".join(lines[-MAX_CAPTURE_LINES:])
        document = {
            "device": device, "source": source, "path": LOG_FILES[source],
            "collected_at": datetime.now(UTC).isoformat(),
            "downloaded_bytes": len(content), "retained_bytes": len(retained),
            "lines": min(len(lines), MAX_CAPTURE_LINES), "truncated": truncated,
            "sha256": hashlib.sha256(retained).hexdigest(), "text": retained.decode("latin-1"),
        }
        path = self._path(device, source)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        atomic_write(path, json.dumps(document).encode())
        return self.metadata(document)

    @staticmethod
    def metadata(document: dict[str, Any]) -> dict[str, Any]:
        return {key: value for key, value in document.items() if key != "text"}

    def list(self, device: str) -> list[dict[str, Any]]:
        return [
            {"source": source, "path": path,
             "capture": self.metadata(document)
             if (document := self.read(device, source)) else None}
            for source, path in LOG_FILES.items()
        ]
