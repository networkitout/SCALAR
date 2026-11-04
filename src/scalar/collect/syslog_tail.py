"""Bounded, acknowledged reads of rsyslog's per-sender daily files."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from datetime import date
from pathlib import Path

from scalar.config import Device
from scalar.detect.findings import Finding
from scalar.detect.severity import Severity
from scalar.secrets.vault import atomic_write


@dataclass(frozen=True)
class Cursor:
    inode: int
    offset: int
    prefix_size: int
    prefix_sha256: str


@dataclass(frozen=True)
class LogBatch:
    device: str
    source_ip: str
    path: str
    start: int
    cursor: Cursor
    lines: tuple[bytes, ...]
    findings: tuple[Finding, ...] = ()


class SyslogTailer:
    def __init__(
        self, root: Path, checkpoints: Path, *, batch_lines: int = 500, max_line_bytes: int = 262144
    ) -> None:
        self.root = root
        self.checkpoints = checkpoints
        self.batch_lines = batch_lines
        self.max_line_bytes = max_line_bytes
        self.cursors: dict[str, Cursor] = {}
        if checkpoints.exists():
            doc = json.loads(checkpoints.read_bytes())
            if doc.get("version") != 1:
                raise ValueError("unsupported syslog checkpoint version")
            for path, value in doc["files"].items():
                cursor = Cursor(**value)
                if cursor.offset < 0 or not 0 <= cursor.prefix_size <= min(4096, cursor.offset):
                    raise ValueError("invalid syslog checkpoint offset")
                self.cursors[path] = cursor

    def batches(self, device: Device) -> Iterator[LogBatch]:
        for address in dict.fromkeys([device.nsip, *device.syslog_sources]):
            directory = self.root / address
            if directory.is_symlink() or not directory.is_dir():
                continue
            for path in sorted(directory.glob("*.log")):
                if path.is_symlink() or not path.is_file():
                    continue
                batch = self._read(device.name, address, path)
                if batch is not None:
                    yield batch

    def _read(self, device: str, address: str, path: Path) -> LogBatch | None:
        relative = path.relative_to(self.root).as_posix()
        previous = self.cursors.get(relative)
        notices: tuple[Finding, ...] = ()
        with path.open("rb") as stream:
            stat = os.fstat(stream.fileno())
            start = previous.offset if previous else 0
            if previous:
                prefix = stream.read(previous.prefix_size)
                changed = (
                    stat.st_ino != previous.inode
                    or stat.st_size < previous.offset
                    or hashlib.sha256(prefix).hexdigest() != previous.prefix_sha256
                )
                if changed:
                    start = 0
                    notices = (
                        Finding(
                            dedup_key=f"log-reset|{device}|{relative}|{stat.st_ino}|{stat.st_mtime_ns}",
                            rule_id="log-source-reset",
                            title="Syslog source truncated or replaced",
                            severity=Severity.HIGH,
                            category="health",
                            device=device,
                            summary=f"{device}: {relative} changed behind the ingestion checkpoint",
                            evidence={
                                "path": relative,
                                "previous_offset": previous.offset,
                                "size": stat.st_size,
                            },
                        ),
                    )
            stream.seek(start)
            lines: list[bytes] = []
            size = 0
            end = start
            for _ in range(self.batch_lines):
                raw = stream.readline(self.max_line_bytes + 1)
                if len(raw) > self.max_line_bytes:
                    raise ValueError(f"{relative}: syslog line exceeds {self.max_line_bytes} bytes")
                if not raw.endswith(b"\n"):
                    break
                lines.append(raw)
                size += len(raw)
                end = stream.tell()
                if size >= 4 * 1024 * 1024:
                    break
            if not lines and not notices:
                return None
            prefix_size = min(4096, end)
            stream.seek(0)
            prefix_sha256 = hashlib.sha256(stream.read(prefix_size)).hexdigest()
            cursor = Cursor(stat.st_ino, end, prefix_size, prefix_sha256)
        return LogBatch(device, address, relative, start, cursor, tuple(lines), notices)

    def commit(self, batch: LogBatch) -> None:
        updated = {**self.cursors, batch.path: batch.cursor}
        data = {"version": 1, "files": {path: asdict(cursor) for path, cursor in updated.items()}}
        atomic_write(self.checkpoints, json.dumps(data, sort_keys=True).encode())
        self.cursors = updated

    def prune(self, before: date) -> int:
        removed = 0
        updated = dict(self.cursors)
        for relative, cursor in self.cursors.items():
            path = self.root / relative
            try:
                day = date.fromisoformat(path.stem)
            except ValueError:
                continue
            if day >= before or path.is_symlink():
                continue
            try:
                stat = path.stat()
                if stat.st_ino != cursor.inode or stat.st_size != cursor.offset:
                    continue
                path.unlink()
                removed += 1
            except FileNotFoundError:
                pass
            updated.pop(relative)
        if updated != self.cursors:
            data = {"version": 1, "files": {path: asdict(cursor)
                                           for path, cursor in updated.items()}}
            atomic_write(self.checkpoints, json.dumps(data, sort_keys=True).encode())
            self.cursors = updated
        return removed
