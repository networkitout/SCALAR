"""Daily zstd frame archives with a durable per-device SHA-256 manifest chain."""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import zstandard

EMPTY_HEAD = "0" * 64
MAX_BATCH_BYTES = 64 * 1024 * 1024


class ArchiveIntegrityError(ValueError):
    pass


@dataclass(frozen=True)
class ArchiveRef:
    path: str
    sha256: str
    chain: str
    size: int
    offset: int
    length: int

    @property
    def locator(self) -> str:
        return f"{self.path}#{self.offset}+{self.length}"


def _encoded(doc: dict[str, Any]) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()


class RawArchive:
    def __init__(self, root: Path) -> None:
        self.root = root
        self._heads: dict[str, str] = {}

    def _directory(self, device: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}", device):
            raise ValueError("invalid archive device name")
        return self.root / device

    def head(self, device: str) -> str:
        if device not in self._heads:
            manifest = self._directory(device) / "manifest.jsonl"
            head = EMPTY_HEAD
            if manifest.exists() and manifest.stat().st_size:
                with manifest.open("rb") as stream:
                    stream.seek(max(0, manifest.stat().st_size - 8192))
                    tail = stream.read()
                if not tail.endswith(b"\n"):
                    raise ArchiveIntegrityError(f"{device}: incomplete archive manifest")
                doc = json.loads(tail.splitlines()[-1])
                head = self._check_entry(doc)
            self._heads[device] = head
        return self._heads[device]

    @staticmethod
    def _check_entry(doc: dict[str, Any]) -> str:
        chain = str(doc["chain"])
        expected = hashlib.sha256(
            _encoded({key: value for key, value in doc.items() if key != "chain"})
        ).hexdigest()
        if chain != expected:
            raise ArchiveIntegrityError("archive manifest checksum mismatch")
        return chain

    def put(self, device: str, raw: bytes, at: datetime | None = None) -> ArchiveRef:
        if len(raw) > MAX_BATCH_BYTES:
            raise ValueError("archive batch exceeds size limit")
        now = (at or datetime.now(UTC)).astimezone(UTC)
        directory = self._directory(device)
        previous = self.head(device)
        digest = hashlib.sha256(raw).hexdigest()
        relative = f"{device}/{now:%Y-%m-%d}.zst"
        destination = self.root / relative
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        compressed = zstandard.ZstdCompressor(level=3).compress(raw)
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(descriptor, "ab") as stream:
            offset = stream.tell()
            stream.write(compressed)
            stream.flush()
            os.fsync(stream.fileno())
        doc: dict[str, Any] = {
            "path": relative,
            "sha256": digest,
            "size": len(raw),
            "stored_at": now.isoformat(),
            "previous": previous,
            "offset": offset,
            "compressed_size": len(compressed),
        }
        chain = hashlib.sha256(_encoded(doc)).hexdigest()
        doc["chain"] = chain
        manifest = directory / "manifest.jsonl"
        descriptor = os.open(manifest, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(descriptor, "ab") as stream:
            stream.write(_encoded(doc) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        if hasattr(os, "O_DIRECTORY"):
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        self._heads[device] = chain
        return ArchiveRef(relative, digest, chain, len(raw), offset, len(compressed))

    def read(self, relative: str, digest: str, size: int, *, offset: int, length: int) -> bytes:
        parts = Path(relative).parts
        if len(parts) != 2 or not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ArchiveIntegrityError("invalid archive reference")
        self._directory(parts[0])
        date.fromisoformat(Path(parts[1]).stem)
        if (not parts[1].endswith(".zst") or not 0 <= size <= MAX_BATCH_BYTES
                or offset < 0 or not 0 < length <= MAX_BATCH_BYTES + 1048576):
            raise ArchiveIntegrityError("invalid archive reference")
        try:
            with (self.root / relative).open("rb") as stream:
                stream.seek(offset)
                compressed = stream.read(length)
            if len(compressed) != length:
                raise ArchiveIntegrityError(f"truncated archive frame: {relative}")
            if zstandard.frame_content_size(compressed) != size:
                raise ArchiveIntegrityError(f"archive frame size mismatch: {relative}")
            raw = zstandard.ZstdDecompressor().decompress(
                compressed, max_output_size=MAX_BATCH_BYTES, allow_extra_data=False
            )
        except (OSError, zstandard.ZstdError) as exc:
            raise ArchiveIntegrityError(f"cannot read archive batch {relative}") from exc
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
            raise ArchiveIntegrityError(f"archive batch checksum mismatch: {relative}")
        return raw

    def verify(
        self, device: str, *, since: date | None = None, expected_head: str | None = None
    ) -> int:
        manifest = self._directory(device) / "manifest.jsonl"
        previous = EMPTY_HEAD
        checked = 0
        ends: dict[str, int] = {}
        if manifest.exists():
            with manifest.open("rb") as stream:
                for line in stream:
                    if not line.endswith(b"\n"):
                        raise ArchiveIntegrityError("incomplete archive manifest")
                    doc = json.loads(line)
                    if doc["previous"] != previous:
                        raise ArchiveIntegrityError("broken archive manifest chain")
                    previous = self._check_entry(doc)
                    if not str(doc["path"]).startswith(device + "/"):
                        raise ArchiveIntegrityError("archive device mismatch")
                    stored = datetime.fromisoformat(doc["stored_at"]).date()
                    if doc["offset"] != ends.get(doc["path"], 0):
                        raise ArchiveIntegrityError("unindexed data in daily archive")
                    ends[doc["path"]] = doc["offset"] + doc["compressed_size"]
                    if since is None or stored >= since:
                        self.read(doc["path"], doc["sha256"], doc["size"],
                                  offset=doc["offset"], length=doc["compressed_size"])
                        checked += 1
        for relative, end in ends.items():
            path = self.root / relative
            if path.exists() and path.stat().st_size != end:
                raise ArchiveIntegrityError("daily archive size differs from its manifest")
        if expected_head is not None and previous != expected_head:
            raise ArchiveIntegrityError("archive head does not match the external anchor")
        return checked

    def prune(self, before: date) -> int:
        removed = 0
        if self.root.exists():
            for path in self.root.glob("*/*.zst"):
                if not path.is_file() or path.is_symlink():
                    continue
                try:
                    day = date.fromisoformat(path.stem)
                except ValueError:
                    continue
                if day < before:
                    path.unlink()
                    removed += 1
        return removed
