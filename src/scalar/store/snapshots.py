"""Content-addressed config snapshot store on the local filesystem.

Layout under <state_dir>/configs/:
    blobs/<sha[:2]>/<sha>.zst           raw config text, zstd-compressed, written once
    index/<device>.<kind>.jsonl         one line per observed change: {sha, at, meta}
    state/<device>.json                 poller bookkeeping (last nsconfig timestamps, ...)

Raw text is kept (not redacted) because it is the forensic record. Every directory is
0700 and every file 0600, owned by the service user. Redaction happens when diffs leave
the process.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

import zstandard

from scalar.secrets.vault import atomic_write

KINDS = frozenset({"running", "saved"})


@dataclass(frozen=True, slots=True)
class Snapshot:
    device: str
    kind: str
    sha256: str
    at: datetime
    meta: dict[str, Any]


class SnapshotStore(Protocol):
    def latest(self, device: str, kind: str) -> Snapshot | None: ...
    def history(self, device: str, kind: str) -> list[Snapshot]: ...
    def put(self, device: str, kind: str, content: str, meta: dict[str, Any] | None = None,
            at: datetime | None = None) -> tuple[Snapshot, bool]: ...
    def content(self, sha256: str) -> str: ...
    def get_state(self, device: str) -> dict[str, Any]: ...
    def set_state(self, device: str, state: dict[str, Any]) -> None: ...


def sha256_text(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", "surrogateescape")).hexdigest()


class FileSnapshotStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        for sub in ("blobs", "index", "state"):
            (root / sub).mkdir(parents=True, exist_ok=True, mode=0o700)

    def _index(self, device: str, kind: str) -> Path:
        if kind not in KINDS:
            raise ValueError(f"unknown snapshot kind {kind!r}")
        return self.root / "index" / f"{device}.{kind}.jsonl"

    def _blob(self, sha: str) -> Path:
        return self.root / "blobs" / sha[:2] / f"{sha}.zst"

    def history(self, device: str, kind: str) -> list[Snapshot]:
        path = self._index(device, kind)
        if not path.exists():
            return []
        out = []
        for line in path.read_text("utf-8").splitlines():
            if line.strip():
                d = json.loads(line)
                out.append(Snapshot(device, kind, d["sha"], datetime.fromisoformat(d["at"]),
                                    d.get("meta", {})))
        return out

    def latest(self, device: str, kind: str) -> Snapshot | None:
        h = self.history(device, kind)
        return h[-1] if h else None

    def put(self, device: str, kind: str, content: str, meta: dict[str, Any] | None = None,
            at: datetime | None = None) -> tuple[Snapshot, bool]:
        """Record content; returns (snapshot, changed). Unchanged content is not re-indexed."""
        sha = sha256_text(content)
        prev = self.latest(device, kind)
        if prev is not None and prev.sha256 == sha:
            return prev, False
        blob = self._blob(sha)
        if not blob.exists():
            blob.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            data = zstandard.ZstdCompressor(level=10).compress(
                content.encode("utf-8", "surrogateescape"))
            atomic_write(blob, data)
        snap = Snapshot(device, kind, sha, at or datetime.now(UTC), meta or {})
        line = json.dumps({"sha": sha, "at": snap.at.isoformat(), "meta": snap.meta},
                          separators=(",", ":"))
        idx = self._index(device, kind)
        fd = os.open(idx, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, (line + "\n").encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        return snap, True

    def content(self, sha256: str) -> str:
        data = zstandard.ZstdDecompressor().decompress(self._blob(sha256).read_bytes())
        text = data.decode("utf-8", "surrogateescape")
        if sha256_text(text) != sha256:
            raise ValueError(f"snapshot blob {sha256} is corrupt")
        return text

    def get_state(self, device: str) -> dict[str, Any]:
        p = self.root / "state" / f"{device}.json"
        if not p.exists():
            return {}
        state: dict[str, Any] = json.loads(p.read_text("utf-8"))
        return state

    def set_state(self, device: str, state: dict[str, Any]) -> None:
        atomic_write(self.root / "state" / f"{device}.json",
                     json.dumps(state, indent=2, sort_keys=True).encode())
