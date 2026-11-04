"""Append-only JSONL record of findings (until the PostgreSQL findings table lands)."""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from scalar.detect.findings import Finding, finding_document
from scalar.redact import registry


class FindingsLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    def append(self, f: Finding, deliveries: list[dict[str, Any]] | None = None) -> None:
        doc = finding_document(f)
        doc["deliveries"] = registry.scrub_value(deliveries or [])
        line = json.dumps(doc, default=str, separators=(",", ":")) + "\n"
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "ab") as stream:
            stream.write(line.encode())
            stream.flush()
            os.fsync(stream.fileno())

    def read(self, since: datetime | None = None) -> Iterator[dict[str, Any]]:
        if not self.path.exists():
            return
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                doc: dict[str, Any] = json.loads(line)
                if since and datetime.fromisoformat(doc["observed_at"]) < since:
                    continue
                yield doc
