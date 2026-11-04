"""Process-wide registry of secret values, used to scrub logs and outbound payloads.

Every credential that is decrypted gets its sensitive values registered here. The logging
filter and the notifier pre-send check use the registry, so a secret that leaks into a
message string is caught even if the code path forgot to redact it.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

MASK = "***REDACTED***"
_MIN_SECRET_LEN = 4  # shorter values would cause absurd over-redaction


class SecretRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._values: set[str] = set()

    def register(self, value: str | None) -> None:
        if value and len(value) >= _MIN_SECRET_LEN:
            with self._lock:
                self._values.add(value)

    def forget(self, value: str | None) -> None:
        if value:
            with self._lock:
                self._values.discard(value)

    def scrub(self, text: str) -> str:
        with self._lock:
            values = sorted(self._values, key=len, reverse=True)
        for v in values:
            if v in text:
                text = text.replace(v, MASK)
        return text

    def contains_secret(self, text: str) -> bool:
        with self._lock:
            return any(v in text for v in self._values)

    def scrub_value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.scrub(value)
        if isinstance(value, dict):
            return {key: self.scrub_value(item) for key, item in value.items()}
        if isinstance(value, list | tuple):
            return [self.scrub_value(item) for item in value]
        return value

    def clear(self) -> None:
        with self._lock:
            self._values.clear()


registry = SecretRegistry()


class RedactingFilter(logging.Filter):
    """Logging filter that scrubs registered secrets from the fully formatted message."""

    def __init__(self, reg: SecretRegistry | None = None) -> None:
        super().__init__()
        self._reg = reg or registry

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        scrubbed = self._reg.scrub(msg)
        if scrubbed != msg:
            record.msg = scrubbed
            record.args = None
        return True
