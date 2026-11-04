from __future__ import annotations

import enum


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, s: str) -> Severity:
        try:
            return cls[s.strip().upper()]
        except KeyError:
            raise ValueError(f"unknown severity {s!r}") from None

    def __str__(self) -> str:
        return self.name.lower()
