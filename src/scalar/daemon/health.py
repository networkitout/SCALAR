"""Best-effort host and daemon resource counters within the service sandbox."""

from __future__ import annotations

import os
import shutil
import socket
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class ResourceMonitor:
    def __init__(self) -> None:
        self._started = time.monotonic()
        self._cpu_sample: tuple[float, float] | None = None
        self._cpu_percent: float | None = None
        self._lock = threading.Lock()

    def snapshot(self, state_dir: Path, log_dir: Path) -> dict[str, Any]:
        with self._lock:
            return self._snapshot(state_dir, log_dir)

    def _snapshot(self, state_dir: Path, log_dir: Path) -> dict[str, Any]:
        now = time.monotonic()
        result: dict[str, Any] = {
            "sampled_at": datetime.now(UTC).isoformat(), "hostname": socket.gethostname(),
            "cpu_count": os.cpu_count(), "load_average": None, "memory": None,
            "host_uptime_seconds": None, "filesystems": {}, "errors": {},
            "process": {"pid": os.getpid(), "uptime_seconds": int(now - self._started),
                        "cpu_percent": None, "cpu_seconds": None, "rss_bytes": None,
                        "peak_rss_bytes": None, "threads": None, "open_fds": None},
        }
        try:
            result["load_average"] = list(os.getloadavg())
        except (AttributeError, OSError) as exc:
            result["errors"]["load_average"] = type(exc).__name__
        try:
            page_size = os.sysconf("SC_PAGE_SIZE")
            total = os.sysconf("SC_PHYS_PAGES") * page_size
            free = os.sysconf("SC_AVPHYS_PAGES") * page_size
            if total > 0 and 0 <= free <= total:
                result["memory"] = {"total_bytes": total, "free_bytes": free}
        except (AttributeError, OSError, ValueError) as exc:
            result["errors"]["memory"] = type(exc).__name__
        try:
            result["host_uptime_seconds"] = int(time.clock_gettime(time.CLOCK_BOOTTIME))
        except (AttributeError, OSError) as exc:
            result["errors"]["host_uptime"] = type(exc).__name__
        try:
            import resource

            usage = resource.getrusage(resource.RUSAGE_SELF)
            cpu = usage.ru_utime + usage.ru_stime
            if self._cpu_sample is not None and now - self._cpu_sample[0] >= 1:
                elapsed, consumed = now - self._cpu_sample[0], cpu - self._cpu_sample[1]
                self._cpu_percent = round(max(0, consumed / elapsed * 100), 2)
                self._cpu_sample = (now, cpu)
            elif self._cpu_sample is None:
                self._cpu_sample = (now, cpu)
            result["process"].update(cpu_percent=self._cpu_percent, cpu_seconds=round(cpu, 2),
                                      peak_rss_bytes=usage.ru_maxrss * 1024)
        except (ImportError, OSError) as exc:
            result["errors"]["process_cpu"] = type(exc).__name__
        try:
            for line in Path("/proc/self/status").read_text().splitlines():
                name, _separator, value = line.partition(":")
                if name == "VmRSS":
                    result["process"]["rss_bytes"] = int(value.split()[0]) * 1024
                elif name == "Threads":
                    result["process"]["threads"] = int(value.strip())
            result["process"]["open_fds"] = sum(1 for _entry in Path("/proc/self/fd").iterdir())
        except (OSError, ValueError, IndexError) as exc:
            result["errors"]["process_memory"] = type(exc).__name__
        for name, path in (("state", state_dir), ("logs", log_dir)):
            try:
                disk = shutil.disk_usage(path)
                result["filesystems"][name] = {
                    "path": str(path), "total_bytes": disk.total, "used_bytes": disk.used,
                    "free_bytes": disk.free,
                    "used_percent": round(disk.used / disk.total * 100, 1) if disk.total else None,
                }
            except OSError as exc:
                result["errors"][f"{name}_filesystem"] = type(exc).__name__
        return result
