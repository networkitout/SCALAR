from datetime import date
from pathlib import Path

import pytest

from netrescale.collect.syslog_tail import SyslogTailer
from netrescale.config import Config, Device
from netrescale.parse.nslog import parse_line, parse_syslog


@pytest.fixture
def feed(tmp_path: Path) -> tuple[SyslogTailer, Device, Path]:
    device = Device(name="gateway", nsip="192.0.2.10")
    root = tmp_path / "syslog"
    directory = root / device.nsip
    directory.mkdir(parents=True)
    path = directory / "2026-10-05.log"
    path.write_bytes(b"first\nsecond\n")
    return SyslogTailer(root, tmp_path / "checkpoints.json", batch_lines=1), device, path


def test_checkpoint_requires_acknowledgement_and_survives_restart(feed) -> None:  # type: ignore[no-untyped-def]
    tailer, device, _path = feed
    batch = next(tailer.batches(device))
    assert batch.lines == (b"first\n",)
    assert next(tailer.batches(device)).lines == batch.lines
    tailer.commit(batch)
    restarted = SyslogTailer(tailer.root, tailer.checkpoints)
    batch = next(restarted.batches(device))
    assert batch.lines == (b"second\n",)
    restarted.commit(batch)
    assert list(restarted.batches(device)) == []


def test_append_and_partial_line(feed) -> None:  # type: ignore[no-untyped-def]
    tailer, device, path = feed
    tailer.batch_lines = 100
    tailer.commit(next(tailer.batches(device)))
    with path.open("ab") as stream:
        stream.write(b"part")
    assert list(tailer.batches(device)) == []
    with path.open("ab") as stream:
        stream.write(b"ial\n")
    batch = next(tailer.batches(device))
    assert batch.lines == (b"partial\n",)
    assert batch.findings == ()


@pytest.mark.parametrize("replacement", [b"", b"short\n", b"different-longer-content\n"])
def test_truncation_or_rewrite_is_reported(feed, replacement: bytes) -> None:  # type: ignore[no-untyped-def]
    tailer, device, path = feed
    tailer.batch_lines = 100
    tailer.commit(next(tailer.batches(device)))
    path.write_bytes(replacement)
    batch = next(tailer.batches(device))
    assert batch.start == 0
    assert batch.findings[0].rule_id == "log-source-reset"
    tailer.commit(batch)
    assert list(tailer.batches(device)) == []


def test_new_day_and_inode_replacement(feed) -> None:  # type: ignore[no-untyped-def]
    tailer, device, path = feed
    tailer.batch_lines = 100
    tailer.commit(next(tailer.batches(device)))
    path.rename(path.with_suffix(".old"))
    path.write_bytes(b"new file\n")
    batch = next(tailer.batches(device))
    assert batch.findings and batch.lines == (b"new file\n",)
    tailer.commit(batch)
    path.with_name("2026-10-06.log").write_bytes(b"next day\n")
    assert next(tailer.batches(device)).lines == (b"next day\n",)


def test_unknown_sources_and_symlinks_not_ingested(feed, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    tailer, device, path = feed
    path.unlink()
    secret = tmp_path / "not-a-log"
    secret.write_bytes(b"do not ingest\n")
    path.symlink_to(secret)
    (tailer.root / "quarantine.log").write_bytes(b"unknown sender\n")
    assert list(tailer.batches(device)) == []


def test_oversized_lines_do_not_advance_checkpoint(feed) -> None:  # type: ignore[no-untyped-def]
    tailer, device, path = feed
    tailer.max_line_bytes = 10
    path.write_bytes(b"x" * 20 + b"\n")
    with pytest.raises(ValueError, match="exceeds"):
        list(tailer.batches(device))
    assert not tailer.checkpoints.exists()


def test_sender_cannot_belong_to_two_devices() -> None:
    with pytest.raises(ValueError, match="multiple devices"):
        Config(
            devices=[
                Device(name="first", nsip="192.0.2.1", syslog_sources=["192.0.2.3"]),
                Device(name="second", nsip="192.0.2.2", syslog_sources=["192.0.2.3"]),
            ]
        )


def test_retention_deletes_only_fully_acknowledged_files(feed) -> None:  # type: ignore[no-untyped-def]
    tailer, device, path = feed
    tailer.commit(next(tailer.batches(device)))
    assert tailer.prune(date(2026, 10, 7)) == 0
    tailer.commit(next(tailer.batches(device)))
    assert tailer.prune(date(2026, 10, 5)) == 0
    assert tailer.prune(date(2026, 10, 7)) == 1
    assert not path.exists()


@pytest.mark.parametrize(("zone", "token", "hour"), [
    ("America/Chicago", "CDT", 15), ("America/Chicago", "GMT", 10),
    ("UTC", "+0200", 8), ("UTC", "-05:00", 15),
])
def test_live_event_timestamps_are_utc(zone: str, token: str, hour: int) -> None:
    line = f"2026/10/05:10:00:00 {token} gateway 0-PPE-0 : default GUI CMD_EXECUTED 1 0 : test"
    event = parse_line("nslog", line, "gateway", device_timezone=zone)
    assert event.ts is not None and event.ts.hour == hour
    stored = f"2026-10-05T23:59:59+00:00 192.0.2.10 <134> {line}\n"
    live = parse_syslog(stored, "gateway", device_timezone=zone)
    assert live.source == "nslog" and live.ts == event.ts
