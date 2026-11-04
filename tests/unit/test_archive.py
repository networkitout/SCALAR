from datetime import UTC, datetime
from pathlib import Path

import pytest

from scalar.store.archive import ArchiveIntegrityError, RawArchive

NOW = datetime(2026, 10, 5, tzinfo=UTC)


def test_archive_roundtrip_restart_and_anchor(tmp_path: Path) -> None:
    archive = RawArchive(tmp_path)
    first = archive.put("gateway", b"first\n\x80\xff\n", NOW)
    second = RawArchive(tmp_path).put("gateway", b"second\n", NOW)
    assert archive.read(first.path, first.sha256, first.size,
                        offset=first.offset, length=first.length) == b"first\n\x80\xff\n"
    assert first.chain != second.chain
    assert RawArchive(tmp_path).verify("gateway", expected_head=second.chain) == 2
    with pytest.raises(ArchiveIntegrityError, match="external anchor"):
        archive.verify("gateway", expected_head=first.chain)


def test_batches_share_one_daily_file(tmp_path: Path) -> None:
    archive = RawArchive(tmp_path)
    first = archive.put("gateway", b"payload\n", NOW)
    second = archive.put("gateway", b"payload\n", NOW)
    assert first.path == second.path
    assert second.offset == first.length
    assert len(list(tmp_path.glob("*/*.zst"))) == 1
    assert archive.verify("gateway") == 2


def test_corrupt_payload_is_detected(tmp_path: Path) -> None:
    archive = RawArchive(tmp_path)
    reference = archive.put("gateway", b"payload\n", NOW)
    (tmp_path / reference.path).write_bytes(b"corrupt")
    with pytest.raises(ArchiveIntegrityError):
        archive.verify("gateway")


def test_corrupt_or_truncated_manifest_is_detected(tmp_path: Path) -> None:
    archive = RawArchive(tmp_path)
    archive.put("gateway", b"payload\n", NOW)
    manifest = tmp_path / "gateway" / "manifest.jsonl"
    manifest.write_bytes(manifest.read_bytes().replace(b'"size":8', b'"size":9'))
    with pytest.raises(ArchiveIntegrityError):
        archive.verify("gateway")
    with manifest.open("ab") as stream:
        stream.write(b"partial")
    with pytest.raises(ArchiveIntegrityError, match="incomplete"):
        RawArchive(tmp_path).head("gateway")


def test_retention_keeps_manifest_chain(tmp_path: Path) -> None:
    archive = RawArchive(tmp_path)
    old = archive.put("gateway", b"old\n", datetime(2025, 1, 1, tzinfo=UTC))
    current = archive.put("gateway", b"current\n", NOW)
    assert archive.prune(NOW.date()) == 1
    assert not (tmp_path / old.path).exists()
    assert archive.verify("gateway", since=NOW.date(), expected_head=current.chain) == 1


@pytest.mark.parametrize("device", ["..", "../vault", "/etc", "bad/name"])
def test_archive_rejects_path_traversal(tmp_path: Path, device: str) -> None:
    with pytest.raises(ValueError, match="device name"):
        RawArchive(tmp_path).put(device, b"data", NOW)
