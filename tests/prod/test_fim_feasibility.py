"""FIM feasibility probe (roadmap Tier 1 item 1): which systemfile paths a real appliance lets
the FIM account list and read. Read-only, and never run in CI (marker prod_probe).

Preferred, with the daemon's own config and vault (run as root on the netrescale host)::

    NETRESCALE_PROBE_DEVICE=ns-gw-02 PYTHONPATH=src .venv/bin/python -m pytest -m prod_probe \
        tests/prod/test_fim_feasibility.py -p no:cacheprovider -s

or, for a lab appliance, with an explicit account (TLS pin or CA bundle required)::

    NETRESCALE_PROBE_HOST=10.0.0.11 NETRESCALE_PROBE_USER=nr_fim \
    NETRESCALE_PROBE_PASSWORD=... NETRESCALE_PROBE_SPKI_PIN=<base64 sha256> ...

The JSON report (NETRESCALE_PROBE_REPORT, default under the pytest tmp dir) lists, per
watched directory: listed / refused / absent / error with the NITRO status and errorcode,
entry counts, the raw field names and filemode values NITRO returned, and whether one small
file could be read. It records hash outcomes only, never file content, and only counts (no
names) for the deny-listed trees. Run it on an HA secondary of each firmware train (13.1,
13.1-FIPS, 14.1) with the nr_fim account, and once with nr_nitro to compare.
"""

import json
import os
import posixpath
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
import pytest

from netrescale.collect.fim import CONTENT_DENY, WATCHES, FimMonitor, content_allowed
from netrescale.config import load_config
from netrescale.runtime import Runtime, default_key_loader
from netrescale.secrets.base import Credential
from netrescale.store.snapshots import FileSnapshotStore
from netrescale.transport.nitro import NitroClient, NitroError, NitroTarget, PermissionDenied

pytestmark = pytest.mark.prod_probe

MISSING = "/var/netrescale-probe-does-not-exist"
POLICY_CHECKS = ("/nsconfig/ssl", "/nsconfig/keys", "/flash/nsconfig/keys", "/var/log")


def _client() -> NitroClient:
    device_name = os.environ.get("NETRESCALE_PROBE_DEVICE")
    if device_name:
        path = Path(os.environ.get("NETRESCALE_CONFIG", "/etc/netrescale/config.yaml"))
        cfg = load_config(path)
        device = cfg.device(device_name)
        runtime = Runtime(cfg, default_key_loader(cfg), config_path=path)
        return runtime.nitro_client(device, credential=cfg.fim_ref(device))
    host = os.environ.get("NETRESCALE_PROBE_HOST")
    user = os.environ.get("NETRESCALE_PROBE_USER")
    password = os.environ.get("NETRESCALE_PROBE_PASSWORD")
    if not (host and user and password):
        pytest.skip("set NETRESCALE_PROBE_DEVICE, or NETRESCALE_PROBE_HOST/_USER/_PASSWORD")
    target = NitroTarget("probe", host, spki_pin=os.environ.get("NETRESCALE_PROBE_SPKI_PIN"),
                         ca_bundle=os.environ.get("NETRESCALE_PROBE_CA_BUNDLE"))
    return NitroClient(target, lambda: Credential(user, password))


def _error(exc: Exception) -> dict[str, Any]:
    status = "refused" if isinstance(exc, PermissionDenied) else "error"
    return {"status": status, "type": type(exc).__name__,
            "http_status": getattr(exc, "status", None),
            "errorcode": getattr(exc, "errorcode", None), "message": str(exc)[:300]}


async def _raw_fields(client: NitroClient, location: str) -> dict[str, Any]:
    """Field names and filemode values exactly as NITRO returned them (no file names)."""
    body = await client._get(
        f"/nitro/v1/config/systemfile?args=filelocation:{quote(location, safe='')}",
        max_bytes=8 * 1024 * 1024)
    items = body.get("systemfile") or []
    items = items if isinstance(items, list) else [items]
    return {"fields": sorted({key for item in items if isinstance(item, dict) for key in item}),
            "filemode_values": sorted({json.dumps(item.get("filemode")) for item in items
                                       if isinstance(item, dict)}),
            "filesize_types": sorted({type(item.get("filesize")).__name__ for item in items
                                      if isinstance(item, dict)}),
            "content_in_listing": any(isinstance(item, dict) and item.get("filecontent")
                                      for item in items)}


async def test_fim_feasibility(tmp_path: Path) -> None:
    requests: list[httpx.Request] = []

    async def record(request: httpx.Request) -> None:
        requests.append(request)

    report: dict[str, Any] = {"watches": {}, "policy_checks": {}}
    client = _client()
    client._http.event_hooks["request"].append(record)
    monitor = FimMonitor("probe", FileSnapshotStore(tmp_path / "state"))
    async with client:
        try:
            report["version"] = await client.version_string()
        except NitroError as exc:
            report["version"] = _error(exc)
        try:
            await client.list_files(MISSING)
            report["missing_directory"] = {"status": "listed"}
        except NitroError as exc:  # what "absent" looks like on this build (VERIFY in fim.py)
            report["missing_directory"] = _error(exc)
        for watch in WATCHES:
            entry: dict[str, Any] = {"tier": watch.tier, "kind": watch.kind}
            report["watches"][watch.root] = entry
            try:
                entry["raw"] = await _raw_fields(client, watch.root)
            except NitroError as exc:
                entry.update(_error(exc))
                continue
            walk = await client.walk_files(watch.root, max_depth=0 if watch.names else
                                           watch.depth, max_entries=2000, max_seconds=30)
            files = [e for e in walk.entries if not e.is_dir]
            entry.update(status="listed", files=len(files),
                         directories=sum(1 for e in walk.entries if e.is_dir),
                         subdirectory_errors={path: _error(exc)
                                              for path, exc in walk.errors.items()},
                         unvisited=len(walk.unvisited), truncated=walk.truncated)
            if watch.names:
                entry["named_present"] = sorted(e.name for e in files
                                                if e.name in dict(watch.names))
            readable = sorted((e for e in files if content_allowed(e.path) and watch.content
                               and e.size is not None and e.size <= 64 * 1024
                               and (not watch.names or e.name in dict(watch.names))),
                              key=lambda e: e.size or 0)
            if readable:
                sha, outcome = await monitor.fetch_hash(client, readable[0].path)
                entry["read"] = {"path": readable[0].path, "outcome": outcome,
                                 "sha256": sha}
        for location in POLICY_CHECKS:  # counts only: these should be refused for nr_fim
            try:
                listed = await client.list_files(location)
                report["policy_checks"][location] = {"status": "listed", "entries": len(listed)}
            except NitroError as exc:
                report["policy_checks"][location] = _error(exc)

    out = Path(os.environ.get("NETRESCALE_PROBE_REPORT", tmp_path / "fim-feasibility.json"))
    out.write_text(json.dumps(report, indent=2, sort_keys=True))
    out.chmod(0o600)
    print(f"\nFIM feasibility report: {out}")

    assert all(r.method == "GET" or r.url.path.endswith(("/login", "/logout"))
               for r in requests)
    reads = []
    for r in requests:
        args = r.url.params.get("args", "")
        if "filename:" in args:
            values = dict(part.split(":", 1) for part in args.split(","))
            reads.append(posixpath.join(values["filelocation"], values["filename"]))
    assert not [path for path in reads
                if any(path.startswith(prefix + "/") for prefix in CONTENT_DENY)]
    assert report["watches"]
