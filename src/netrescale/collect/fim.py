"""Read-only file-integrity monitoring (FIM) over NITRO ``systemfile``.

Tier A, on every config probe: boot hooks (rc.netscaler, nsbefore.sh, nsafter.sh), SSH keys
(/nsconfig/ssh, /var/pubkey), crontabs (/var/cron/tabs, /etc/crontab) and /etc/httpd.conf.
Content is hashed whenever the listing metadata moves and at least every
``rehash_interval``, so an edit with a forged mtime is still caught.

Tier B, every ``webroot_interval``: web roots (logon pages, VPN and EPA scripts, portal
templates), staging directories (/var/tmp, /tmp, /var/nstmp) and crash artifacts (/var/core,
/var/crash; metadata only). New and changed files are hashed first, within a per-pass budget;
the rest of the budget re-hashes the web-root files verified longest ago. Tier A is compared
and its findings staged before Tier B starts, so a slow or failing walk cannot hold them back.

Content is never read under CONTENT_DENY (keys, certificates, core dumps), for private-key
file names, or for anything in the SSH directories except ``authorized_keys*`` and ``*.pub``:
those files are compared on listing metadata only. A directory NITRO refuses, fails to list,
or lists only in part, a refused or failed read, and content the hash budget has not reached
yet are coverage gaps and raise `fim-coverage-unknown`; none is treated as clean.

A directory's first listing records its baseline and reports an inventory to review, so an
already-compromised baseline is not trusted silently. A directory that appears later is a
change, not a baseline. After a firmware change the image-managed web roots and httpd.conf
are re-baselined in one HIGH finding that lists the scripts it accepted.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import posixpath
import re
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import httpx

from netrescale.config import FimDefaults
from netrescale.detect.findings import Finding, finding_document, finding_from_document
from netrescale.detect.severity import Severity
from netrescale.store.snapshots import SnapshotStore
from netrescale.transport.nitro import (
    AuthRejected,
    NitroClient,
    NitroError,
    PermissionDenied,
    SystemFileEntry,
    WalkResult,
)

log = logging.getLogger(__name__)

Kind = Literal["boot_hook", "cron", "ssh", "httpd", "webroot", "staging", "crash"]
STATE_VERSION = 1
MAX_HASH_BYTES = 1024 * 1024  # larger files are compared on metadata only
MAX_LISTED = 50  # files named in one finding's evidence
PENDING_PASSES = 6  # Tier B passes a moved file may wait for the hash budget before it is
#                     reported on metadata (a reboot can move every mtime at once)

SCRIPT_SUFFIXES = (".php", ".phtml", ".php5", ".xhtml", ".pl", ".py", ".sh", ".js", ".cgi")

# Hard-coded and not configurable: file content under these trees is never requested, whatever
# the NITRO account may allow. /nsconfig is a symlink to /flash/nsconfig, so both are listed.
CONTENT_DENY = ("/nsconfig/ssl", "/nsconfig/keys", "/flash/nsconfig/ssl", "/flash/nsconfig/keys",
                "/var/core", "/var/crash")
# In the SSH directories only public material is read; host and user private keys never are.
SSH_DIRS = ("/nsconfig/ssh", "/flash/nsconfig/ssh", "/var/pubkey")
_SSH_READABLE = re.compile(r"^(authorized_keys[^/]*|[^/]+\.pub)$")
# Any host or user key file name, public halves included (they are compared on metadata), so
# a backup or renamed private key is never read. appliance.py's read policy matches the same.
_PRIVATE_KEY_NAME = re.compile(
    r"^(ssh_host_|id_(rsa|dsa|ecdsa|ed25519)).*$|^.*\.(key|pem|p12|pfx|ppk)$", re.IGNORECASE)

# Published NetScaler intrusion artifacts inside the walked trees (docs/design.md, host sweep).
# These and the TIER_B paths below name directories on the appliance, not local temp files.
KNOWN_IOC_PATHS = frozenset({"/var/tmp/the", "/var/tmp/npc", "/var/tmp/sh",  # noqa: S108
                             "/var/tmp/conf/npc.conf",  # noqa: S108
                             "/var/tmp/conf/multi_account.conf"})  # noqa: S108


@dataclass(frozen=True, slots=True)
class Watch:
    root: str
    tier: Literal["A", "B"]
    kind: Kind
    names: tuple[tuple[str, Kind], ...] = ()  # only these entries of root, no subdirectories
    depth: int = 0  # directory levels below root
    content: bool = True  # hash file content (CONTENT_DENY still applies)

    def kind_of(self, name: str) -> Kind:
        return dict(self.names).get(name, self.kind)

    @property
    def image_managed(self) -> bool:
        """Replaced by a firmware upgrade, so its changes are re-baselined after one."""
        return self.kind == "webroot" or self.root == "/etc"


TIER_A: tuple[Watch, ...] = (
    Watch("/nsconfig", "A", "boot_hook", names=(("rc.netscaler", "boot_hook"),
                                                 ("nsbefore.sh", "boot_hook"),
                                                 ("nsafter.sh", "boot_hook"))),
    Watch("/nsconfig/ssh", "A", "ssh"),
    Watch("/var/pubkey", "A", "ssh", depth=1),  # /var/pubkey/<user>/authorized_keys
    Watch("/var/cron/tabs", "A", "cron"),
    Watch("/etc", "A", "httpd", names=(("httpd.conf", "httpd"), ("crontab", "cron"))),
)
TIER_B: tuple[Watch, ...] = (
    Watch("/var/netscaler/logon", "B", "webroot", depth=8),  # LogonPoint, themes
    Watch("/netscaler/ns_gui/vpn", "B", "webroot", depth=8),
    Watch("/netscaler/ns_gui/epa/scripts", "B", "webroot", depth=8),
    Watch("/var/vpn", "B", "webroot", depth=8),  # theme/, themes/
    Watch("/netscaler/portal/templates", "B", "webroot", depth=8),
    Watch("/var/tmp/netscaler/portal/templates", "B", "webroot", depth=8),  # noqa: S108
    Watch("/var/tmp", "B", "staging", depth=4),  # noqa: S108
    Watch("/tmp", "B", "staging", depth=4),  # noqa: S108
    Watch("/var/nstmp", "B", "staging", depth=4),
    Watch("/var/core", "B", "crash", depth=2, content=False),
    Watch("/var/crash", "B", "crash", depth=1, content=False),
)
WATCHES = TIER_A + TIER_B


def _under(path: str, roots: Iterable[str]) -> bool:
    return any(path == root or path.startswith(root + "/") for root in roots)


def content_allowed(path: str) -> bool:
    """Whether FIM may read ``path``'s content: False under CONTENT_DENY, for private-key file
    names, in SSH directories for anything but authorized_keys* and *.pub, and for any path
    that is not absolute and normalized ('..' cannot step around the deny list)."""
    if (not path.startswith("/") or path.startswith("//")
            or posixpath.normpath(path) != path):
        return False
    if _under(path, CONTENT_DENY):
        return False
    name = posixpath.basename(path)
    if _PRIVATE_KEY_NAME.match(name):
        return False
    return not _under(path, SSH_DIRS) or bool(_SSH_READABLE.match(name))


def is_script(path: str) -> bool:
    return posixpath.basename(path).lower().endswith(SCRIPT_SUFFIXES)


def _absent(exc: NitroError) -> bool:
    # VERIFY: the errorcode/message a real appliance returns for a missing directory.
    return exc.status == 404 or any(text in str(exc).lower()
                                    for text in ("no such file", "does not exist"))


def _gap_reason(exc: NitroError) -> str:
    return "refused by the command policy" if isinstance(exc, PermissionDenied) else (
        "listing failed")


# Record "content" outcomes that leave a file's content unverified, as coverage gaps.
_CONTENT_GAPS = {"denied": "content refused by the command policy",
                 "error": "content could not be read",
                 "unreadable-name": "file name cannot be requested through NITRO",
                 "not-hashed": "content not hashed yet (hash budget)"}
_PENDING_GAP = "changed content not verified yet (hash budget)"
_TIER_B_PATHS = "web roots, temp and crash directories"
REBASELINE_EXPIRES = timedelta(hours=24)
TIME_LIMIT_CLEARS_AFTER = 3  # Tier B passes in time before a time-limit gap is cleared


def _gone(path: str, root: str, seen: set[str], listed: set[str]) -> bool:
    """Whether this pass proves ``path`` no longer exists: the nearest listed ancestor directory
    does not contain the next component (a deleted subdirectory takes its files with it)."""
    child, parent = path, posixpath.dirname(path)
    while True:
        if parent in listed:
            return child not in seen
        if parent == root or len(parent) <= len(root):
            return False
        child, parent = parent, posixpath.dirname(parent)


Change = Literal["added", "modified", "removed"]


@dataclass(frozen=True, slots=True)
class FileChange:
    path: str
    kind: Kind
    change: Change
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    verified: bool  # True when content hashes were compared, not only listing metadata

    def evidence(self) -> dict[str, Any]:
        doc: dict[str, Any] = {"path": self.path, "change": self.change,
                               "verified": self.verified}
        for label, entry in (("before", self.before), ("after", self.after)):
            if entry is not None:
                doc[label] = {key: entry.get(key) for key in ("size", "mtime", "sha256",
                                                              "content")}
        return doc


def classify(change: FileChange) -> tuple[str, Severity] | None:
    """Rule id and severity for one change, or None when the change is expected churn."""
    script = is_script(change.path)
    if change.path in KNOWN_IOC_PATHS and change.change != "removed":
        return "fim-known-ioc-path", Severity.CRITICAL
    if change.kind == "boot_hook":
        return "fim-boot-hook-changed", Severity.CRITICAL
    if change.kind == "cron":
        return "fim-crontab-changed", Severity.CRITICAL
    if change.kind == "ssh":
        keys = "authorized_keys" in posixpath.basename(change.path)
        return "fim-ssh-keys-changed", Severity.CRITICAL if keys else Severity.HIGH
    if change.kind == "httpd":
        return "fim-httpd-conf-changed", Severity.HIGH
    if change.kind == "webroot":
        if change.change == "removed":
            return "fim-webroot-file-removed", Severity.LOW
        if script and change.change == "added":
            return "fim-webroot-new-script", Severity.CRITICAL
        if script:
            return ("fim-webroot-script-modified",
                    Severity.CRITICAL if change.verified else Severity.HIGH)
        return (("fim-webroot-new-file" if change.change == "added"
                 else "fim-webroot-file-modified"), Severity.MEDIUM)
    if change.kind == "staging" and change.change == "added" and script:
        return "fim-staging-new-script", Severity.HIGH
    if change.kind == "crash" and change.change == "added":
        return "fim-crash-artifact", Severity.HIGH
    return None


_TITLES = {
    "fim-known-ioc-path": "Known NetScaler intrusion artifact present on the appliance",
    "fim-boot-hook-changed": "NetScaler boot hook changed (rc.netscaler / nsbefore.sh / "
                             "nsafter.sh)",
    "fim-crontab-changed": "Crontab changed on the appliance",
    "fim-ssh-keys-changed": "SSH keys changed on the appliance",
    "fim-httpd-conf-changed": "Appliance web server configuration (httpd.conf) changed",
    "fim-webroot-new-script": "New script file in a NetScaler web root (possible webshell)",
    "fim-webroot-script-modified": "Script file in a NetScaler web root was modified",
    "fim-webroot-new-file": "New file in a NetScaler web root",
    "fim-webroot-file-modified": "File in a NetScaler web root was modified",
    "fim-webroot-file-removed": "File removed from a NetScaler web root",
    "fim-staging-new-script": "New script file in an appliance temp directory",
    "fim-crash-artifact": "New core dump or crash file on the appliance",
}
_MITRE = {
    "fim-known-ioc-path": ("T1505.003",), "fim-boot-hook-changed": ("T1037",),
    "fim-crontab-changed": ("T1053.003",), "fim-ssh-keys-changed": ("T1098.004",),
    "fim-httpd-conf-changed": ("T1505.003",), "fim-webroot-new-script": ("T1505.003",),
    "fim-webroot-script-modified": ("T1505.003", "T1056.003"),
    "fim-webroot-file-modified": ("T1056.003",), "fim-staging-new-script": ("T1105",),
    "fim-crash-artifact": ("T1190",),
}


def _printable(path: str) -> str:
    """A path for a one-line summary: file names are attacker-chosen and may hold newlines or
    terminal escapes, so control characters are shown escaped (evidence keeps the raw name)."""
    return "".join(c if c.isprintable() else c.encode("unicode_escape").decode("ascii")
                   for c in path)[:300]


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def _listed(items: list[dict[str, Any]]) -> dict[str, Any]:
    return {"files": items[:MAX_LISTED], "count": len(items),
            "more": max(0, len(items) - MAX_LISTED)}


@dataclass
class _Observation:
    watch: Watch
    entry: SystemFileEntry
    previous: dict[str, Any] | None
    need_hash: bool
    priority: tuple[int, bool, str]  # rank, not a script, last content check (oldest first)
    sha256: str | None = None
    content: str = ""  # outcome of the content fetch, "" when none was attempted

    @property
    def moved(self) -> bool:
        return self.previous is None or (self.previous.get("size"),
                                         self.previous.get("mtime")) != (self.entry.size,
                                                                         self.entry.modified)


@dataclass
class _Pass:
    """One tier of one tick: list the watches, hash within the budget, then compare. compare()
    and gaps() make no appliance requests, so an interrupted pass leaves the baseline as it
    was."""

    monitor: FimMonitor
    client: NitroClient
    state: dict[str, Any]
    now: datetime
    walks: list[tuple[Watch, WalkResult]] = field(default_factory=list)
    walk_deadline: float | None = None  # Tier B listing budget
    hash_deadline: float | None = None  # Tier B content budget, separate from listing
    changes: list[FileChange] = field(default_factory=list)
    upgrade_changes: list[FileChange] = field(default_factory=list)
    baselined: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    time_limited: dict[str, str] = field(default_factory=dict)  # root -> directories cut off
    dirty: bool = False

    @property
    def settings(self) -> FimDefaults:
        return self.monitor.settings

    async def survey(self, watch: Watch) -> None:
        if watch.names:
            walk = WalkResult(watch.root)
            try:
                wanted = dict(watch.names)
                walk.entries = [entry for entry in await self.client.list_files(watch.root)
                                if entry.name in wanted]
                walk.listed.add(watch.root)
            except AuthRejected:
                raise
            except NitroError as exc:
                walk.errors[watch.root] = exc
        else:
            if watch.tier == "B" and self.walk_deadline is None:
                self.walk_deadline = self.monitor.clock() + self.settings.walk_seconds
            remaining = (max(0.0, self.walk_deadline - self.monitor.clock())
                         if self.walk_deadline is not None else 60.0)
            nested = {other.root for other in self.monitor.watches
                      if other.root != watch.root and other.root.startswith(watch.root + "/")}
            walk = await self.client.walk_files(
                watch.root, max_depth=min(watch.depth, self.settings.max_depth),
                max_entries=self.settings.max_entries, max_seconds=remaining, prune=nested,
                clock=self.monitor.clock)
        # Only the watched directory itself may be missing (then it is empty). A subdirectory
        # its parent just listed but that cannot be listed stays a gap.
        error = walk.errors.get(watch.root)
        if error is not None and _absent(error):
            walk.errors.pop(watch.root)
            walk.listed.add(watch.root)
        self.walks.append((watch, walk))

    def _owned(self, watch: Watch) -> dict[str, dict[str, Any]]:
        return {path: entry for path, entry in self.state["files"].items()
                if entry.get("root") == watch.root}

    def observations(self) -> list[_Observation]:
        """Files seen this pass, with whether and how urgently their content is hashed:
        Tier A always when due; Tier B new or moved files first, then never-hashed ones, then
        a rolling re-hash of web-root files (scripts first, least recently checked first)."""
        rehash = timedelta(seconds=self.settings.rehash_interval)
        out = []
        for watch, walk in self.walks:
            owned = self._owned(watch)
            for entry in walk.entries:
                if entry.is_dir:
                    continue
                previous = owned.get(entry.path)
                obs = _Observation(watch, entry, previous, False, (9, True, ""))
                checked = (previous or {}).get("checked_at") or ""
                due = not checked or self.now - datetime.fromisoformat(checked) >= rehash
                unhashed = previous is not None and previous.get("sha256") is None and due
                stale = previous is not None and previous.get("sha256") is not None and due
                if watch.tier == "A":
                    rank = 0 if obs.moved or unhashed or stale else 9
                elif obs.moved:
                    rank = 1
                elif unhashed:
                    rank = 2
                elif stale and watch.kind == "webroot":  # staging re-hashes would be churn
                    rank = 3
                else:
                    rank = 9
                obs.need_hash = _hashable(watch, entry) and rank < 9
                obs.priority = (rank, not is_script(entry.path), checked)
                out.append(obs)
        return out

    async def hash(self, observations: list[_Observation]) -> None:
        budget = self.settings.max_hashes
        for obs in sorted((o for o in observations if o.need_hash), key=lambda o: o.priority):
            if obs.watch.tier == "B":
                if self.hash_deadline is None:
                    self.hash_deadline = self.monitor.clock() + self.settings.walk_seconds
                if budget <= 0 or self.monitor.clock() >= self.hash_deadline:
                    obs.content = "deferred"
                    continue
                budget -= 1
            obs.sha256, obs.content = await self.monitor.fetch_hash(self.client, obs.entry.path)

    def compare(self, observations: list[_Observation]) -> None:
        files: dict[str, dict[str, Any]] = self.state["files"]
        roots: dict[str, dict[str, Any]] = self.state["roots"]
        by_watch: dict[str, list[_Observation]] = {}
        for obs in observations:
            by_watch.setdefault(obs.watch.root, []).append(obs)
        for watch, walk in self.walks:
            root_state = roots.setdefault(watch.root, {})
            root_first = not root_state.get("baselined_at")
            if root_first and watch.root not in walk.listed:
                continue  # nothing to baseline yet; the gap is reported
            owned = self._owned(watch)

            def unseen_before(path: str, owned: dict[str, dict[str, Any]] = owned,
                              root: str = watch.root, root_first: bool = root_first) -> bool:
                """True when no earlier pass could see ``path``'s directory: the root's first
                listing, or a subdirectory that was known (listed by its parent) but refused
                or beyond a limit until now. A directory that is itself new is a change."""
                if root_first:
                    return True
                directory = posixpath.dirname(path)
                while directory != root and len(directory) > len(root):
                    record = owned.get(directory)
                    if record is not None:
                        return not record.get("listed")
                    directory = posixpath.dirname(directory)
                return False

            seen: set[str] = set()
            for entry in walk.entries:
                seen.add(entry.path)
                if entry.is_dir:
                    previous = owned.get(entry.path) or {}
                    record = {"root": watch.root, "dir": True, "mtime": entry.modified,
                              "listed": entry.path in walk.listed or bool(previous.get("listed"))}
                    if files.get(entry.path) != record:
                        files[entry.path], self.dirty = record, True
            for obs in by_watch.get(watch.root, []):
                self._compare_file(watch, obs, unseen_before(obs.entry.path))
            for path, previous in owned.items():
                if path in seen or not _gone(path, watch.root, seen, walk.listed):
                    continue  # still there, or in a directory that was not listed this pass
                del files[path]
                self.dirty = True
                if not previous.get("dir") and not root_first:
                    self._record(FileChange(path, watch.kind_of(posixpath.basename(path)),
                                            "removed", previous, None, verified=False), watch)
            if root_first:
                root_state["baselined_at"] = self.now.isoformat()
                self.baselined.setdefault(watch.root, [])
                self.dirty = True

    def _compare_file(self, watch: Watch, obs: _Observation, first: bool) -> None:
        files: dict[str, dict[str, Any]] = self.state["files"]
        entry, previous, moved = obs.entry, obs.previous, obs.moved
        kind = watch.kind_of(entry.name)
        if (obs.content == "deferred" and moved and previous is not None
                and entry.size is not None and previous.get("size") == entry.size):
            # Over this pass's hash budget with only the mtime moved (a reboot re-extracting
            # the image looks like this): keep the old record so the file is hashed first next
            # pass, and show it as a gap meanwhile. A size change is reported now, on metadata,
            # and so is a file still waiting after PENDING_PASSES passes.
            since = previous.get("pending_since")
            limit = timedelta(seconds=PENDING_PASSES * self.settings.webroot_interval)
            if since is None or self.now - datetime.fromisoformat(since) < limit:
                if since is None:
                    files[entry.path] = {**previous, "pending_since": self.now.isoformat()}
                    self.dirty = True
                return
        attempted = obs.content not in {"", "deferred"}
        record: dict[str, Any] = {
            "root": watch.root, "size": entry.size, "mtime": entry.modified, "sha256": None,
            "hashed_at": None,
            "checked_at": self.now.isoformat() if attempted else None,
            "content": obs.content if attempted else _why_not_hashed(watch, entry)}
        if obs.sha256 is not None:
            record.update(sha256=obs.sha256, hashed_at=self.now.isoformat())
        elif previous is not None and not moved:
            # Unchanged listing and no new hash: keep the last verified hash. A failed re-read
            # is a coverage gap (record["content"]) until a read succeeds.
            record.update(sha256=previous.get("sha256"), hashed_at=previous.get("hashed_at"))
            if not attempted:
                record.update(checked_at=previous.get("checked_at"),
                              content=previous.get("content", record["content"]))
        change: FileChange | None = None
        if previous is None:
            if first:
                self.baselined.setdefault(watch.root, []).append(
                    {"path": entry.path, "kind": kind, "size": entry.size,
                     "sha256": record["sha256"]})
            else:
                change = FileChange(entry.path, kind, "added", None, record,
                                    verified=record["sha256"] is not None)
        elif obs.sha256 is not None and previous.get("sha256") is not None:
            if obs.sha256 != previous["sha256"]:
                change = FileChange(entry.path, kind, "modified", previous, record, verified=True)
        elif (obs.sha256 is not None and watch.tier == "B" and entry.size is not None
              and previous.get("size") == entry.size):
            # First hash of a web-root file the budget had not reached, mtime-only move. Until
            # now its directory showed a "content not hashed yet" coverage gap.
            pass
        elif moved:
            # Content not compared (denied, unreadable, too large, never hashed, or waiting
            # too long for the budget): report on metadata, and forget the old hash so a later
            # re-hash is not a second change.
            change = FileChange(entry.path, kind, "modified", previous, record, verified=False)
        if files.get(entry.path) != record:
            files[entry.path], self.dirty = record, True
        if change is not None:
            self._record(change, watch)
        if first and entry.path in KNOWN_IOC_PATHS:
            self._record(FileChange(entry.path, kind, "added", None, record,
                                    verified=record["sha256"] is not None), watch)

    def _record(self, change: FileChange, watch: Watch) -> None:
        rebaseline = self.state.get("rebaseline") or {}
        if (watch.root in rebaseline.get("roots", []) and watch.image_managed
                and change.kind in {"webroot", "httpd"}):
            self.upgrade_changes.append(change)  # never boot hooks, crontabs or SSH keys
        else:
            self.changes.append(change)

    def gaps(self) -> None:
        """Store each watch's current coverage gaps. Limits and content gaps are keyed by the
        watched root (with the affected directories in the details), so a walk that stops at a
        different directory each time does not look like a new gap."""
        roots: dict[str, dict[str, Any]] = self.state["roots"]
        for watch, walk in self.walks:
            gaps: set[tuple[str, str]] = set()
            details: dict[str, str] = {}
            for directory, exc in walk.errors.items():
                gaps.add((directory, _gap_reason(exc)))
                details[directory] = str(exc)[:200]
            limited: dict[str, list[str]] = {}
            for directory, limit in walk.unvisited.items():
                if limit == "depth" and watch.tier == "A":
                    continue  # deliberately out of scope
                limited.setdefault(limit, []).append(directory)
            if timed_out := limited.pop("time", None):
                # Which root runs out of time varies with appliance latency: one pass-wide gap.
                self.time_limited[watch.root] = ", ".join(sorted(timed_out)[:20])
            for limit, directories in limited.items():
                reason = f"not fully listed ({limit} limit reached)"
                gaps.add((watch.root, reason))
                details[f"{watch.root}: {reason}"] = ", ".join(sorted(directories)[:20])
            for record in self._owned(watch).values():
                if record.get("pending_since"):
                    gaps.add((watch.root, _PENDING_GAP))
                elif (content_gap := _CONTENT_GAPS.get(record.get("content", ""))) is not None:
                    gaps.add((watch.root, content_gap))
            current = sorted([path, reason] for path, reason in gaps)
            root_state = roots.setdefault(watch.root, {})
            status = ("ok" if not current else
                      "refused" if watch.root in walk.errors else "partial")
            if (root_state.get("gaps") != current or root_state.get("status") != status
                    or root_state.get("details") != details):
                root_state.update(gaps=current, status=status, details=details)
                self.dirty = True


def _hashable(watch: Watch, entry: SystemFileEntry) -> bool:
    return (watch.content and content_allowed(entry.path)
            and (entry.size is None or entry.size <= MAX_HASH_BYTES)
            and (watch.kind != "staging" or is_script(entry.path)
                 or entry.path in KNOWN_IOC_PATHS))


def _why_not_hashed(watch: Watch, entry: SystemFileEntry) -> str:
    if not watch.content or not content_allowed(entry.path):
        return "never-read"
    if entry.size is not None and entry.size > MAX_HASH_BYTES:
        return "too-large"
    if not _hashable(watch, entry):
        return "metadata-only"  # staging churn: only scripts and known artifacts are hashed
    return "not-hashed"


@dataclass
class FimMonitor:
    """FIM for one device. tick() is called on every config probe with a NITRO client whose
    session the caller keeps; findings stay pending until acknowledge(), like ConfigPoller."""

    device: str
    store: SnapshotStore
    settings: FimDefaults = field(default_factory=FimDefaults)
    clock: Callable[[], float] = time.monotonic
    watches: tuple[Watch, ...] = WATCHES
    _state: dict[str, Any] | None = field(default=None, init=False, repr=False)
    last_tick: datetime | None = field(default=None, init=False)
    # summary() as of the last tick: status.json reads this from another thread, never the
    # live state a tick is changing.
    status: dict[str, Any] = field(default_factory=dict, init=False)

    @property
    def key(self) -> str:
        return f"_fim-{self.device}"  # "_" cannot start a device name: no collision

    def _load(self) -> dict[str, Any]:
        if self._state is None:
            state = self.store.get_state(self.key)
            if state.get("version") != STATE_VERSION:
                state = {"version": STATE_VERSION, "files": {}, "roots": {}}
            self._state = state
        return self._state

    async def _save(self) -> None:
        state = self._load()
        await asyncio.to_thread(self.store.set_state, self.key, state)

    async def fetch_hash(self, client: NitroClient, path: str) -> tuple[str | None, str]:
        """(sha256, outcome) of ``path``'s content. The only place FIM reads file content.
        Any failure on one file is an outcome (a coverage gap), never an abort of the pass."""
        if not content_allowed(path):  # defence in depth: callers already filter
            return None, "never-read"
        location, name = posixpath.split(path)
        try:
            data = await client.system_file(name, location, max_bytes=MAX_HASH_BYTES)
        except ValueError:  # "," ":" or "\\" in the name cannot be expressed in NITRO args
            return None, "unreadable-name"
        except PermissionDenied:
            return None, "denied"
        except AuthRejected:
            raise
        except NitroError as exc:
            # A file this pass just listed that the read calls missing is not trusted to be
            # gone: the next listing decides. Until then it is unverified.
            return None, "too-large" if exc.status == 413 else "error"
        except httpx.TransportError as exc:  # e.g. a FIFO or a hung read timing out
            log.info("%s: reading %s failed: %s", self.device, _printable(path),
                     type(exc).__name__)
            return None, "error"
        return hashlib.sha256(data).hexdigest(), "ok"

    async def _run(self, run: _Pass, watches: Iterable[Watch], *, check_version: bool) -> None:
        for watch in watches:
            await run.survey(watch)
        observations = run.observations()
        await self._check_build(run, check_version, observations)
        await run.hash(observations)
        run.compare(observations)
        run.gaps()

    async def tick(self, client: NitroClient, now: datetime | None = None) -> list[Finding]:
        now = now or datetime.now(UTC)
        state = await asyncio.to_thread(self._load)
        if state.get("pending_findings"):
            return [finding_from_document(doc) for doc in state["pending_findings"]]
        last_b = state.get("tier_b_at")
        due_b = (last_b is None or now - datetime.fromisoformat(last_b)
                 >= timedelta(seconds=self.settings.webroot_interval))
        tier_a = _Pass(self, client, state, now)
        await self._run(tier_a, [w for w in self.watches if w.tier == "A"],
                        check_version=False)
        findings = self._change_findings([tier_a], state, now)
        if findings:  # staged first: an interrupted Tier B pass cannot lose them
            state["pending_findings"] = [finding_document(finding) for finding in findings]
        runs = [tier_a]
        dirty = tier_a.dirty
        if due_b:
            tier_b = _Pass(self, client, state, now)
            try:
                async with asyncio.timeout(2 * self.settings.walk_seconds + 90):
                    await self._run(tier_b, [w for w in self.watches if w.tier == "B"],
                                    check_version=True)
            except Exception as exc:  # noqa: BLE001 - reported as a gap; Tier A still counts
                log.warning("%s: web-root pass failed: %s: %s", self.device,
                            type(exc).__name__, exc)
                state["tier_b_error"] = type(exc).__name__
            else:
                state.pop("tier_b_error", None)
                runs.append(tier_b)
                findings = self._change_findings(runs, state, now)
                dirty = dirty or tier_b.dirty
            state["tier_b_at"] = now.isoformat()  # a failed pass is retried next interval
            dirty = True
            if len(runs) > 1 and runs[1].time_limited:
                state["time_limited"] = {"at": now.isoformat(), "roots": runs[1].time_limited}
            elif len(runs) > 1 and (limited := state.get("time_limited")) and (
                    now - datetime.fromisoformat(limited["at"]) >= timedelta(
                        seconds=TIME_LIMIT_CLEARS_AFTER * self.settings.webroot_interval)):
                state.pop("time_limited")
        if rebaseline := state.get("rebaseline"):
            # A root leaves the re-baseline after the first pass that tried it since the
            # upgrade, complete or not: later changes there are reported normally.
            done = {watch.root for run in runs for watch, _walk in run.walks}
            rebaseline["roots"] = [root for root in rebaseline["roots"] if root not in done]
            if (not rebaseline["roots"]
                    or now - datetime.fromisoformat(rebaseline["at"]) >= REBASELINE_EXPIRES):
                state.pop("rebaseline")
            dirty = True
        coverage = self._coverage_finding(state, now)
        if coverage is not None:
            findings.append(coverage)
            dirty = True
        self.last_tick = now
        self.status = self.summary()
        if findings:
            state["pending_findings"] = [finding_document(finding) for finding in findings]
        if dirty or findings:
            await self._save()
        return findings

    def acknowledge(self) -> None:
        state = self._load()
        if state.pop("pending_findings", None):
            self.store.set_state(self.key, state)

    async def _check_build(self, run: _Pass, check: bool,
                           observations: Iterable[_Observation]) -> None:
        """Read the firmware version on every Tier B pass, and whenever an image-managed file
        moved; a new build schedules the image-managed watches for re-baselining."""
        state = run.state
        moved = any(obs.watch.image_managed and obs.moved for obs in observations)
        if not (check or moved):
            return
        try:
            build: str | None = await run.client.version_string()
            state.pop("build_error", None)
        except AuthRejected:
            raise
        except NitroError as exc:
            build = None
            if state.get("build_error") != _gap_reason(exc):
                state["build_error"] = _gap_reason(exc)
                run.dirty = True
        if not build:
            return
        previous = state.get("build")
        if previous != build:
            state["build"] = build
            run.dirty = True
        if previous and previous != build:
            log.info("%s: firmware changed; re-baselining web roots and httpd.conf", self.device)
            state["rebaseline"] = {"from": previous, "to": build, "at": run.now.isoformat(),
                                   "roots": [watch.root for watch in self.watches
                                             if watch.image_managed]}

    # ---- findings -------------------------------------------------------------------------

    def _change_findings(self, runs: list[_Pass], state: dict[str, Any],
                         now: datetime) -> list[Finding]:
        """One finding per rule, one re-baseline and one baseline finding for the tick."""
        findings: list[Finding] = []
        grouped: dict[str, list[tuple[FileChange, Severity]]] = {}
        for change in (change for run in runs for change in run.changes):
            rule = classify(change)
            if rule is not None:
                grouped.setdefault(rule[0], []).append((change, rule[1]))
        for rule_id, items in grouped.items():
            findings.append(self._change_finding(rule_id, items, state, now))
        if upgrade := [change for run in runs for change in run.upgrade_changes]:
            findings.append(self._upgrade_finding(upgrade, state, now))
        if baselined := {root: items for run in runs for root, items in run.baselined.items()}:
            findings.append(self._baseline_finding(baselined, now))
        return findings

    def _change_finding(self, rule_id: str, items: list[tuple[FileChange, Severity]],
                        state: dict[str, Any], now: datetime) -> Finding:
        severity = max(severity for _change, severity in items)
        paths = sorted(_printable(change.path) for change, _severity in items)
        shown = ", ".join(paths[:3]) + (f" and {len(paths) - 3} more" if len(paths) > 3 else "")
        unverified = sum(1 for change, _severity in items if not change.verified)
        note = (f"; {unverified} compared on listing metadata only (content not read)"
                if unverified else "")
        evidence: dict[str, Any] = _listed([change.evidence() for change, _severity in
                                            sorted(items, key=lambda item: item[0].path)])
        rebaseline = state.get("rebaseline") or {}
        if rebaseline and any(change.path.startswith("/etc/") for change, _ in items):
            # e.g. /etc/crontab replaced by the upgrade: still reported at full severity.
            note += (f"; the firmware changed from {rebaseline.get('from')!r} to "
                     f"{rebaseline.get('to')!r} at the same time")
            evidence["firmware_change"] = {"from": rebaseline.get("from"),
                                           "to": rebaseline.get("to")}
        identity = _digest([change.evidence() for change, _severity in items])
        return Finding(
            dedup_key=f"{rule_id}|{self.device}|{identity[:16]}",
            rule_id=rule_id, title=_TITLES[rule_id], severity=severity, category="sweep",
            device=self.device,
            summary=f"{self.device}: {', '.join(sorted({c.change for c, _ in items}))}: "
                    f"{shown}{note}",
            observed_at=now,
            evidence={**evidence,
                      "remediation": "Preserve evidence before changing the appliance: "
                                     "collect the file and a techsupport bundle, compare it "
                                     "with a known-good node of the same build, and treat "
                                     "the device as compromised until explained."},
            mitre=_MITRE.get(rule_id, ()))

    def _upgrade_finding(self, upgrade: list[FileChange], state: dict[str, Any],
                         now: datetime) -> Finding:
        rebaseline = state.get("rebaseline") or {}
        changes = sorted(upgrade, key=lambda change: change.path)
        scripts = [change.evidence() for change in changes
                   if change.change != "removed" and (is_script(change.path)
                                                      or change.kind != "webroot")]
        identity = _digest([change.evidence() for change in changes])
        return Finding(
            dedup_key=f"fim-rebaselined-after-upgrade|{self.device}|{identity[:16]}",
            rule_id="fim-rebaselined-after-upgrade",
            title="Firmware changed: web roots and httpd.conf re-baselined; review accepted "
                  "scripts",
            severity=Severity.HIGH, category="sweep", device=self.device,
            summary=(f"{self.device}: firmware changed from {rebaseline.get('from')!r} to "
                     f"{rebaseline.get('to')!r}; {len(changes)} change(s) in image-managed "
                     f"paths were accepted into the new baseline, {len(scripts)} of them "
                     "scripts or configuration files to review"),
            observed_at=now,
            evidence={"from": rebaseline.get("from"), "to": rebaseline.get("to"),
                      "review": _listed(scripts),
                      "counts": {kind: sum(1 for c in changes if c.change == kind)
                                 for kind in ("added", "modified", "removed")},
                      "remediation": "Compare the accepted scripts with another node on the "
                                     "same build; a webshell planted around the upgrade "
                                     "would be in this list."},
            mitre=("T1505.003",))

    def _baseline_finding(self, baselined: dict[str, list[dict[str, Any]]],
                          now: datetime) -> Finding:
        inventory: dict[str, list[dict[str, Any]]] = {}
        for items in baselined.values():
            for item in items:
                kind = item["kind"]
                if kind in {"webroot", "staging"} and not is_script(item["path"]):
                    continue
                inventory.setdefault(kind, []).append(item)
        counts = {root: len(items) for root, items in sorted(baselined.items())}
        return Finding(
            dedup_key=f"fim-baseline-recorded|{self.device}|{_digest(counts)[:16]}|"
                      f"{now.isoformat()}",
            rule_id="fim-baseline-recorded",
            title="File-integrity baseline recorded; review the inventory",
            severity=Severity.MEDIUM, category="sweep", device=self.device,
            summary=(f"{self.device}: file-integrity baseline recorded for "
                     f"{sum(counts.values())} file(s) in {len(counts)} watched "
                     f"director{'y' if len(counts) == 1 else 'ies'} not visible before. It "
                     "is not assumed clean: review the boot hooks, crontabs, SSH keys and "
                     "web-root scripts it accepted"),
            observed_at=now,
            evidence={"files_per_directory": counts,
                      "inventory": {kind: _listed(sorted(items, key=lambda i: i["path"]))
                                    for kind, items in sorted(inventory.items())}})

    def coverage_gaps(self) -> list[list[str]]:
        state = self._load()
        gaps = [[path, reason] for root in state["roots"].values()
                for path, reason in root.get("gaps", [])]
        if state.get("build_error"):
            gaps.append(["show ns version", f"{state['build_error']}: firmware upgrades "
                                            "cannot be recognized"])
        if state.get("tier_b_error"):
            gaps.append([_TIER_B_PATHS, f"pass failed ({state['tier_b_error']})"])
        if state.get("time_limited"):
            gaps.append([_TIER_B_PATHS, "not fully listed (walk_seconds time limit reached)"])
        return sorted(gaps)

    def _coverage_finding(self, state: dict[str, Any], now: datetime) -> Finding | None:
        """`fim-coverage-unknown` whenever a gap appears that was not reported yet (listing all
        current gaps); a shrinking set is recorded quietly (e.g. a hash catch-up making
        progress), and `fim-coverage-restored` follows once no gap is left."""
        gaps = self.coverage_gaps()
        reported = state.get("coverage_reported") or []
        if gaps == reported:
            return None
        state["coverage_reported"] = gaps
        if gaps and all(gap in reported for gap in gaps):
            return None
        if not gaps:
            return Finding(
                dedup_key=f"fim-coverage-restored|{self.device}|{now.isoformat()}",
                rule_id="fim-coverage-restored", title="File-integrity coverage restored",
                severity=Severity.INFO, category="health", device=self.device,
                summary=f"{self.device}: every monitored path was checked completely",
                observed_at=now)
        tier_a = {watch.root for watch in self.watches if watch.tier == "A"}
        critical_paths = any(path == "show ns version" or _under(path, tier_a)
                             for path, _reason in gaps)
        shown = "; ".join(f"{_printable(path)} ({reason})" for path, reason in gaps[:5])
        details = {key: value for root in state["roots"].values()
                   for key, value in root.get("details", {}).items()}
        details.update({f"{root}: cut off by the time limit": cut for root, cut in
                        (state.get("time_limited") or {}).get("roots", {}).items()})
        return Finding(
            dedup_key=f"fim-coverage-unknown|{self.device}|{_digest(gaps)[:16]}",
            rule_id="fim-coverage-unknown",
            title="File-integrity coverage unknown for some appliance paths",
            severity=Severity.HIGH if critical_paths else Severity.MEDIUM,
            category="health", device=self.device,
            summary=(f"{self.device}: {len(gaps)} path(s) could not be fully checked, so "
                     f"changes there would go unseen: {shown}"
                     + (f" and {len(gaps) - 5} more" if len(gaps) > 5 else "")),
            observed_at=now,
            evidence={"gaps": gaps[:200], "errors": dict(sorted(details.items())[:50]),
                      "remediation": "Allow these paths in the FIM account's command policy "
                                     "(netrescale snippets), raise the FIM limits if a walk "
                                     "or the hash budget is cut short, or cover the paths "
                                     "with NetScaler Console FIM or an SSH sweep."})

    def summary(self) -> dict[str, Any]:
        """Bounded status for status.json."""
        state = self._load()
        files = state.get("files", {})
        return {"last_tick": self.last_tick.isoformat() if self.last_tick else None,
                "tier_b_at": state.get("tier_b_at"), "build": state.get("build"),
                "files": sum(1 for entry in files.values() if not entry.get("dir")),
                "directories": {root: data.get("status", "pending")
                                for root, data in sorted(state.get("roots", {}).items())},
                "coverage_gaps": self.coverage_gaps()[:50],
                "rebaseline_pending": bool(state.get("rebaseline"))}
