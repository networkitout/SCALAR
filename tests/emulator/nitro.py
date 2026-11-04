"""A small stateful NITRO emulator served through httpx.MockTransport.

It mirrors the parts of NITRO that scalar uses: login/logout with a NITRO_AUTH_TOKEN
cookie, session expiry (errorcode 444), bad credentials (errorcode 354, HTTP 401),
command-policy denials (HTTP 403), and the config/stat resources the collectors read.
Real response shapes get re-checked against `scalar probe` output from production.
"""

from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote

import httpx


@dataclass
class FakeNitro:
    users: dict[str, str] = field(default_factory=lambda: {"sc_nitro": "nitro-password"})
    version: str = "NetScaler NS14.1: Build 73.37.nc, Date: Sep 20 2026, 10:00:00   (64-bit)"
    running: str = "#NS14.1 Build 73.37\nset ns hostName ns-gw-01\n"
    saved: str = "#NS14.1 Build 73.37\nset ns hostName ns-gw-01\n"
    lastconfigchangedtime: str = "Mon Oct  5 10:00:00 2026"
    lastconfigsavetime: str = "Mon Oct  5 10:00:00 2026"
    denied: set[str] = field(default_factory=set)  # resources the cmdPolicy denies
    resources: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    files: dict[str, bytes] = field(default_factory=dict)  # absolute path -> content
    file_times: dict[str, str] = field(default_factory=dict)  # path -> filemodifiedtime
    dirs: set[str] = field(default_factory=set)  # directories beyond those implied by files
    denied_paths: set[str] = field(default_factory=set)  # cmdPolicy denies these and below
    denied_reads: set[str] = field(default_factory=set)  # listing allowed, content refused
    missing_reads: set[str] = field(default_factory=set)  # listed, but a read says "No such file"
    missing_listings: set[str] = field(default_factory=set)  # listed by the parent, then 404
    transport_errors: set[str] = field(default_factory=set)  # requests time out (e.g. a FIFO)
    sessions: set[str] = field(default_factory=set)
    requests: list[httpx.Request] = field(default_factory=list)
    login_attempts: int = 0

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def expire_sessions(self) -> None:
        self.sessions.clear()

    @property
    def config_changed(self) -> bool:
        return self.running != self.saved

    # ---- handler --------------------------------------------------------------------------

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if request.method == "POST" and path == "/nitro/v1/config/login":
            return self._login(request)
        if request.method == "POST" and path == "/nitro/v1/config/logout":
            self.sessions.discard(self._token(request) or "")
            return _ok({})
        if request.method != "GET":
            return _err(405, 1, "method not allowed in emulator")
        if self._token(request) not in self.sessions:
            return _err(401, 444, "Session expired or killed. Please login again")
        parts = path.split("/")  # ['', 'nitro', 'v1', kind, resource, (name)]
        kind, resource = parts[3], parts[4]
        if resource in self.denied:
            return _err(403, 2138, "Not authorized to execute this command")
        if kind == "config":
            return self._config(resource, request)
        return _ok({resource: self.resources.get(resource, [{}])[0]})

    def _token(self, request: httpx.Request) -> str | None:
        cookie = request.headers.get("cookie", "")
        for part in cookie.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "NITRO_AUTH_TOKEN":
                return v
        return None

    def _login(self, request: httpx.Request) -> httpx.Response:
        self.login_attempts += 1
        body = json.loads(request.content)["login"]
        if self.users.get(body.get("username")) != body.get("password"):
            return _err(401, 354, "Invalid username or password")
        token = secrets.token_hex(16)
        self.sessions.add(token)
        resp = _ok({"sessionid": token})
        resp.headers["set-cookie"] = f"NITRO_AUTH_TOKEN={token}; path=/nitro/v1"
        return resp

    def _config(self, resource: str, request: httpx.Request) -> httpx.Response:
        if request.url.params.get("count") == "yes":
            return _ok({resource: [{"__count": len(self.resources.get(resource, []))}]})
        if resource == "nsversion":
            return _ok({"nsversion": {"version": self.version, "mode": "1"}})
        if resource == "nsconfig":
            return _ok({"nsconfig": {
                "lastconfigchangedtime": self.lastconfigchangedtime,
                "lastconfigsavetime": self.lastconfigsavetime,
                "configchanged": self.config_changed,
            }})
        if resource == "nsrunningconfig":
            return _ok({"nsrunningconfig": {"response": self.running}})
        if resource == "nssavedconfig":
            return _ok({"nssavedconfig": {"textblob": self.saved}})
        if resource == "systemfile" and resource not in self.resources:
            entries = [entry.partition(b":") for entry in
                       request.url.query.removeprefix(b"args=").split(b",")]
            keys = [key for key, _separator, _value in entries]
            if (any(separator != b":" for _key, separator, _value in entries)
                    or sorted(keys) not in ([b"filelocation"], [b"filelocation", b"filename"])):
                return _err(400, 1, "Invalid args in query parameters")
            args = {key.decode("ascii"): unquote(value.decode("ascii"))
                    for key, _separator, value in entries}
            target = args["filelocation"].rstrip("/") + (
                f"/{args['filename']}" if "filename" in args else "")
            if target in self.transport_errors:
                raise httpx.ReadTimeout("emulated read timeout", request=request)
            if "filename" not in args:
                if target in self.missing_listings:
                    return _err(404, 344, "No such file or directory")
                return self._listing(args["filelocation"])
            path = f"{args['filelocation'].rstrip('/')}/{args['filename']}"
            if path in self.missing_reads:
                return _err(404, 344, "No such file")
            if self._path_denied(path) or self._path_denied(path, self.denied_reads):
                return _err(403, 2138, "Not authorized to execute this command")
            if path not in self.files:
                return _err(404, 344, "No such file")
            content = self.files[path]
            return _ok({"systemfile": [{"filename": args["filename"],
                                       "filelocation": args["filelocation"],
                                       "fileencoding": "BASE64", "filesize": len(content),
                                       "filecontent": base64.b64encode(content).decode()}]})
        return _ok({resource: self.resources.get(resource, [])})

    def _path_denied(self, path: str, denied_paths: set[str] | None = None) -> bool:
        return any(path == denied or path.startswith(denied.rstrip("/") + "/")
                   for denied in (self.denied_paths if denied_paths is None else denied_paths))

    def _listing(self, location: str) -> httpx.Response:
        """`show system file -fileLocation <dir>`: one level, directories flagged DIRECTORY."""
        location = location.rstrip("/") or "/"
        if self._path_denied(location):
            return _err(403, 2138, "Not authorized to execute this command")
        prefix = "/" if location == "/" else location + "/"
        known = {*self.files, *self.dirs}
        if location != "/" and location not in self.dirs and not any(
                path.startswith(prefix) for path in known):
            return _err(404, 344, "No such file or directory")
        children: dict[str, dict[str, Any]] = {}
        for path in sorted(known):
            if not path.startswith(prefix):
                continue
            head, separator, _rest = path[len(prefix):].partition("/")
            if not head:
                continue
            stamp = self.file_times.get(prefix + head, "Mon Oct  5 10:00:00 2026")
            if separator or path not in self.files:
                children[head] = {"filename": head, "filelocation": location,
                                  "filemode": ["DIRECTORY"], "filesize": "512",
                                  "filemodifiedtime": stamp, "fileaccesstime": stamp}
            else:
                children[head] = {"filename": head, "filelocation": location,
                                  "filesize": str(len(self.files[path])),
                                  "filemodifiedtime": stamp, "fileaccesstime": stamp}
        return _ok({"systemfile": list(children.values())} if children else {})


def _ok(extra: dict[str, Any]) -> httpx.Response:
    return httpx.Response(200, json={"errorcode": 0, "message": "Done", "severity": "NONE",
                                     **extra})


def _err(status: int, code: int, message: str) -> httpx.Response:
    return httpx.Response(status, json={"errorcode": code, "message": message,
                                        "severity": "ERROR"})
