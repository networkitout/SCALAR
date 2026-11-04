"""Read-only NITRO REST client.

* Only GET is allowed, plus the POSTs for login and logout. This is enforced in a request hook,
  so a coding mistake elsewhere can't change appliance configuration.
* One session per device: log in once and re-login once if the session expires. A rejected
  login is reported to the lockout guard and never retried.
* Every connection is SPKI-pinned (or CA-validated) before credentials are sent.
"""

from __future__ import annotations

import base64
import contextlib
import logging
import time
from collections import deque
from collections.abc import Callable, Collection
from dataclasses import dataclass, field
from types import TracebackType
from typing import Any
from urllib.parse import quote

import httpx

from netrescale.secrets.base import Credential
from netrescale.transport.tls import PinnedTransport, make_ssl_context

log = logging.getLogger(__name__)

_LOGIN_PATH = "/nitro/v1/config/login"
_LOGOUT_PATH = "/nitro/v1/config/logout"
_ALLOWED_POSTS = frozenset({_LOGIN_PATH, _LOGOUT_PATH})
ERR_BAD_CREDENTIALS = 354
ERR_SESSION_EXPIRED = 444
MAX_FILE_LOCATION = 127  # systemfile.filelocation limit in the NITRO reference


class NitroError(Exception):
    def __init__(self, message: str, *, status: int | None = None,
                 errorcode: int | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.errorcode = errorcode


class ReadOnlyViolation(NitroError):
    pass


class AuthRejected(NitroError):
    """The appliance rejected the username/password. Do not retry with the same credential."""


class PermissionDenied(NitroError):
    """Authenticated, but the account's command policy does not allow this request."""


@dataclass(frozen=True, slots=True)
class SystemFileEntry:
    """One entry of a ``systemfile`` directory listing: metadata only, never content."""

    name: str
    location: str
    size: int | None
    modified: str
    mode: tuple[str, ...] = ()

    @property
    def is_dir(self) -> bool:
        return "DIRECTORY" in self.mode

    @property
    def path(self) -> str:
        return f"{self.location.rstrip('/')}/{self.name}"


@dataclass
class WalkResult:
    """What a bounded walk saw. Only directories in ``listed`` were listed completely, so only
    they can prove that a file is gone; ``errors`` and ``unvisited`` are coverage gaps."""

    root: str
    entries: list[SystemFileEntry] = field(default_factory=list)
    listed: set[str] = field(default_factory=set)
    errors: dict[str, NitroError] = field(default_factory=dict)  # directory -> why not listed
    unvisited: dict[str, str] = field(default_factory=dict)  # directory -> limit that skipped it
    truncated: str | None = None  # "entries" or "time" when the walk stopped early

    @property
    def complete(self) -> bool:
        return not (self.errors or self.unvisited or self.truncated)


@dataclass(frozen=True, slots=True)
class NitroTarget:
    name: str
    host: str
    port: int = 443
    spki_pin: str | None = None
    ca_bundle: str | None = None
    timeout: float = 30.0
    spki_pinning: bool = True

    def __post_init__(self) -> None:
        if self.spki_pinning and not self.spki_pin and not self.ca_bundle:
            raise ValueError(f"{self.name}: a TLS pin or a CA bundle is required "
                             "(certificate verification is never disabled)")


async def _enforce_read_only(request: httpx.Request) -> None:
    path = request.url.path
    if not path.startswith("/nitro/v1/"):
        raise ReadOnlyViolation(f"refusing request outside /nitro/v1/: {path}")
    if request.method == "GET":
        return
    if request.method == "POST" and path in _ALLOWED_POSTS:
        return
    raise ReadOnlyViolation(f"refusing {request.method} {path}: netrescale is read-only")


def _errorcode(resp: httpx.Response) -> int | None:
    try:
        body = resp.json()
    except ValueError:
        return None
    code = body.get("errorcode") if isinstance(body, dict) else None
    return int(code) if isinstance(code, int | str) and str(code).lstrip("-").isdigit() else None


def _message(resp: httpx.Response) -> str:
    with contextlib.suppress(ValueError):
        body = resp.json()
        if isinstance(body, dict) and body.get("message"):
            return str(body["message"])
    return resp.reason_phrase or f"HTTP {resp.status_code}"


class NitroClient:
    def __init__(
        self,
        target: NitroTarget,
        credential_source: Callable[[], Credential],
        *,
        on_auth_rejected: Callable[[], None] | None = None,
        session_timeout: int = 900,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.target = target
        self._credential_source = credential_source
        self._on_auth_rejected = on_auth_rejected
        self._session_timeout = session_timeout
        if transport is None:
            pin = target.spki_pin if target.spki_pinning else None
            ctx = make_ssl_context(pin=pin, ca_bundle=target.ca_bundle)
            transport = (PinnedTransport(target.host, pin, ctx)
                         if pin else httpx.AsyncHTTPTransport(verify=ctx, trust_env=False))
        self._http = httpx.AsyncClient(
            base_url=f"https://{target.host}:{target.port}",
            transport=transport,
            timeout=target.timeout,
            headers={"Accept": "application/json", "User-Agent": "netrescale"},
            event_hooks={"request": [_enforce_read_only]},
            follow_redirects=False,
            trust_env=False,
        )
        self._logged_in = False

    async def __aenter__(self) -> NitroClient:
        return self

    async def __aexit__(self, exc_type: type[BaseException] | None, exc: BaseException | None,
                        tb: TracebackType | None) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        try:
            await self.logout()
        finally:
            await self._http.aclose()

    # ---- session ------------------------------------------------------------------------

    async def login(self) -> None:
        cred = self._credential_source()
        payload = {"login": {"username": cred.username, "password": cred.reveal_password(),
                             "timeout": self._session_timeout}}
        resp = await self._http.post(_LOGIN_PATH, json=payload)
        code = _errorcode(resp)
        if resp.status_code == 401 or code == ERR_BAD_CREDENTIALS:
            self._logged_in = False
            if self._on_auth_rejected:
                self._on_auth_rejected()
            raise AuthRejected(f"{self.target.name}: login rejected for {cred.username!r}: "
                               f"{_message(resp)}", status=resp.status_code, errorcode=code)
        if resp.status_code >= 400 or (code not in (None, 0)):
            raise NitroError(f"{self.target.name}: login failed: {_message(resp)}",
                             status=resp.status_code, errorcode=code)
        self._logged_in = True

    async def logout(self) -> None:
        if not self._logged_in:
            return
        self._logged_in = False
        try:
            await self._http.post(_LOGOUT_PATH, json={"logout": {}})
        except httpx.HTTPError as exc:  # best effort; the session will time out
            log.debug("%s: logout failed: %s", self.target.name, exc)
        self._http.cookies.clear()

    # ---- requests -----------------------------------------------------------------------

    async def _get_response(self, path: str, params: dict[str, str] | None,
                            max_bytes: int | None) -> httpx.Response:
        if max_bytes is None:
            return await self._http.get(path, params=params)
        async with self._http.stream("GET", path, params=params) as response:
            content = bytearray()
            async for chunk in response.aiter_bytes(chunk_size=65536):
                if len(content) + len(chunk) > max_bytes:
                    raise NitroError("Log download exceeds the transfer limit; use forwarded "
                                     "syslog or upload a smaller log file", status=413)
                content.extend(chunk)
            return httpx.Response(response.status_code, content=bytes(content),
                                  request=response.request)

    async def _get(self, path: str, params: dict[str, str] | None = None, *,
                   max_bytes: int | None = None) -> dict[str, Any]:
        if not self._logged_in:
            await self.login()
        resp = await self._get_response(path, params, max_bytes)
        code = _errorcode(resp)
        if resp.status_code == 401 or code == ERR_SESSION_EXPIRED:
            log.info("%s: NITRO session expired; logging in again", self.target.name)
            self._logged_in = False
            await self.login()
            resp = await self._get_response(path, params, max_bytes)
            code = _errorcode(resp)
        if resp.status_code == 403:
            raise PermissionDenied(f"{self.target.name}: not permitted: GET {path}: "
                                   f"{_message(resp)}", status=403, errorcode=code)
        if resp.status_code >= 400 or (code not in (None, 0)):
            raise NitroError(f"{self.target.name}: GET {path} failed: {_message(resp)}",
                             status=resp.status_code, errorcode=code)
        body = resp.json()
        if not isinstance(body, dict):
            raise NitroError(f"{self.target.name}: unexpected response for {path}")
        return body

    async def config(self, resource: str, name: str | None = None, *,
                     attrs: list[str] | None = None, count: bool = False,
                     args: dict[str, str] | None = None) -> dict[str, Any]:
        return await self._resource("config", resource, name, attrs=attrs, count=count,
                                    args=args)

    async def stat(self, resource: str, name: str | None = None) -> dict[str, Any]:
        return await self._resource("stat", resource, name)

    async def _resource(self, kind: str, resource: str, name: str | None, *,
                        attrs: list[str] | None = None, count: bool = False,
                        args: dict[str, str] | None = None) -> dict[str, Any]:
        path = f"/nitro/v1/{kind}/{quote(resource, safe='')}"
        if name is not None:
            path += "/" + quote(name, safe="")
        params: dict[str, str] = {}
        if attrs:
            params["attrs"] = ",".join(attrs)
        if count:
            params["count"] = "yes"
        if args:
            params["args"] = ",".join(f"{k}:{quote(v, safe='')}" for k, v in args.items())
        return await self._get(path, params or None)

    async def count(self, resource: str) -> int:
        body = await self.config(resource, count=True)
        items = body.get(resource) or []
        return int(items[0].get("__count", 0)) if items else 0

    # ---- typed helpers ------------------------------------------------------------------

    async def version_string(self) -> str:
        body = await self.config("nsversion")
        return str(_first(body, "nsversion").get("version", ""))

    async def config_state(self) -> dict[str, Any]:
        """lastconfigchangedtime / lastconfigsavetime / configchanged and friends."""
        return _first(await self.config("nsconfig"), "nsconfig")

    async def running_config(self) -> str:
        return str(_first(await self.config("nsrunningconfig"), "nsrunningconfig")
                   .get("response", ""))

    async def saved_config(self) -> str:
        return str(_first(await self.config("nssavedconfig"), "nssavedconfig")
                   .get("textblob", ""))

    async def ha_nodes(self) -> list[dict[str, Any]]:
        return list((await self.config("hanode")).get("hanode") or [])

    async def system_file(self, filename: str, location: str, *,
                          max_bytes: int = 16 * 1024 * 1024) -> bytes:
        if (not filename or any(character in filename for character in "/\\,:\r\n")
                or filename in {".", ".."}):
            raise ValueError("filename must not contain a path")
        _check_location(location)
        args = f"filename:{quote(filename, safe='')},filelocation:{quote(location, safe='')}"
        body = await self._get(
            f"/nitro/v1/config/systemfile?args={args}",
            max_bytes=4 * ((max_bytes + 2) // 3) + 65536,
        )
        item = _first(body, "systemfile")
        if (item.get("filename") != filename
                or str(item.get("filelocation", "")).rstrip("/") != location.rstrip("/")):
            raise NitroError("The ADC returned a different file than requested")
        encoded = item.get("filecontent")
        if not isinstance(encoded, str) or item.get("fileencoding", "BASE64") != "BASE64":
            raise NitroError("The ADC did not expose BASE64 log content through systemfile")
        if len(encoded) > 4 * ((max_bytes + 2) // 3):
            raise NitroError("Log file exceeds the transfer limit", status=413)
        try:
            content = base64.b64decode(encoded, validate=True)
        except ValueError:
            raise NitroError("The ADC returned invalid BASE64 log content") from None
        if len(content) > max_bytes:
            raise NitroError("Log file exceeds the transfer limit", status=413)
        return content

    async def list_files(self, location: str, *,
                         max_bytes: int = 8 * 1024 * 1024) -> list[SystemFileEntry]:
        """One directory level through ``GET systemfile?args=filelocation:<location>``.
        Any file content in the response is ignored. Raises PermissionDenied when the command
        policy refuses the location."""
        _check_location(location)
        if len(location) > MAX_FILE_LOCATION:
            raise ValueError("file location is too long for NITRO")
        try:
            body = await self._get(
                f"/nitro/v1/config/systemfile?args=filelocation:{quote(location, safe='')}",
                max_bytes=max_bytes)
        except NitroError as exc:
            if exc.status != 413 or isinstance(exc, PermissionDenied):
                raise
            raise NitroError(f"{self.target.name}: the listing of {location} exceeds the "
                             "transfer limit", status=413) from None
        items = body.get("systemfile") or []
        if isinstance(items, dict):
            items = [items]
        if not isinstance(items, list):
            raise NitroError(f"{self.target.name}: malformed systemfile listing for {location}")
        wanted = location.rstrip("/") or "/"
        entries = []
        for item in items:
            name = item.get("filename") if isinstance(item, dict) else None
            if not isinstance(name, str) or not name or any(c in name for c in "/\0"):
                raise NitroError(f"{self.target.name}: malformed systemfile listing for "
                                 f"{location}")
            if name in {".", ".."}:
                continue
            listed = str(item.get("filelocation") or wanted).rstrip("/") or "/"
            if listed != wanted:
                raise NitroError("The ADC listed a different directory than requested")
            mode = item.get("filemode") or ()
            entries.append(SystemFileEntry(
                name=name, location=wanted, size=_int_or_none(item.get("filesize")),
                modified=str(item.get("filemodifiedtime") or ""),
                mode=(mode,) if isinstance(mode, str) else tuple(str(m) for m in mode)))
        return entries

    async def walk_files(self, root: str, *, max_depth: int = 8, max_entries: int = 5000,
                         max_seconds: float = 60.0, prune: Collection[str] = (),
                         clock: Callable[[], float] = time.monotonic) -> WalkResult:
        """Breadth-first listing of ``root`` and up to ``max_depth`` levels below it, bounded by
        total entries and wall time. A directory that cannot be listed (refused, missing,
        malformed, or a name NITRO arguments cannot express) is recorded, not raised; login
        failures and transport errors propagate. ``prune`` directories are not descended."""
        deadline = clock() + max_seconds
        result = WalkResult(root)
        queue: deque[tuple[str, int]] = deque([(root, 0)])
        while queue:
            location, depth = queue.popleft()
            if location in result.listed or location in result.errors:
                continue  # a symlink loop back to a directory already listed
            if clock() >= deadline:
                result.truncated = "time"
                result.unvisited.update({location: "time", **{d: "time" for d, _ in queue}})
                break
            try:
                listing = await self.list_files(location)
            except AuthRejected:
                raise
            except NitroError as exc:
                result.errors[location] = exc
                continue
            except ValueError as exc:  # e.g. a name with "," or ":", or a path over 127 chars
                result.errors[location] = NitroError(f"cannot list through NITRO: {exc}")
                continue
            if len(result.entries) + len(listing) > max_entries:
                result.truncated = "entries"
                result.unvisited.update({location: "entries", **{d: "entries" for d, _ in queue}})
                break
            result.listed.add(location)
            result.entries.extend(listing)
            for entry in listing:
                if not entry.is_dir or entry.path in prune:
                    continue
                if depth >= max_depth:
                    result.unvisited[entry.path] = "depth"
                else:
                    queue.append((entry.path, depth + 1))
        return result


def _check_location(location: str) -> None:
    if (not location.startswith("/") or any(character in location for character in ",:\r\n\0")
            or any(part in {".", ".."} for part in location.split("/"))):
        raise ValueError("invalid file location")


def _int_or_none(value: object) -> int | None:
    try:
        return int(str(value))
    except ValueError:
        return None


def _first(body: dict[str, Any], key: str) -> dict[str, Any]:
    value = body.get(key)
    if isinstance(value, list):
        value = value[0] if value else {}
    if not isinstance(value, dict):
        raise NitroError(f"response has no {key!r} object")
    return value
