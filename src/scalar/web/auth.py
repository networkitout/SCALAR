"""Local web users and bounded, revocable, process-local browser sessions."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Literal

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError

from scalar.secrets.vault import atomic_write

USERNAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
Role = Literal["admin", "operator", "viewer"]


class AuthenticationError(ValueError):
    pass


class LoginThrottled(AuthenticationError):
    pass


@dataclass(frozen=True)
class User:
    password_hash: str
    role: Role = "admin"
    enabled: bool = True

    @property
    def version(self) -> str:
        return hashlib.sha256(json.dumps(asdict(self), sort_keys=True).encode()).hexdigest()


def load_accounts(path: Path) -> dict[str, User]:
    if not path.exists():
        return {}
    if path.stat().st_size > 1048576:
        raise AuthenticationError("web user file exceeds its size limit")
    document = json.loads(path.read_bytes())
    if document.get("version") not in (1, 2) or not isinstance(document.get("users"), dict):
        raise AuthenticationError("invalid web user file")
    users = {}
    legacy_admin = "admin" if "admin" in document["users"] else next(iter(document["users"]), None)
    for name, value in document["users"].items():
        if not isinstance(name, str) or not USERNAME.fullmatch(name):
            raise AuthenticationError("invalid web user entry")
        if document["version"] == 1 and isinstance(value, str):
            users[name] = User(value, "admin" if name == legacy_admin else "operator")
        elif (
            isinstance(value, dict)
            and isinstance(value.get("password_hash"), str)
            and value.get("role") in ("admin", "operator", "viewer")
            and isinstance(value.get("enabled"), bool)
        ):
            users[name] = User(value["password_hash"], value["role"], value["enabled"])
        else:
            raise AuthenticationError("invalid web user entry")
    return users


def load_users(path: Path) -> dict[str, str]:
    return {name: user.password_hash for name, user in load_accounts(path).items() if user.enabled}


@contextmanager
def account_lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path = path.with_suffix(".lock")
    try:
        import fcntl
    except ModuleNotFoundError:
        with lock_path.open("a") as _stream:
            yield
        return

    with lock_path.open("a") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def update_user(
    path: Path,
    username: str,
    *,
    password: str | None = None,
    role: Role | None = None,
    enabled: bool | None = None,
    remove: bool = False,
    create_only: bool = False,
) -> None:
    if not USERNAME.fullmatch(username):
        raise AuthenticationError(
            "username must be 1-64 letters, digits, dots, underscores or hyphens"
        )
    if password is not None and not 16 <= len(password) <= 256:
        raise AuthenticationError("password must be between 16 and 256 characters")
    if role is not None and role not in ("admin", "operator", "viewer"):
        raise AuthenticationError("invalid user role")
    encoded = PasswordHasher().hash(password) if password is not None else None
    with account_lock(path):
        users = load_accounts(path)
        previous = users.get(username)
        if create_only and previous is not None:
            raise AuthenticationError("user already exists")
        if previous is None and (encoded is None or remove):
            raise AuthenticationError("user does not exist")
        if remove:
            users.pop(username)
        else:
            users[username] = User(
                encoded or (previous.password_hash if previous else ""),
                role if role is not None else previous.role if previous else "admin",
                enabled if enabled is not None else previous.enabled if previous else True,
            )
        if not any(user.enabled and user.role == "admin" for user in users.values()):
            raise AuthenticationError("at least one enabled administrator must remain")
        atomic_write(
            path,
            json.dumps(
                {"version": 2, "users": {name: asdict(user) for name, user in users.items()}},
                indent=2,
            ).encode(),
        )


def set_password(path: Path, username: str, password: str) -> None:
    update_user(path, username, password=password)


@dataclass(frozen=True)
class Session:
    username: str
    csrf: str
    expires: float
    version: str
    role: Role = "admin"
    authenticated_at: float = field(default_factory=time.monotonic)


class AuthStore:
    def __init__(self, path: Path, *, session_seconds: int = 28800) -> None:
        self.path = path
        self.session_seconds = session_seconds
        self._hasher = PasswordHasher()
        self._dummy = self._hasher.hash(secrets.token_urlsafe(32))
        self._sessions: OrderedDict[str, Session] = OrderedDict()
        self._attempts: OrderedDict[str, list[float]] = OrderedDict()
        self._failures: OrderedDict[str, list[float]] = OrderedDict()
        self._lock = threading.Lock()
        self._cache: tuple[tuple[int, int, int], dict[str, User]] | None = None
        self._verifications = threading.BoundedSemaphore(2)

    def _accounts(self) -> dict[str, User]:
        """Parse the user file only when it changes; updates replace it atomically."""
        try:
            info = self.path.stat()
        except FileNotFoundError:
            return {}
        stamp = (info.st_mtime_ns, info.st_ino, info.st_size)
        cached = self._cache
        if cached is not None and cached[0] == stamp:
            return cached[1]
        users = load_accounts(self.path)
        self._cache = (stamp, users)
        return users

    @staticmethod
    def _key(value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()

    def login(self, username: str, password: str, remote: str) -> tuple[str, Session]:
        now = time.monotonic()
        with self._lock:
            attempts = [stamp for stamp in self._attempts.get(remote, []) if now - stamp < 300]
            if len(attempts) >= 5:
                raise LoginThrottled("too many login attempts; try again in five minutes")
            self._attempts[remote] = [*attempts, now]
            self._attempts.move_to_end(remote)
            while len(self._attempts) > 4096:
                self._attempts.popitem(last=False)
            account = username.casefold()
            failures = [stamp for stamp in self._failures.get(account, []) if now - stamp < 900]
            if len(failures) >= 10:
                raise LoginThrottled("too many failed sign-ins for this account; try again later")
        if not self._verifications.acquire(blocking=False):
            raise LoginThrottled("login service is busy; try again shortly")
        try:
            users = self._accounts()
            user = users.get(username)
            encoded = user.password_hash if user else self._dummy
            try:
                valid: bool = self._hasher.verify(encoded, password)
            except VerificationError:
                valid = False
            if not valid or user is None or not user.enabled:
                with self._lock:
                    recent = [s for s in self._failures.get(username.casefold(), [])
                              if time.monotonic() - s < 900]
                    self._failures[username.casefold()] = [*recent, time.monotonic()]
                    while len(self._failures) > 4096:
                        self._failures.popitem(last=False)
                raise AuthenticationError("invalid username or password")
        finally:
            self._verifications.release()
        token = secrets.token_urlsafe(32)
        session = Session(
            username,
            secrets.token_urlsafe(32),
            time.monotonic() + self.session_seconds,
            user.version,
            user.role,
        )
        with self._lock:
            self._attempts.pop(remote, None)
            self._failures.pop(username.casefold(), None)
            self._sessions[self._key(token)] = session
            while len(self._sessions) > 1024:
                self._sessions.popitem(last=False)
        return token, session

    def session(self, token: str) -> Session | None:
        key = self._key(token)
        with self._lock:
            session = self._sessions.get(key)
        if session is None:
            return None
        user = self._accounts().get(session.username)
        if (
            session.expires <= time.monotonic()
            or user is None
            or not user.enabled
            or session.version != user.version
        ):
            self.logout(token)
            return None
        return session

    def logout(self, token: str) -> None:
        with self._lock:
            self._sessions.pop(self._key(token), None)

    def reauthenticate(self, token: str, password: str, remote: str) -> Session:
        current = self.session(token)
        if current is None:
            raise AuthenticationError("session expired")
        temporary, verified = self.login(current.username, password, remote)
        self.logout(temporary)
        refreshed = replace(current, authenticated_at=verified.authenticated_at)
        with self._lock:
            self._sessions[self._key(token)] = refreshed
        return refreshed
