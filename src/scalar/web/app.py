"""Authenticated, local-first monitoring API and packaged browser application."""

import hmac
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, SecretStr
from sqlalchemy.exc import SQLAlchemyError
from starlette.middleware.trustedhost import TrustedHostMiddleware

from scalar import __version__
from scalar.administration import ADMIN_ACTIONS, OPERATOR_ACTIONS, READ_ACTIONS, SELF_ACTIONS
from scalar.config import Config
from scalar.control import MAX_REQUEST, ControlClient, ControlError
from scalar.detect.findings import Finding
from scalar.detect.severity import Severity
from scalar.store.database import Database
from scalar.web.auth import AuthenticationError, AuthStore, LoginThrottled, Session, load_users
from scalar.web.data import WebData

COOKIE = "scalar_session"
STATIC = Path(__file__).parent / "static"


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: SecretStr = Field(min_length=1, max_length=256)


class AdminBody(BaseModel):
    action: str = Field(pattern=r"^[a-z][a-z.]{0,63}$")
    parameters: dict[str, Any] = Field(default_factory=dict)


class ReauthenticationBody(BaseModel):
    password: SecretStr = Field(min_length=1, max_length=256)


class AdministrationClient(Protocol):
    async def call(self, actor: str, action: str,
                   parameters: dict[str, Any] | None = None) -> dict[str, Any]: ...


def create_app(cfg: Config, database: Database | None = None, *, demo: bool = False,
               control: AdministrationClient | None = None,
               auth_store: AuthStore | None = None) -> FastAPI:
    if demo and (database is None or database.engine.dialect.name != "sqlite"):
        raise ValueError("demo mode requires an isolated SQLite database")
    store = database or Database(cfg.database_url)
    data = WebData(cfg, store, preview=demo)
    auth = auth_store or AuthStore(
        cfg.paths.state_dir / "web-users.json", session_seconds=cfg.web.session_hours * 3600
    )
    administration = control or ControlClient(cfg.paths.control_socket)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        yield
        if database is None:
            store.close()

    app = FastAPI(
        title="SCALAR", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan
    )

    def refresh_config(candidate: Config) -> bool:
        nonlocal cfg, data
        if (candidate.web != cfg.web or candidate.paths != cfg.paths
                or candidate.database_url != cfg.database_url):
            return False
        cfg = candidate
        data = WebData(candidate, store, preview=demo)
        return True

    app.state.refresh_config = refresh_config
    hosts = list(cfg.web.allowed_hosts)
    if cfg.web.public_url:
        hosts.append(urlsplit(cfg.web.public_url).hostname or "localhost")
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts, www_redirect=False)

    @app.middleware("http")
    async def boundary(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if cfg.web.require_https and cfg.web.public_url and request.url.scheme != "https":
            return RedirectResponse(
                cfg.web.public_url.rstrip("/") + request.url.path, status_code=307
            )
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            length = request.headers.get("content-length", "")
            limit = MAX_REQUEST if request.url.path == "/api/admin/action" else 8192
            if not length.isdecimal() or int(length) > limit:
                return JSONResponse(
                    {"detail": "Request body is missing or too large"}, status_code=413
                )
            expected = cfg.web.public_url or str(request.base_url).rstrip("/")
            origin = request.headers.get("origin")
            if origin and origin.rstrip("/") != expected.rstrip("/"):
                return JSONResponse({"detail": "Origin not permitted"}, status_code=403)
        response = await call_next(request)
        response.headers.update(
            {
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "X-Frame-Options": "DENY",
                "Content-Security-Policy": (
                    "default-src 'self'; script-src 'self'; style-src 'self'; "
                    "font-src 'self'; img-src 'self' data:; connect-src 'self'; "
                    "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
                ),
            }
        )
        if cfg.web.require_https:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    def session(request: Request) -> Session:
        if demo:
            return Session("Preview", "preview", float("inf"), "preview")
        try:
            current = auth.session(request.cookies.get(COOKIE, ""))
        except (OSError, ValueError):
            raise HTTPException(503, "Web authentication is unavailable") from None
        if current is None:
            raise HTTPException(401, "Sign in required")
        return current

    def mutation(request: Request, current: Annotated[Session, Depends(session)]) -> Session:
        if demo:
            raise HTTPException(409, "Actions are disabled in the preview")
        if not hmac.compare_digest(request.headers.get("x-csrf-token", ""), current.csrf):
            raise HTTPException(403, "Session verification failed")
        return current

    @app.exception_handler(SQLAlchemyError)
    async def database_error(_request: Request, _error: SQLAlchemyError) -> JSONResponse:
        return JSONResponse(
            {"detail": "PostgreSQL is unavailable or uninitialized"}, status_code=503
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, _error: RequestValidationError) -> JSONResponse:
        return JSONResponse({"detail": "Invalid request parameters"}, status_code=422)

    @app.exception_handler(ControlError)
    async def administration_error(_request: Request, error: ControlError) -> JSONResponse:
        return JSONResponse({"detail": str(error)}, status_code=error.status)

    @app.get("/api/auth")
    def auth_status() -> dict[str, Any]:
        try:
            configured = bool(load_users(auth.path))
        except (OSError, ValueError):
            configured = False
        return {"configured": configured or demo, "demo": demo}

    @app.post("/api/login")
    def login(body: LoginBody, request: Request, response: Response) -> dict[str, str]:
        remote = request.client.host if request.client else "local"
        try:
            token, current = auth.login(body.username, body.password.get_secret_value(), remote)
        except LoginThrottled as exc:
            raise HTTPException(429, str(exc), headers={"Retry-After": "300"}) from None
        except AuthenticationError:
            raise HTTPException(401, "Invalid username or password") from None
        except (OSError, ValueError):
            raise HTTPException(503, "Web authentication is unavailable") from None
        response.set_cookie(
            COOKIE,
            token,
            httponly=True,
            secure=cfg.web.require_https or request.url.scheme == "https",
            samesite="strict",
            max_age=cfg.web.session_hours * 3600,
            path="/",
        )
        return {"username": current.username, "csrf": current.csrf}

    @app.get("/api/session")
    def whoami(current: Annotated[Session, Depends(session)]) -> dict[str, Any]:
        return {
            "username": current.username,
            "csrf": current.csrf,
            "demo": demo,
            "version": __version__,
            "role": current.role,
        }

    @app.post("/api/reauth")
    def reauthenticate(body: ReauthenticationBody, request: Request,
                       _current: Annotated[Session, Depends(mutation)]) -> dict[str, bool]:
        try:
            auth.reauthenticate(request.cookies.get(COOKIE, ""), body.password.get_secret_value(),
                                request.client.host if request.client else "local")
        except LoginThrottled as exc:
            raise HTTPException(429, str(exc)) from None
        except AuthenticationError:
            raise HTTPException(403, "Password verification failed") from None
        return {"verified": True}

    @app.post("/api/admin/action")
    async def admin_action(body: AdminBody, request: Request,
                           current: Annotated[Session, Depends(session)]) -> dict[str, Any]:
        if demo:
            if body.action not in {"settings.get", "users.list", "credentials.list", "vault.status",
                                   "platform.status", "rules.list", "audit.list"}:
                raise HTTPException(409, "Actions are disabled in the preview")
        else:
            mutation(request, current)
        allowed = (body.action in SELF_ACTIONS or
                   (body.action in OPERATOR_ACTIONS and current.role in ("operator", "admin")) or
                   (body.action in ADMIN_ACTIONS and current.role == "admin"))
        if not allowed:
            raise HTTPException(403, "This operation is not permitted for your role")
        if (body.action not in READ_ACTIONS and body.action not in SELF_ACTIONS
                and time.monotonic() - current.authenticated_at > 600):
            raise HTTPException(428, "Reauthentication required")
        result = await administration.call(current.username, body.action, body.parameters)
        if body.action == "settings.save" and result.get("applied"):
            refresh_config(Config.model_validate(body.parameters["document"]))
        return result

    @app.post("/api/logout")
    def logout(
        request: Request, response: Response, _current: Annotated[Session, Depends(mutation)]
    ) -> dict[str, bool]:
        auth.logout(request.cookies.get(COOKIE, ""))
        response.delete_cookie(COOKIE, path="/")
        return {"ok": True}

    protected = [Depends(session)]

    @app.get("/api/overview", dependencies=protected)
    def overview() -> dict[str, Any]:
        return data.overview()

    @app.get("/api/devices", dependencies=protected)
    def devices() -> dict[str, Any]:
        return {"items": data.devices()}

    @app.get("/api/health")
    def health(current: Annotated[Session, Depends(session)]) -> dict[str, Any]:
        access: Literal["admin", "operator", "none"] = (
            "admin" if current.role == "admin" else "operator" if current.role == "operator"
            else "none"
        )
        return data.health(action_access=access)

    @app.get("/api/records/{kind}", dependencies=protected)
    def records(
        kind: Literal["findings", "events"],
        days: Annotated[int, Query(ge=1, le=400)] = 7,
        minimum: Literal["info", "low", "medium", "high", "critical"] = "info",
        device: str = "",
        category: str = "",
        query: Annotated[str, Query(max_length=200)] = "",
        offset: Annotated[int, Query(ge=0, le=100000)] = 0,
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
    ) -> dict[str, Any]:
        try:
            return data.search(
                kind,
                days=days,
                minimum=minimum,
                device=device,
                category=category,
                query=query,
                offset=offset,
                limit=limit,
            )
        except KeyError:
            raise HTTPException(404, "Device not found") from None

    @app.get("/api/configurations/{device}", dependencies=protected)
    def configurations(
        device: str,
        kind: Literal["running", "saved"] = "running",
        index: Annotated[int | None, Query(ge=0)] = None,
        compare_index: Annotated[int | None, Query(ge=0)] = None,
    ) -> dict[str, Any]:
        if compare_index is not None and index is None:
            raise HTTPException(422, "Select a snapshot to compare")
        try:
            return data.configurations(device, kind, index, compare_index)
        except KeyError:
            raise HTTPException(404, "Device or snapshot not found") from None
        except (OSError, ValueError):
            raise HTTPException(503, "Configuration history is unavailable") from None

    @app.get("/api/delivery", dependencies=protected)
    def delivery() -> dict[str, Any]:
        return data.delivery()

    @app.post("/api/delivery/test")
    def test_delivery(current: Annotated[Session, Depends(mutation)]) -> dict[str, Any]:
        if current.role == "viewer":
            raise HTTPException(403, "Viewer accounts cannot send notifications")
        targets = [name for name in ("smtp", "siem", "webhook") if getattr(cfg.notify, name)]
        if not targets:
            raise HTTPException(409, "No notification channels are configured")
        store.save_finding(
            Finding(
                f"web-notification-test|{uuid.uuid4()}",
                "notification-test",
                "SCALAR delivery test",
                Severity.CRITICAL,
                "health",
                None,
                f"Delivery test requested by web user {current.username}",
            ),
            targets,
        )
        return {"queued": targets}

    @app.get("/api/settings", dependencies=protected)
    def settings() -> dict[str, Any]:
        return {
            "retention": cfg.retention.model_dump(),
            "syslog": cfg.syslog.model_dump(),
            "intervals": cfg.defaults.intervals.model_dump(),
            "ha_pairs": [pair.model_dump() for pair in cfg.ha_pairs],
            "version": __version__,
        }

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC / "index.html", media_type="text/html")

    app.mount("/static", StaticFiles(directory=STATIC, check_dir=False), name="static")
    return app
