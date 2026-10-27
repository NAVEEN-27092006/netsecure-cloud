"""NetSecure Cloud HTTP application."""

from __future__ import annotations

import secrets
import sqlite3
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .auth import hash_password, verify_password
from .config import Settings
from .database import Database
from .monitor import _resolve_public_addresses, probe_tcp
from .rate_limit import RateLimiter
from .schemas import (
    BootstrapRequest,
    CheckResponse,
    DashboardResponse,
    LoginRequest,
    TargetCreateRequest,
    TargetResponse,
    UserResponse,
)

COOKIE_NAME = "netsecure_session"


def _client_ip(request: Request) -> str:
    # Deliberately do not trust X-Forwarded-For unless a reverse proxy is configured to sanitize it.
    return request.client.host if request.client else "unknown"


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    database = Database(settings.database_path)
    limiter = RateLimiter()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        database.initialize()
        yield

    app = FastAPI(
        title="NetSecure Cloud",
        version="0.1.0",
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.database = database

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store" if request.url.path.startswith("/api/") else "public, max-age=300"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; script-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; base-uri 'self'; frame-ancestors 'none'"
        )
        return response

    def current_user(request: Request) -> dict:
        user = database.find_session_user(request.cookies.get(COOKIE_NAME))
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sign in is required.")
        return user

    def limit_or_reject(key: str, *, limit: int, window_seconds: int) -> None:
        if not limiter.allow(key, limit=limit, window_seconds=window_seconds):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please wait and try again.",
            )

    def issue_session(response: Response, user_id: int) -> None:
        token = secrets.token_urlsafe(48)
        database.create_session(user_id, token, settings.session_hours)
        response.set_cookie(
            key=COOKIE_NAME,
            value=token,
            max_age=settings.session_hours * 60 * 60,
            httponly=True,
            secure=settings.cookie_secure,
            samesite="lax",
            path="/",
        )

    @app.exception_handler(sqlite3.IntegrityError)
    async def integrity_error_handler(_: Request, __: sqlite3.IntegrityError):
        return JSONResponse(status_code=409, content={"detail": "That record already exists."})

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "service": "netsecure-cloud", "environment": settings.environment}

    @app.get("/api/setup-status")
    def setup_status() -> dict:
        return {"needs_bootstrap": not database.has_users()}

    @app.post("/api/auth/bootstrap", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
    def bootstrap(payload: BootstrapRequest, request: Request, response: Response) -> dict:
        limit_or_reject(f"bootstrap:{_client_ip(request)}", limit=5, window_seconds=900)
        if database.has_users():
            raise HTTPException(status_code=403, detail="An administrator has already been created.")
        user = database.create_user(payload.username, hash_password(payload.password))
        issue_session(response, user["id"])
        database.audit(
            action="bootstrap_admin",
            detail=f"Created initial administrator {user['username']}",
            user_id=user["id"],
            ip_address=_client_ip(request),
        )
        return user

    @app.post("/api/auth/login", response_model=UserResponse)
    def login(payload: LoginRequest, request: Request, response: Response) -> dict:
        limit_or_reject(f"login:{_client_ip(request)}", limit=5, window_seconds=900)
        user = database.find_user_by_username(payload.username)
        if not user or not verify_password(payload.password, user["password_hash"]):
            database.audit(
                action="login_failed",
                detail=f"Failed login attempt for {payload.username[:32]}",
                user_id=None,
                ip_address=_client_ip(request),
            )
            raise HTTPException(status_code=401, detail="Invalid username or password.")
        issue_session(response, user["id"])
        database.audit(
            action="login_success",
            detail=f"Signed in as {user['username']}",
            user_id=user["id"],
            ip_address=_client_ip(request),
        )
        return {"id": user["id"], "username": user["username"]}

    @app.post("/api/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
    def logout(request: Request, response: Response, user: dict = Depends(current_user)) -> Response:
        database.delete_session(request.cookies.get(COOKIE_NAME))
        database.audit(
            action="logout",
            detail=f"Signed out {user['username']}",
            user_id=user["id"],
            ip_address=_client_ip(request),
        )
        response.delete_cookie(COOKIE_NAME, path="/")
        return response

    @app.get("/api/auth/me", response_model=UserResponse)
    def me(user: dict = Depends(current_user)) -> dict:
        return user

    @app.get("/api/dashboard", response_model=DashboardResponse)
    def dashboard(_: dict = Depends(current_user)) -> dict:
        targets = database.list_targets_with_latest_result()
        return {
            "targets": targets,
            "online_count": sum(target["latest_status"] == "online" for target in targets),
            "offline_count": sum(target["latest_status"] == "offline" for target in targets),
            "unknown_count": sum(target["latest_status"] is None for target in targets),
        }

    @app.post("/api/targets", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
    def add_target(
        payload: TargetCreateRequest, request: Request, user: dict = Depends(current_user)
    ) -> dict:
        try:
            _resolve_public_addresses(payload.host, payload.port, settings.allow_private_targets)
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        target = database.add_target(
            name=payload.name,
            host=payload.host,
            port=payload.port,
            check_type=payload.check_type,
            user_id=user["id"],
        )
        database.audit(
            action="target_created",
            detail=f"Added target {target['host']}:{target['port']}",
            user_id=user["id"],
            ip_address=_client_ip(request),
        )
        return target

    @app.delete("/api/targets/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
    def delete_target(
        target_id: int, request: Request, user: dict = Depends(current_user)
    ) -> Response:
        target = database.get_target(target_id)
        if not target:
            raise HTTPException(status_code=404, detail="Target was not found.")
        database.delete_target(target_id)
        database.audit(
            action="target_deleted",
            detail=f"Deleted target {target['host']}:{target['port']}",
            user_id=user["id"],
            ip_address=_client_ip(request),
        )
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.post("/api/targets/{target_id}/check", response_model=CheckResponse)
    def check_target(
        target_id: int, request: Request, user: dict = Depends(current_user)
    ) -> dict:
        limit_or_reject(f"check:{user['id']}", limit=30, window_seconds=60)
        target = database.get_target(target_id)
        if not target:
            raise HTTPException(status_code=404, detail="Target was not found.")
        result = probe_tcp(
            target["host"],
            target["port"],
            allow_private_targets=settings.allow_private_targets,
        )
        saved_result = database.add_check_result(
            target_id=target_id,
            status=result.status,
            response_ms=result.response_ms,
            error_message=result.error_message,
        )
        database.audit(
            action="target_checked",
            detail=f"Checked {target['host']}:{target['port']} -> {result.status}",
            user_id=user["id"],
            ip_address=_client_ip(request),
        )
        return saved_result

    @app.get("/api/targets/{target_id}/history", response_model=list[CheckResponse])
    def target_history(
        target_id: int, limit: int = 20, _: dict = Depends(current_user)
    ) -> list[dict]:
        if not 1 <= limit <= 100:
            raise HTTPException(status_code=422, detail="History limit must be between 1 and 100.")
        if not database.get_target(target_id):
            raise HTTPException(status_code=404, detail="Target was not found.")
        return database.list_history(target_id, limit)

    app.mount("/", StaticFiles(directory=settings.frontend_path, html=True), name="frontend")
    return app


app = create_app()
