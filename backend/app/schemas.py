"""Request and response shapes for the public API."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator


HOST_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


class BootstrapRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=128)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=32)
    password: str = Field(min_length=1, max_length=128)


class TargetCreateRequest(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    check_type: Literal["tcp"] = "tcp"

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        return " ".join(value.strip().split())

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        host = value.strip().lower().rstrip(".")
        if "://" in host or "/" in host or "@" in host or not HOST_PATTERN.fullmatch(host):
            raise ValueError("Host must be a plain hostname or IP address, without a URL or path.")
        return host


class UserResponse(BaseModel):
    id: int
    username: str


class TargetResponse(BaseModel):
    id: int
    name: str
    host: str
    port: int
    check_type: str
    created_at: datetime
    latest_status: str | None = None
    latest_response_ms: float | None = None
    latest_checked_at: datetime | None = None
    latest_error: str | None = None


class CheckResponse(BaseModel):
    id: int
    target_id: int
    status: str
    response_ms: float | None
    error_message: str | None
    checked_at: datetime


class DashboardResponse(BaseModel):
    targets: list[TargetResponse]
    online_count: int
    offline_count: int
    unknown_count: int
