"""Pydantic schemas for tenant management."""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field


class TenantCreate(BaseModel):
    """Payload for creating a tenant."""

    name: str = Field(..., min_length=1, max_length=255)
    upstream_host: str = Field(..., min_length=1, max_length=255)
    upstream_port: int = Field(default=443, ge=1, le=65535)
    enabled: bool = True


class TenantUpdate(BaseModel):
    """Payload for partially updating a tenant."""

    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    upstream_host: Optional[str] = Field(default=None, min_length=1, max_length=255)
    upstream_port: Optional[int] = Field(default=None, ge=1, le=65535)
    enabled: Optional[bool] = None


class TenantResponse(BaseModel):
    """Tenant representation returned by the API."""

    id: UUID
    name: str
    upstream_host: str
    upstream_port: int
    enabled: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class TenantCreateResponse(TenantResponse):
    """Tenant creation response with one-time plaintext API key."""

    api_key: str
