"""Pydantic schemas for blocklist management and sync."""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from app.models.blocklist import BlocklistReason


class BlocklistCreate(BaseModel):
    """Payload for adding an IP or CIDR to the blocklist."""

    tenant_id: UUID
    ip_address: str = Field(..., min_length=1, max_length=45)
    cidr_prefix: Optional[int] = Field(default=None, ge=0, le=128)
    reason: BlocklistReason = BlocklistReason.manual
    added_by: str = Field(default="api", min_length=1, max_length=255)
    expires_at: Optional[datetime] = None

    @field_validator("ip_address")
    @classmethod
    def validate_ip_address(cls, value: str) -> str:
        """Accept a plain IP address or a CIDR string."""
        try:
            if "/" in value:
                ipaddress.ip_network(value, strict=False)
            else:
                ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("ip_address must be a valid IP address or CIDR") from exc
        return value


class BlocklistResponse(BaseModel):
    """Blocklist entry returned by the management API."""

    id: int
    tenant_id: UUID
    ip_address: str
    cidr_prefix: Optional[int]
    reason: BlocklistReason
    added_by: str
    expires_at: Optional[datetime]
    created_at: datetime

    model_config = {"from_attributes": True}


class EdgeBlocklistEntry(BaseModel):
    """Blocklist entry shape consumed by Rust sidecar sync."""

    ip: str
    reason: str
    added_at: int
    expires_at: Optional[int] = None


class BlocklistSyncResponse(BaseModel):
    """Versioned full-sync response for edge components."""

    entries: list[EdgeBlocklistEntry]
    version: int
