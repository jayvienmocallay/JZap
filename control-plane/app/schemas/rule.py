"""Pydantic schemas for protection rules."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Generic, Optional, TypeVar
from uuid import UUID

from pydantic import BaseModel, Field

from app.models.rule import RuleType, TargetType

T = TypeVar("T")


# ── Request schemas ─────────────────────────────────────────────────────


class RuleCreate(BaseModel):
    """Payload for creating a new rule."""

    tenant_id: UUID
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    rule_type: RuleType
    target: TargetType
    pattern: str = Field(..., min_length=1, max_length=1024)
    action_params: Optional[dict[str, Any]] = None
    priority: int = Field(default=0, ge=0)
    enabled: bool = True


class RuleUpdate(BaseModel):
    """Payload for partially updating a rule.

    All fields are optional so callers can send only the fields they want
    to change.
    """

    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    description: Optional[str] = None
    rule_type: Optional[RuleType] = None
    target: Optional[TargetType] = None
    pattern: Optional[str] = Field(default=None, min_length=1, max_length=1024)
    action_params: Optional[dict[str, Any]] = None
    priority: Optional[int] = Field(default=None, ge=0)
    enabled: Optional[bool] = None


# ── Response schemas ────────────────────────────────────────────────────


class RuleResponse(BaseModel):
    """Serialised representation of a Rule returned to callers."""

    id: UUID
    tenant_id: UUID
    name: str
    description: Optional[str]
    rule_type: RuleType
    target: TargetType
    pattern: str
    action_params: Optional[dict[str, Any]]
    priority: int
    enabled: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ── Generic paginated response ──────────────────────────────────────────


class PaginatedResponse(BaseModel, Generic[T]):
    """Generic wrapper for paginated list endpoints."""

    items: list[T]
    page: int
    per_page: int
    total: int
