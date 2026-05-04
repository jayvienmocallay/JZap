"""SQLAlchemy model for protection rules."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class RuleType(str, enum.Enum):
    """Allowed rule types."""

    rate_limit = "rate_limit"
    threshold = "threshold"
    block = "block"
    challenge = "challenge"
    allow = "allow"


class TargetType(str, enum.Enum):
    """What the rule matches against."""

    ip = "ip"
    cidr = "cidr"
    asn = "asn"
    country = "country"
    path = "path"
    header = "header"
    user_agent = "user_agent"


class Rule(Base):
    __tablename__ = "rules"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    rule_type: Mapped[RuleType] = mapped_column(
        Enum(RuleType, name="rule_type_enum"), nullable=False
    )
    target: Mapped[TargetType] = mapped_column(
        Enum(TargetType, name="target_type_enum"), nullable=False
    )
    pattern: Mapped[str] = mapped_column(String(1024), nullable=False)
    action_params: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    priority: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<Rule id={self.id} name={self.name!r} type={self.rule_type}>"
