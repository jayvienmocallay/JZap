"""SQLAlchemy model for the IP blocklist."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, Enum, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class BlocklistReason(str, enum.Enum):
    """Why an IP was added to the blocklist."""

    manual = "manual"
    auto_ratelimit = "auto_ratelimit"
    threat_intel = "threat_intel"
    geo_block = "geo_block"


class BlocklistEntry(Base):
    __tablename__ = "blocklist"

    id: Mapped[int] = mapped_column(
        BigInteger, primary_key=True, autoincrement=True
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, index=True
    )
    ip_address: Mapped[str] = mapped_column(
        String(45), nullable=False, index=True
    )
    cidr_prefix: Mapped[int | None] = mapped_column(
        Integer, nullable=True, doc="CIDR prefix length, e.g. 24 for /24"
    )
    reason: Mapped[BlocklistReason] = mapped_column(
        Enum(BlocklistReason, name="blocklist_reason_enum"), nullable=False
    )
    added_by: Mapped[str] = mapped_column(String(255), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<BlocklistEntry id={self.id} ip={self.ip_address}>"
