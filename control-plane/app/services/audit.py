"""Small audit-log helper with hash chaining."""

from __future__ import annotations

import hashlib
import json
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog


async def write_audit_log(
    db: AsyncSession,
    *,
    actor: str,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    tenant_id: UUID | None = None,
    before_state: dict[str, Any] | None = None,
    after_state: dict[str, Any] | None = None,
    source_ip: str | None = None,
) -> AuditLog:
    """Append an audit row and chain it to the previous row hash."""
    prev_hash = await _latest_hash(db)
    payload = {
        "tenant_id": str(tenant_id) if tenant_id else None,
        "actor": actor,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "before_state": before_state,
        "after_state": after_state,
        "source_ip": source_ip,
        "prev_hash": prev_hash,
    }
    row_hash = hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()

    entry = AuditLog(
        tenant_id=tenant_id,
        actor=actor,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        before_state=before_state,
        after_state=after_state,
        source_ip=source_ip,
        prev_hash=prev_hash,
        row_hash=row_hash,
    )
    db.add(entry)
    return entry


async def _latest_hash(db: AsyncSession) -> str | None:
    result = await db.execute(
        select(AuditLog.row_hash).order_by(AuditLog.id.desc()).limit(1)
    )
    return result.scalar_one_or_none()
