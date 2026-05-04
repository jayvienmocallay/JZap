"""Blocklist management endpoints."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_redis, verify_api_key
from app.models.blocklist import BlocklistEntry, BlocklistReason
from app.models.tenant import Tenant
from app.schemas.blocklist import (
    BlocklistCreate,
    BlocklistResponse,
    BlocklistSyncResponse,
    EdgeBlocklistEntry,
)
from app.schemas.rule import PaginatedResponse
from app.services.audit import write_audit_log
from app.services.redis_pubsub import RulePropagator

router = APIRouter(
    prefix="/blocklist",
    tags=["Blocklist"],
    dependencies=[Depends(verify_api_key)],
)


@router.get("")
async def sync_blocklist(
    request: Request,
    tenant_id: UUID | None = None,
    db: AsyncSession = Depends(get_db),
):
    """Return the full active blocklist for edge sync.

    This shape is consumed by the Rust sidecar: `{ entries, version }`.
    Management pagination lives at `/api/v1/blocklist/manage`.
    """
    rows = await _active_entries(db, tenant_id=tenant_id, include_allowlist=False)
    version = _blocklist_version(rows)

    # The current Go agent expects {"entries": ["1.2.3.4"]}. The Rust sidecar
    # expects {"entries": [{...}], "version": N}. Keep both deployable while
    # the edge clients converge on one contract.
    user_agent = request.headers.get("user-agent", "")
    if user_agent.startswith("jzap-agent/"):
        return {"entries": [row.ip_address for row in rows], "version": version}

    return BlocklistSyncResponse(
        entries=[_to_edge_entry(row) for row in rows],
        version=version,
    )


@router.get("/manage", response_model=PaginatedResponse[BlocklistResponse])
async def list_blocklist(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    tenant_id: UUID | None = None,
    reason: BlocklistReason | None = None,
    active_only: bool = True,
    db: AsyncSession = Depends(get_db),
):
    """List blocklist entries for management views."""
    filters = []
    if tenant_id is not None:
        filters.append(BlocklistEntry.tenant_id == tenant_id)
    if reason is not None:
        filters.append(BlocklistEntry.reason == reason)
    if active_only:
        now = datetime.now(timezone.utc)
        filters.append(
            (BlocklistEntry.expires_at.is_(None)) | (BlocklistEntry.expires_at > now)
        )

    total_query = select(func.count()).select_from(BlocklistEntry)
    list_query = select(BlocklistEntry).order_by(BlocklistEntry.created_at.desc())
    if filters:
        total_query = total_query.where(*filters)
        list_query = list_query.where(*filters)

    total = await db.scalar(total_query)
    result = await db.execute(
        list_query.offset((page - 1) * per_page).limit(per_page)
    )
    return {
        "items": result.scalars().all(),
        "page": page,
        "per_page": per_page,
        "total": total or 0,
    }


@router.post("", response_model=BlocklistResponse, status_code=status.HTTP_201_CREATED)
async def add_to_blocklist(
    payload: BlocklistCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis=Depends(get_redis),
):
    """Add an IP or CIDR to the blocklist."""
    if await db.get(Tenant, payload.tenant_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")

    entry = BlocklistEntry(**payload.model_dump())
    db.add(entry)
    await db.flush()

    await RulePropagator(redis).publish_blocklist_update(entry.ip_address, "add")
    await write_audit_log(
        db,
        actor=payload.added_by,
        action="add_blocklist_entry",
        resource_type="blocklist",
        resource_id=str(entry.id),
        tenant_id=entry.tenant_id,
        after_state=_blocklist_state(entry),
        source_ip=request.client.host if request.client else None,
    )
    return entry


@router.delete("/{ip}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_from_blocklist(
    ip: str,
    request: Request,
    tenant_id: UUID | None = None,
    db: AsyncSession = Depends(get_db),
    redis=Depends(get_redis),
):
    """Remove active blocklist entries by IP/CIDR string."""
    filters = [BlocklistEntry.ip_address == ip]
    if tenant_id is not None:
        filters.append(BlocklistEntry.tenant_id == tenant_id)

    result = await db.execute(select(BlocklistEntry).where(*filters))
    rows = result.scalars().all()
    if not rows:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Blocklist entry not found")

    for row in rows:
        await write_audit_log(
            db,
            actor="api",
            action="remove_blocklist_entry",
            resource_type="blocklist",
            resource_id=str(row.id),
            tenant_id=row.tenant_id,
            before_state=_blocklist_state(row),
            source_ip=request.client.host if request.client else None,
        )

    await db.execute(delete(BlocklistEntry).where(*filters))
    await RulePropagator(redis).publish_blocklist_update(ip, "remove")
    return None


@router.post("/sync", status_code=status.HTTP_202_ACCEPTED)
async def force_sync(redis=Depends(get_redis)):
    """Publish a full-sync signal so edge components can re-fetch."""
    await RulePropagator(redis).publish_blocklist_update("*", "full_sync")
    return {"message": "blocklist full-sync event published"}


async def _active_entries(
    db: AsyncSession,
    *,
    tenant_id: UUID | None,
    include_allowlist: bool,
) -> list[BlocklistEntry]:
    now = datetime.now(timezone.utc)
    query = select(BlocklistEntry).where(
        (BlocklistEntry.expires_at.is_(None)) | (BlocklistEntry.expires_at > now)
    )
    if tenant_id is not None:
        query = query.where(BlocklistEntry.tenant_id == tenant_id)
    if not include_allowlist:
        query = query.where(BlocklistEntry.reason != BlocklistReason.allowlist)

    result = await db.execute(query.order_by(BlocklistEntry.id.asc()))
    return list(result.scalars().all())


def _to_edge_entry(row: BlocklistEntry) -> EdgeBlocklistEntry:
    return EdgeBlocklistEntry(
        ip=row.ip_address,
        reason=_rust_block_reason(row.reason),
        added_at=int(row.created_at.timestamp()),
        expires_at=int(row.expires_at.timestamp()) if row.expires_at else None,
    )


def _blocklist_version(rows: list[BlocklistEntry]) -> int:
    if not rows:
        return 0
    return max(row.id for row in rows)


def _rust_block_reason(reason: BlocklistReason) -> str:
    return {
        BlocklistReason.manual: "Manual",
        BlocklistReason.auto_ratelimit: "AutoRateLimit",
        BlocklistReason.threat_intel: "ThreatIntel",
        BlocklistReason.geo_block: "GeoBlock",
    }.get(reason, "Manual")


def _blocklist_state(entry: BlocklistEntry) -> dict[str, object]:
    return {
        "id": entry.id,
        "tenant_id": str(entry.tenant_id),
        "ip_address": entry.ip_address,
        "cidr_prefix": entry.cidr_prefix,
        "reason": entry.reason.value,
        "added_by": entry.added_by,
        "expires_at": entry.expires_at.isoformat() if entry.expires_at else None,
    }
