"""Tenant management endpoints."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, verify_api_key
from app.models.tenant import Tenant
from app.schemas.rule import PaginatedResponse
from app.schemas.tenant import TenantCreate, TenantCreateResponse, TenantResponse, TenantUpdate
from app.services.audit import write_audit_log
from app.services.security import generate_api_key, hash_api_key

router = APIRouter(
    prefix="/tenants",
    tags=["Tenants"],
    dependencies=[Depends(verify_api_key)],
)


@router.get("", response_model=PaginatedResponse[TenantResponse])
async def list_tenants(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """List tenants with pagination."""
    total = await db.scalar(select(func.count()).select_from(Tenant))
    result = await db.execute(
        select(Tenant)
        .order_by(Tenant.created_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
    )
    return {
        "items": result.scalars().all(),
        "page": page,
        "per_page": per_page,
        "total": total or 0,
    }


@router.post("", response_model=TenantCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_tenant(
    payload: TenantCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Register a tenant and return its plaintext API key once."""
    api_key = generate_api_key()
    tenant = Tenant(
        name=payload.name,
        api_key_hash=hash_api_key(api_key),
        upstream_host=payload.upstream_host,
        upstream_port=payload.upstream_port,
        enabled=payload.enabled,
    )
    db.add(tenant)
    try:
        await db.flush()
    except IntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Tenant name already exists",
        ) from exc

    await write_audit_log(
        db,
        actor="api",
        action="create_tenant",
        resource_type="tenant",
        resource_id=str(tenant.id),
        tenant_id=tenant.id,
        after_state=_tenant_state(tenant),
        source_ip=request.client.host if request.client else None,
    )

    return TenantCreateResponse(
        id=tenant.id,
        name=tenant.name,
        upstream_host=tenant.upstream_host,
        upstream_port=tenant.upstream_port,
        enabled=tenant.enabled,
        created_at=tenant.created_at,
        updated_at=tenant.updated_at,
        api_key=api_key,
    )


@router.get("/{tenant_id}", response_model=TenantResponse)
async def get_tenant(
    tenant_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Retrieve a tenant by ID."""
    tenant = await db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
    return tenant


@router.put("/{tenant_id}", response_model=TenantResponse)
async def update_tenant(
    tenant_id: UUID,
    payload: TenantUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Update tenant details."""
    tenant = await db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")

    before = _tenant_state(tenant)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(tenant, field, value)

    try:
        await db.flush()
    except IntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Tenant name already exists",
        ) from exc

    await write_audit_log(
        db,
        actor="api",
        action="update_tenant",
        resource_type="tenant",
        resource_id=str(tenant.id),
        tenant_id=tenant.id,
        before_state=before,
        after_state=_tenant_state(tenant),
        source_ip=request.client.host if request.client else None,
    )
    return tenant


@router.delete("/{tenant_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_tenant(
    tenant_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Disable a tenant without deleting historical data."""
    tenant = await db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")

    before = _tenant_state(tenant)
    tenant.enabled = False
    await write_audit_log(
        db,
        actor="api",
        action="disable_tenant",
        resource_type="tenant",
        resource_id=str(tenant.id),
        tenant_id=tenant.id,
        before_state=before,
        after_state=_tenant_state(tenant),
        source_ip=request.client.host if request.client else None,
    )
    return None


def _tenant_state(tenant: Tenant) -> dict[str, object]:
    return {
        "id": str(tenant.id),
        "name": tenant.name,
        "upstream_host": tenant.upstream_host,
        "upstream_port": tenant.upstream_port,
        "enabled": tenant.enabled,
    }
