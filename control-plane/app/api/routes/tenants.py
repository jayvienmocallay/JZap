"""Tenant management endpoints (stubs — Phase 6 implementation)."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query

from app.api.deps import verify_api_key

router = APIRouter(
    prefix="/tenants",
    tags=["Tenants"],
    dependencies=[Depends(verify_api_key)],
)


@router.get("/")
async def list_tenants(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
):
    """List all tenants with pagination.

    TODO (Phase 6): Query tenants from DB, return paginated results.
    """
    return {
        "items": [],
        "page": page,
        "per_page": per_page,
        "total": 0,
    }


@router.post("/", status_code=201)
async def create_tenant():
    """Register a new tenant.

    TODO (Phase 6): Validate TenantCreate schema, generate API key,
    hash and persist, return tenant record with plaintext key (once).
    """
    return {"message": "stub — tenant creation not yet implemented"}


@router.get("/{tenant_id}")
async def get_tenant(tenant_id: UUID):
    """Retrieve a single tenant by ID.

    TODO (Phase 6): Fetch tenant from DB, return 404 if missing.
    """
    return {"message": "stub", "tenant_id": str(tenant_id)}


@router.put("/{tenant_id}")
async def update_tenant(tenant_id: UUID):
    """Update tenant details.

    TODO (Phase 6): Validate TenantUpdate schema, apply changes,
    write audit log entry.
    """
    return {"message": "stub — tenant update not yet implemented", "tenant_id": str(tenant_id)}


@router.delete("/{tenant_id}", status_code=204)
async def delete_tenant(tenant_id: UUID):
    """Delete (disable) a tenant.

    TODO (Phase 6): Soft-delete tenant, revoke API key, cascade
    disable rules, write audit log.
    """
    return None
