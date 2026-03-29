"""Blocklist management endpoints (stubs — Phase 6 implementation)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.api.deps import verify_api_key

router = APIRouter(
    prefix="/blocklist",
    tags=["Blocklist"],
    dependencies=[Depends(verify_api_key)],
)


@router.get("/")
async def list_blocklist(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
):
    """List blocklist entries.

    The agent polls this endpoint to synchronise its local blocklist.

    TODO (Phase 6): Query BlocklistEntry table, support filtering by
    tenant_id, reason, active-only (not expired), pagination.
    """
    return {
        "items": [],
        "page": page,
        "per_page": per_page,
        "total": 0,
    }


@router.post("/", status_code=201)
async def add_to_blocklist():
    """Add an IP (or CIDR) to the blocklist.

    TODO (Phase 6): Validate input, persist BlocklistEntry, publish
    blocklist-update event via Redis pub/sub, write audit log.
    """
    return {"message": "stub — blocklist add not yet implemented"}


@router.delete("/{ip}")
async def remove_from_blocklist(ip: str):
    """Remove an IP from the blocklist.

    TODO (Phase 6): Look up entry by IP, delete or mark expired,
    publish removal event, write audit log.
    """
    return {"message": "stub — blocklist removal not yet implemented", "ip": ip}


@router.post("/sync", status_code=202)
async def force_sync():
    """Force-push the full blocklist to all connected agents.

    TODO (Phase 6): Publish a full-sync event on Redis pub/sub so
    every agent re-fetches the blocklist.
    """
    return {"message": "stub — blocklist sync not yet implemented"}
