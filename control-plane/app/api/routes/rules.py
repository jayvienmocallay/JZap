"""Rule management endpoints (stubs — Phase 6 implementation)."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query

from app.api.deps import verify_api_key

router = APIRouter(
    prefix="/rules",
    tags=["Rules"],
    dependencies=[Depends(verify_api_key)],
)


@router.get("/")
async def list_rules(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
):
    """List all rules with pagination.

    TODO (Phase 6): Query rules from DB with pagination, filtering by
    tenant_id, rule_type, enabled status, etc.
    """
    return {
        "items": [],
        "page": page,
        "per_page": per_page,
        "total": 0,
    }


@router.post("/", status_code=201)
async def create_rule():
    """Create a new protection rule.

    TODO (Phase 6): Validate RuleCreate schema, persist to DB, publish
    rule-update event via Redis pub/sub, write audit log entry.
    """
    return {"message": "stub — rule creation not yet implemented"}


@router.get("/{rule_id}")
async def get_rule(rule_id: UUID):
    """Retrieve a single rule by ID.

    TODO (Phase 6): Fetch rule from DB, return 404 if missing.
    """
    return {"message": "stub", "rule_id": str(rule_id)}


@router.put("/{rule_id}")
async def update_rule(rule_id: UUID):
    """Update an existing rule.

    TODO (Phase 6): Validate RuleUpdate schema, apply partial update,
    publish change event, write audit log with before/after state.
    """
    return {"message": "stub — rule update not yet implemented", "rule_id": str(rule_id)}


@router.delete("/{rule_id}", status_code=204)
async def delete_rule(rule_id: UUID):
    """Delete a rule.

    TODO (Phase 6): Soft-delete or hard-delete rule, publish removal
    event, write audit log entry.
    """
    return None
