"""Rule management endpoints."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_redis, verify_api_key
from app.models.rule import Rule, RuleType
from app.models.tenant import Tenant
from app.schemas.rule import PaginatedResponse, RuleCreate, RuleResponse, RuleUpdate
from app.services.audit import write_audit_log
from app.services.redis_pubsub import RulePropagator

router = APIRouter(
    prefix="/rules",
    tags=["Rules"],
    dependencies=[Depends(verify_api_key)],
)


@router.get("", response_model=PaginatedResponse[RuleResponse])
async def list_rules(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    tenant_id: UUID | None = None,
    rule_type: RuleType | None = None,
    enabled: bool | None = None,
    db: AsyncSession = Depends(get_db),
):
    """List rules with pagination and basic filters."""
    filters = []
    if tenant_id is not None:
        filters.append(Rule.tenant_id == tenant_id)
    if rule_type is not None:
        filters.append(Rule.rule_type == rule_type)
    if enabled is not None:
        filters.append(Rule.enabled == enabled)

    total_query = select(func.count()).select_from(Rule)
    list_query = select(Rule).order_by(Rule.priority.desc(), Rule.created_at.desc())
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


@router.post("", response_model=RuleResponse, status_code=status.HTTP_201_CREATED)
async def create_rule(
    payload: RuleCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis=Depends(get_redis),
):
    """Create a protection rule."""
    await _ensure_tenant_exists(db, payload.tenant_id)
    rule = Rule(**payload.model_dump())
    db.add(rule)
    await db.flush()

    await RulePropagator(redis).publish_rule_update(str(rule.id), "create")
    await write_audit_log(
        db,
        actor="api",
        action="create_rule",
        resource_type="rule",
        resource_id=str(rule.id),
        tenant_id=rule.tenant_id,
        after_state=_rule_state(rule),
        source_ip=request.client.host if request.client else None,
    )
    return rule


@router.get("/{rule_id}", response_model=RuleResponse)
async def get_rule(rule_id: UUID, db: AsyncSession = Depends(get_db)):
    """Retrieve a rule by ID."""
    rule = await db.get(Rule, rule_id)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return rule


@router.put("/{rule_id}", response_model=RuleResponse)
async def update_rule(
    rule_id: UUID,
    payload: RuleUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis=Depends(get_redis),
):
    """Partially update a protection rule."""
    rule = await db.get(Rule, rule_id)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")

    before = _rule_state(rule)
    updates = payload.model_dump(exclude_unset=True)
    if "tenant_id" in updates:
        await _ensure_tenant_exists(db, updates["tenant_id"])
    for field, value in updates.items():
        setattr(rule, field, value)

    await db.flush()
    await RulePropagator(redis).publish_rule_update(str(rule.id), "update")
    await write_audit_log(
        db,
        actor="api",
        action="update_rule",
        resource_type="rule",
        resource_id=str(rule.id),
        tenant_id=rule.tenant_id,
        before_state=before,
        after_state=_rule_state(rule),
        source_ip=request.client.host if request.client else None,
    )
    return rule


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(
    rule_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis=Depends(get_redis),
):
    """Delete a rule."""
    rule = await db.get(Rule, rule_id)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")

    before = _rule_state(rule)
    tenant_id = rule.tenant_id
    await db.delete(rule)
    await RulePropagator(redis).publish_rule_update(str(rule_id), "delete")
    await write_audit_log(
        db,
        actor="api",
        action="delete_rule",
        resource_type="rule",
        resource_id=str(rule_id),
        tenant_id=tenant_id,
        before_state=before,
        source_ip=request.client.host if request.client else None,
    )
    return None


async def _ensure_tenant_exists(db: AsyncSession, tenant_id: UUID) -> None:
    if await db.get(Tenant, tenant_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")


def _rule_state(rule: Rule) -> dict[str, object]:
    return {
        "id": str(rule.id),
        "tenant_id": str(rule.tenant_id),
        "name": rule.name,
        "description": rule.description,
        "rule_type": rule.rule_type.value,
        "target": rule.target.value,
        "pattern": rule.pattern,
        "action_params": rule.action_params,
        "priority": rule.priority,
        "enabled": rule.enabled,
    }
