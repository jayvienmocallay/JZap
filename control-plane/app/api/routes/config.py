"""Runtime configuration endpoints for data-plane components."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.deps import verify_api_key
from app.schemas.config import XdpConfigResponse

router = APIRouter(
    prefix="/config",
    tags=["Config"],
    dependencies=[Depends(verify_api_key)],
)


@router.get("/xdp", response_model=XdpConfigResponse)
async def get_xdp_config():
    """Return baseline XDP tunables for Rust sidecar sync.

    This is intentionally static for the first deployable control-plane pass.
    Later phases can store these values per tenant or globally in the database.
    """
    return XdpConfigResponse()
