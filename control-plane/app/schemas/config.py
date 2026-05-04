"""Schemas for runtime data-plane configuration."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class XdpConfigResponse(BaseModel):
    """XDP tunables consumed by the Rust sidecar."""

    pps_limit: Optional[int] = Field(default=10000, ge=1)
    udp_pps_limit: Optional[int] = Field(default=5000, ge=1)
    icmp_pps_limit: Optional[int] = Field(default=100, ge=1)
    syn_pps_limit: Optional[int] = Field(default=1000, ge=1)
    enable_geo_filter: Optional[bool] = False
    amplification_threshold: Optional[int] = Field(default=10, ge=1)
    geo_rules: Optional[list[dict]] = None
