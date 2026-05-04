"""Security helpers for API key generation and hashing."""

from __future__ import annotations

import hashlib
import secrets

from app.config import get_settings


def generate_api_key() -> str:
    """Create a tenant API key; returned only once on tenant creation."""
    return f"jzap_{secrets.token_urlsafe(32)}"


def hash_api_key(api_key: str) -> str:
    """Hash an API key with the configured salt for storage."""
    settings = get_settings()
    payload = f"{settings.api_key_salt}:{api_key}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
