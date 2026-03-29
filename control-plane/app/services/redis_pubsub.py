"""Redis pub/sub service for propagating rule & blocklist changes to agents.

Stub implementation — full logic will be added in Phase 6.
"""

from __future__ import annotations

import json
from typing import Any, AsyncGenerator

import redis.asyncio as aioredis


CHANNEL_RULES = "jzap:rules"
CHANNEL_BLOCKLIST = "jzap:blocklist"


class RulePropagator:
    """Publishes rule / blocklist mutations over Redis pub/sub."""

    def __init__(self, redis_client: aioredis.Redis) -> None:
        self._redis = redis_client

    async def publish_rule_update(self, rule_id: str, action: str) -> None:
        """Publish a rule change event.

        Args:
            rule_id: UUID of the affected rule.
            action: One of "create", "update", "delete".

        TODO (Phase 6): Serialise the full rule payload so agents can
        apply the change without an extra API round-trip.
        """
        message = json.dumps({"rule_id": rule_id, "action": action})
        await self._redis.publish(CHANNEL_RULES, message)

    async def publish_blocklist_update(self, ip: str, action: str) -> None:
        """Publish a blocklist change event.

        Args:
            ip: The IP address (or CIDR) that was added/removed.
            action: One of "add", "remove", "full_sync".

        TODO (Phase 6): Include tenant_id and expiry metadata.
        """
        message = json.dumps({"ip": ip, "action": action})
        await self._redis.publish(CHANNEL_BLOCKLIST, message)

    async def subscribe_rule_updates(self) -> AsyncGenerator[dict[str, Any], None]:
        """Yield rule-update events as they arrive.

        TODO (Phase 6): Implement proper reconnection logic and
        back-pressure handling.
        """
        pubsub = self._redis.pubsub()
        await pubsub.subscribe(CHANNEL_RULES)
        try:
            async for message in pubsub.listen():
                if message["type"] == "message":
                    yield json.loads(message["data"])
        finally:
            await pubsub.unsubscribe(CHANNEL_RULES)
            await pubsub.aclose()
