"""Password reset token lifecycle helpers."""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.events import get_redis
from app.models.system_settings import SystemSetting

# Key prefixes for Redis
TOKEN_PREFIX = "pwd_reset:token:"
USER_PREFIX = "pwd_reset:user:"
DB_FALLBACK_KEY = "password_reset_tokens"


def _hash_token(token: str) -> str:
    """Hash a raw reset token before persistence or lookup."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


async def create_password_reset_token(identity_id: uuid.UUID, db: AsyncSession | None = None) -> tuple[str, datetime]:
    """Create a new single-use token and invalidate older unused tokens in Redis."""
    raw_token = secrets.token_urlsafe(32)
    token_hash = _hash_token(raw_token)

    now = datetime.now(timezone.utc)
    expiry_minutes = get_settings().PASSWORD_RESET_TOKEN_EXPIRE_MINUTES
    expires_at = now + timedelta(minutes=expiry_minutes)

    try:
        redis = await get_redis()
        user_key = f"{USER_PREFIX}{identity_id}"

        # Invalidate previous token for this user if exists
        old_token_hash = await redis.get(user_key)
        if old_token_hash:
            await redis.delete(f"{TOKEN_PREFIX}{old_token_hash}")

        # Store the new token (bi-directional mapping for easy invalidation)
        token_key = f"{TOKEN_PREFIX}{token_hash}"
        ttl_seconds = int(expiry_minutes * 60)

        async with redis.pipeline(transaction=True) as pipe:
            pipe.setex(token_key, ttl_seconds, str(identity_id))
            pipe.setex(user_key, ttl_seconds, token_hash)
            await pipe.execute()
    except Exception as exc:
        if db is None:
            raise
        logger.warning(f"Redis unavailable for password reset token storage; using DB fallback: {exc}")
        await _store_password_reset_token_in_db(db, identity_id, token_hash, expires_at)

    return raw_token, expires_at


async def get_public_base_url(db: AsyncSession) -> str:
    """Resolve the public base URL used for user-facing links."""
    configured_url = (get_settings().PUBLIC_BASE_URL or "").strip()
    if configured_url:
        return configured_url.rstrip("/")

    from app.services.platform_service import platform_service

    return await platform_service.get_public_base_url(db)


async def build_password_reset_url(db: AsyncSession, raw_token: str, base_url: str | None = None) -> str:
    """Build the user-facing reset URL."""
    resolved_base_url = base_url or await get_public_base_url(db)
    return f"{resolved_base_url.rstrip('/')}/reset-password?token={raw_token}"


async def consume_password_reset_token(raw_token: str, db: AsyncSession | None = None) -> dict | None:
    """Load a valid reset token from Redis and mark it used (by deleting)."""
    token_hash = _hash_token(raw_token)
    try:
        redis = await get_redis()
        token_key = f"{TOKEN_PREFIX}{token_hash}"

        identity_id_str = await redis.get(token_key)
        if not identity_id_str:
            if db is not None:
                return await _consume_password_reset_token_from_db(db, token_hash)
            return None

        identity_id = uuid.UUID(identity_id_str)
        user_key = f"{USER_PREFIX}{identity_id}"

        # Atomic delete to ensure single-use
        async with redis.pipeline(transaction=True) as pipe:
            pipe.delete(token_key)
            pipe.delete(user_key)
            await pipe.execute()

        return {"identity_id": identity_id}
    except Exception as exc:
        if db is None:
            raise
        logger.warning(f"Redis unavailable for password reset token lookup; using DB fallback: {exc}")
        return await _consume_password_reset_token_from_db(db, token_hash)


async def _load_password_reset_store(db: AsyncSession) -> tuple[SystemSetting | None, dict]:
    result = await db.execute(select(SystemSetting).where(SystemSetting.key == DB_FALLBACK_KEY))
    setting = result.scalar_one_or_none()
    value = dict(setting.value or {}) if setting and setting.value else {}
    return setting, value


async def _store_password_reset_token_in_db(
    db: AsyncSession,
    identity_id: uuid.UUID,
    token_hash: str,
    expires_at: datetime,
) -> None:
    setting, value = await _load_password_reset_store(db)
    tokens = dict(value.get("tokens") or {})
    users = dict(value.get("users") or {})
    identity_key = str(identity_id)

    old_token_hash = users.get(identity_key)
    if old_token_hash:
        tokens.pop(old_token_hash, None)

    tokens[token_hash] = {
        "identity_id": identity_key,
        "expires_at": expires_at.isoformat(),
    }
    users[identity_key] = token_hash

    next_value = {"tokens": tokens, "users": users}
    if setting:
        setting.value = next_value
    else:
        db.add(SystemSetting(key=DB_FALLBACK_KEY, value=next_value))
    await db.flush()


async def _consume_password_reset_token_from_db(db: AsyncSession, token_hash: str) -> dict | None:
    setting, value = await _load_password_reset_store(db)
    if not setting:
        return None

    tokens = dict(value.get("tokens") or {})
    users = dict(value.get("users") or {})
    token_data = tokens.pop(token_hash, None)
    if not token_data:
        return None

    try:
        identity_id = uuid.UUID(str(token_data["identity_id"]))
        expires_at = datetime.fromisoformat(str(token_data["expires_at"]))
    except (KeyError, TypeError, ValueError):
        setting.value = {"tokens": tokens, "users": users}
        await db.flush()
        return None

    users.pop(str(identity_id), None)
    setting.value = {"tokens": tokens, "users": users}
    await db.flush()

    if expires_at <= datetime.now(timezone.utc):
        return None

    return {"identity_id": identity_id}
