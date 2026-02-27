import hashlib
import secrets
from datetime import date, datetime

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from .models import User, Settings

# ── Password hashing (stdlib, no dependencies) ──
def hash_password(password: str) -> tuple[str, str]:
    """Returns (hash_hex, salt_hex)."""
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return h.hex(), salt

def verify_password(password: str, stored_hash: str, stored_salt: str) -> bool:
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), stored_salt.encode(), 100_000)
    return secrets.compare_digest(h.hex(), stored_hash)


# ── Session tokens (in-memory store, resets on deploy — acceptable for Vercel) ──
_sessions: dict[str, int] = {}  # token -> user_id

def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    _sessions[token] = user_id
    return token

def get_user_id_from_session(token: str | None) -> int | None:
    if not token:
        return None
    return _sessions.get(token)

def destroy_session(token: str | None):
    if token and token in _sessions:
        del _sessions[token]


# ── Request helpers ──
def get_session_token(request: Request) -> str | None:
    return request.cookies.get("ct_session")

async def get_current_user(request: Request, db: AsyncSession) -> User | None:
    token = get_session_token(request)
    uid = get_user_id_from_session(token)
    if uid is None:
        return None
    user = (await db.execute(select(User).where(User.id == uid))).scalar_one_or_none()
    return user

async def get_or_create_settings(db: AsyncSession, user_id: int) -> Settings:
    s = (await db.execute(
        select(Settings).where(Settings.user_id == user_id).limit(1)
    )).scalar_one_or_none()
    if not s:
        s = Settings(
            user_id=user_id,
            unit_comm_discount_le_200=190.0,
            unit_comm_discount_gt_200=140.0,
            permaplate=40.0, nitro_fill=40.0, pulse=40.0,
            finance_non_subvented=40.0, warranty=25.0, tire_wheel=25.0,
            hourly_rate_ny_offset=15.0,
            new_volume_bonus_15_16=1000.0, new_volume_bonus_17_18=1200.0,
            new_volume_bonus_19_20=1500.0, new_volume_bonus_21_24=2000.0,
            new_volume_bonus_25_plus=2800.0,
            used_volume_bonus_8_10=350.0, used_volume_bonus_11_12=500.0,
            used_volume_bonus_13_plus=1000.0,
            spot_bonus_5_9=50.0, spot_bonus_10_12=80.0, spot_bonus_13_plus=100.0,
            quarterly_bonus_threshold_units=60, quarterly_bonus_amount=1200.0,
        )
        db.add(s)
        await db.commit()
        await db.refresh(s)
    return s
