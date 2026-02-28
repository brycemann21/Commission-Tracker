"""
auth.py — Full authentication layer for Commission Tracker.

Strategy:
  - PRIMARY: Supabase Auth (email/password, magic link, password reset)
    via the Supabase REST API. When SUPABASE_URL + SUPABASE_ANON_KEY are
    set, all sign-up / sign-in / password-reset flows go through Supabase.
    We then mirror the user into our local `users` table keyed by supabase_id.

  - FALLBACK: Legacy username/password (pbkdf2_hmac) when Supabase env
    vars are absent. Existing accounts continue to work.

Sessions:
  - Stored in the `user_sessions` DB table (persistent across restarts).
  - TTL: 30 days (remember me) or 24 hours (session only).
  - Cleanup task runs on startup + periodically to purge expired rows.

Password Reset:
  - Supabase mode: delegates to Supabase's built-in reset-by-email.
  - Legacy mode: generates a `password_reset_tokens` row and you can
    wire up an SMTP sender (see send_reset_email stub below).
"""

import hashlib
import logging
import os
import secrets
from datetime import datetime, timedelta
from typing import Optional

import httpx
from fastapi import Request
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import PasswordResetToken, User, UserSession

logger = logging.getLogger("auth")

# ── Supabase config ────────────────────────────────────────────────────────────
SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY", "")
SUPABASE_AUTH_URL = f"{SUPABASE_URL}/auth/v1" if SUPABASE_URL else ""
SUPABASE_ENABLED = bool(SUPABASE_URL and SUPABASE_ANON_KEY)

# App's own public URL (needed to build password-reset redirect links)
APP_URL = os.environ.get("APP_URL", "http://localhost:8000").rstrip("/")

# Session TTLs
SESSION_TTL_REMEMBER = timedelta(days=30)
SESSION_TTL_SHORT = timedelta(hours=24)


# ── Password hashing (legacy fallback) ────────────────────────────────────────
def hash_password(password: str) -> tuple[str, str]:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return h.hex(), salt


def verify_password(password: str, stored_hash: str, stored_salt: str) -> bool:
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), stored_salt.encode(), 100_000)
    return secrets.compare_digest(h.hex(), stored_hash)


# ── Supabase Auth helpers ──────────────────────────────────────────────────────
def _supabase_headers() -> dict:
    return {
        "apikey": SUPABASE_ANON_KEY,
        "Content-Type": "application/json",
    }


async def supabase_sign_up(email: str, password: str) -> dict:
    """
    Register a new user via Supabase Auth.
    Returns {"user": {...}, "access_token": "...", "error": "..."}.
    """
    if not SUPABASE_ENABLED:
        return {"error": "Supabase not configured"}
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(
            f"{SUPABASE_AUTH_URL}/signup",
            headers=_supabase_headers(),
            json={"email": email, "password": password},
        )
    data = r.json()
    if r.status_code not in (200, 201):
        msg = data.get("error_description") or data.get("msg") or data.get("message") or "Sign-up failed"
        return {"error": _friendly_error(msg)}
    return data


async def supabase_sign_in(email: str, password: str) -> dict:
    """
    Sign in via Supabase Auth (email + password).
    Returns Supabase session dict or {"error": "..."}.
    """
    if not SUPABASE_ENABLED:
        return {"error": "Supabase not configured"}
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(
            f"{SUPABASE_AUTH_URL}/token?grant_type=password",
            headers=_supabase_headers(),
            json={"email": email, "password": password},
        )
    data = r.json()
    if r.status_code != 200:
        msg = data.get("error_description") or data.get("msg") or data.get("message") or "Invalid credentials"
        return {"error": _friendly_error(msg)}
    return data


async def supabase_reset_password(email: str) -> dict:
    """
    Trigger Supabase's built-in password reset email.
    The email contains a link pointing back to APP_URL/auth/reset-confirm.
    """
    if not SUPABASE_ENABLED:
        return {"error": "Supabase not configured"}
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(
            f"{SUPABASE_AUTH_URL}/recover",
            headers=_supabase_headers(),
            json={
                "email": email,
                "redirect_to": f"{APP_URL}/auth/reset-confirm",
            },
        )
    if r.status_code == 200:
        return {}
    data = r.json()
    msg = data.get("error_description") or data.get("msg") or "Reset failed"
    return {"error": _friendly_error(msg)}


async def supabase_update_password(access_token: str, new_password: str) -> dict:
    """Update the password for the currently authenticated Supabase user."""
    if not SUPABASE_ENABLED:
        return {"error": "Supabase not configured"}
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.put(
            f"{SUPABASE_AUTH_URL}/user",
            headers={**_supabase_headers(), "Authorization": f"Bearer {access_token}"},
            json={"password": new_password},
        )
    if r.status_code == 200:
        return {}
    data = r.json()
    msg = data.get("error_description") or data.get("msg") or "Update failed"
    return {"error": _friendly_error(msg)}


async def supabase_verify_token_hash(token_hash: str, token_type: str = "recovery") -> dict:
    """
    Exchange a PKCE token_hash for a session (access_token).
    Used when Supabase sends ?token_hash= instead of #access_token= in the reset link.
    """
    if not SUPABASE_ENABLED:
        return {"error": "Supabase not configured"}
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(
            f"{SUPABASE_AUTH_URL}/verify",
            headers=_supabase_headers(),
            json={"token_hash": token_hash, "type": token_type},
        )
    data = r.json()
    if r.status_code == 200:
        return data
    msg = data.get("error_description") or data.get("msg") or "Verification failed"
    return {"error": _friendly_error(msg)}


async def supabase_get_user(access_token: str) -> dict | None:
    """Fetch Supabase user record from an access token."""
    if not SUPABASE_ENABLED:
        return None
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(
            f"{SUPABASE_AUTH_URL}/user",
            headers={**_supabase_headers(), "Authorization": f"Bearer {access_token}"},
        )
    if r.status_code == 200:
        return r.json()
    return None


def _friendly_error(msg: str) -> str:
    """Map Supabase error strings to user-friendly messages."""
    m = msg.lower()
    if "invalid login" in m or "invalid credentials" in m or "email not confirmed" in m:
        return "Incorrect email or password. Please try again."
    if "email already" in m or "already registered" in m or "already exists" in m:
        return "An account with this email already exists."
    if "password should be" in m or "password must" in m:
        return "Password must be at least 6 characters."
    if "rate limit" in m or "too many" in m:
        return "Too many attempts. Please wait a few minutes and try again."
    if "user not found" in m:
        return "No account found with that email address."
    if "token" in m and ("invalid" in m or "expired" in m):
        return "This reset link has expired or already been used. Please request a new one."
    return msg


# ── Local user sync ────────────────────────────────────────────────────────────
async def get_or_create_user_from_supabase(
    db: AsyncSession,
    supabase_user: dict,
    display_name: str = "",
) -> User:
    """
    Given a Supabase user dict, find or create the matching local User row.
    """
    sb_id = supabase_user.get("id", "")
    email = (supabase_user.get("email") or "").lower().strip()
    email_verified = supabase_user.get("email_confirmed_at") is not None

    # Try by supabase_id first (most stable)
    user = (
        await db.execute(select(User).where(User.supabase_id == sb_id))
    ).scalar_one_or_none()

    if user is None and email:
        # Fallback: existing account with matching email (legacy migration)
        user = (
            await db.execute(select(User).where(User.email == email))
        ).scalar_one_or_none()
        if user:
            user.supabase_id = sb_id

    if user is None:
        # Brand-new user
        username = email.split("@")[0][:80] if email else sb_id[:80]
        # Ensure username is unique
        base = username
        i = 1
        while (await db.execute(select(User).where(User.username == username))).scalar_one_or_none():
            username = f"{base}{i}"
            i += 1
        user = User(
            username=username,
            email=email,
            display_name=display_name or username,
            supabase_id=sb_id,
            email_verified=email_verified,
            password_hash="",
            password_salt="",
            created_at=datetime.utcnow().isoformat(),
        )
        db.add(user)
    else:
        user.email = email
        user.email_verified = email_verified
        if not user.supabase_id:
            user.supabase_id = sb_id

    await db.commit()
    await db.refresh(user)
    return user


# ── DB-backed session management ───────────────────────────────────────────────
async def create_session(
    db: AsyncSession,
    user_id: int,
    remember_me: bool = False,
    request: Request | None = None,
) -> str:
    token = secrets.token_urlsafe(64)
    ttl = SESSION_TTL_REMEMBER if remember_me else SESSION_TTL_SHORT
    ua = None
    ip = None
    if request:
        ua = (request.headers.get("user-agent") or "")[:256]
        ip = request.client.host if request.client else None

    session = UserSession(
        token=token,
        user_id=user_id,
        expires_at=datetime.utcnow() + ttl,
        remember_me=remember_me,
        user_agent=ua,
        ip_address=ip,
    )
    db.add(session)
    await db.commit()
    return token


async def get_user_id_from_session(db: AsyncSession, token: str | None) -> int | None:
    if not token:
        return None
    row = (
        await db.execute(
            select(UserSession).where(
                UserSession.token == token,
                UserSession.expires_at > datetime.utcnow(),
            )
        )
    ).scalar_one_or_none()
    return row.user_id if row else None


async def destroy_session(db: AsyncSession, token: str | None):
    if not token:
        return
    await db.execute(delete(UserSession).where(UserSession.token == token))
    await db.commit()


async def destroy_all_user_sessions(db: AsyncSession, user_id: int):
    """Log out all devices for a user."""
    await db.execute(delete(UserSession).where(UserSession.user_id == user_id))
    await db.commit()


async def cleanup_expired_sessions(db: AsyncSession):
    """Delete expired session rows. Call periodically."""
    result = await db.execute(
        delete(UserSession).where(UserSession.expires_at <= datetime.utcnow())
    )
    await db.commit()
    deleted = result.rowcount
    if deleted:
        logger.info(f"Session cleanup: removed {deleted} expired session(s)")
    return deleted


# ── Password reset tokens (legacy fallback) ────────────────────────────────────
async def create_reset_token(db: AsyncSession, user_id: int) -> str:
    token = secrets.token_urlsafe(48)
    row = PasswordResetToken(
        token=token,
        user_id=user_id,
        expires_at=datetime.utcnow() + timedelta(hours=1),
    )
    db.add(row)
    await db.commit()
    return token


async def validate_reset_token(db: AsyncSession, token: str) -> int | None:
    """Returns user_id if valid and unused, else None."""
    row = (
        await db.execute(
            select(PasswordResetToken).where(
                PasswordResetToken.token == token,
                PasswordResetToken.used == False,
                PasswordResetToken.expires_at > datetime.utcnow(),
            )
        )
    ).scalar_one_or_none()
    return row.user_id if row else None


async def consume_reset_token(db: AsyncSession, token: str):
    row = (
        await db.execute(select(PasswordResetToken).where(PasswordResetToken.token == token))
    ).scalar_one_or_none()
    if row:
        row.used = True
        await db.commit()


# ── Request helpers ────────────────────────────────────────────────────────────
def get_session_token(request: Request) -> str | None:
    return request.cookies.get("ct_session")


async def get_current_user(request: Request, db: AsyncSession) -> User | None:
    token = get_session_token(request)
    uid = await get_user_id_from_session(db, token)
    if uid is None:
        return None
    return (await db.execute(select(User).where(User.id == uid))).scalar_one_or_none()


# ── Settings helper (unchanged) ───────────────────────────────────────────────
from .models import Settings


async def get_or_create_settings(db: AsyncSession, user_id: int) -> Settings:
    s = (
        await db.execute(select(Settings).where(Settings.user_id == user_id).limit(1))
    ).scalar_one_or_none()
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
