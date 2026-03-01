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

Serverless optimizations applied:
  - Module-level httpx.AsyncClient with keep-alive (reused across warm
    Lambda invocations — skips DNS + TCP + TLS per Supabase call).
  - Module-level SSL context (avoid re-creating per DB connection).
  - In-memory session cache (TTL=30s) to halve DB round-trips on every
    request's auth middleware check without meaningful staleness risk.
"""

import hashlib
import logging
import os
import secrets
import ssl as _ssl_mod
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import asyncpg
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

APP_URL = os.environ.get("APP_URL", "http://localhost:8000").rstrip("/")

SESSION_TTL_REMEMBER = timedelta(days=30)
SESSION_TTL_SHORT = timedelta(hours=24)

# ── Shared HTTP client (module-level — reused across warm Lambda invocations) ──
# Avoids per-request DNS resolution + TCP + TLS handshake to Supabase.
_http_client: httpx.AsyncClient | None = None

def _get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(
            timeout=10,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )
    return _http_client

# ── In-memory session cache ────────────────────────────────────────────────────
# Every authenticated request hits the DB to validate the session cookie.
# Caching (token → user_id) for 30s cuts ~50% of DB round-trips on warm
# invocations. The risk window is tiny: a revoked session stays valid for
# at most 30 more seconds, which is acceptable for this use case.
_SESSION_CACHE: dict[str, tuple[int, float]] = {}
_SESSION_CACHE_TTL = 30.0  # seconds

def _cache_get(token: str) -> int | None:
    entry = _SESSION_CACHE.get(token)
    if entry and time.monotonic() < entry[1]:
        return entry[0]
    if entry:
        del _SESSION_CACHE[token]
    return None

def _cache_set(token: str, user_id: int) -> None:
    if len(_SESSION_CACHE) > 500:
        cutoff = time.monotonic()
        expired = [k for k, v in _SESSION_CACHE.items() if v[1] < cutoff]
        for k in expired:
            del _SESSION_CACHE[k]
    _SESSION_CACHE[token] = (user_id, time.monotonic() + _SESSION_CACHE_TTL)

def _cache_delete(token: str) -> None:
    _SESSION_CACHE.pop(token, None)

def _cache_delete_user(user_id: int) -> None:
    to_del = [k for k, v in _SESSION_CACHE.items() if v[0] == user_id]
    for k in to_del:
        del _SESSION_CACHE[k]

# ── SSL context (module-level — avoid re-creating per connection) ──────────────
# Supabase transaction pooler uses proper SSL certs trusted by system CAs.
# We use verify_mode=CERT_REQUIRED with system CA bundle for security.
# If you encounter SSL errors with a self-signed cert, set env var
# CT_SSL_VERIFY=0 to fall back to unverified mode.
_pg_ssl_ctx: _ssl_mod.SSLContext | None = None

def _get_ssl_ctx() -> _ssl_mod.SSLContext:
    global _pg_ssl_ctx
    if _pg_ssl_ctx is None:
        ctx = _ssl_mod.create_default_context()
        if os.environ.get("CT_SSL_VERIFY", "1") == "0":
            # Fallback for self-signed certs (not recommended for production)
            ctx.check_hostname = False
            ctx.verify_mode = _ssl_mod.CERT_NONE
        # else: defaults to check_hostname=True, verify_mode=CERT_REQUIRED
        _pg_ssl_ctx = ctx
    return _pg_ssl_ctx

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
    return {"apikey": SUPABASE_ANON_KEY, "Content-Type": "application/json"}

async def supabase_sign_up(email: str, password: str) -> dict:
    if not SUPABASE_ENABLED:
        return {"error": "Supabase not configured"}
    r = await _get_http_client().post(
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
    if not SUPABASE_ENABLED:
        return {"error": "Supabase not configured"}
    r = await _get_http_client().post(
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
    if not SUPABASE_ENABLED:
        return {"error": "Supabase not configured"}
    r = await _get_http_client().post(
        f"{SUPABASE_AUTH_URL}/recover",
        headers=_supabase_headers(),
        json={"email": email, "redirect_to": f"{APP_URL}/auth/reset-confirm"},
    )
    if r.status_code == 200:
        return {}
    data = r.json()
    return {"error": _friendly_error(data.get("error_description") or data.get("msg") or "Reset failed")}

async def supabase_update_password(access_token: str, new_password: str) -> dict:
    if not SUPABASE_ENABLED:
        return {"error": "Supabase not configured"}
    r = await _get_http_client().put(
        f"{SUPABASE_AUTH_URL}/user",
        headers={**_supabase_headers(), "Authorization": f"Bearer {access_token}"},
        json={"password": new_password},
    )
    if r.status_code == 200:
        return {}
    data = r.json()
    return {"error": _friendly_error(data.get("error_description") or data.get("msg") or "Update failed")}

async def supabase_verify_token_hash(token_hash: str, token_type: str = "recovery") -> dict:
    if not SUPABASE_ENABLED:
        return {"error": "Supabase not configured"}
    r = await _get_http_client().post(
        f"{SUPABASE_AUTH_URL}/verify",
        headers=_supabase_headers(),
        json={"token_hash": token_hash, "type": token_type},
    )
    data = r.json()
    if r.status_code == 200:
        return data
    return {"error": _friendly_error(data.get("error_description") or data.get("msg") or "Verification failed")}

async def supabase_get_user(access_token: str) -> dict | None:
    if not SUPABASE_ENABLED:
        return None
    r = await _get_http_client().get(
        f"{SUPABASE_AUTH_URL}/user",
        headers={**_supabase_headers(), "Authorization": f"Bearer {access_token}"},
    )
    return r.json() if r.status_code == 200 else None

def _friendly_error(msg: str) -> str:
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
    sb_id = supabase_user.get("id", "")
    email = (supabase_user.get("email") or "").lower().strip()
    email_verified = supabase_user.get("email_confirmed_at") is not None

    user = (await db.execute(select(User).where(User.supabase_id == sb_id))).scalar_one_or_none()

    if user is None and email:
        user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
        if user:
            user.supabase_id = sb_id

    if user is None:
        username = email.split("@")[0][:80] if email else sb_id[:80]
        base = username
        i = 1
        while (await db.execute(select(User).where(User.username == username))).scalar_one_or_none():
            username = f"{base}{i}"
            i += 1
        user = User(
            username=username, email=email,
            display_name=display_name or username,
            supabase_id=sb_id, email_verified=email_verified,
            password_hash="", password_salt="",
            created_at=datetime.now(timezone.utc).isoformat(),
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

# ── Raw asyncpg connection helper ─────────────────────────────────────────────
async def _raw_pg_conn() -> asyncpg.Connection | None:
    raw_dsn = os.environ.get("DATABASE_URL", "").strip().split("?")[0]
    if not raw_dsn or "postgres" not in raw_dsn:
        return None
    try:
        return await asyncpg.connect(dsn=raw_dsn, ssl=_get_ssl_ctx(), statement_cache_size=0)
    except Exception as e:
        logger.warning(f"raw_pg_conn failed: {e}")
        return None

# ── DB-backed session management ──────────────────────────────────────────────
async def create_session(
    db: AsyncSession,
    user_id: int,
    remember_me: bool = False,
    request: Request | None = None,
) -> str:
    token = secrets.token_urlsafe(64)
    ttl = SESSION_TTL_REMEMBER if remember_me else SESSION_TTL_SHORT
    expires_at = datetime.now(timezone.utc) + ttl
    ua = (request.headers.get("user-agent") or "")[:256] if request else None
    ip = (request.client.host if request.client else None) if request else None

    conn = await _raw_pg_conn()
    if conn:
        try:
            await conn.execute(
                """INSERT INTO user_sessions (token, user_id, created_at, expires_at, remember_me, user_agent, ip_address)
                   VALUES ($1, $2, NOW(), $3, $4, $5, $6)""",
                token, user_id, expires_at, remember_me, ua, ip
            )
        finally:
            await conn.close()
    else:
        db.add(UserSession(
            token=token, user_id=user_id, expires_at=expires_at,
            remember_me=remember_me, user_agent=ua, ip_address=ip,
        ))
        await db.commit()

    _cache_set(token, user_id)
    return token


async def get_user_id_from_session(db: AsyncSession | None, token: str | None) -> int | None:
    if not token:
        return None

    # Fast path: in-memory cache hit — no DB round-trip needed
    cached = _cache_get(token)
    if cached is not None:
        return cached

    conn = await _raw_pg_conn()
    if conn:
        try:
            row = await conn.fetchrow(
                "SELECT user_id FROM user_sessions WHERE token = $1 AND expires_at > NOW()",
                token
            )
            if row:
                _cache_set(token, row["user_id"])
                return row["user_id"]
            return None
        finally:
            await conn.close()
    else:
        row = (
            await db.execute(
                select(UserSession).where(
                    UserSession.token == token,
                    UserSession.expires_at > datetime.now(timezone.utc),
                )
            )
        ).scalar_one_or_none()
        if row:
            _cache_set(token, row.user_id)
            return row.user_id
        return None


async def destroy_session(db: AsyncSession, token: str | None):
    if not token:
        return
    _cache_delete(token)
    conn = await _raw_pg_conn()
    if conn:
        try:
            await conn.execute("DELETE FROM user_sessions WHERE token = $1", token)
        finally:
            await conn.close()
    else:
        await db.execute(delete(UserSession).where(UserSession.token == token))
        await db.commit()


async def destroy_all_user_sessions(db: AsyncSession, user_id: int):
    _cache_delete_user(user_id)
    conn = await _raw_pg_conn()
    if conn:
        try:
            await conn.execute("DELETE FROM user_sessions WHERE user_id = $1", user_id)
        finally:
            await conn.close()
    else:
        await db.execute(delete(UserSession).where(UserSession.user_id == user_id))
        await db.commit()


async def cleanup_expired_sessions(db: AsyncSession):
    conn = await _raw_pg_conn()
    if conn:
        try:
            r1 = await conn.execute("DELETE FROM user_sessions WHERE expires_at <= NOW()")
            r2 = await conn.execute("DELETE FROM password_reset_tokens WHERE expires_at <= NOW()")
            deleted = int(r1.split()[-1]) + int(r2.split()[-1])
            if deleted:
                logger.info(f"Session cleanup: removed {deleted} expired row(s)")
            return deleted
        finally:
            await conn.close()
    else:
        result = await db.execute(
            delete(UserSession).where(UserSession.expires_at <= datetime.now(timezone.utc))
        )
        await db.commit()
        return result.rowcount

# ── Password reset tokens (legacy fallback) ────────────────────────────────────
async def create_reset_token(db: AsyncSession, user_id: int) -> str:
    token = secrets.token_urlsafe(48)
    db.add(PasswordResetToken(
        token=token, user_id=user_id,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    ))
    await db.commit()
    return token


async def validate_reset_token(db: AsyncSession, token: str) -> int | None:
    row = (
        await db.execute(
            select(PasswordResetToken).where(
                PasswordResetToken.token == token,
                PasswordResetToken.used == False,
                PasswordResetToken.expires_at > datetime.now(timezone.utc),
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

# ── Settings helper ───────────────────────────────────────────────────────────
from .models import Settings


async def get_or_create_settings(db: AsyncSession, user_id: int) -> Settings:
    s = (
        await db.execute(select(Settings).where(Settings.user_id == user_id).limit(1))
    ).scalar_one_or_none()
    if not s:
        s = Settings(
            user_id=user_id,
            unit_comm_discount_le_200=190.0, unit_comm_discount_gt_200=140.0,
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
