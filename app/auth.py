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
  - Module-level asyncpg connection POOL (reused across warm Lambda
    invocations — eliminates ~100-300ms TCP+TLS per DB call).
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

def _utcnow() -> datetime:
    """Return current UTC time as a naive datetime.
    
    The DB columns use TIMESTAMP (not TIMESTAMPTZ), and asyncpg requires
    naive datetimes for TIMESTAMP columns. datetime.utcnow() is deprecated
    in Python 3.12, so we use this wrapper instead.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)

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
_SESSION_CACHE: dict[str, tuple[int, int | None, str, float]] = {}
_SESSION_CACHE_TTL = 30.0  # seconds

def _cache_get(token: str) -> tuple[int, int | None, str] | None:
    """Returns (user_id, dealership_id, role) or None."""
    entry = _SESSION_CACHE.get(token)
    if entry and time.monotonic() < entry[3]:
        return (entry[0], entry[1], entry[2])
    if entry:
        del _SESSION_CACHE[token]
    return None

def _cache_set(token: str, user_id: int, dealership_id: int | None = None, role: str = "salesperson") -> None:
    if len(_SESSION_CACHE) > 500:
        cutoff = time.monotonic()
        expired = [k for k, v in _SESSION_CACHE.items() if v[3] < cutoff]
        for k in expired:
            del _SESSION_CACHE[k]
    _SESSION_CACHE[token] = (user_id, dealership_id, role, time.monotonic() + _SESSION_CACHE_TTL)

def _cache_delete(token: str) -> None:
    _SESSION_CACHE.pop(token, None)

def _cache_delete_user(user_id: int) -> None:
    to_del = [k for k, v in _SESSION_CACHE.items() if v[0] == user_id]
    for k in to_del:
        del _SESSION_CACHE[k]

# ── SSL context (module-level — avoid re-creating per connection) ──────────────
# Supabase's transaction pooler (port 6543) uses a self-signed certificate in
# its chain, so standard CA verification will fail. This is expected and
# documented by Supabase — the pooler terminates TLS at their proxy layer.
# We disable hostname/cert verification for the DB connection only.
# The Supabase Auth REST API (via httpx) still uses full HTTPS verification.
_pg_ssl_ctx: _ssl_mod.SSLContext | None = None

def _get_ssl_ctx() -> _ssl_mod.SSLContext:
    global _pg_ssl_ctx
    if _pg_ssl_ctx is None:
        ctx = _ssl_mod.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl_mod.CERT_NONE
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
            created_at=_utcnow().isoformat(),
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

# ── asyncpg connection pool (module-level — reused across warm invocations) ──
# Replaces the old _raw_pg_conn() which opened a NEW TCP+TLS connection on
# every call (~100-300ms each). The pool keeps 1-5 warm connections that are
# reused across requests within the same Lambda invocation.
_pg_pool: asyncpg.Pool | None = None
_pg_pool_dsn: str | None = None

def _get_pg_dsn() -> str | None:
    """Parse DATABASE_URL into a clean asyncpg-compatible DSN."""
    raw = os.environ.get("DATABASE_URL", "").strip()
    if not raw or "postgres" not in raw:
        return None
    # Strip query params (sslmode etc. — we handle SSL ourselves)
    return raw.split("?")[0]

async def _get_pg_pool() -> asyncpg.Pool | None:
    """Get or create the module-level asyncpg connection pool.
    
    On first call (cold start), creates a pool with min_size=1 so one
    connection is established immediately. On subsequent calls within the
    same warm Lambda, returns the existing pool instantly.
    """
    global _pg_pool, _pg_pool_dsn
    dsn = _get_pg_dsn()
    if not dsn:
        return None
    if _pg_pool is not None and not _pg_pool._closed and _pg_pool_dsn == dsn:
        return _pg_pool
    try:
        _pg_pool = await asyncpg.create_pool(
            dsn=dsn,
            ssl=_get_ssl_ctx(),
            statement_cache_size=0,
            min_size=1,        # Keep 1 warm connection ready
            max_size=5,        # Cap for serverless (Supabase free tier = 60 total)
            max_inactive_connection_lifetime=120,  # Drop idle conns after 2 min
            command_timeout=10,
        )
        _pg_pool_dsn = dsn
        return _pg_pool
    except Exception as e:
        logger.warning(f"pg pool creation failed: {e}")
        return None

async def _raw_pg_execute(query: str, *args) -> str | None:
    """Execute a query via the pool. Returns the status string or None."""
    pool = await _get_pg_pool()
    if not pool:
        return None
    async with pool.acquire() as conn:
        return await conn.execute(query, *args)

async def _raw_pg_fetchrow(query: str, *args) -> asyncpg.Record | None:
    """Fetch a single row via the pool. Returns the Record or None."""
    pool = await _get_pg_pool()
    if not pool:
        return None
    async with pool.acquire() as conn:
        return await conn.fetchrow(query, *args)

# Keep backward-compat alias for main.py startup migration (needs a raw conn)
async def _raw_pg_conn() -> asyncpg.Connection | None:
    """Get a raw connection from the pool for DDL/migration use.
    
    IMPORTANT: Caller must release via conn.close() or use as context manager.
    For normal queries, prefer _raw_pg_execute/_raw_pg_fetchrow instead.
    """
    pool = await _get_pg_pool()
    if not pool:
        return None
    try:
        return await pool.acquire()
    except Exception as e:
        logger.warning(f"pool acquire failed: {e}")
        return None

async def _release_pg_conn(conn) -> None:
    """Release a connection back to the pool (instead of closing it)."""
    pool = await _get_pg_pool()
    if pool and conn:
        try:
            await pool.release(conn)
        except Exception:
            pass

# ── DB-backed session management ──────────────────────────────────────────────
async def create_session(
    db: AsyncSession,
    user_id: int,
    remember_me: bool = False,
    request: Request | None = None,
) -> str:
    token = secrets.token_urlsafe(64)
    ttl = SESSION_TTL_REMEMBER if remember_me else SESSION_TTL_SHORT
    expires_at = _utcnow() + ttl
    ua = (request.headers.get("user-agent") or "")[:256] if request else None
    ip = (request.client.host if request.client else None) if request else None

    result = await _raw_pg_execute(
        """INSERT INTO user_sessions (token, user_id, created_at, expires_at, remember_me, user_agent, ip_address)
           VALUES ($1, $2, NOW(), $3, $4, $5, $6)""",
        token, user_id, expires_at, remember_me, ua, ip
    )
    if result is None:
        # Fallback to SQLAlchemy (SQLite or pool unavailable)
        db.add(UserSession(
            token=token, user_id=user_id, expires_at=expires_at,
            remember_me=remember_me, user_agent=ua, ip_address=ip,
        ))
        await db.commit()

    _cache_set(token, user_id)
    return token


async def get_user_id_from_session(db: AsyncSession | None, token: str | None) -> tuple[int, int | None, str] | None:
    """Returns (user_id, dealership_id, role) or None.
    Joins user_sessions with users to get tenancy info in a single query."""
    if not token:
        return None

    # Fast path: in-memory cache hit — no DB round-trip needed
    cached = _cache_get(token)
    if cached is not None:
        return cached

    row = await _raw_pg_fetchrow(
        """SELECT s.user_id, u.dealership_id, COALESCE(u.role, 'salesperson') AS role
           FROM user_sessions s
           JOIN users u ON u.id = s.user_id
           WHERE s.token = $1 AND s.expires_at > NOW()""",
        token
    )
    if row is not None:
        result = (row["user_id"], row["dealership_id"], row["role"])
        _cache_set(token, *result)
        return result

    # Fallback to SQLAlchemy (SQLite or pool unavailable)
    if db is not None:
        from sqlalchemy import text as sa_text
        sa_row = (
            await db.execute(
                sa_text("""
                    SELECT s.user_id, u.dealership_id, COALESCE(u.role, 'salesperson') AS role
                    FROM user_sessions s
                    JOIN users u ON u.id = s.user_id
                    WHERE s.token = :token AND s.expires_at > :now
                """),
                {"token": token, "now": _utcnow()}
            )
        ).first()
        if sa_row:
            result = (sa_row.user_id, sa_row.dealership_id, sa_row.role)
            _cache_set(token, *result)
            return result

    return None


async def destroy_session(db: AsyncSession, token: str | None):
    if not token:
        return
    _cache_delete(token)
    result = await _raw_pg_execute("DELETE FROM user_sessions WHERE token = $1", token)
    if result is None:
        await db.execute(delete(UserSession).where(UserSession.token == token))
        await db.commit()


async def destroy_all_user_sessions(db: AsyncSession, user_id: int):
    _cache_delete_user(user_id)
    result = await _raw_pg_execute("DELETE FROM user_sessions WHERE user_id = $1", user_id)
    if result is None:
        await db.execute(delete(UserSession).where(UserSession.user_id == user_id))
        await db.commit()


async def cleanup_expired_sessions(db: AsyncSession):
    pool = await _get_pg_pool()
    if pool:
        async with pool.acquire() as conn:
            r1 = await conn.execute("DELETE FROM user_sessions WHERE expires_at <= NOW()")
            r2 = await conn.execute("DELETE FROM password_reset_tokens WHERE expires_at <= NOW()")
            deleted = int(r1.split()[-1]) + int(r2.split()[-1])
            if deleted:
                logger.info(f"Session cleanup: removed {deleted} expired row(s)")
            return deleted
    else:
        result = await db.execute(
            delete(UserSession).where(UserSession.expires_at <= _utcnow())
        )
        await db.commit()
        return result.rowcount

# ── Password reset tokens (legacy fallback) ────────────────────────────────────
async def create_reset_token(db: AsyncSession, user_id: int) -> str:
    token = secrets.token_urlsafe(48)
    db.add(PasswordResetToken(
        token=token, user_id=user_id,
        expires_at=_utcnow() + timedelta(hours=1),
    ))
    await db.commit()
    return token


async def validate_reset_token(db: AsyncSession, token: str) -> int | None:
    row = (
        await db.execute(
            select(PasswordResetToken).where(
                PasswordResetToken.token == token,
                PasswordResetToken.used == False,
                PasswordResetToken.expires_at > _utcnow(),
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


async def get_or_create_settings(db: AsyncSession, user_id: int, dealership_id: int | None = None) -> Settings:
    """Get settings for a dealership. Falls back to user_id lookup for backward compat.
    
    Settings are per-dealership (the pay plan is set by the dealer, not individual salespeople).
    The user_id fallback handles pre-migration data where settings were per-user.
    """
    # Primary: look up by dealership_id
    if dealership_id:
        s = (
            await db.execute(select(Settings).where(Settings.dealership_id == dealership_id).limit(1))
        ).scalar_one_or_none()
        if s:
            return s

    # Fallback: look up by user_id (pre-migration data)
    s = (
        await db.execute(select(Settings).where(Settings.user_id == user_id).limit(1))
    ).scalar_one_or_none()
    if s:
        # Backfill dealership_id if missing
        if dealership_id and not s.dealership_id:
            s.dealership_id = dealership_id
            await db.commit()
        return s

    # Create new settings for this dealership
    s = Settings(
        user_id=user_id,
        dealership_id=dealership_id,
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
