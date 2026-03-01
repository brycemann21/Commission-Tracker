
import asyncio
import base64
import calendar
import csv
import difflib
import io
import json as _json
import logging
import os
import random
import re
import secrets
import time
import traceback
import urllib.parse
from datetime import date, datetime, timedelta, timezone


def _utcnow() -> datetime:
    """Naive UTC datetime — required by asyncpg for TIMESTAMP (not TIMESTAMPTZ) columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Form, Depends, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import NullPool
from sqlalchemy import select, func, or_, and_, text as sa_text

from .models import Base, User, Deal, Settings, Goal, UserSession, PasswordResetToken, Reminder
from .schemas import DealIn
from .payplan import calc_commission
from .utils import parse_date, today
from .auth import (
    # Legacy password helpers
    hash_password, verify_password,
    # Supabase Auth
    SUPABASE_ENABLED,
    supabase_sign_up, supabase_sign_in,
    supabase_reset_password, supabase_update_password, supabase_verify_token_hash, supabase_get_user,
    get_or_create_user_from_supabase,
    # Session management (DB-backed)
    create_session, get_user_id_from_session, destroy_session,
    destroy_all_user_sessions, cleanup_expired_sessions,
    # Password reset (legacy)
    create_reset_token, validate_reset_token, consume_reset_token,
    # Request helpers
    get_session_token, get_current_user, get_or_create_settings,
)


logger = logging.getLogger("main")

# ─── DB setup ───
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite+aiosqlite:////tmp/commission.db").strip()

def _sanitize_url(url: str) -> str:
    try:
        p = urllib.parse.urlsplit(url)
        qs = [(k, v) for k, v in urllib.parse.parse_qsl(p.query, keep_blank_values=True)
              if k.lower() not in {"sslmode", "sslrootcert", "sslcert", "sslkey"}]
        return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, urllib.parse.urlencode(qs), p.fragment))
    except Exception:
        return url

db_url = _sanitize_url(DATABASE_URL)
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql+asyncpg://", 1)
elif db_url.startswith("postgresql://") and "+asyncpg" not in db_url:
    db_url = db_url.replace("postgresql://", "postgresql+asyncpg://", 1)

import asyncpg as _asyncpg

connect_args = {}
_is_pg = "asyncpg" in db_url
_ssl_ctx = None

if _is_pg:
    # Import the shared SSL context from auth to avoid creating duplicate contexts
    from .auth import _get_ssl_ctx as _auth_get_ssl_ctx
    _ssl_ctx = _auth_get_ssl_ctx()
    connect_args = {
        "ssl": _ssl_ctx,
        "statement_cache_size": 0,
        "prepared_statement_cache_size": 0,
        "prepared_statement_name_func": lambda: f"__asyncpg_{secrets.token_hex(8)}__",
    }

engine = create_async_engine(
    db_url, echo=False, future=True,
    connect_args=connect_args,
    poolclass=NullPool,
)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)


# ─── CSRF Protection (double-submit cookie pattern) ───
# On every page load, set a random CSRF token as a cookie + inject into forms as a hidden field.
# On every POST, verify the form value matches the cookie value.
# Since an attacker can't read our cookie from their domain, they can't forge the hidden field.

CSRF_COOKIE = "ct_csrf"
CSRF_FORM_FIELD = "csrf_token"

def _generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)

def _get_or_set_csrf(request: Request, response=None) -> str:
    """Get existing CSRF token from cookie or generate a new one."""
    existing = request.cookies.get(CSRF_COOKIE)
    if existing and len(existing) >= 32:
        return existing
    token = _generate_csrf_token()
    if response:
        is_secure = not os.environ.get("DATABASE_URL", "").startswith("sqlite")
        response.set_cookie(
            CSRF_COOKIE, token,
            httponly=False,  # JS needs to read it for AJAX
            samesite="lax",
            secure=is_secure,
            max_age=60 * 60 * 24,  # 24 hours
        )
    return token

def _validate_csrf(request_token: str | None, cookie_token: str | None) -> bool:
    """Constant-time comparison of form token vs cookie token."""
    if not request_token or not cookie_token:
        return False
    return secrets.compare_digest(request_token, cookie_token)


# ─── App setup ───
@asynccontextmanager
async def lifespan(application: FastAPI):
    await _run_startup_migrations()
    yield

app = FastAPI(title="Commission Tracker", lifespan=lifespan)
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

templates.env.filters["md"] = lambda v: f"{v.month}/{v.day}" if v else ""
templates.env.globals["today"] = today
templates.env.globals["current_month"] = lambda: today().strftime("%Y-%m")
templates.env.globals["csrf_field_name"] = CSRF_FORM_FIELD

def _csrf_hidden(token: str) -> str:
    """Return an HTML hidden input for CSRF protection."""
    return f'<input type="hidden" name="{CSRF_FORM_FIELD}" value="{token}"/>'


# Override TemplateResponse to auto-inject CSRF token into every template context
_original_template_response = templates.TemplateResponse

def _csrf_template_response(name, context, **kwargs):
    """Wrapper that injects csrf_token into every template context automatically."""
    request = context.get("request")
    if request:
        token = request.cookies.get(CSRF_COOKIE) or _generate_csrf_token()
        context["csrf_token"] = token
        context["csrf_hidden"] = _csrf_hidden(token)
        # Store on request.state so the CSRF middleware can set the matching cookie
        request.state._csrf_generated = token
    return _original_template_response(name, context, **kwargs)

templates.TemplateResponse = _csrf_template_response

static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.exception_handler(Exception)
async def _exc(request: Request, exc: Exception):
    logger.error(f"Unhandled exception at {request.url}: {traceback.format_exc()}")
    return HTMLResponse(
        """<!DOCTYPE html><html><head><title>Error</title>
        <style>body{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f8fafc}
        .box{text-align:center;padding:2rem;max-width:400px}h1{font-size:1.5rem;color:#0f172a;margin-bottom:.5rem}
        p{color:#64748b;font-size:.95rem}a{color:#6366f1;text-decoration:none}a:hover{text-decoration:underline}</style></head>
        <body><div class="box"><h1>Something went wrong</h1>
        <p>An unexpected error occurred. The issue has been logged.</p>
        <p style="margin-top:1.5rem"><a href="/">← Back to Dashboard</a></p></div></body></html>""",
        status_code=500,
    )

async def get_db():
    async with SessionLocal() as session:
        yield session


# ─── Auth helpers ───
PUBLIC_PATHS = {"/login", "/register", "/forgot-password", "/auth/reset-confirm"}

@app.middleware("http")
async def csrf_middleware(request: Request, call_next):
    """CSRF double-submit cookie validation for all state-changing POST requests."""
    if request.method == "POST" and not request.url.path.startswith("/api/"):
        cookie_token = request.cookies.get(CSRF_COOKIE)
        if not cookie_token:
            return HTMLResponse(
                '<h1>403 Forbidden</h1><p>Missing CSRF token. Please <a href="/">go back</a> and try again.</p>',
                status_code=403,
            )
    response = await call_next(request)
    # Ensure CSRF cookie is always set — use the same token the form used
    if not request.cookies.get(CSRF_COOKIE):
        token = getattr(request.state, "_csrf_generated", None) or _generate_csrf_token()
        is_secure = not os.environ.get("DATABASE_URL", "").startswith("sqlite")
        response.set_cookie(
            CSRF_COOKIE, token,
            httponly=False, samesite="lax", secure=is_secure,
            max_age=60 * 60 * 24,
        )
    return response


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    # Cache static assets aggressively
    if request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    return response


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if path.startswith("/static"):
        return await call_next(request)

    token = get_session_token(request)

    # Session check uses raw asyncpg (no SQLAlchemy, pgBouncer-safe)
    # Pass None as db — get_user_id_from_session uses raw pg when available
    uid_val = await get_user_id_from_session(None, token)

    # For public pages: auto-redirect to dashboard if already logged in
    if path in PUBLIC_PATHS:
        if uid_val is not None:
            return RedirectResponse(url="/", status_code=303)
        return await call_next(request)

    # Protected pages
    if uid_val is None:
        dest = request.url.path
        if request.url.query:
            dest += f"?{request.url.query}"
        return RedirectResponse(url=f"/login?next={dest}", status_code=303)

    request.state.user_id = uid_val
    # Set CSRF token on request state for templates
    request.state.csrf_token = request.cookies.get(CSRF_COOKIE, _generate_csrf_token())
    response = await call_next(request)
    # Piggyback probabilistic session cleanup (fire-and-forget, safe for serverless)
    try:
        asyncio.ensure_future(maybe_cleanup_sessions())
    except Exception:
        pass
    return response


def uid(request: Request) -> int:
    return request.state.user_id

async def _user(request: Request, db: AsyncSession) -> User:
    return (await db.execute(select(User).where(User.id == uid(request)))).scalar_one()


# ─── Startup / Migrations ───
# We use raw asyncpg for DDL because SQLAlchemy's asyncpg dialect
# calls prepare() during initialization, which pgBouncer rejects.
async def _run_startup_migrations():
    if not _is_pg:
        # SQLite: use SQLAlchemy create_all (no pgBouncer issues)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        # Session cleanup on startup
        async with SessionLocal() as db:
            await cleanup_expired_sessions(db)
        return

    # PostgreSQL (Supabase): use raw asyncpg connection for DDL
    # Parse the DB URL to get asyncpg-compatible DSN
    raw_dsn = DATABASE_URL.strip()
    # Strip query params
    if "?" in raw_dsn:
        raw_dsn = raw_dsn.split("?")[0]

    conn = await _asyncpg.connect(
        dsn=raw_dsn,
        ssl=_ssl_ctx,
        statement_cache_size=0,
    )
    try:
        # Rename profiles→users if needed (from previous deploy)
        try:
            await conn.execute("ALTER TABLE IF EXISTS profiles RENAME TO users")
        except Exception:
            pass

        # Drop broken FK constraints
        for tbl in ("deals", "settings", "goals"):
            try:
                await conn.execute(f"ALTER TABLE {tbl} DROP CONSTRAINT IF EXISTS {tbl}_user_id_fkey")
            except Exception:
                pass

        # Create users table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(80) UNIQUE NOT NULL,
                display_name VARCHAR(120) DEFAULT '',
                password_hash VARCHAR(256) NOT NULL,
                password_salt VARCHAR(64) NOT NULL,
                created_at VARCHAR(32) DEFAULT ''
            )
        """)

        # Create settings table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                id SERIAL PRIMARY KEY,
                user_id INTEGER,
                unit_comm_discount_le_200 FLOAT DEFAULT 190.0,
                unit_comm_discount_gt_200 FLOAT DEFAULT 140.0,
                permaplate FLOAT DEFAULT 40.0,
                nitro_fill FLOAT DEFAULT 40.0,
                pulse FLOAT DEFAULT 40.0,
                finance_non_subvented FLOAT DEFAULT 40.0,
                warranty FLOAT DEFAULT 25.0,
                tire_wheel FLOAT DEFAULT 25.0,
                hourly_rate_ny_offset FLOAT DEFAULT 15.0,
                new_volume_bonus_15_16 FLOAT DEFAULT 1000.0,
                new_volume_bonus_17_18 FLOAT DEFAULT 1200.0,
                new_volume_bonus_19_20 FLOAT DEFAULT 1500.0,
                new_volume_bonus_21_24 FLOAT DEFAULT 2000.0,
                new_volume_bonus_25_plus FLOAT DEFAULT 2800.0,
                used_volume_bonus_8_10 FLOAT DEFAULT 350.0,
                used_volume_bonus_11_12 FLOAT DEFAULT 500.0,
                used_volume_bonus_13_plus FLOAT DEFAULT 1000.0,
                spot_bonus_5_9 FLOAT DEFAULT 50.0,
                spot_bonus_10_12 FLOAT DEFAULT 80.0,
                spot_bonus_13_plus FLOAT DEFAULT 100.0,
                quarterly_bonus_threshold_units INTEGER DEFAULT 60,
                quarterly_bonus_amount FLOAT DEFAULT 1200.0
            )
        """)

        # Create goals table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS goals (
                id SERIAL PRIMARY KEY,
                user_id INTEGER,
                year INTEGER NOT NULL,
                month INTEGER NOT NULL,
                unit_goal INTEGER DEFAULT 20,
                commission_goal FLOAT DEFAULT 8000.0
            )
        """)

        # Create deals table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS deals (
                id SERIAL PRIMARY KEY,
                user_id INTEGER,
                sold_date DATE,
                delivered_date DATE,
                scheduled_date DATE,
                status VARCHAR(24) DEFAULT 'Pending',
                tag VARCHAR(24) DEFAULT '',
                customer VARCHAR(120) DEFAULT '',
                stock_num VARCHAR(40) DEFAULT '',
                model VARCHAR(120) DEFAULT '',
                new_used VARCHAR(16) DEFAULT '',
                deal_type VARCHAR(32) DEFAULT '',
                business_manager VARCHAR(80) DEFAULT '',
                spot_sold BOOLEAN DEFAULT false,
                discount_gt_200 BOOLEAN DEFAULT false,
                aim_presentation VARCHAR(3) DEFAULT 'X',
                permaplate BOOLEAN DEFAULT false,
                nitro_fill BOOLEAN DEFAULT false,
                pulse BOOLEAN DEFAULT false,
                finance_non_subvented BOOLEAN DEFAULT false,
                warranty BOOLEAN DEFAULT false,
                tire_wheel BOOLEAN DEFAULT false,
                hold_amount FLOAT DEFAULT 0.0,
                aim_amount FLOAT DEFAULT 0.0,
                fi_pvr FLOAT DEFAULT 0.0,
                notes TEXT DEFAULT '',
                unit_comm FLOAT DEFAULT 0.0,
                add_ons FLOAT DEFAULT 0.0,
                trade_hold_comm FLOAT DEFAULT 0.0,
                total_deal_comm FLOAT DEFAULT 0.0,
                pay_date DATE,
                is_paid BOOLEAN DEFAULT false,
                on_delivery_board BOOLEAN DEFAULT false,
                gas_ready BOOLEAN DEFAULT false,
                inspection_ready BOOLEAN DEFAULT false,
                insurance_ready BOOLEAN DEFAULT false
            )
        """)

        # Add missing columns to existing tables (idempotent)
        for tbl in ("deals", "settings", "goals"):
            try:
                await conn.execute(f"ALTER TABLE {tbl} ADD COLUMN IF NOT EXISTS user_id INTEGER")
            except Exception:
                pass

        # Add commission_override column to deals if missing
        try:
            await conn.execute("ALTER TABLE deals ADD COLUMN IF NOT EXISTS commission_override FLOAT")
        except Exception:
            pass

        # Create user_sessions table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS user_sessions (
                id SERIAL PRIMARY KEY,
                token VARCHAR(128) UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT NOW(),
                expires_at TIMESTAMP NOT NULL,
                remember_me BOOLEAN DEFAULT false,
                user_agent VARCHAR(256),
                ip_address VARCHAR(64)
            )
        """)
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(token)")

        # Create password_reset_tokens table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id SERIAL PRIMARY KEY,
                token VARCHAR(128) UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT NOW(),
                expires_at TIMESTAMP NOT NULL,
                used BOOLEAN DEFAULT false
            )
        """)
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_reset_tokens_token ON password_reset_tokens(token)")

        # Add new columns to users table (idempotent)
        for col, typ in [
            ("email", "VARCHAR(254)"),
            ("supabase_id", "VARCHAR(64)"),
            ("email_verified", "BOOLEAN DEFAULT false"),
        ]:
            try:
                await conn.execute(f"ALTER TABLE users ADD COLUMN IF NOT EXISTS {col} {typ}")
            except Exception:
                pass

        # Add unique indexes for new user columns
        try:
            await conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email) WHERE email IS NOT NULL")
        except Exception:
            pass
        try:
            await conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_supabase_id ON users(supabase_id) WHERE supabase_id IS NOT NULL")
        except Exception:
            pass

        for col, typ, dflt in [
            ("hourly_rate_ny_offset", "FLOAT", "15.0"),
            ("new_volume_bonus_15_16", "FLOAT", "1000.0"), ("new_volume_bonus_17_18", "FLOAT", "1200.0"),
            ("new_volume_bonus_19_20", "FLOAT", "1500.0"), ("new_volume_bonus_21_24", "FLOAT", "2000.0"),
            ("new_volume_bonus_25_plus", "FLOAT", "2800.0"),
            ("used_volume_bonus_8_10", "FLOAT", "350.0"), ("used_volume_bonus_11_12", "FLOAT", "500.0"),
            ("used_volume_bonus_13_plus", "FLOAT", "1000.0"),
            ("spot_bonus_5_9", "FLOAT", "50.0"), ("spot_bonus_10_12", "FLOAT", "80.0"),
            ("spot_bonus_13_plus", "FLOAT", "100.0"),
            ("quarterly_bonus_threshold_units", "INTEGER", "60"),
            ("quarterly_bonus_amount", "FLOAT", "1200.0"),
        ]:
            try:
                await conn.execute(f"ALTER TABLE settings ADD COLUMN IF NOT EXISTS {col} {typ} DEFAULT {dflt}")
            except Exception:
                pass

        # Create reminders table
        try:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS reminders (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    title VARCHAR(200) NOT NULL,
                    body TEXT DEFAULT '',
                    due_date DATE,
                    is_done BOOLEAN DEFAULT false,
                    created_at TIMESTAMP DEFAULT NOW()
                )
            """)
        except Exception:
            pass

        # Add indexes for deals table — speeds up all dashboard and filter queries
        try:
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_deals_user_id ON deals(user_id)")
        except Exception: pass
        try:
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_deals_user_status ON deals(user_id, status)")
        except Exception: pass
        try:
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_deals_user_delivered ON deals(user_id, delivered_date)")
        except Exception: pass
        try:
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_deals_user_sold ON deals(user_id, sold_date)")
        except Exception: pass
        try:
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_deals_import_batch ON deals(import_batch_id) WHERE import_batch_id IS NOT NULL")
        except Exception: pass
        try:
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_deals_delivery_board ON deals(user_id, on_delivery_board) WHERE on_delivery_board = true")
        except Exception: pass
        try:
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_reminders_user ON reminders(user_id, is_done, due_date)")
        except Exception: pass

        # Fix goals unique constraint — ensure it includes user_id
        # Old constraint was on (year, month) only which breaks multi-user
        try:
            await conn.execute("ALTER TABLE goals DROP CONSTRAINT IF EXISTS goals_year_month_unique")
        except Exception:
            pass
        try:
            await conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS goals_user_year_month_idx
                ON goals(user_id, year, month)
            """)
        except Exception:
            pass
    finally:
        # Clean up expired sessions via raw asyncpg (avoids pgBouncer prepared stmt issue)
        try:
            await conn.execute("DELETE FROM user_sessions WHERE expires_at <= NOW()")
            await conn.execute("DELETE FROM password_reset_tokens WHERE expires_at <= NOW()")
        except Exception as e:
            pass
        await conn.close()





# Vercel is serverless — no persistent background tasks.
# Instead, we piggyback cleanup on ~1% of incoming requests.

async def maybe_cleanup_sessions():
    """Probabilistic cleanup: runs on roughly 1 in 100 requests."""
    if not _is_pg:
        return
    if random.randint(1, 100) != 1:
        return
    try:
        from .auth import _raw_pg_conn
        conn = await _raw_pg_conn()
        if conn:
            try:
                await conn.execute("DELETE FROM user_sessions WHERE expires_at <= NOW()")
                await conn.execute("DELETE FROM password_reset_tokens WHERE expires_at <= NOW()")
            finally:
                await conn.close()
    except Exception as e:
        logger.warning(f"Session cleanup error: {e}")


# ─── Utility functions ───
def month_bounds(d: date):
    start = date(d.year, d.month, 1)
    end = date(d.year + 1, 1, 1) if d.month == 12 else date(d.year, d.month + 1, 1)
    return start, end

async def get_overdue_reminders(db: AsyncSession, user_id: int) -> int:
    """Returns count of overdue reminders for nav badge — used on all pages."""
    try:
        result = await db.execute(
            select(func.count()).where(Reminder.user_id == user_id, Reminder.is_done == False, Reminder.due_date < today())
        )
        return result.scalar() or 0
    except Exception:
        return 0

def quarter_bounds(d: date):
    q = ((d.month - 1) // 3) * 3 + 1
    start = date(d.year, q, 1)
    end = date(d.year + 1, 1, 1) if q == 10 else date(d.year, q + 3, 1)
    return start, end

def _tiered(count, tiers):
    for mn, mx, amt in tiers:
        if count >= mn and (mx is None or count <= mx):
            return amt, (f"{mn}+" if mx is None else f"{mn}-{mx}")
    return 0.0, "--"

def _tiered_spot(count, tiers):
    for mn, mx, per in tiers:
        if count >= mn and (mx is None or count <= mx):
            label = f"{mn}+" if mx is None else f"{mn}-{mx}"
            return float(count) * float(per), float(per), label
    return 0.0, 0.0, "--"

def _next_tier(count, tiers):
    asc = sorted(tiers, key=lambda x: x[0])
    for mn, mx, amt in asc:
        if count < mn:
            return {"tier": f"{mn}+" if mx is None else f"{mn}–{mx}", "at": mn, "need": mn - count, "amount": float(amt)}
    return {"tier": "Maxed", "at": None, "need": 0, "amount": 0.0}

def _next_spot(count, tiers):
    asc = sorted(tiers, key=lambda x: x[0])
    for mn, mx, per in asc:
        if count < mn:
            return {"tier": f"{mn}+" if mx is None else f"{mn}–{mx}", "at": mn, "need": mn - count, "per": float(per)}
    return {"tier": "Maxed", "at": None, "need": 0, "per": 0.0}

def _pct(n, d):
    return round((n / d) * 100.0, 1) if d > 0 else None


# ════════════════════════════════════════════════
# AUTH ROUTES
# ════════════════════════════════════════════════

# ── Rate limiting for login (in-memory, resets on cold start) ──
# Tracks failed login attempts per IP. On serverless, this provides
# burst protection during warm Lambda periods. Persistent rate limiting
# would require Redis/Upstash but this covers the common case.
_LOGIN_ATTEMPTS: dict[str, list[float]] = {}  # ip -> list of timestamps
_LOGIN_RATE_LIMIT = 10  # max attempts per window
_LOGIN_RATE_WINDOW = 900.0  # 15 minute window

def _check_rate_limit(ip: str) -> bool:
    """Returns True if the IP is rate-limited (too many attempts)."""
    now = time.monotonic()
    attempts = _LOGIN_ATTEMPTS.get(ip, [])
    # Prune old attempts outside the window
    attempts = [t for t in attempts if now - t < _LOGIN_RATE_WINDOW]
    _LOGIN_ATTEMPTS[ip] = attempts
    return len(attempts) >= _LOGIN_RATE_LIMIT

def _record_failed_login(ip: str):
    """Record a failed login attempt for rate limiting."""
    now = time.monotonic()
    if ip not in _LOGIN_ATTEMPTS:
        _LOGIN_ATTEMPTS[ip] = []
    _LOGIN_ATTEMPTS[ip].append(now)
    # Periodic cleanup: if cache grows too large, prune all expired entries
    if len(_LOGIN_ATTEMPTS) > 1000:
        cutoff = now - _LOGIN_RATE_WINDOW
        _LOGIN_ATTEMPTS.clear()


def _set_session_cookie(resp, token: str, remember_me: bool):
    """Set the session cookie with appropriate TTL."""
    max_age = 60 * 60 * 24 * 30 if remember_me else None  # 30 days or session cookie
    is_secure = not os.environ.get("DATABASE_URL", "").startswith("sqlite")
    resp.set_cookie(
        "ct_session", token,
        httponly=True,
        samesite="lax",
        secure=is_secure,
        max_age=max_age,
    )


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = "", next: str = "/"):
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": error,
        "success": "",
        "mode": "login",
        "supabase_enabled": SUPABASE_ENABLED,
        "next": next,
    })


@app.post("/login")
async def login_post(
    request: Request,
    db: AsyncSession = Depends(get_db),
    email: str = Form(""),
    username: str = Form(""),
    password: str = Form(...),
    remember_me: str = Form(""),
    next: str = Form("/"),
):
    remember = remember_me.lower() in ("on", "1", "true", "yes")
    # Prevent open redirect: only allow relative paths (no //evil.com or protocol-relative)
    redirect_to = next if (next.startswith("/") and not re.match(r'^//|^/\\', next)) else "/"
    error_ctx = {
        "request": request, "mode": "login", "success": "",
        "supabase_enabled": SUPABASE_ENABLED, "next": redirect_to,
    }

    # Rate limiting check
    client_ip = (request.client.host if request and request.client else "unknown")
    if _check_rate_limit(client_ip):
        return templates.TemplateResponse("login.html", {
            **error_ctx, "error": "Too many login attempts. Please wait a few minutes and try again."
        })

    if SUPABASE_ENABLED:
        # ── Supabase path ──
        login_email = (email or username).strip().lower()
        if not login_email or not password:
            return templates.TemplateResponse("login.html", {
                **error_ctx, "error": "Please enter your email and password."
            })
        result = await supabase_sign_in(login_email, password)
        if "error" in result:
            _record_failed_login(client_ip)
            return templates.TemplateResponse("login.html", {**error_ctx, "error": result["error"]})

        sb_user = result.get("user") or {}
        local_user = await get_or_create_user_from_supabase(db, sb_user)
        await get_or_create_settings(db, local_user.id)
        token = await create_session(db, local_user.id, remember_me=remember, request=request)

    else:
        # ── Legacy path ──
        uname = (username or email).strip().lower()
        if not uname or not password:
            return templates.TemplateResponse("login.html", {
                **error_ctx, "error": "Please enter your username and password."
            })
        # Simple brute-force protection: rate limiting + artificial delay
        # Timing-safe: always do the DB lookup and verify even on lockout path to prevent timing attacks
        user = (await db.execute(select(User).where(User.username == uname))).scalar_one_or_none()
        pw_ok = bool(user and verify_password(password, user.password_hash, user.password_salt))
        if not pw_ok:
            _record_failed_login(client_ip)
            # Small artificial delay to slow down automated attacks
            await asyncio.sleep(0.5)
            return templates.TemplateResponse("login.html", {
                **error_ctx, "error": "Incorrect username or password. Please try again."
            })
        token = await create_session(db, user.id, remember_me=remember, request=request)

    resp = RedirectResponse(url=redirect_to, status_code=303)
    _set_session_cookie(resp, token, remember)
    return resp


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request, error: str = ""):
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": error,
        "success": "",
        "mode": "register",
        "supabase_enabled": SUPABASE_ENABLED,
        "next": "/",
    })


@app.post("/register")
async def register_post(
    request: Request,
    db: AsyncSession = Depends(get_db),
    email: str = Form(""),
    username: str = Form(""),
    display_name: str = Form(""),
    password: str = Form(...),
    password2: str = Form(...),
):
    error_ctx = {
        "request": request, "mode": "register", "success": "",
        "supabase_enabled": SUPABASE_ENABLED, "next": "/",
    }

    if SUPABASE_ENABLED:
        # ── Supabase path ──
        reg_email = email.strip().lower()
        errors = []
        if not reg_email or "@" not in reg_email:
            errors.append("A valid email address is required.")
        if len(password) < 6:
            errors.append("Password must be at least 6 characters.")
        if password != password2:
            errors.append("Passwords don't match.")
        if errors:
            return templates.TemplateResponse("login.html", {**error_ctx, "error": " ".join(errors)})

        result = await supabase_sign_up(reg_email, password)
        if "error" in result:
            return templates.TemplateResponse("login.html", {**error_ctx, "error": result["error"]})

        sb_user = result.get("user") or {}
        # Supabase may require email confirmation — check if session exists
        session_data = result.get("session")
        local_user = await get_or_create_user_from_supabase(
            db, sb_user, display_name=display_name.strip() or reg_email.split("@")[0]
        )
        await get_or_create_settings(db, local_user.id)

        if not session_data:
            # Email confirmation required — show success message
            return templates.TemplateResponse("login.html", {
                **error_ctx,
                "mode": "login",
                "error": "",
                "success": "Account created! Check your email to confirm before signing in.",
            })

        token = await create_session(db, local_user.id, remember_me=False, request=request)
        resp = RedirectResponse(url="/", status_code=303)
        _set_session_cookie(resp, token, False)
        return resp

    else:
        # ── Legacy path ──
        uname = (username or email).strip().lower()
        errors = []
        if len(uname) < 3:
            errors.append("Username must be at least 3 characters.")
        if len(password) < 6:
            errors.append("Password must be at least 6 characters.")
        if password != password2:
            errors.append("Passwords don't match.")
        existing = (await db.execute(select(User).where(User.username == uname))).scalar_one_or_none()
        if existing:
            errors.append("Username already taken.")
        if errors:
            return templates.TemplateResponse("login.html", {**error_ctx, "error": " ".join(errors)})

        pw_hash, pw_salt = hash_password(password)
        user = User(
            username=uname,
            display_name=(display_name.strip() or uname),
            password_hash=pw_hash,
            password_salt=pw_salt,
            created_at=_utcnow().isoformat(),
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
        await get_or_create_settings(db, user.id)
        token = await create_session(db, user.id, remember_me=False, request=request)
        resp = RedirectResponse(url="/", status_code=303)
        _set_session_cookie(resp, token, False)
        return resp


# ── Forgot Password ────────────────────────────────────────────────────────────
@app.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request, error: str = "", success: str = ""):
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": error,
        "success": success,
        "mode": "forgot",
        "supabase_enabled": SUPABASE_ENABLED,
        "next": "/",
    })


@app.post("/forgot-password")
async def forgot_password_post(
    request: Request,
    db: AsyncSession = Depends(get_db),
    email: str = Form(...),
):
    email = email.strip().lower()
    error_ctx = {
        "request": request, "mode": "forgot",
        "supabase_enabled": SUPABASE_ENABLED, "next": "/",
    }
    # Always show a generic success so we don't leak whether an account exists
    generic_ok = "If an account with that email exists, you'll receive a reset link shortly."

    if SUPABASE_ENABLED:
        result = await supabase_reset_password(email)
        if "error" in result:
            return templates.TemplateResponse("login.html", {**error_ctx, "error": result["error"], "success": ""})
        return templates.TemplateResponse("login.html", {**error_ctx, "error": "", "success": generic_ok})

    else:
        # Legacy: find user and create token
        user = (await db.execute(
            select(User).where((User.email == email) | (User.username == email))
        )).scalar_one_or_none()
        if user:
            token = await create_reset_token(db, user.id)
            reset_url = f"{request.base_url}reset-password?token={token}"
            # TODO: send email with reset_url via your SMTP provider
            # Do NOT log reset_url — it contains a valid auth token
        return templates.TemplateResponse("login.html", {**error_ctx, "error": "", "success": generic_ok})


# ── Reset Password Confirm (Supabase callback + legacy token) ──────────────────
@app.get("/auth/reset-confirm", response_class=HTMLResponse)
async def reset_confirm_page(
    request: Request,
    access_token: str = "",
    token_hash: str = "",
    type: str = "",
    error: str = "",
    error_description: str = "",
):
    """
    Supabase redirects here after the user clicks the reset link in their email.
    Handles both legacy (#access_token fragment) and PKCE (?token_hash=) flows.
    Also handles Supabase error redirects (?error=...&error_description=...).
    """
    # Surface Supabase errors (e.g. expired link)
    if error:
        friendly = error_description or "This reset link is invalid or has expired. Please request a new one."
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": friendly,
            "success": "",
            "mode": "forgot",
            "supabase_enabled": SUPABASE_ENABLED,
            "next": "/",
        })
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": "",
        "success": "",
        "mode": "reset_confirm",
        "access_token": access_token,
        "token_hash": token_hash,
        "supabase_enabled": SUPABASE_ENABLED,
        "next": "/",
    })


@app.post("/auth/reset-confirm")
async def reset_confirm_post(
    request: Request,
    db: AsyncSession = Depends(get_db),
    access_token: str = Form(""),
    token_hash: str = Form(""),
    token: str = Form(""),
    password: str = Form(...),
    password2: str = Form(...),
):
    error_ctx = {
        "request": request, "mode": "reset_confirm", "success": "",
        "supabase_enabled": SUPABASE_ENABLED, "next": "/",
        "access_token": access_token, "token_hash": token_hash,
    }
    if password != password2:
        return templates.TemplateResponse("login.html", {**error_ctx, "error": "Passwords don't match."})
    if len(password) < 6:
        return templates.TemplateResponse("login.html", {**error_ctx, "error": "Password must be at least 6 characters."})

    # PKCE flow: exchange token_hash for access_token first
    if SUPABASE_ENABLED and token_hash and not access_token:
        verify = await supabase_verify_token_hash(token_hash)
        if "error" in verify:
            return templates.TemplateResponse("login.html", {**error_ctx, "error": verify["error"]})
        access_token = (verify.get("access_token") or
                        (verify.get("session") or {}).get("access_token", ""))

    if SUPABASE_ENABLED and access_token:
        result = await supabase_update_password(access_token, password)
        if "error" in result:
            return templates.TemplateResponse("login.html", {**error_ctx, "error": result["error"]})
        return templates.TemplateResponse("login.html", {
            **error_ctx, "mode": "login", "error": "",
            "success": "Password updated! You can now sign in with your new password."
        })

    elif token:
        # Legacy reset token
        user_id = await validate_reset_token(db, token)
        if not user_id:
            return templates.TemplateResponse("login.html", {
                **error_ctx, "error": "This reset link has expired or already been used. Please request a new one."
            })
        user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
        if not user:
            return templates.TemplateResponse("login.html", {**error_ctx, "error": "Account not found."})
        pw_hash, pw_salt = hash_password(password)
        user.password_hash = pw_hash
        user.password_salt = pw_salt
        await consume_reset_token(db, token)
        await destroy_all_user_sessions(db, user_id)
        await db.commit()
        return templates.TemplateResponse("login.html", {
            **error_ctx, "mode": "login", "error": "",
            "success": "Password updated! You can now sign in."
        })

    return templates.TemplateResponse("login.html", {**error_ctx, "error": "Invalid reset request."})


@app.get("/reset-password", response_class=HTMLResponse)
async def reset_password_legacy(request: Request, token: str = ""):
    """Legacy reset-password page for email links in non-Supabase mode."""
    error = ""
    if token:
        async with SessionLocal() as db:
            valid_uid = await validate_reset_token(db, token)
        if not valid_uid:
            error = "This reset link has expired or already been used."
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": error,
        "success": "",
        "mode": "reset_confirm",
        "access_token": "",
        "token": token,
        "supabase_enabled": SUPABASE_ENABLED,
        "next": "/",
    })


@app.get("/logout")
async def logout(request: Request, db: AsyncSession = Depends(get_db)):
    token = get_session_token(request)
    await destroy_session(db, token)
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie("ct_session")
    return resp


@app.get("/api/session-status")
async def session_status(request: Request):
    """Returns seconds remaining on current session — used by timeout warning."""
    from .auth import _raw_pg_conn
    token = get_session_token(request)
    if not token:
        return JSONResponse({"seconds_remaining": 0, "authenticated": False})
    if not _is_pg:
        return JSONResponse({"seconds_remaining": 86400, "authenticated": True, "remember_me": True})
    try:
        conn = await _raw_pg_conn()
        if not conn:
            return JSONResponse({"seconds_remaining": 86400, "authenticated": True, "remember_me": False})
        try:
            row = await conn.fetchrow(
                "SELECT expires_at, remember_me FROM user_sessions WHERE token = $1 AND expires_at > NOW()",
                token
            )
        finally:
            await conn.close()
        if not row:
            return JSONResponse({"seconds_remaining": 0, "authenticated": False})
        delta = (row["expires_at"] - _utcnow()).total_seconds()
        return JSONResponse({
            "seconds_remaining": max(0, int(delta)),
            "authenticated": True,
            "remember_me": row["remember_me"],
        })
    except Exception as e:
        logger.warning(f"session_status error: {e}")
        return JSONResponse({"seconds_remaining": 86400, "authenticated": True, "remember_me": False})


@app.post("/api/session-extend")
async def session_extend(request: Request):
    """Actually extends the current session's expiry by its original TTL."""
    from .auth import _raw_pg_conn, SESSION_TTL_SHORT, SESSION_TTL_REMEMBER, _cache_set
    token = get_session_token(request)
    if not token:
        return JSONResponse({"ok": False, "error": "No session"}, status_code=401)

    if not _is_pg:
        return JSONResponse({"ok": True, "seconds_remaining": 86400})

    try:
        conn = await _raw_pg_conn()
        if not conn:
            return JSONResponse({"ok": False, "error": "DB unavailable"}, status_code=503)
        try:
            row = await conn.fetchrow(
                "SELECT user_id, remember_me FROM user_sessions WHERE token = $1 AND expires_at > NOW()",
                token
            )
            if not row:
                return JSONResponse({"ok": False, "error": "Session expired"}, status_code=401)

            ttl = SESSION_TTL_REMEMBER if row["remember_me"] else SESSION_TTL_SHORT
            new_expires = _utcnow() + ttl
            await conn.execute(
                "UPDATE user_sessions SET expires_at = $1 WHERE token = $2",
                new_expires, token
            )
            # Update the in-memory cache too
            _cache_set(token, row["user_id"])

            return JSONResponse({
                "ok": True,
                "seconds_remaining": int(ttl.total_seconds()),
            })
        finally:
            await conn.close()
    except Exception as e:
        logger.warning(f"session_extend error: {e}")
        return JSONResponse({"ok": False, "error": "Internal error"}, status_code=500)



@app.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    month: str | None = None,
    year: int | None = None,
    db: AsyncSession = Depends(get_db),
):
    user_id = uid(request)
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one()
    s = await get_or_create_settings(db, user_id)

    today_date = today()

    # ── Parse month/year ──────────────────────────────────────────────────────
    month_str = (month or "").strip()
    if year is not None and month_str and month_str.isdigit():
        sel_y, sel_m = int(year), int(month_str)
    else:
        m = re.fullmatch(r"(\d{4})-(\d{1,2})", month_str)
        if m:
            sel_y, sel_m = int(m.group(1)), int(m.group(2))
        else:
            sel_y = int(year) if year is not None else today_date.year
            sel_m = today_date.month
    sel_m = max(1, min(12, sel_m))

    d0 = date(sel_y, sel_m, 1)
    start_m, end_m = month_bounds(d0)
    month_key = f"{sel_y:04d}-{sel_m:02d}"

    # Previous month bounds
    py, pm = (sel_y - 1, 12) if sel_m == 1 else (sel_y, sel_m - 1)
    ps, pe = month_bounds(date(py, pm, 1))

    # Quarter bounds
    qs, qe = quarter_bounds(d0)

    # Year bounds
    yr_start = date(sel_y, 1, 1)
    yr_end = date(sel_y + 1, 1, 1)

    # ── All SQL queries run concurrently ──────────────────────────────────────
    # Instead of loading all deals and filtering in Python, each set of numbers
    # is computed with a targeted SQL query. This is the core serverless
    # optimization: less data transferred, less memory, faster response.



    async def _q_delivered_mtd():
        return (await db.execute(
            select(Deal).where(
                Deal.user_id == user_id, Deal.status == "Delivered",
                Deal.delivered_date >= start_m, Deal.delivered_date < end_m,
            )
        )).scalars().all()

    async def _q_prev_del():
        return (await db.execute(
            select(
                func.count().label("cnt"),
                func.sum(Deal.total_deal_comm).label("comm"),
            ).where(
                Deal.user_id == user_id, Deal.status == "Delivered",
                Deal.delivered_date >= ps, Deal.delivered_date < pe,
            )
        )).one()

    async def _q_qtd_count():
        return (await db.execute(
            select(func.count()).where(
                Deal.user_id == user_id, Deal.status == "Delivered",
                Deal.delivered_date >= qs, Deal.delivered_date < qe,
            )
        )).scalar() or 0

    async def _q_yr_trend():
        rows = (await db.execute(
            select(
                func.extract("month", Deal.delivered_date).label("mo"),
                func.count().label("cnt"),
                func.sum(Deal.total_deal_comm).label("comm"),
            ).where(
                Deal.user_id == user_id, Deal.status == "Delivered",
                Deal.delivered_date >= yr_start, Deal.delivered_date < yr_end,
            ).group_by(func.extract("month", Deal.delivered_date))
        )).all()
        ubm = [0] * 12; cbm = [0.0] * 12
        ytd_units = 0; ytd_comm = 0.0
        for row in rows:
            idx = int(row.mo) - 1
            ubm[idx] = row.cnt; cbm[idx] = float(row.comm or 0)
            ytd_units += row.cnt; ytd_comm += float(row.comm or 0)
        return ubm, cbm, ytd_units, ytd_comm

    async def _q_pending():
        return (await db.execute(
            select(Deal).where(Deal.user_id == user_id, Deal.status.in_(["Pending", "Scheduled"]))
            .order_by(Deal.sold_date.asc().nullslast())
        )).scalars().all()

    async def _q_goal():
        return (await db.execute(
            select(Goal).where(Goal.user_id == user_id, Goal.year == sel_y, Goal.month == sel_m).limit(1)
        )).scalar_one_or_none()

    async def _q_todays():
        return (await db.execute(
            select(Deal).where(
                Deal.user_id == user_id,
                Deal.status.notin_(["Delivered", "Dead"]),
                Deal.scheduled_date == today_date,
            )
        )).scalars().all()

    async def _q_overdue():
        return (await db.execute(
            select(func.count()).where(
                Reminder.user_id == user_id,
                Reminder.is_done == False,
                Reminder.due_date < today(),
            )
        )).scalar() or 0

    async def _q_years():
        rows = (await db.execute(
            select(
                func.extract("year", Deal.delivered_date).label("y1"),
                func.extract("year", Deal.sold_date).label("y2"),
            ).where(Deal.user_id == user_id)
        )).all()
        yrs = {today_date.year}
        for r in rows:
            if r.y1: yrs.add(int(r.y1))
            if r.y2: yrs.add(int(r.y2))
        return sorted(yrs, reverse=True)

    (
        delivered_mtd,
        prev_row,
        qtd_count,
        (ubm, cbm, ytd_units, ytd_comm),
        pending_all,
        goal,
        todays,
        overdue_count,
        years,
    ) = await asyncio.gather(
        _q_delivered_mtd(), _q_prev_del(), _q_qtd_count(), _q_yr_trend(),
        _q_pending(), _q_goal(), _q_todays(), _q_overdue(), _q_years(),
    )

    # ── Stats (computed from the small delivered_mtd list) ───────────────────
    units_mtd = len(delivered_mtd)
    comm_mtd = sum((d.total_deal_comm or 0) for d in delivered_mtd)
    paid_comm = sum((d.total_deal_comm or 0) for d in delivered_mtd if d.is_paid)
    new_mtd = sum(1 for d in delivered_mtd if (d.new_used or "").lower() == "new")
    used_mtd = sum(1 for d in delivered_mtd if (d.new_used or "").lower() == "used")
    avg_deal = comm_mtd / units_mtd if units_mtd else 0.0

    prev_units = prev_row.cnt or 0
    prev_comm = float(prev_row.comm or 0)

    # ── Closing rates ─────────────────────────────────────────────────────────
    dt = units_mtd
    pulse_y = sum(1 for d in delivered_mtd if d.pulse)
    nitro_y = sum(1 for d in delivered_mtd if d.nitro_fill)
    perma_y = sum(1 for d in delivered_mtd if d.permaplate)
    aim_y = sum(1 for d in delivered_mtd if (d.aim_presentation or "X") == "Yes")
    aim_n = sum(1 for d in delivered_mtd if (d.aim_presentation or "X") == "No")
    closing_rates = {
        "pulse": {"label": "Pulse", "yes": pulse_y, "den": dt, "pct": _pct(pulse_y, dt)},
        "nitro": {"label": "Nitro Fill", "yes": nitro_y, "den": dt, "pct": _pct(nitro_y, dt)},
        "permaplate": {"label": "PermaPlate", "yes": perma_y, "den": dt, "pct": _pct(perma_y, dt)},
        "aim": {"label": "Aim", "yes": aim_y, "den": aim_y + aim_n, "pct": _pct(aim_y, aim_y + aim_n)},
    }

    # ── Bonus tiers ───────────────────────────────────────────────────────────
    vol_tiers = [(25,None,float(s.new_volume_bonus_25_plus)),(21,24,float(s.new_volume_bonus_21_24)),
                 (19,20,float(s.new_volume_bonus_19_20)),(17,18,float(s.new_volume_bonus_17_18)),(15,16,float(s.new_volume_bonus_15_16))]
    used_tiers = [(13,None,float(s.used_volume_bonus_13_plus)),(11,12,float(s.used_volume_bonus_11_12)),(8,10,float(s.used_volume_bonus_8_10))]
    spot_tiers = [(13,None,float(s.spot_bonus_13_plus)),(10,12,float(s.spot_bonus_10_12)),(5,9,float(s.spot_bonus_5_9))]

    vol_amt, vol_tier = _tiered(units_mtd, vol_tiers)
    used_amt, used_tier = _tiered(used_mtd, used_tiers)
    spots = sum(1 for d in delivered_mtd if d.spot_sold)
    spot_total, spot_per, spot_tier = _tiered_spot(spots, spot_tiers)

    q_hit = qtd_count >= int(s.quarterly_bonus_threshold_units or 0)
    q_bonus = float(s.quarterly_bonus_amount) if q_hit else 0.0
    bonus_total = float(vol_amt) + float(used_amt) + float(spot_total) + q_bonus

    # ── Projections ───────────────────────────────────────────────────────────
    pend_month = [d for d in pending_all if d.sold_date and start_m <= d.sold_date < end_m]
    proj_units = units_mtd + len(pend_month)
    proj_comm = comm_mtd + sum((d.total_deal_comm or 0) for d in pend_month)
    proj_used = used_mtd + sum(1 for d in pend_month if (d.new_used or "").lower() == "used")
    pv, _ = _tiered(proj_units, vol_tiers)
    pu, _ = _tiered(proj_used, used_tiers)
    proj_bonus = float(pv) + float(pu) + float(spot_total) + q_bonus

    bonus_breakdown = {
        "volume": {"units": units_mtd, "new_units": new_mtd, "used_units": used_mtd, "tier": vol_tier, "amount": float(vol_amt), "next": _next_tier(units_mtd, vol_tiers)},
        "used": {"units": used_mtd, "tier": used_tier, "amount": float(used_amt), "next": _next_tier(used_mtd, used_tiers)},
        "spot": {"spots": spots, "tier": spot_tier, "per": float(spot_per), "amount": float(spot_total), "next": _next_spot(spots, spot_tiers)},
        "quarterly": {"units_qtd": qtd_count, "threshold": int(s.quarterly_bonus_threshold_units or 0), "hit": q_hit, "amount": q_bonus,
                       "q_label": f"Q{((sel_m-1)//3)+1}", "next": {"tier": "Hit" if q_hit else f"{int(s.quarterly_bonus_threshold_units or 0)} units",
                       "need": 0 if q_hit else max(0, int(s.quarterly_bonus_threshold_units or 0) - qtd_count), "amount": float(s.quarterly_bonus_amount or 0)}},
        "total": bonus_total,
    }

    # ── Pending deal ages ─────────────────────────────────────────────────────
    for d in pending_all:
        d.days_pending = (today_date - d.sold_date).days if d.sold_date else 0

    # ── Milestones ────────────────────────────────────────────────────────────
    milestones = []
    if vol_amt > 0: milestones.append(f"Volume Bonus unlocked — ${vol_amt:,.0f}")
    if used_amt > 0: milestones.append(f"Used Bonus unlocked — ${used_amt:,.0f}")
    if spot_total > 0: milestones.append(f"Spot Bonus active — ${spot_total:,.0f}")
    if q_hit: milestones.append(f"Quarterly target hit — ${q_bonus:,.0f}")

    goals = {"unit_goal": goal.unit_goal if goal else 20, "commission_goal": goal.commission_goal if goal else 8000.0, "has_custom": goal is not None}

    resp = templates.TemplateResponse("dashboard.html", {
        "request": request, "user": user,
        "month": month_key, "selected_year": sel_y, "selected_month": sel_m,
        "year_options": years, "month_options": [{"num": i, "label": calendar.month_name[i]} for i in range(1,13)],
        "units_mtd": units_mtd, "closing_rates": closing_rates,
        "comm_mtd": comm_mtd, "paid_comm_mtd": paid_comm, "pending_comm_mtd": comm_mtd - paid_comm,
        "new_mtd": new_mtd, "used_mtd": used_mtd, "avg_per_deal": avg_deal,
        "current_bonus_total": bonus_total, "bonus_breakdown": bonus_breakdown,
        "units_ytd": ytd_units, "comm_ytd": ytd_comm,
        "pending": len(pending_all), "pending_deals": pending_all[:15], "pending_deals_all": pending_all,
        "year": sel_y, "month_labels": ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"],
        "units_by_month": ubm, "comm_by_month": cbm,
        "prev_units": prev_units, "prev_comm": prev_comm,
        "units_diff": units_mtd - prev_units, "comm_diff": comm_mtd - prev_comm,
        "proj_units": proj_units, "proj_comm": proj_comm,
        "proj_bonus_total": proj_bonus, "bonus_uplift": proj_bonus - bonus_total,
        "pending_in_month_count": len(pend_month),
        "goals": goals, "milestones": milestones, "todays_deliveries": todays,
        "overdue_reminders": overdue_count,
    })
    resp.set_cookie("ct_year", str(sel_y), httponly=False, samesite="lax")
    resp.set_cookie("ct_month", str(sel_m), httponly=False, samesite="lax")
    return resp


# ════════════════════════════════════════════════
# GOALS
# ════════════════════════════════════════════════
@app.post("/goals/save")
async def goals_save(request: Request, unit_goal: int = Form(20), commission_goal: float = Form(8000.0), db: AsyncSession = Depends(get_db)):
    user_id = uid(request)
    td = today()
    try: y = int(request.cookies.get("ct_year") or td.year)
    except: y = td.year
    try: m = int(request.cookies.get("ct_month") or td.month)
    except: m = td.month
    # Use upsert to handle the unique constraint on (user_id, year, month) safely
    await db.execute(sa_text("""
        INSERT INTO goals (user_id, year, month, unit_goal, commission_goal)
        VALUES (:uid, :y, :m, :u, :c)
        ON CONFLICT (user_id, year, month)
        DO UPDATE SET unit_goal=:u, commission_goal=:c
    """), {"uid": user_id, "y": y, "m": m, "u": unit_goal, "c": commission_goal})
    await db.commit()
    return RedirectResponse(url=f"/?year={y}&month={m}", status_code=303)


# ════════════════════════════════════════════════
# DEALS LIST
# ════════════════════════════════════════════════
@app.get("/deals", response_class=HTMLResponse)
async def deals_list(
    request: Request,
    q: str | None = None, status: str | None = None, paid: str | None = None,
    month: int | None = None, year: int | None = None, _nav: str | None = None,
    search_all: str | None = None,
    db: AsyncSession = Depends(get_db)
):
    user_id = uid(request)
    td = today()
    # Start from query params, fall back to cookies, fall back to today
    try: y = year or int(request.cookies.get("ct_year") or td.year)
    except: y = td.year
    try: m = month or int(request.cookies.get("ct_month") or td.month)
    except: m = td.month
    # Handle prev/next navigation
    if _nav == "prev":
        m -= 1
        if m < 1: m = 12; y -= 1
    elif _nav == "next":
        m += 1
        if m > 12: m = 1; y += 1
    m = max(1, min(12, m))
    start_sel, end_sel = month_bounds(date(y, m, 1))

    stmt = select(Deal).where(Deal.user_id == user_id).order_by(Deal.sold_date.asc().nullslast(), Deal.id.asc())

    # Cross-month search: if searching, ignore month filter entirely
    searching_all = bool(search_all == "1" and q and q.strip())
    if not searching_all:
        stmt = stmt.where(or_(
            # Sold in the selected month
            and_(Deal.sold_date.is_not(None), Deal.sold_date >= start_sel, Deal.sold_date < end_sel),
            # Delivered in the selected month but sold in a different month (cross-month carryover)
            and_(Deal.delivered_date.is_not(None), Deal.delivered_date >= start_sel, Deal.delivered_date < end_sel,
                 or_(Deal.sold_date.is_(None), Deal.sold_date < start_sel, Deal.sold_date >= end_sel)),
            # Any Pending or Scheduled deal carries over until delivered/dead
            Deal.status.in_(["Pending", "Scheduled"]),
        ))
    if status and status != "All": stmt = stmt.where(Deal.status == status)
    if paid == "Paid": stmt = stmt.where(Deal.is_paid.is_(True))
    elif paid == "Pending": stmt = stmt.where(Deal.is_paid.is_(False))
    if q and q.strip():
        like = f"%{q.strip()}%"
        stmt = stmt.where((Deal.customer.ilike(like)) | (Deal.stock_num.ilike(like)) | (Deal.model.ilike(like)))

    deals = (await db.execute(stmt)).scalars().all()
    user = await _user(request, db)
    resp = templates.TemplateResponse("deals.html", {
        "request": request, "user": user, "deals": deals, "q": q or "", "status": status or "All", "paid": paid or "All",
        "selected_year": y, "selected_month": m,
        "searching_all": searching_all,
        "overdue_reminders": await get_overdue_reminders(db, user_id),
    })
    resp.set_cookie("ct_year", str(y), httponly=False, samesite="lax")
    resp.set_cookie("ct_month", str(m), httponly=False, samesite="lax")
    return resp


# ════════════════════════════════════════════════
# DEAL FORM
# ════════════════════════════════════════════════
@app.get("/deals/new", response_class=HTMLResponse)
async def deal_new(request: Request, db: AsyncSession = Depends(get_db)):
    user_id = uid(request)
    settings = await get_or_create_settings(db, user_id)
    start_m, end_m = month_bounds(today())
    dels = (await db.execute(select(Deal).where(Deal.user_id == user_id, Deal.status == "Delivered", Deal.delivered_date >= start_m, Deal.delivered_date < end_m))).scalars().all()
    u = len(dels); c = sum((d.total_deal_comm or 0) for d in dels)
    user = await _user(request, db)
    return templates.TemplateResponse("deal_form.html", {
        "request": request, "user": user, "deal": None, "settings": settings,
        "next_url": request.query_params.get("next") or "",
        "overdue_reminders": await get_overdue_reminders(db, user_id),
        "mtd": {"units": u, "comm": c, "avg": c/u if u else 0, "month_label": today().strftime("%B %Y")},
    })

@app.get("/deals/{deal_id}/edit", response_class=HTMLResponse)
async def deal_edit(deal_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    user_id = uid(request)
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id, Deal.user_id == user_id))).scalar_one_or_none()
    if not deal: return RedirectResponse(url="/deals", status_code=303)
    settings = await get_or_create_settings(db, user_id)
    embed = request.query_params.get("embed") == "1"
    start_m, end_m = month_bounds(today())
    dels = (await db.execute(select(Deal).where(Deal.user_id == user_id, Deal.status == "Delivered", Deal.delivered_date >= start_m, Deal.delivered_date < end_m))).scalars().all()
    u = len(dels); c = sum((d.total_deal_comm or 0) for d in dels)
    user = await _user(request, db)
    return templates.TemplateResponse("deal_form.html", {
        "request": request, "user": user, "deal": deal, "settings": settings, "embed": embed,
        "next_url": request.query_params.get("next") or "",
        "overdue_reminders": await get_overdue_reminders(db, user_id),
        "mtd": {"units": u, "comm": c, "avg": c/u if u else 0, "month_label": today().strftime("%B %Y")},
    })


@app.post("/deals/save")
async def deal_save(
    request: Request,
    deal_id: int | None = Form(None), sold_date: str | None = Form(None),
    delivered_date: str | None = Form(None), scheduled_date: str | None = Form(None),
    status: str = Form("Pending"), tag: str = Form(""), customer: str = Form(""),
    stock_num: str | None = Form(None), model: str | None = Form(None),
    new_used: str | None = Form(None), deal_type: str | None = Form(None),
    business_manager: str | None = Form(None), spot_sold: int = Form(0),
    discount_gt_200: str = Form("No"),  # kept as str from form, converted below
    aim_presentation: str = Form("X"),
    permaplate: int = Form(0), nitro_fill: int = Form(0), pulse: int = Form(0),
    finance_non_subvented: int = Form(0), warranty: int = Form(0), tire_wheel: int = Form(0),
    hold_amount: float = Form(0.0), aim_amount: float = Form(0.0), fi_pvr: float = Form(0.0),
    notes: str | None = Form(None), pay_date: str | None = Form(None), is_paid: int = Form(0),
    commission_override: str | None = Form(None),
    next: str | None = Form(None), db: AsyncSession = Depends(get_db),
):
    user_id = uid(request)
    settings = await get_or_create_settings(db, user_id)

    sold = parse_date(sold_date)
    if sold is None and not deal_id: sold = today()
    delivered = today() if bool(spot_sold) else parse_date(delivered_date)
    pay = parse_date(pay_date)
    sched = parse_date(scheduled_date)
    if status == "Scheduled" and sched is None: sched = today()
    if status != "Scheduled": sched = None
    if bool(is_paid) and pay is None: pay = today()

    dt = (deal_type or "").strip()
    if dt.lower() in ("f",): dt = "Finance"
    elif dt.lower() in ("c",): dt = "Cash/Sub-Vented"
    elif dt.lower() in ("l",): dt = "Lease"

    if bool(spot_sold): status = "Delivered"

    existing = None
    if deal_id:
        existing = (await db.execute(select(Deal).where(Deal.id == deal_id, Deal.user_id == user_id))).scalar_one_or_none()
        if not existing: return RedirectResponse(url="/deals", status_code=303)
        if delivered is None: delivered = existing.delivered_date

    deal_in = DealIn(
        sold_date=sold, delivered_date=delivered, scheduled_date=sched, status=status,
        tag=(tag or "").strip(), customer=customer.strip(),
        stock_num=(stock_num or "").strip(), model=(model or "").strip(),
        new_used=new_used or "", deal_type=dt, business_manager=(business_manager or ""),
        spot_sold=bool(spot_sold), discount_gt_200=(discount_gt_200 or "No").strip().lower() in ("yes","y","true","1"),
        aim_presentation=(aim_presentation or "X"),
        permaplate=bool(permaplate), nitro_fill=bool(nitro_fill), pulse=bool(pulse),
        finance_non_subvented=bool(dt in ("Finance","Lease") or finance_non_subvented),
        warranty=bool(warranty), tire_wheel=bool(tire_wheel),
        hold_amount=float(hold_amount or 0), aim_amount=float(aim_amount or 0), fi_pvr=float(fi_pvr or 0),
        notes=notes or "", pay_date=pay, is_paid=bool(is_paid),
    )
    uc, ao, th, tot = calc_commission(deal_in, settings)

    # If user provided a manual override, use it as total_deal_comm
    comm_ov: float | None = None
    if commission_override is not None and commission_override.strip() != "":
        try:
            comm_ov = float(commission_override.replace("$", "").replace(",", "").strip())
        except ValueError:
            comm_ov = None
    if comm_ov is not None:
        tot = comm_ov

    if deal_id:
        for k, v in deal_in.model_dump().items(): setattr(existing, k, v)
        existing.unit_comm = uc; existing.add_ons = ao; existing.trade_hold_comm = th; existing.total_deal_comm = tot
        existing.commission_override = comm_ov
    else:
        deal = Deal(**deal_in.model_dump(), user_id=user_id, unit_comm=uc, add_ons=ao, trade_hold_comm=th, total_deal_comm=tot, commission_override=comm_ov)
        db.add(deal)
    await db.commit()
    return RedirectResponse(url=(next or "/deals"), status_code=303)


@app.post("/deals/{deal_id}/toggle_paid")
async def toggle_paid(deal_id: int, request: Request, next: str | None = Form(None), db: AsyncSession = Depends(get_db)):
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id, Deal.user_id == uid(request)))).scalar_one_or_none()
    if not deal: return JSONResponse({"ok": False, "error": "Not found"}, status_code=404)
    deal.is_paid = not deal.is_paid
    if deal.is_paid and not deal.pay_date: deal.pay_date = today()
    await db.commit()
    if "application/json" in request.headers.get("accept", ""):
        return JSONResponse({"ok": True, "is_paid": deal.is_paid})
    return RedirectResponse(url=(next or "/deals"), status_code=303)


@app.post("/deals/{deal_id}/quick_update")
async def quick_update_deal(deal_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Inline field update — accepts JSON {field, value}, returns {ok, new_value}."""
    user_id = uid(request)
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id, Deal.user_id == user_id))).scalar_one_or_none()
    if not deal:
        return JSONResponse({"ok": False, "error": "Not found"}, status_code=404)
    body = await request.json()
    field = body.get("field", "")
    value = body.get("value", "")
    settings = await get_or_create_settings(db, user_id)

    ALLOWED = {"notes", "status", "tag", "sold_date", "delivered_date", "scheduled_date",
               "customer", "stock_num", "model", "new_used", "deal_type",
               "business_manager", "commission_override"}
    if field not in ALLOWED:
        return JSONResponse({"ok": False, "error": "Field not allowed"}, status_code=400)

    if field in ("sold_date", "delivered_date", "scheduled_date"):
        setattr(deal, field, parse_date(value) if value else None)
    elif field == "status":
        if value not in ("Pending", "Delivered", "Dead", "Scheduled"):
            return JSONResponse({"ok": False, "error": "Invalid status"}, status_code=400)
        setattr(deal, field, value)
        if value == "Delivered" and not deal.delivered_date:
            deal.delivered_date = deal.sold_date or today()
        if value == "Scheduled" and not deal.scheduled_date:
            deal.scheduled_date = today()
    elif field == "commission_override":
        if value == "" or value is None:
            deal.commission_override = None
        else:
            try:
                deal.commission_override = float(str(value).replace("$","").replace(",",""))
            except ValueError:
                return JSONResponse({"ok": False, "error": "Invalid number"}, status_code=400)
        # Recalc total
        deal_in = DealIn(**{c.key: getattr(deal, c.key) for c in deal.__table__.columns if c.key in DealIn.model_fields})
        uc, ao, th, tot = calc_commission(deal_in, settings)
        deal.total_deal_comm = deal.commission_override if deal.commission_override is not None else tot
    else:
        setattr(deal, field, value)

    await db.commit()
    return JSONResponse({"ok": True})


@app.post("/deals/{deal_id}/mark_delivered")
async def mark_delivered(deal_id: int, request: Request, redirect: str | None = Form(None), month: str | None = Form(None), db: AsyncSession = Depends(get_db)):
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id, Deal.user_id == uid(request)))).scalar_one_or_none()
    if not deal: return JSONResponse({"ok": False, "error": "Not found"}, status_code=404)
    deal.status = "Delivered"; deal.delivered_date = today()
    await db.commit()
    if "application/json" in request.headers.get("accept", ""):
        return JSONResponse({"ok": True, "status": "Delivered", "delivered_date": deal.delivered_date.isoformat()})
    return RedirectResponse(url=(redirect or (f"/?month={month}" if month else "/")), status_code=303)

@app.post("/deals/{deal_id}/mark_dead")
async def mark_dead(deal_id: int, request: Request, redirect: str | None = Form(None), month: str | None = Form(None), db: AsyncSession = Depends(get_db)):
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id, Deal.user_id == uid(request)))).scalar_one_or_none()
    if not deal: return JSONResponse({"ok": False, "error": "Not found"}, status_code=404)
    deal.status = "Dead"
    await db.commit()
    if "application/json" in request.headers.get("accept", ""):
        return JSONResponse({"ok": True, "status": "Dead"})
    return RedirectResponse(url=(redirect or (f"/?month={month}" if month else "/")), status_code=303)

# Backwards compat aliases
@app.post("/deals/{deal_id}/deliver")
async def deliver_old(deal_id: int, request: Request, month: str | None = Form(None), db: AsyncSession = Depends(get_db)):
    return await mark_delivered(deal_id, request, None, month, db)

@app.post("/deals/{deal_id}/dead")
async def dead_old(deal_id: int, request: Request, month: str | None = Form(None), db: AsyncSession = Depends(get_db)):
    return await mark_dead(deal_id, request, None, month, db)

@app.post("/deals/{deal_id}/delete")
async def deal_delete(deal_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id, Deal.user_id == uid(request)))).scalar_one_or_none()
    if not deal: return RedirectResponse(url="/deals", status_code=303)
    await db.delete(deal); await db.commit()
    return RedirectResponse(url="/deals", status_code=303)


# ════════════════════════════════════════════════
# DELIVERY BOARD
# ════════════════════════════════════════════════
@app.get("/delivery", response_class=HTMLResponse)
async def delivery_board(request: Request, db: AsyncSession = Depends(get_db)):
    user_id = uid(request)
    board = (await db.execute(
        select(Deal).where(Deal.user_id == user_id, Deal.on_delivery_board == True, Deal.status.notin_(["Delivered","Dead"]))
        .order_by(Deal.scheduled_date.asc().nullslast(), Deal.sold_date.asc().nullslast())
    )).scalars().all()
    prep = [d for d in board if not (d.gas_ready and d.inspection_ready and d.insurance_ready)]
    ready = [d for d in board if d.gas_ready and d.inspection_ready and d.insurance_ready]
    week_ago = today() - timedelta(days=7)
    delivered = (await db.execute(
        select(Deal).where(Deal.user_id == user_id, Deal.on_delivery_board == True, Deal.status == "Delivered", Deal.delivered_date >= week_ago)
        .order_by(Deal.delivered_date.desc())
    )).scalars().all()
    user = await _user(request, db)
    return templates.TemplateResponse("delivery_board.html", {"request": request, "user": user, "prep": prep, "ready": ready, "delivered": delivered, "total": len(prep)+len(ready), "overdue_reminders": await get_overdue_reminders(db, uid(request))})

@app.post("/delivery/{deal_id}/toggle")
async def delivery_toggle(deal_id: int, request: Request, field: str = Form(...), db: AsyncSession = Depends(get_db)):
    if field not in {"gas_ready","inspection_ready","insurance_ready"}: return RedirectResponse(url="/delivery", status_code=303)
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id, Deal.user_id == uid(request)))).scalar_one_or_none()
    if not deal: return JSONResponse({"ok": False}, status_code=404)
    setattr(deal, field, not getattr(deal, field)); await db.commit()
    if "application/json" in request.headers.get("accept", ""):
        return JSONResponse({"ok": True, "value": getattr(deal, field)})
    return RedirectResponse(url="/delivery", status_code=303)

@app.post("/delivery/{deal_id}/deliver")
async def delivery_deliver(deal_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id, Deal.user_id == uid(request)))).scalar_one_or_none()
    if not deal: return JSONResponse({"ok": False, "error": "Not found"}, status_code=404)
    deal.status = "Delivered"; deal.delivered_date = today(); await db.commit()
    if "application/json" in request.headers.get("accept", ""):
        return JSONResponse({"ok": True})
    return RedirectResponse(url="/delivery", status_code=303)

@app.post("/delivery/{deal_id}/remove")
async def delivery_remove(deal_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id, Deal.user_id == uid(request)))).scalar_one_or_none()
    if not deal: return JSONResponse({"ok": False}, status_code=404)
    deal.on_delivery_board = False; deal.gas_ready = False; deal.inspection_ready = False; deal.insurance_ready = False
    await db.commit()
    if "application/json" in request.headers.get("accept", ""):
        return JSONResponse({"ok": True})
    return RedirectResponse(url="/delivery", status_code=303)

@app.post("/delivery/{deal_id}/push")
async def delivery_push(deal_id: int, request: Request, next: str | None = Form(None), db: AsyncSession = Depends(get_db)):
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id, Deal.user_id == uid(request)))).scalar_one_or_none()
    if not deal: return RedirectResponse(url="/delivery", status_code=303)
    deal.on_delivery_board = True; await db.commit()
    return RedirectResponse(url=(next or "/delivery"), status_code=303)


# ════════════════════════════════════════════════
# CSV EXPORT
# ════════════════════════════════════════════════
@app.get("/reports/export")
async def export_csv(request: Request, month: str | None = None, db: AsyncSession = Depends(get_db)):
    user_id = uid(request)
    stmt = select(Deal).where(Deal.user_id == user_id).order_by(Deal.sold_date.desc().nullslast())
    if month:
        try:
            y, m = month.split("-"); d0 = date(int(y), int(m), 1); s, e = month_bounds(d0)
            stmt = stmt.where(or_(and_(Deal.sold_date >= s, Deal.sold_date < e), and_(Deal.delivered_date >= s, Deal.delivered_date < e)))
        except: pass
    deals = (await db.execute(stmt)).scalars().all()
    out = io.StringIO(); w = csv.writer(out)
    w.writerow(["Sold Date","Delivered Date","Customer","Stock #","Model","New/Used","F/C/L","F&I","Status","Tag","Spot","Discount>200","PermaPlate","Nitro Fill","Pulse","Finance","Warranty","Tire&Wheel","Aim","Hold Amount","Unit Comm","Add-ons","Trade Hold","Total Comm","Paid","Pay Date","Notes"])
    for d in deals:
        w.writerow([d.sold_date or "",d.delivered_date or "",d.customer,d.stock_num,d.model,d.new_used,d.deal_type,d.business_manager,d.status,d.tag,
                     "Y" if d.spot_sold else "N",d.discount_gt_200,"Y" if d.permaplate else "N","Y" if d.nitro_fill else "N",
                     "Y" if d.pulse else "N","Y" if d.finance_non_subvented else "N","Y" if d.warranty else "N","Y" if d.tire_wheel else "N",
                     d.aim_presentation,d.hold_amount,f"{d.unit_comm:.2f}",f"{d.add_ons:.2f}",f"{d.trade_hold_comm:.2f}",f"{d.total_deal_comm:.2f}",
                     "Y" if d.is_paid else "N",d.pay_date or "",d.notes or ""])
    out.seek(0)
    return StreamingResponse(iter([out.getvalue()]), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=commission-export-{month or 'all'}.csv"})


# ════════════════════════════════════════════════
# CSV IMPORT (with AI column mapping)
# ════════════════════════════════════════════════

# Known field targets for AI mapping
_IMPORT_FIELDS = {
    "customer": ["customer","customer name","name","buyer","client","purchaser","last name","cust name","cust"],
    "sold_date": ["sold date","sold","sale date","date sold","contract date","date","sell date","s date"],
    "delivered_date": ["delivered date","delivery date","del date","date delivered","deliver","del"],
    "scheduled_date": ["scheduled date","schedule date","appt date","appointment","sched"],
    "status": ["status","deal status","state"],
    "stock_num": ["stock #","stock number","stock","vin","unit #","unit number","stk","stk#","stk #","stock#"],
    "model": ["model","vehicle","car","description","year make model","ymm","vehicle model","make model"],
    "new_used": ["new/used","new used","type","n/u","condition","n","nu"],
    "deal_type": ["f/c/l","deal type","finance type","fcl","fin type","f","deal"],
    "business_manager": ["f&i","fi","business manager","finance manager","fi mgr","bm","fin mgr","f&i mgr"],
    "spot_sold": ["spot","spot sold","spot delivery","spotted"],
    "discount_gt_200": ["discount>200","discount over 200","discount","disc>200","over 200","disc"],
    "aim_presentation": ["aim","aim presentation","demo"],
    "permaplate": ["permaplate","perma plate","perm"],
    "nitro_fill": ["nitro fill","nitro","nitrogen","nitrofill"],
    "pulse": ["pulse","pulse protection"],
    "finance_non_subvented": ["finance","finance product","non subvented","non-subvented"],
    "warranty": ["warranty","extended warranty","ext warranty","ew"],
    "tire_wheel": ["tire&wheel","tire wheel","tire & wheel","t&w","tires"],
    "hold_amount": ["hold amount","hold","holdback","hold $","gross hold"],
    "aim_amount": ["aim amount","aim $","aim gross"],
    "fi_pvr": ["fi pvr","pvr","per vehicle retail","f&i pvr"],
    "is_paid": ["paid","payment","pay status","bb"],
    "pay_date": ["pay date","paid date","payment date","check date"],
    "notes": ["notes","note","comments","comment","remarks","memo"],
    "tag": ["tag","deal tag","category"],
}

def _smart_map_columns(csv_headers: list[str]) -> dict[str, str]:
    """
    Map CSV column headers to internal field names using fuzzy matching.
    Returns {csv_header: internal_field_name}.
    Falls back to exact/fuzzy keyword matching — no API call needed.
    """
    mapping = {}
    used_fields = set()
    headers_lower = {h: h.strip().lower() for h in csv_headers}

    for csv_col, col_lower in headers_lower.items():
        best_field = None
        best_score = 0.0

        for field, keywords in _IMPORT_FIELDS.items():
            if field in used_fields:
                continue
            for kw in keywords:
                # Exact match
                if col_lower == kw:
                    best_field = field
                    best_score = 1.0
                    break
                # Fuzzy match
                score = difflib.SequenceMatcher(None, col_lower, kw).ratio()
                if score > best_score and score > 0.7:
                    best_score = score
                    best_field = field
            if best_score == 1.0:
                break

        if best_field and best_score >= 0.7:
            mapping[csv_col] = best_field
            used_fields.add(best_field)

    return mapping


def _parse_row(row: dict, mapping: dict[str, str], settings) -> DealIn | None:
    """Convert a raw CSV row using the column mapping into a DealIn."""
    def _get(field): return (row.get(
        next((c for c, f in mapping.items() if f == field), ""), ""
    ) or "").strip()

    def _yn(val): return val.lower() in ("y","yes","1","true","x") if val else False
    def _yn_field(field): return _yn(_get(field))

    cust = _get("customer")
    if not cust:
        return None

    sold = parse_date(_get("sold_date"))
    delivered = parse_date(_get("delivered_date"))
    sched = parse_date(_get("scheduled_date"))

    st = _get("status") or "Pending"
    if st.lower() in ("delivered","d","del"): st = "Delivered"
    elif st.lower() in ("dead","x","lost"): st = "Dead"
    elif st.lower() in ("scheduled","sched","appt"): st = "Scheduled"
    else: st = "Pending"

    nu = _get("new_used")
    if nu.lower() in ("n","new"): nu = "New"
    elif nu.lower() in ("u","used"): nu = "Used"
    else: nu = nu.title() if nu else ""

    dt = _get("deal_type")
    if dt.lower() in ("f","finance","fin"): dt = "Finance"
    elif dt.lower() in ("c","cash","cash/sub-vented","sub","subvented"): dt = "Cash/Sub-Vented"
    elif dt.lower() in ("l","lease"): dt = "Lease"

    aim_raw = _get("aim_presentation")
    if aim_raw.lower() in ("y","yes","1"): aim = "Yes"
    elif aim_raw.lower() in ("n","no","0"): aim = "No"
    else: aim = "X"

    try: hold = float(_get("hold_amount").replace("$","").replace(",","") or 0)
    except: hold = 0.0
    try: aim_amt = float(_get("aim_amount").replace("$","").replace(",","") or 0)
    except: aim_amt = 0.0
    try: fi_pvr = float(_get("fi_pvr").replace("$","").replace(",","") or 0)
    except: fi_pvr = 0.0

    fin = _yn_field("finance_non_subvented") or dt in ("Finance","Lease")
    discount = _yn_field("discount_gt_200")
    spot = _yn_field("spot_sold")

    if spot and not delivered: delivered = sold or today()
    if spot: st = "Delivered"

    return DealIn(
        sold_date=sold, delivered_date=delivered, scheduled_date=sched,
        status=st, tag=_get("tag"), customer=cust,
        stock_num=_get("stock_num"), model=_get("model"),
        new_used=nu, deal_type=dt, business_manager=_get("business_manager"),
        spot_sold=spot, discount_gt_200=discount, aim_presentation=aim,
        permaplate=_yn_field("permaplate"), nitro_fill=_yn_field("nitro_fill"),
        pulse=_yn_field("pulse"), finance_non_subvented=fin,
        warranty=_yn_field("warranty"), tire_wheel=_yn_field("tire_wheel"),
        hold_amount=hold, aim_amount=aim_amt, fi_pvr=fi_pvr,
        notes=_get("notes"),
        pay_date=parse_date(_get("pay_date")),
        is_paid=_yn_field("is_paid"),
    )


@app.get("/import", response_class=HTMLResponse)
async def import_page(request: Request, db: AsyncSession = Depends(get_db)):
    user = await _user(request, db)
    return templates.TemplateResponse("import.html", {
        "request": request, "user": user, "result": None,
        "preview": None, "mapping": None,
    })


def _find_header_row(text: str) -> tuple[list[str], list[dict]]:
    """
    Find the real header row in a CSV by skipping blank/empty leading rows.
    Returns (headers, data_rows).
    """
    raw_rows = list(csv.reader(io.StringIO(text)))
    header_idx = 0
    for i, row in enumerate(raw_rows):
        # A real header row has at least 2 non-empty cells
        non_empty = [c.strip() for c in row if c.strip()]
        if len(non_empty) >= 2:
            header_idx = i
            break

    headers = [h.strip() for h in raw_rows[header_idx]]
    data_rows = []
    for row in raw_rows[header_idx + 1:]:
        if not any(c.strip() for c in row):
            continue  # skip blank rows
        # Pad or truncate row to match header length
        padded = list(row) + [""] * max(0, len(headers) - len(row))
        data_rows.append(dict(zip(headers, padded[:len(headers)])))

    return headers, data_rows


@app.post("/import/preview", response_class=HTMLResponse)
async def import_preview(request: Request, file: UploadFile = File(...), db: AsyncSession = Depends(get_db)):
    """Step 1: Upload CSV, detect columns, show mapping preview before committing."""

    user = await _user(request, db)
    raw = await file.read()
    text = raw.decode("utf-8-sig")

    headers, rows = _find_header_row(text)

    mapping = _smart_map_columns(headers)

    # Build preview of first 5 rows
    preview_rows = []
    for row in rows[:5]:
        deal = _parse_row(row, mapping, None)
        if deal:
            preview_rows.append({
                "customer": deal.customer,
                "sold_date": str(deal.sold_date or ""),
                "model": deal.model,
                "status": deal.status,
                "new_used": deal.new_used,
                "deal_type": deal.deal_type,
            })

    # Build sample values per column (first 3 non-empty values)
    sample_values: dict[str, list[str]] = {}
    for h in headers:
        vals = []
        for row in rows:
            v = (row.get(h) or "").strip()
            if v and v not in vals:
                vals.append(v)
            if len(vals) >= 3:
                break
        sample_values[h] = vals

    # Store raw CSV in session via hidden field (base64 for safety)
    csv_b64 = base64.b64encode(raw).decode()
    fname = file.filename or "upload.csv"

    return templates.TemplateResponse("import.html", {
        "request": request, "user": user, "result": None,
        "preview": preview_rows,
        "mapping": mapping,
        "csv_headers": list(headers),
        "all_fields": list(_IMPORT_FIELDS.keys()),
        "total_rows": len(rows),
        "csv_b64": csv_b64,
        "filename": fname,
        "sample_values": sample_values,
    })


@app.post("/import/review", response_class=HTMLResponse)
async def import_review(request: Request, db: AsyncSession = Depends(get_db)):
    """Step 2: Show all parsed rows as an editable table before final import."""
    form = await request.form()
    user = await _user(request, db)

    csv_b64 = form.get("csv_b64", "")
    fname = form.get("filename", "upload.csv")
    if not csv_b64:
        return RedirectResponse(url="/import", status_code=303)

    raw = base64.b64decode(csv_b64)
    text = raw.decode("utf-8-sig")
    headers, rows = _find_header_row(text)

    # Rebuild mapping from form
    mapping = {}
    for h in headers:
        fv = form.get(f"map_{h}", "")
        if fv:
            mapping[h] = fv
    if not mapping:
        mapping = _smart_map_columns(headers)

    # Parse all rows into editable deals
    deal_rows = []
    for i, row in enumerate(rows):
        deal = _parse_row(row, mapping, None)
        if deal:
            deal_rows.append({
                "idx": i,
                "customer": deal.customer,
                "sold_date": str(deal.sold_date or ""),
                "delivered_date": str(deal.delivered_date or ""),
                "scheduled_date": str(deal.scheduled_date or ""),
                "status": deal.status,
                "model": deal.model,
                "stock_num": deal.stock_num,
                "new_used": deal.new_used,
                "deal_type": deal.deal_type,
                "notes": deal.notes or "",
            })

    deals_json = _json.dumps(deal_rows)

    return templates.TemplateResponse("import_review.html", {
        "request": request, "user": user,
        "deal_rows": deal_rows,
        "deals_json": deals_json,
        "csv_b64": csv_b64,
        "filename": fname,
        "total": len(deal_rows),
    })


@app.post("/import", response_class=HTMLResponse)
async def import_csv(request: Request, db: AsyncSession = Depends(get_db)):
    """Step 3: Final import using per-row overrides from the review step."""
    form = await request.form()
    user_id = uid(request)
    user = await _user(request, db)
    settings = await get_or_create_settings(db, user_id)

    csv_b64 = form.get("csv_b64", "")
    overrides_json = form.get("overrides_json", "[]")
    skip_indices_raw = form.getlist("skip_idx")
    skip_indices = set(int(x) for x in skip_indices_raw if x.isdigit())

    if not csv_b64:
        return templates.TemplateResponse("import.html", {
            "request": request, "user": user,
            "result": {"imported": 0, "skipped": 0, "errors": ["No CSV data found. Please re-upload."]},
            "preview": None, "mapping": None, "sample_values": {},
        })

    try:
        overrides = {int(k): v for k, v in _json.loads(overrides_json).items()}
    except Exception:
        overrides = {}

    raw = base64.b64decode(csv_b64)
    text = raw.decode("utf-8-sig")
    headers, rows = _find_header_row(text)
    mapping = _smart_map_columns(headers)

    import_batch_id = f"imp_{secrets.token_hex(8)}_{_utcnow().strftime('%Y%m%d%H%M%S')}"
    imported = skipped = 0
    errors = []

    # Pre-load existing stock numbers for duplicate detection (normalized to uppercase)
    existing_stocks = set(
        r[0].strip().upper() for r in (await db.execute(
            select(Deal.stock_num).where(Deal.user_id == user_id, Deal.stock_num.isnot(None), Deal.stock_num != "")
        )).all() if r[0]
    )
    duplicates_skipped = 0

    for i, row in enumerate(rows):
        if i in skip_indices:
            skipped += 1
            continue
        try:
            deal_in = _parse_row(row, mapping, settings)
            if deal_in is None:
                skipped += 1
                continue
            # Duplicate detection — skip if stock number already exists (case-insensitive)
            if deal_in.stock_num and deal_in.stock_num.strip() and deal_in.stock_num.strip().upper() in existing_stocks:
                skipped += 1
                duplicates_skipped += 1
                continue
            # Apply per-row overrides from the review editor
            ov = overrides.get(i, {})
            if "status" in ov and ov["status"]:
                deal_in.status = ov["status"]
            if "sold_date" in ov and ov["sold_date"]:
                deal_in.sold_date = parse_date(ov["sold_date"])
            if "delivered_date" in ov and ov["delivered_date"]:
                deal_in.delivered_date = parse_date(ov["delivered_date"])
            if "scheduled_date" in ov and ov["scheduled_date"]:
                deal_in.scheduled_date = parse_date(ov["scheduled_date"])
            if "notes" in ov:
                deal_in.notes = ov["notes"]
            # Auto-fill delivered_date if status=Delivered and missing
            if deal_in.status == "Delivered" and not deal_in.delivered_date:
                deal_in.delivered_date = deal_in.sold_date or today()

            uc, ao, th, tot = calc_commission(deal_in, settings)
            db.add(Deal(
                **deal_in.model_dump(),
                user_id=user_id,
                unit_comm=uc, add_ons=ao, trade_hold_comm=th, total_deal_comm=tot,
                import_batch_id=import_batch_id,
            ))
            imported += 1
        except Exception as e:
            errors.append(f"Row {i+2}: {e}")

    try:
        await db.commit()
    except Exception as e:
        errors.append(f"Database error: {e}")
        imported = 0
        import_batch_id = None

    return templates.TemplateResponse("import.html", {
        "request": request, "user": user,
        "result": {
            "imported": imported, "skipped": skipped, "errors": errors,
            "duplicates_skipped": duplicates_skipped,
            "batch_id": import_batch_id if imported > 0 else None,
            "filename": form.get("filename", "upload.csv"),
        },
        "preview": None, "mapping": None, "sample_values": {},
    })


# ════════════════════════════════════════════════
# BULK DEAL MANAGEMENT
# ════════════════════════════════════════════════

@app.post("/import/undo/{batch_id}")
async def undo_import(batch_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    """Delete all deals from a specific import batch."""
    user_id = uid(request)
    result = await db.execute(
        select(Deal).where(Deal.user_id == user_id, Deal.import_batch_id == batch_id)
    )
    deals = result.scalars().all()
    count = len(deals)
    for deal in deals:
        await db.delete(deal)
    await db.commit()
    return RedirectResponse(
        url=f"/import?undone={count}&batch={batch_id}",
        status_code=303
    )


@app.get("/import/history", response_class=HTMLResponse)
async def import_history(request: Request, db: AsyncSession = Depends(get_db)):
    """Show all past import batches with undo option."""
    user_id = uid(request)
    # Get distinct batch IDs with counts
    rows = (await db.execute(
        select(
            Deal.import_batch_id,
            func.count(Deal.id).label("count"),
            func.min(Deal.sold_date).label("earliest"),
            func.max(Deal.sold_date).label("latest"),
        )
        .where(Deal.user_id == user_id, Deal.import_batch_id.isnot(None))
        .group_by(Deal.import_batch_id)
        .order_by(Deal.import_batch_id.desc())
    )).all()

    batches = []
    for row in rows:
        batch_id = row[0]
        # Extract timestamp from batch ID format: imp_XXXXXXXX_YYYYMMDDHHMMSS
        try:
            ts_str = batch_id.split("_")[-1]
            ts = datetime.strptime(ts_str, "%Y%m%d%H%M%S")
            imported_at = ts.strftime("%b %d, %Y at %I:%M %p")
        except Exception:
            imported_at = "Unknown"
        batches.append({
            "batch_id": batch_id,
            "count": row[1],
            "earliest": row[2],
            "latest": row[3],
            "imported_at": imported_at,
        })

    user = await _user(request, db)
    return templates.TemplateResponse("import.html", {
        "request": request, "user": user,
        "result": None, "preview": None, "mapping": None,
        "sample_values": {}, "batches": batches,
        "show_history": True,
    })


@app.post("/deals/bulk-delete")
async def bulk_delete_deals(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Delete multiple selected deals by ID."""
    user_id = uid(request)
    form = await request.form()
    deal_ids = form.getlist("deal_ids")
    redirect_url = form.get("redirect", "/deals")
    if not deal_ids:
        return RedirectResponse(url=redirect_url, status_code=303)
    count = 0
    for did in deal_ids:
        try:
            deal = (await db.execute(
                select(Deal).where(Deal.id == int(did), Deal.user_id == user_id)
            )).scalar_one_or_none()
            if deal:
                await db.delete(deal)
                count += 1
        except Exception:
            pass
    await db.commit()
    return RedirectResponse(url=redirect_url, status_code=303)


# ════════════════════════════════════════════════
# REMINDERS
# ════════════════════════════════════════════════

@app.get("/reminders", response_class=HTMLResponse)
async def reminders_page(request: Request, db: AsyncSession = Depends(get_db)):
    user_id = uid(request)
    reminders = (await db.execute(
        select(Reminder).where(Reminder.user_id == user_id).order_by(Reminder.is_done, Reminder.due_date.nulls_last(), Reminder.created_at.desc())
    )).scalars().all()
    return templates.TemplateResponse("reminders.html", {"request": request, "reminders": reminders, "today": today(), "overdue_reminders": await get_overdue_reminders(db, uid(request))})

@app.post("/reminders/save")
async def reminder_save(
    request: Request,
    reminder_id: int | None = Form(None),
    title: str = Form(""),
    body: str = Form(""),
    due_date: str | None = Form(None),
    db: AsyncSession = Depends(get_db),
):
    user_id = uid(request)
    due = parse_date(due_date) if due_date else None
    if reminder_id:
        r = (await db.execute(select(Reminder).where(Reminder.id == reminder_id, Reminder.user_id == user_id))).scalar_one_or_none()
        if r:
            r.title = title.strip(); r.body = body.strip(); r.due_date = due
    else:
        r = Reminder(user_id=user_id, title=title.strip(), body=body.strip(), due_date=due)
        db.add(r)
    await db.commit()
    await db.refresh(r)
    return JSONResponse({"ok": True, "id": r.id, "title": r.title, "body": r.body,
                         "due_date": r.due_date.isoformat() if r.due_date else None,
                         "is_done": r.is_done})

@app.post("/reminders/{reminder_id}/toggle")
async def reminder_toggle(reminder_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    r = (await db.execute(select(Reminder).where(Reminder.id == reminder_id, Reminder.user_id == uid(request)))).scalar_one_or_none()
    if not r: return JSONResponse({"ok": False}, status_code=404)
    r.is_done = not r.is_done
    await db.commit()
    return JSONResponse({"ok": True, "is_done": r.is_done})

@app.post("/reminders/{reminder_id}/delete")
async def reminder_delete(reminder_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    r = (await db.execute(select(Reminder).where(Reminder.id == reminder_id, Reminder.user_id == uid(request)))).scalar_one_or_none()
    if r: await db.delete(r); await db.commit()
    return JSONResponse({"ok": True})

# ════════════════════════════════════════════════
# PAY PLAN
# ════════════════════════════════════════════════
@app.get("/payplan", response_class=HTMLResponse)
async def payplan_get(request: Request, db: AsyncSession = Depends(get_db)):
    # Note: fi_pvr and aim_amount are stored on deals for reference/reporting
    # but are not currently used in commission calculation (payplan.py).
    # They can be added to calc_commission() in the future if the pay plan changes.
    s = await get_or_create_settings(db, uid(request))
    user = await _user(request, db)
    return templates.TemplateResponse("payplan.html", {"request": request, "user": user, "s": s, "overdue_reminders": await get_overdue_reminders(db, uid(request))})

@app.post("/payplan")
async def payplan_post(
    request: Request,
    unit_comm_discount_le_200: float = Form(...), unit_comm_discount_gt_200: float = Form(...),
    permaplate: float = Form(...), nitro_fill: float = Form(...), pulse: float = Form(...),
    finance_non_subvented: float = Form(...), warranty: float = Form(...), tire_wheel: float = Form(...),
    hourly_rate_ny_offset: float = Form(...),
    new_volume_bonus_15_16: float = Form(...), new_volume_bonus_17_18: float = Form(...),
    new_volume_bonus_19_20: float = Form(...), new_volume_bonus_21_24: float = Form(...),
    new_volume_bonus_25_plus: float = Form(...),
    used_volume_bonus_8_10: float = Form(...), used_volume_bonus_11_12: float = Form(...),
    used_volume_bonus_13_plus: float = Form(...),
    spot_bonus_5_9: float = Form(...), spot_bonus_10_12: float = Form(...),
    spot_bonus_13_plus: float = Form(...),
    quarterly_bonus_threshold_units: int = Form(...), quarterly_bonus_amount: float = Form(...),
    db: AsyncSession = Depends(get_db),
):
    s = await get_or_create_settings(db, uid(request))
    for f in ["unit_comm_discount_le_200","unit_comm_discount_gt_200","permaplate","nitro_fill","pulse",
              "finance_non_subvented","warranty","tire_wheel","hourly_rate_ny_offset",
              "new_volume_bonus_15_16","new_volume_bonus_17_18","new_volume_bonus_19_20",
              "new_volume_bonus_21_24","new_volume_bonus_25_plus",
              "used_volume_bonus_8_10","used_volume_bonus_11_12","used_volume_bonus_13_plus",
              "spot_bonus_5_9","spot_bonus_10_12","spot_bonus_13_plus",
              "quarterly_bonus_threshold_units","quarterly_bonus_amount"]:
        setattr(s, f, locals()[f])
    await db.commit()
    return RedirectResponse(url="/payplan", status_code=303)

# Backwards compat
@app.get("/settings")
async def _sr(): return RedirectResponse(url="/payplan", status_code=307)
@app.post("/settings")
async def _sp(): return RedirectResponse(url="/payplan", status_code=303)
