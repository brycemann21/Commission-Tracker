
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

from fastapi import FastAPI, Request, Form, Depends, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy import select, func, or_, and_, text as sa_text

from .models import Base, User, Deal, Settings, Goal, UserSession, PasswordResetToken, Reminder, Dealership, Invite, Post, PostUpvote, PollOption, PollVote, DealerProduct, DealProduct, DealerBonus
from .schemas import DealIn
from .payplan import CommissionEngine, MonthStats, _pct
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
    pool_size=2,           # Keep 2 warm connections
    max_overflow=3,        # Allow up to 5 total under burst
    pool_recycle=120,      # Recycle connections every 2 min (serverless-friendly)
    pool_pre_ping=True,    # Verify connection is alive before use
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

# ── GZip compression — reduces HTML/JSON payloads by ~70% ──
from fastapi.middleware.gzip import GZipMiddleware
app.add_middleware(GZipMiddleware, minimum_size=1000)

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

# Serve service worker from root path so it can control the entire site scope
@app.get("/sw.js")
async def service_worker():
    sw_path = os.path.join(os.path.dirname(__file__), "static", "sw.js")
    return StreamingResponse(
        open(sw_path, "rb"),
        media_type="application/javascript",
        headers={"Cache-Control": "no-cache", "Service-Worker-Allowed": "/"},
    )


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
PUBLIC_PREFIXES = ("/join/",)  # Invite links must be accessible without login

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
    if path.startswith("/static") or path in ("/sw.js",):
        return await call_next(request)

    token = get_session_token(request)

    # Session check uses raw asyncpg (no SQLAlchemy, pgBouncer-safe)
    # Returns (user_id, dealership_id, role) or None
    session_info = await get_user_id_from_session(None, token)

    # For public pages: auto-redirect to dashboard if already logged in
    is_invite = any(path.startswith(p) for p in PUBLIC_PREFIXES)
    if path in PUBLIC_PATHS:
        if session_info is not None:
            return RedirectResponse(url="/", status_code=303)
        return await call_next(request)
    # Invite links: accessible to anyone — logged-in or not
    if is_invite:
        return await call_next(request)

    # Protected pages
    if session_info is None:
        dest = request.url.path
        if request.url.query:
            dest += f"?{request.url.query}"
        return RedirectResponse(url=f"/login?next={dest}", status_code=303)

    uid_val, dealership_id_val, role_val, is_super_admin_val = session_info
    request.state.user_id = uid_val
    request.state.dealership_id = dealership_id_val
    request.state.role = role_val
    request.state.is_super_admin = is_super_admin_val

    # Admin mode toggle — super admins can switch between platform view and salesperson view
    request.state.admin_mode = is_super_admin_val and request.cookies.get("admin_mode") == "1"
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

def user_dealership_id(request: Request) -> int | None:
    """Get the current user's dealership_id from request state."""
    return getattr(request.state, "dealership_id", None)

def user_role(request: Request) -> str:
    """Get the current user's role from request state."""
    return getattr(request.state, "role", "salesperson")

def is_super_admin(request: Request) -> bool:
    """Check if the current user is the platform super admin."""
    return getattr(request.state, "is_super_admin", False)

def is_admin_mode(request: Request) -> bool:
    """Check if super admin has the platform admin view toggled on."""
    return getattr(request.state, "admin_mode", False)

async def _user(request: Request, db: AsyncSession) -> User:
    return (await db.execute(select(User).where(User.id == uid(request)))).scalar_one()


async def _create_dealership_for_user(
    db: AsyncSession, user: User, name_hint: str = "",
    google_place_id: str = "", address: str = "", phone: str = "",
) -> User:
    """Create a new dealership and make the user its admin.
    Called during registration when a user signs up without an invite.
    New dealerships start as is_active=False (pending super-admin approval)."""
    import re as _re
    dealer_name = name_hint or user.display_name or user.username
    if not any(kw in dealer_name.lower() for kw in ("dealer", "motor", "auto", "car", "toyota", "honda", "ford", "chevy", "bmw", "mercedes", "kia", "hyundai", "nissan", "subaru", "mazda")):
        dealer_name = f"{dealer_name}'s Dealership"
    # Generate a URL-safe slug
    base_slug = _re.sub(r'[^a-z0-9]+', '-', (dealer_name or "dealer").lower()).strip('-')[:60]
    slug = base_slug
    i = 1
    while (await db.execute(select(Dealership).where(Dealership.slug == slug))).scalar_one_or_none():
        slug = f"{base_slug}-{i}"
        i += 1

    # Check if a dealership with this Google Place ID already exists
    existing_dealer = None
    if google_place_id:
        existing_dealer = (await db.execute(
            select(Dealership).where(Dealership.google_place_id == google_place_id)
        )).scalar_one_or_none()

    if existing_dealer:
        # Dealership already exists from Google Places — join it as salesperson (pending verification)
        user.dealership_id = existing_dealer.id
        user.role = "salesperson"
        user.is_verified = False
        await db.commit()
        await db.refresh(user)
        logger.info(f"User {user.id} joined existing dealership '{existing_dealer.name}' (id={existing_dealer.id}) via Google Place ID")
        return user

    dealership = Dealership(
        name=dealer_name,
        slug=slug,
        is_active=False,  # Pending super-admin approval
        subscription_status="pending",
        google_place_id=google_place_id or None,
        address=address or None,
        phone=phone or None,
    )
    db.add(dealership)
    await db.commit()
    await db.refresh(dealership)

    # Assign user as admin of this dealership
    user.dealership_id = dealership.id
    user.role = "admin"
    user.is_verified = True  # The creator is auto-verified
    await db.commit()
    await db.refresh(user)

    logger.info(f"Created dealership '{dealer_name}' (id={dealership.id}, active=False) for user {user.id}")
    return user


def _require_admin(request: Request):
    """Raise 403 if the current user is not an admin or super_admin."""
    if is_super_admin(request):
        return
    if user_role(request) != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

def _require_admin_or_manager(request: Request):
    """Raise 403 if the current user is not an admin, manager, or super_admin."""
    if is_super_admin(request):
        return
    if user_role(request) not in ("admin", "manager"):
        raise HTTPException(status_code=403, detail="Manager access required")

def _require_super_admin(request: Request):
    """Raise 403 if the current user is not the platform super admin."""
    if not is_super_admin(request):
        raise HTTPException(status_code=403, detail="Platform admin access required")


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
    # Acquire a connection from the shared pool (initializes pool on cold start)
    from .auth import _get_pg_pool, _release_pg_conn
    pool = await _get_pg_pool()
    if not pool:
        logger.error("Failed to create asyncpg pool for migrations")
        return

    conn = await pool.acquire()
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

        # ════════════════════════════════════════════════════════════════
        # PHASE 1 — Multi-tenancy migration
        # All DDL is idempotent (IF NOT EXISTS / ADD COLUMN IF NOT EXISTS)
        # ════════════════════════════════════════════════════════════════

        # 1. Create dealerships table
        try:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS dealerships (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(200) NOT NULL,
                    slug VARCHAR(80) UNIQUE NOT NULL,
                    timezone VARCHAR(64) DEFAULT 'America/New_York',
                    created_at TIMESTAMP DEFAULT NOW(),
                    is_active BOOLEAN DEFAULT true,
                    stripe_customer_id VARCHAR(128),
                    stripe_subscription_id VARCHAR(128),
                    subscription_status VARCHAR(32) DEFAULT 'trialing',
                    max_users INTEGER DEFAULT 5
                )
            """)
        except Exception:
            pass

        # 2. Add dealership_id and role to users
        for col, typ in [
            ("dealership_id", "INTEGER"),
            ("role", "VARCHAR(24) DEFAULT 'salesperson'"),
        ]:
            try:
                await conn.execute(f"ALTER TABLE users ADD COLUMN IF NOT EXISTS {col} {typ}")
            except Exception:
                pass

        # 2b. Add Google Places fields to dealerships (Deploy 2)
        for col, typ in [
            ("google_place_id", "VARCHAR(200)"),
            ("address", "VARCHAR(300)"),
            ("phone", "VARCHAR(30)"),
        ]:
            try:
                await conn.execute(f"ALTER TABLE dealerships ADD COLUMN IF NOT EXISTS {col} {typ}")
            except Exception:
                pass

        # 3. Add dealership_id to data tables
        for tbl in ("deals", "settings", "goals", "reminders"):
            try:
                await conn.execute(f"ALTER TABLE {tbl} ADD COLUMN IF NOT EXISTS dealership_id INTEGER")
            except Exception:
                pass

        # 4. Create invites table
        try:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS invites (
                    id SERIAL PRIMARY KEY,
                    token VARCHAR(128) UNIQUE NOT NULL,
                    dealership_id INTEGER NOT NULL,
                    email VARCHAR(254),
                    role VARCHAR(24) DEFAULT 'salesperson',
                    created_by INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT NOW(),
                    expires_at TIMESTAMP NOT NULL,
                    used BOOLEAN DEFAULT false,
                    used_by INTEGER
                )
            """)
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_invites_token ON invites(token)")
        except Exception:
            pass

        # 5. Auto-migrate existing data: if there are users without a dealership,
        #    create a "default" dealership and assign everything to it.
        #    This ensures zero downtime — existing data keeps working.
        try:
            orphan_count = await conn.fetchval(
                "SELECT COUNT(*) FROM users WHERE dealership_id IS NULL"
            )
            if orphan_count and orphan_count > 0:
                # Check if a default dealership already exists
                default_d = await conn.fetchval(
                    "SELECT id FROM dealerships WHERE slug = 'default' LIMIT 1"
                )
                if not default_d:
                    default_d = await conn.fetchval("""
                        INSERT INTO dealerships (name, slug, subscription_status)
                        VALUES ('My Dealership', 'default', 'free')
                        RETURNING id
                    """)

                # Assign all orphaned users to the default dealership as admin
                await conn.execute(
                    "UPDATE users SET dealership_id = $1, role = 'admin' WHERE dealership_id IS NULL",
                    default_d
                )

                # Also fix any users who got the dealership but not the admin role
                # (edge case: columns added with defaults before UPDATE ran)
                await conn.execute(
                    "UPDATE users SET role = 'admin' WHERE dealership_id = $1 AND (role IS NULL OR role = 'salesperson')",
                    default_d
                )

                # Assign all orphaned data to the default dealership
                for tbl in ("deals", "settings", "goals", "reminders"):
                    try:
                        await conn.execute(
                            f"UPDATE {tbl} SET dealership_id = $1 WHERE dealership_id IS NULL",
                            default_d
                        )
                    except Exception:
                        pass

                # Also migrate settings: if settings have user_id but no dealership_id,
                # copy the dealership_id from the user
                try:
                    await conn.execute("""
                        UPDATE settings s
                        SET dealership_id = u.dealership_id
                        FROM users u
                        WHERE s.user_id = u.id AND s.dealership_id IS NULL AND u.dealership_id IS NOT NULL
                    """)
                except Exception:
                    pass

                logger.info(f"Multi-tenancy migration: assigned {orphan_count} user(s) to dealership {default_d}")
        except Exception as e:
            logger.warning(f"Multi-tenancy auto-migration error: {e}")

        # 6. Indexes for multi-tenancy queries
        try:
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_users_dealership ON users(dealership_id)")
        except Exception: pass
        try:
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_deals_dealership ON deals(dealership_id)")
        except Exception: pass
        try:
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_deals_dealership_user ON deals(dealership_id, user_id)")
        except Exception: pass
        try:
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_settings_dealership ON settings(dealership_id)")
        except Exception: pass
        try:
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_goals_dealership ON goals(dealership_id)")
        except Exception: pass
        try:
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_reminders_dealership ON reminders(dealership_id, user_id)")
        except Exception: pass

        # 7. Ensure at least one admin exists per dealership
        # If a dealership has no admins (e.g. migration edge case), promote the first user
        try:
            dealerships_without_admin = await conn.fetch("""
                SELECT d.id FROM dealerships d
                WHERE NOT EXISTS (
                    SELECT 1 FROM users u WHERE u.dealership_id = d.id AND u.role = 'admin'
                )
            """)
            for row in dealerships_without_admin:
                first_user = await conn.fetchval(
                    "SELECT id FROM users WHERE dealership_id = $1 ORDER BY id ASC LIMIT 1",
                    row["id"]
                )
                if first_user:
                    await conn.execute(
                        "UPDATE users SET role = 'admin' WHERE id = $1",
                        first_user
                    )
                    logger.info(f"Promoted user {first_user} to admin for dealership {row['id']}")
        except Exception as e:
            logger.warning(f"Admin promotion check error: {e}")

        # 8. Super admin + verification columns
        for col, typ in [
            ("is_super_admin", "BOOLEAN DEFAULT false"),
            ("is_verified", "BOOLEAN DEFAULT false"),
            ("verified_by", "INTEGER"),
            ("verified_at", "TIMESTAMP"),
        ]:
            try:
                await conn.execute(f"ALTER TABLE users ADD COLUMN IF NOT EXISTS {col} {typ}")
            except Exception:
                pass

        # 9. Set the first ever user (id=1 or lowest id) as super_admin — this is you (the platform owner)
        # Only runs if no super_admin exists yet
        try:
            has_super = await conn.fetchval("SELECT COUNT(*) FROM users WHERE is_super_admin = true")
            if not has_super or has_super == 0:
                first_uid = await conn.fetchval("SELECT id FROM users ORDER BY id ASC LIMIT 1")
                if first_uid:
                    await conn.execute(
                        "UPDATE users SET is_super_admin = true, is_verified = true, role = 'admin' WHERE id = $1",
                        first_uid
                    )
                    logger.info(f"Designated user {first_uid} as platform super admin")
        except Exception as e:
            logger.warning(f"Super admin setup error: {e}")

        # 10. Community tables + notification tracking
        for col, typ in [("brand", "VARCHAR(80)"), ("state", "VARCHAR(2)")]:
            try:
                await conn.execute(f"ALTER TABLE dealerships ADD COLUMN IF NOT EXISTS {col} {typ}")
            except Exception:
                pass
        try:
            await conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_community_visit TIMESTAMP")
        except Exception:
            pass

        try:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS posts (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    dealership_id INTEGER,
                    post_type VARCHAR(16) NOT NULL,
                    anonymity VARCHAR(16) DEFAULT 'brand',
                    title VARCHAR(200) DEFAULT '',
                    body TEXT DEFAULT '',
                    payload TEXT DEFAULT '{}',
                    upvote_count INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT NOW(),
                    is_deleted BOOLEAN DEFAULT false
                )
            """)
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(created_at DESC)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_posts_dealership ON posts(dealership_id)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_posts_type ON posts(post_type)")
        except Exception:
            pass

        try:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS post_upvotes (
                    id SERIAL PRIMARY KEY,
                    post_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT NOW(),
                    UNIQUE(post_id, user_id)
                )
            """)
        except Exception:
            pass

        try:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS poll_options (
                    id SERIAL PRIMARY KEY,
                    post_id INTEGER NOT NULL,
                    label VARCHAR(200) NOT NULL,
                    vote_count INTEGER DEFAULT 0,
                    sort_order INTEGER DEFAULT 0
                )
            """)
        except Exception:
            pass

        try:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS poll_votes (
                    id SERIAL PRIMARY KEY,
                    post_id INTEGER NOT NULL,
                    option_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT NOW(),
                    UNIQUE(post_id, user_id)
                )
            """)
        except Exception:
            pass

        # 11. Pay auditor + gross-based pay plan fields
        for col, typ in [
            ("pay_type", "VARCHAR(16) DEFAULT 'flat'"),
            ("gross_front_pct", "FLOAT DEFAULT 0"), ("gross_back_pct", "FLOAT DEFAULT 0"),
            ("mini_deal", "FLOAT DEFAULT 0"), ("pack_deduction", "FLOAT DEFAULT 0"),
        ]:
            try:
                await conn.execute(f"ALTER TABLE settings ADD COLUMN IF NOT EXISTS {col} {typ}")
            except Exception:
                pass
        for col, typ in [
            ("front_gross", "FLOAT DEFAULT 0"), ("back_gross", "FLOAT DEFAULT 0"),
            ("expected_commission", "FLOAT DEFAULT 0"), ("actual_paid", "FLOAT"),
        ]:
            try:
                await conn.execute(f"ALTER TABLE deals ADD COLUMN IF NOT EXISTS {col} {typ}")
            except Exception:
                pass

        # 12. Custom products per dealership
        try:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS dealer_products (
                    id SERIAL PRIMARY KEY,
                    dealership_id INTEGER NOT NULL,
                    name VARCHAR(100) NOT NULL,
                    commission FLOAT DEFAULT 0,
                    sort_order INTEGER DEFAULT 0,
                    is_active BOOLEAN DEFAULT true
                )
            """)
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_dealer_products_dlr ON dealer_products(dealership_id)")
        except Exception:
            pass
        try:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS deal_products (
                    id SERIAL PRIMARY KEY,
                    deal_id INTEGER NOT NULL,
                    product_id INTEGER NOT NULL,
                    commission_override FLOAT
                )
            """)
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_deal_products_deal ON deal_products(deal_id)")
        except Exception:
            pass

        # 13. Custom bonuses per dealership
        try:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS dealer_bonuses (
                    id SERIAL PRIMARY KEY,
                    dealership_id INTEGER NOT NULL,
                    name VARCHAR(100) NOT NULL,
                    category VARCHAR(32) DEFAULT 'custom',
                    threshold_min INTEGER DEFAULT 0,
                    threshold_max INTEGER,
                    amount FLOAT DEFAULT 0,
                    bonus_type VARCHAR(16) DEFAULT 'flat',
                    period VARCHAR(16) DEFAULT 'monthly',
                    sort_order INTEGER DEFAULT 0,
                    is_active BOOLEAN DEFAULT true
                )
            """)
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_dealer_bonuses_dlr ON dealer_bonuses(dealership_id)")
        except Exception:
            pass
        # Add bonus_type column if table already exists without it
        try:
            await conn.execute("ALTER TABLE dealer_bonuses ADD COLUMN IF NOT EXISTS bonus_type VARCHAR(16) DEFAULT 'flat'")
        except Exception:
            pass

    finally:
        # Clean up expired sessions via raw asyncpg (avoids pgBouncer prepared stmt issue)
        try:
            await conn.execute("DELETE FROM user_sessions WHERE expires_at <= NOW()")
            await conn.execute("DELETE FROM password_reset_tokens WHERE expires_at <= NOW()")
        except Exception as e:
            pass
        await pool.release(conn)





# Vercel is serverless — no persistent background tasks.
# Instead, we piggyback cleanup on ~1% of incoming requests.

async def maybe_cleanup_sessions():
    """Probabilistic cleanup: runs on roughly 1 in 100 requests."""
    if not _is_pg:
        return
    if random.randint(1, 100) != 1:
        return
    try:
        from .auth import _raw_pg_execute
        await _raw_pg_execute("DELETE FROM user_sessions WHERE expires_at <= NOW()")
        await _raw_pg_execute("DELETE FROM password_reset_tokens WHERE expires_at <= NOW()")
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

async def get_new_community_posts(db: AsyncSession, user_id: int) -> bool:
    """Check if there are community posts newer than user's last visit."""
    try:
        user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
        if not user or not user.last_community_visit:
            # Never visited — show dot if any posts exist
            count = (await db.execute(
                select(func.count()).where(Post.is_deleted == False)
            )).scalar() or 0
            return count > 0
        count = (await db.execute(
            select(func.count()).where(
                Post.is_deleted == False,
                Post.created_at > user.last_community_visit,
                Post.user_id != user_id,  # Don't count your own posts
            )
        )).scalar() or 0
        return count > 0
    except Exception:
        return False

def quarter_bounds(d: date):
    q = ((d.month - 1) // 3) * 3 + 1
    start = date(d.year, q, 1)
    end = date(d.year + 1, 1, 1) if q == 10 else date(d.year, q + 3, 1)
    return start, end

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
        await get_or_create_settings(db, local_user.id, local_user.dealership_id)
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
    dealership_name: str = Form(""),
    google_place_id: str = Form(""),
    dealership_address: str = Form(""),
    dealership_phone: str = Form(""),
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

        # If user doesn't have a dealership yet, create one (new signup)
        if not local_user.dealership_id:
            local_user = await _create_dealership_for_user(
                db, local_user,
                name_hint=dealership_name.strip() or display_name.strip(),
                google_place_id=google_place_id.strip(),
                address=dealership_address.strip(),
                phone=dealership_phone.strip(),
            )

        await get_or_create_settings(db, local_user.id, local_user.dealership_id)

        if not session_data:
            # Email confirmation required — show success message
            return templates.TemplateResponse("login.html", {
                **error_ctx,
                "mode": "login",
                "error": "",
                "success": "Account created! Check your email to confirm before signing in.",
            })

        token = await create_session(db, local_user.id, remember_me=False, request=request)
        resp = RedirectResponse(url="/onboarding", status_code=303)
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

        # Create a dealership for this new user (they become admin)
        user = await _create_dealership_for_user(
            db, user,
            name_hint=dealership_name.strip() or display_name.strip(),
            google_place_id=google_place_id.strip(),
            address=dealership_address.strip(),
            phone=dealership_phone.strip(),
        )

        await get_or_create_settings(db, user.id, user.dealership_id)
        token = await create_session(db, user.id, remember_me=False, request=request)
        resp = RedirectResponse(url="/onboarding", status_code=303)
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
    from .auth import _raw_pg_fetchrow
    token = get_session_token(request)
    if not token:
        return JSONResponse({"seconds_remaining": 0, "authenticated": False})
    if not _is_pg:
        return JSONResponse({"seconds_remaining": 86400, "authenticated": True, "remember_me": True})
    try:
        row = await _raw_pg_fetchrow(
            "SELECT expires_at, remember_me FROM user_sessions WHERE token = $1 AND expires_at > NOW()",
            token
        )
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
    from .auth import _raw_pg_fetchrow, _raw_pg_execute, SESSION_TTL_SHORT, SESSION_TTL_REMEMBER, _cache_set
    token = get_session_token(request)
    if not token:
        return JSONResponse({"ok": False, "error": "No session"}, status_code=401)

    if not _is_pg:
        return JSONResponse({"ok": True, "seconds_remaining": 86400})

    try:
        row = await _raw_pg_fetchrow(
            "SELECT user_id, remember_me FROM user_sessions WHERE token = $1 AND expires_at > NOW()",
            token
        )
        if not row:
            return JSONResponse({"ok": False, "error": "Session expired"}, status_code=401)

        ttl = SESSION_TTL_REMEMBER if row["remember_me"] else SESSION_TTL_SHORT
        new_expires = _utcnow() + ttl
        await _raw_pg_execute(
            "UPDATE user_sessions SET expires_at = $1 WHERE token = $2",
            new_expires, token
        )
        # Update the in-memory cache too
        _cache_set(token, row["user_id"])

        return JSONResponse({
            "ok": True,
            "seconds_remaining": int(ttl.total_seconds()),
        })
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
    s = await get_or_create_settings(db, user_id, user_dealership_id(request))

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
                Deal.status == "Scheduled",
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

    # ── Commission engine setup ──────────────────────────────────────────────
    d_id = user_dealership_id(request)
    products = []
    bonuses = []
    if d_id:
        products = (await db.execute(
            select(DealerProduct).where(DealerProduct.dealership_id == d_id, DealerProduct.is_active == True)
            .order_by(DealerProduct.sort_order)
        )).scalars().all()
        bonuses = (await db.execute(
            select(DealerBonus).where(DealerBonus.dealership_id == d_id, DealerBonus.is_active == True)
            .order_by(DealerBonus.category, DealerBonus.threshold_min.desc())
        )).scalars().all()

    engine = CommissionEngine(s, products, bonuses)

    # ── Dynamic closing rates (all products) ──────────────────────────────────
    deal_ids = [d.id for d in delivered_mtd]
    deal_product_map = {}
    if deal_ids:
        dp_rows = (await db.execute(
            select(DealProduct.deal_id, DealProduct.product_id).where(DealProduct.deal_id.in_(deal_ids))
        )).all()
        for row in dp_rows:
            deal_product_map.setdefault(row.deal_id, set()).add(row.product_id)

    closing_rates = engine.calc_closing_rates(delivered_mtd, deal_product_map)

    # ── Bonus calculation (single path) ────────────────────────────────────────
    spots = sum(1 for d in delivered_mtd if d.spot_sold)
    pend_month = [d for d in pending_all if d.sold_date and start_m <= d.sold_date < end_m]
    proj_units = units_mtd + len(pend_month)
    proj_used = used_mtd + sum(1 for d in pend_month if (d.new_used or "").lower() == "used")
    proj_comm = comm_mtd + sum((d.total_deal_comm or 0) for d in pend_month)

    # Gross totals for gross_pct bonus calculations
    total_front_gross = sum((d.front_gross or 0) for d in delivered_mtd)
    total_back_gross = sum((d.back_gross or 0) for d in delivered_mtd)

    stats = MonthStats(
        units_mtd=units_mtd, new_mtd=new_mtd, used_mtd=used_mtd,
        spots=spots, qtd_count=qtd_count, ytd_units=ytd_units,
        proj_units=proj_units, proj_used=proj_used,
        total_front_gross_mtd=total_front_gross, total_back_gross_mtd=total_back_gross,
    )
    bonus_result = engine.calc_bonuses(stats)
    bonus_total = bonus_result.total
    proj_bonus = bonus_result.projected_total

    # Build bonus_breakdown for template (unified format)
    bonus_breakdown = {
        "total": bonus_total,
        "custom_list": [
            {
                "name": t.name, "category": t.category, "range": t.range_label,
                "amount": t.amount_per, "earned": t.earned, "hit": t.hit,
                "need": t.need, "count": t.count, "period": t.period,
                "bonus_type": t.bonus_type,
            }
            for t in bonus_result.tiers
        ],
    }

    # ── Pending deal ages ─────────────────────────────────────────────────────
    for d in pending_all:
        d.days_pending = (today_date - d.sold_date).days if d.sold_date else 0

    # ── Milestones ────────────────────────────────────────────────────────────
    milestones = engine.milestones(bonus_result)

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
        INSERT INTO goals (user_id, dealership_id, year, month, unit_goal, commission_goal)
        VALUES (:uid, :did, :y, :m, :u, :c)
        ON CONFLICT (user_id, year, month)
        DO UPDATE SET unit_goal=:u, commission_goal=:c, dealership_id=COALESCE(goals.dealership_id, :did)
    """), {"uid": user_id, "did": user_dealership_id(request), "y": y, "m": m, "u": unit_goal, "c": commission_goal})
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
    settings = await get_or_create_settings(db, user_id, user_dealership_id(request))
    start_m, end_m = month_bounds(today())
    dels = (await db.execute(select(Deal).where(Deal.user_id == user_id, Deal.status == "Delivered", Deal.delivered_date >= start_m, Deal.delivered_date < end_m))).scalars().all()
    u = len(dels); c = sum((d.total_deal_comm or 0) for d in dels)
    user = await _user(request, db)
    d_id = user_dealership_id(request)
    products = (await db.execute(
        select(DealerProduct).where(DealerProduct.dealership_id == d_id, DealerProduct.is_active == True)
        .order_by(DealerProduct.sort_order)
    )).scalars().all() if d_id else []
    return templates.TemplateResponse("deal_form.html", {
        "request": request, "user": user, "deal": None, "settings": settings,
        "products": products, "deal_product_ids": set(),
        "next_url": request.query_params.get("next") or "",
        "overdue_reminders": await get_overdue_reminders(db, user_id),
        "mtd": {"units": u, "comm": c, "avg": c/u if u else 0, "month_label": today().strftime("%B %Y")},
    })

@app.get("/deals/{deal_id}/edit", response_class=HTMLResponse)
async def deal_edit(deal_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    user_id = uid(request)
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id, Deal.user_id == user_id))).scalar_one_or_none()
    if not deal: return RedirectResponse(url="/deals", status_code=303)
    settings = await get_or_create_settings(db, user_id, user_dealership_id(request))
    embed = request.query_params.get("embed") == "1"
    start_m, end_m = month_bounds(today())
    dels = (await db.execute(select(Deal).where(Deal.user_id == user_id, Deal.status == "Delivered", Deal.delivered_date >= start_m, Deal.delivered_date < end_m))).scalars().all()
    u = len(dels); c = sum((d.total_deal_comm or 0) for d in dels)
    user = await _user(request, db)
    d_id = user_dealership_id(request)
    products = (await db.execute(
        select(DealerProduct).where(DealerProduct.dealership_id == d_id, DealerProduct.is_active == True)
        .order_by(DealerProduct.sort_order)
    )).scalars().all() if d_id else []
    # Load which products are attached to this deal
    deal_prods = (await db.execute(
        select(DealProduct.product_id).where(DealProduct.deal_id == deal.id)
    )).scalars().all()
    deal_product_ids = set(deal_prods)
    return templates.TemplateResponse("deal_form.html", {
        "request": request, "user": user, "deal": deal, "settings": settings, "embed": embed,
        "products": products, "deal_product_ids": deal_product_ids,
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
    front_gross: float = Form(0.0), back_gross: float = Form(0.0),
    actual_paid: str | None = Form(None),
    notes: str | None = Form(None), pay_date: str | None = Form(None), is_paid: int = Form(0),
    commission_override: str | None = Form(None),
    next: str | None = Form(None), db: AsyncSession = Depends(get_db),
):
    user_id = uid(request)
    settings = await get_or_create_settings(db, user_id, user_dealership_id(request))

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
        front_gross=float(front_gross or 0), back_gross=float(back_gross or 0),
        notes=notes or "", pay_date=pay, is_paid=bool(is_paid),
    )

    # Parse product checkboxes BEFORE commission calc so we can include them
    form_data = await request.form()
    product_ids = set(int(k.split("_")[1]) for k in form_data.keys() if k.startswith("product_") and form_data[k])

    # Load dealer products for commission engine
    d_id = user_dealership_id(request)
    dealer_products = []
    if d_id:
        dealer_products = (await db.execute(
            select(DealerProduct).where(DealerProduct.dealership_id == d_id, DealerProduct.is_active == True)
        )).scalars().all()

    engine = CommissionEngine(settings, dealer_products, [])
    comm_result = engine.calc_deal(deal_in, product_ids if product_ids else None)
    uc, ao, th, tot = comm_result.unit_comm, comm_result.addon_comm, comm_result.trade_hold_comm, comm_result.total

    # If user provided a manual override, use it as total_deal_comm
    comm_ov: float | None = None
    if commission_override is not None and commission_override.strip() != "":
        try:
            comm_ov = float(commission_override.replace("$", "").replace(",", "").strip())
        except ValueError:
            comm_ov = None
    if comm_ov is not None:
        tot = comm_ov

    # Parse actual_paid
    actual_paid_val: float | None = None
    if actual_paid is not None and actual_paid.strip() != "":
        try:
            actual_paid_val = float(actual_paid.replace("$", "").replace(",", "").strip())
        except ValueError:
            actual_paid_val = None

    if deal_id:
        for k, v in deal_in.model_dump().items(): setattr(existing, k, v)
        existing.unit_comm = uc; existing.add_ons = ao; existing.trade_hold_comm = th; existing.total_deal_comm = tot
        existing.commission_override = comm_ov
        existing.expected_commission = tot
        existing.actual_paid = actual_paid_val if actual_paid_val is not None else existing.actual_paid
        the_deal = existing
    else:
        deal = Deal(**deal_in.model_dump(), user_id=user_id, dealership_id=user_dealership_id(request),
                     unit_comm=uc, add_ons=ao, trade_hold_comm=th, total_deal_comm=tot,
                     commission_override=comm_ov, expected_commission=tot, actual_paid=actual_paid_val)
        db.add(deal)
        the_deal = deal

    await db.commit()
    if not deal_id:
        await db.refresh(the_deal)

    # Sync deal_products join table
    old_prods = (await db.execute(
        select(DealProduct).where(DealProduct.deal_id == the_deal.id)
    )).scalars().all()
    for op in old_prods:
        await db.delete(op)
    for pid in product_ids:
        db.add(DealProduct(deal_id=the_deal.id, product_id=pid))

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
    settings = await get_or_create_settings(db, user_id, user_dealership_id(request))

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
        if value == "Pending":
            deal.scheduled_date = None
    elif field == "commission_override":
        if value == "" or value is None:
            deal.commission_override = None
        else:
            try:
                deal.commission_override = float(str(value).replace("$","").replace(",",""))
            except ValueError:
                return JSONResponse({"ok": False, "error": "Invalid number"}, status_code=400)
        # Recalc total using engine
        deal_in = DealIn(**{c.key: getattr(deal, c.key) for c in deal.__table__.columns if c.key in DealIn.model_fields})
        # Load this deal's products
        d_id = user_dealership_id(request)
        dealer_products = (await db.execute(
            select(DealerProduct).where(DealerProduct.dealership_id == d_id, DealerProduct.is_active == True)
        )).scalars().all() if d_id else []
        dp_rows = (await db.execute(
            select(DealProduct.product_id).where(DealProduct.deal_id == deal.id)
        )).scalars().all()
        deal_prod_ids = set(dp_rows)
        eng = CommissionEngine(settings, dealer_products, [])
        cr = eng.calc_deal(deal_in, deal_prod_ids if deal_prod_ids else None)
        uc, ao, th, tot = cr.unit_comm, cr.addon_comm, cr.trade_hold_comm, cr.total
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
    # Auto-clear from delivery board — delivered deals don't need to stay on it
    deal.on_delivery_board = False; deal.gas_ready = False; deal.inspection_ready = False; deal.insurance_ready = False
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
    user = await _user(request, db)
    return templates.TemplateResponse("delivery_board.html", {"request": request, "user": user, "prep": prep, "ready": ready, "total": len(prep)+len(ready), "overdue_reminders": await get_overdue_reminders(db, uid(request))})

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
    deal.status = "Delivered"; deal.delivered_date = today()
    # Auto-clear from delivery board — no need to keep delivered deals on it
    deal.on_delivery_board = False; deal.gas_ready = False; deal.inspection_ready = False; deal.insurance_ready = False
    await db.commit()
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
    settings = await get_or_create_settings(db, user_id, user_dealership_id(request))

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

            uc, ao, th, tot = 0.0, 0.0, 0.0, 0.0
            # Use engine for import commission calc (no products attached during import)
            _eng = CommissionEngine(settings, [], [])
            _cr = _eng.calc_deal(deal_in)
            uc, ao, th, tot = _cr.unit_comm, _cr.addon_comm, _cr.trade_hold_comm, _cr.total
            db.add(Deal(
                **deal_in.model_dump(),
                user_id=user_id,
                dealership_id=user_dealership_id(request),
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
        r = Reminder(user_id=user_id, dealership_id=user_dealership_id(request), title=title.strip(), body=body.strip(), due_date=due)
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
    s = await get_or_create_settings(db, uid(request), user_dealership_id(request))
    user = await _user(request, db)
    is_admin = user_role(request) == "admin"
    d_id = user_dealership_id(request)

    # Get custom products for this dealership
    products = []
    if d_id:
        products = (await db.execute(
            select(DealerProduct).where(DealerProduct.dealership_id == d_id, DealerProduct.is_active == True)
            .order_by(DealerProduct.sort_order, DealerProduct.name)
        )).scalars().all()

    # Seed defaults if no custom products exist (migrate from hardcoded ones)
    if d_id and not products:
        defaults = [
            ("PermaPlate", s.permaplate), ("Nitro Fill", s.nitro_fill), ("Pulse/GPS", s.pulse),
            ("Finance", s.finance_non_subvented), ("Warranty", s.warranty), ("Tire & Wheel", s.tire_wheel),
        ]
        for i, (name, comm) in enumerate(defaults):
            db.add(DealerProduct(dealership_id=d_id, name=name, commission=comm, sort_order=i))
        await db.commit()
        products = (await db.execute(
            select(DealerProduct).where(DealerProduct.dealership_id == d_id, DealerProduct.is_active == True)
            .order_by(DealerProduct.sort_order, DealerProduct.name)
        )).scalars().all()

    # Get custom bonuses
    bonuses = []
    if d_id:
        bonuses = (await db.execute(
            select(DealerBonus).where(DealerBonus.dealership_id == d_id, DealerBonus.is_active == True)
            .order_by(DealerBonus.category, DealerBonus.sort_order, DealerBonus.threshold_min)
        )).scalars().all()

    # Seed defaults if no custom bonuses exist
    if d_id and not bonuses:
        defaults = [
            ("New Volume 15-16", "volume_new", 15, 16, s.new_volume_bonus_15_16, "monthly"),
            ("New Volume 17-18", "volume_new", 17, 18, s.new_volume_bonus_17_18, "monthly"),
            ("New Volume 19-20", "volume_new", 19, 20, s.new_volume_bonus_19_20, "monthly"),
            ("New Volume 21-24", "volume_new", 21, 24, s.new_volume_bonus_21_24, "monthly"),
            ("New Volume 25+", "volume_new", 25, None, s.new_volume_bonus_25_plus, "monthly"),
            ("Used Volume 8-10", "volume_used", 8, 10, s.used_volume_bonus_8_10, "monthly"),
            ("Used Volume 11-12", "volume_used", 11, 12, s.used_volume_bonus_11_12, "monthly"),
            ("Used Volume 13+", "volume_used", 13, None, s.used_volume_bonus_13_plus, "monthly"),
            ("Spot Bonus 5-9", "spot", 5, 9, s.spot_bonus_5_9, "monthly"),
            ("Spot Bonus 10-12", "spot", 10, 12, s.spot_bonus_10_12, "monthly"),
            ("Spot Bonus 13+", "spot", 13, None, s.spot_bonus_13_plus, "monthly"),
            ("Quarterly Bonus", "quarterly", s.quarterly_bonus_threshold_units, None, s.quarterly_bonus_amount, "quarterly"),
        ]
        for i, (name, cat, mn, mx, amt, per) in enumerate(defaults):
            if amt and amt > 0:
                db.add(DealerBonus(
                    dealership_id=d_id, name=name, category=cat,
                    threshold_min=mn, threshold_max=mx, amount=amt, period=per, sort_order=i,
                ))
        await db.commit()
        bonuses = (await db.execute(
            select(DealerBonus).where(DealerBonus.dealership_id == d_id, DealerBonus.is_active == True)
            .order_by(DealerBonus.category, DealerBonus.sort_order, DealerBonus.threshold_min)
        )).scalars().all()

    # Group bonuses by category for the template
    bonus_groups = {}
    for b in bonuses:
        bonus_groups.setdefault(b.category, []).append(b)

    return templates.TemplateResponse("payplan.html", {
        "request": request, "user": user, "s": s, "is_admin": is_admin,
        "products": products,
        "bonuses": bonuses, "bonus_groups": bonus_groups,
        "overdue_reminders": await get_overdue_reminders(db, uid(request)),
        "has_new_posts": await get_new_community_posts(db, uid(request)),
    })

@app.post("/payplan")
async def payplan_post(
    request: Request,
    pay_type: str = Form("flat"),
    gross_front_pct: float = Form(0.0), gross_back_pct: float = Form(0.0),
    mini_deal: float = Form(0.0), pack_deduction: float = Form(0.0),
    unit_comm_discount_le_200: float = Form(0.0), unit_comm_discount_gt_200: float = Form(0.0),
    permaplate: float = Form(0.0), nitro_fill: float = Form(0.0), pulse: float = Form(0.0),
    finance_non_subvented: float = Form(0.0), warranty: float = Form(0.0), tire_wheel: float = Form(0.0),
    hourly_rate_ny_offset: float = Form(0.0),
    new_volume_bonus_15_16: float = Form(0.0), new_volume_bonus_17_18: float = Form(0.0),
    new_volume_bonus_19_20: float = Form(0.0), new_volume_bonus_21_24: float = Form(0.0),
    new_volume_bonus_25_plus: float = Form(0.0),
    used_volume_bonus_8_10: float = Form(0.0), used_volume_bonus_11_12: float = Form(0.0),
    used_volume_bonus_13_plus: float = Form(0.0),
    spot_bonus_5_9: float = Form(0.0), spot_bonus_10_12: float = Form(0.0),
    spot_bonus_13_plus: float = Form(0.0),
    quarterly_bonus_threshold_units: int = Form(0), quarterly_bonus_amount: float = Form(0.0),
    db: AsyncSession = Depends(get_db),
):
    # Only admins can change the pay plan — it affects the entire dealership
    _require_admin(request)
    s = await get_or_create_settings(db, uid(request), user_dealership_id(request))
    if pay_type in ("flat", "gross", "hybrid"):
        s.pay_type = pay_type
    s.gross_front_pct = gross_front_pct
    s.gross_back_pct = gross_back_pct
    s.mini_deal = mini_deal
    s.pack_deduction = pack_deduction
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


@app.post("/payplan/product/add")
async def payplan_add_product(
    request: Request, db: AsyncSession = Depends(get_db),
    product_name: str = Form(""), product_commission: float = Form(0.0),
):
    """Add a custom product to the dealership."""
    _require_admin(request)
    d_id = user_dealership_id(request)
    if not d_id or not product_name.strip():
        return RedirectResponse(url="/payplan", status_code=303)
    max_order = (await db.execute(
        select(func.max(DealerProduct.sort_order)).where(DealerProduct.dealership_id == d_id)
    )).scalar() or 0
    db.add(DealerProduct(
        dealership_id=d_id, name=product_name.strip()[:100],
        commission=product_commission, sort_order=max_order + 1,
    ))
    await db.commit()
    return RedirectResponse(url="/payplan", status_code=303)


@app.post("/payplan/product/{product_id}/update")
async def payplan_update_product(
    product_id: int, request: Request, db: AsyncSession = Depends(get_db),
    product_name: str = Form(""), product_commission: float = Form(0.0),
):
    """Update a custom product."""
    _require_admin(request)
    p = (await db.execute(
        select(DealerProduct).where(DealerProduct.id == product_id, DealerProduct.dealership_id == user_dealership_id(request))
    )).scalar_one_or_none()
    if p:
        if product_name.strip(): p.name = product_name.strip()[:100]
        p.commission = product_commission
        await db.commit()
    return RedirectResponse(url="/payplan", status_code=303)


@app.post("/payplan/product/{product_id}/delete")
async def payplan_delete_product(product_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Soft-delete a custom product."""
    _require_admin(request)
    p = (await db.execute(
        select(DealerProduct).where(DealerProduct.id == product_id, DealerProduct.dealership_id == user_dealership_id(request))
    )).scalar_one_or_none()
    if p:
        p.is_active = False
        await db.commit()
    return RedirectResponse(url="/payplan", status_code=303)


@app.post("/payplan/bonus/add")
async def payplan_add_bonus(
    request: Request, db: AsyncSession = Depends(get_db),
    bonus_name: str = Form(""), bonus_category: str = Form("custom"),
    bonus_min: int = Form(0), bonus_max: str = Form(""),
    bonus_amount: float = Form(0.0), bonus_period: str = Form("monthly"),
    bonus_type: str = Form("flat"),
):
    """Add a custom bonus tier."""
    _require_admin(request)
    d_id = user_dealership_id(request)
    if not d_id or not bonus_name.strip():
        return RedirectResponse(url="/payplan", status_code=303)
    mx = int(bonus_max) if bonus_max.strip() and bonus_max.strip().isdigit() else None
    if bonus_category not in ("volume_new", "volume_used", "spot", "quarterly", "custom"):
        bonus_category = "custom"
    if bonus_period not in ("monthly", "quarterly", "yearly"):
        bonus_period = "monthly"
    if bonus_type not in ("flat", "gross_pct"):
        bonus_type = "flat"
    max_order = (await db.execute(
        select(func.max(DealerBonus.sort_order)).where(DealerBonus.dealership_id == d_id)
    )).scalar() or 0
    db.add(DealerBonus(
        dealership_id=d_id, name=bonus_name.strip()[:100], category=bonus_category,
        threshold_min=bonus_min, threshold_max=mx, amount=bonus_amount,
        bonus_type=bonus_type, period=bonus_period, sort_order=max_order + 1,
    ))
    await db.commit()
    return RedirectResponse(url="/payplan", status_code=303)


@app.post("/payplan/bonus/{bonus_id}/delete")
async def payplan_delete_bonus(bonus_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Soft-delete a bonus tier."""
    _require_admin(request)
    b = (await db.execute(
        select(DealerBonus).where(DealerBonus.id == bonus_id, DealerBonus.dealership_id == user_dealership_id(request))
    )).scalar_one_or_none()
    if b:
        b.is_active = False
        await db.commit()
    return RedirectResponse(url="/payplan", status_code=303)


# Backwards compat
@app.get("/settings")
async def _sr(): return RedirectResponse(url="/payplan", status_code=307)
@app.post("/settings")
async def _sp(): return RedirectResponse(url="/payplan", status_code=303)


# ════════════════════════════════════════════════
# TEAM MANAGEMENT (admin/manager) + DEALERSHIP STATS (all team)
# ════════════════════════════════════════════════

@app.get("/team", response_class=HTMLResponse)
async def team_page(request: Request, tab: str = "stats", month: str | None = None, db: AsyncSession = Depends(get_db)):
    """Team page with tabs: Stats (everyone), Members (admin/manager), Invites (admin)."""
    d_id = user_dealership_id(request)
    if not d_id:
        return RedirectResponse(url="/", status_code=303)
    user = await _user(request, db)
    role = user_role(request)
    is_admin = role == "admin"
    is_manager_or_admin = role in ("admin", "manager")

    # Get dealership info
    dealership = (await db.execute(
        select(Dealership).where(Dealership.id == d_id)
    )).scalar_one_or_none()

    # Get all team members
    team = (await db.execute(
        select(User).where(User.dealership_id == d_id).order_by(User.role.asc(), User.display_name.asc())
    )).scalars().all()

    # Get pending invites (for Members tab)
    invites = (await db.execute(
        select(Invite).where(Invite.dealership_id == d_id, Invite.used == False)
        .order_by(Invite.created_at.desc())
    )).scalars().all()

    # ── Stats tab data ──
    today_date = today()
    # Parse month
    if month:
        m = re.fullmatch(r"(\d{4})-(\d{1,2})", month)
        if m:
            sel_y, sel_m = int(m.group(1)), int(m.group(2))
        else:
            sel_y, sel_m = today_date.year, today_date.month
    else:
        sel_y, sel_m = today_date.year, today_date.month
    sel_m = max(1, min(12, sel_m))
    d0 = date(sel_y, sel_m, 1)
    start_m, end_m = month_bounds(d0)
    month_key = f"{sel_y:04d}-{sel_m:02d}"

    # Previous month
    py, pm = (sel_y - 1, 12) if sel_m == 1 else (sel_y, sel_m - 1)
    ps, pe = month_bounds(date(py, pm, 1))

    # Year bounds
    yr_start = date(sel_y, 1, 1)
    yr_end = date(sel_y + 1, 1, 1)

    # All delivered deals this month for the entire dealership
    delivered_mtd = (await db.execute(
        select(Deal).where(
            Deal.dealership_id == d_id, Deal.status == "Delivered",
            Deal.delivered_date >= start_m, Deal.delivered_date < end_m,
        )
    )).scalars().all()

    # Previous month stats
    prev_row = (await db.execute(
        select(
            func.count().label("cnt"),
            func.sum(Deal.total_deal_comm).label("comm"),
        ).where(
            Deal.dealership_id == d_id, Deal.status == "Delivered",
            Deal.delivered_date >= ps, Deal.delivered_date < pe,
        )
    )).one()

    # Year trend
    yr_rows = (await db.execute(
        select(
            func.extract("month", Deal.delivered_date).label("mo"),
            func.count().label("cnt"),
        ).where(
            Deal.dealership_id == d_id, Deal.status == "Delivered",
            Deal.delivered_date >= yr_start, Deal.delivered_date < yr_end,
        ).group_by(func.extract("month", Deal.delivered_date))
    )).all()
    ubm = [0] * 12
    for row in yr_rows:
        ubm[int(row.mo) - 1] = row.cnt

    # Pipeline
    pending_all = (await db.execute(
        select(Deal).where(Deal.dealership_id == d_id, Deal.status.in_(["Pending", "Scheduled"]))
    )).scalars().all()

    # ── Compute stats ──
    total_units = len(delivered_mtd)
    new_count = sum(1 for d in delivered_mtd if (d.new_used or "").lower() == "new")
    used_count = sum(1 for d in delivered_mtd if (d.new_used or "").lower() == "used")
    prev_units = prev_row.cnt or 0

    # Add-on penetration rates (dealership-wide)
    dt = total_units
    pulse_y = sum(1 for d in delivered_mtd if d.pulse)
    nitro_y = sum(1 for d in delivered_mtd if d.nitro_fill)
    perma_y = sum(1 for d in delivered_mtd if d.permaplate)
    warranty_y = sum(1 for d in delivered_mtd if d.warranty)
    finance_y = sum(1 for d in delivered_mtd if d.finance_non_subvented)
    tw_y = sum(1 for d in delivered_mtd if d.tire_wheel)
    aim_y = sum(1 for d in delivered_mtd if (d.aim_presentation or "X") == "Yes")
    aim_n = sum(1 for d in delivered_mtd if (d.aim_presentation or "X") == "No")
    addon_rates = {
        "Pulse": {"yes": pulse_y, "total": dt, "pct": round(pulse_y / dt * 100, 1) if dt else 0},
        "Nitro Fill": {"yes": nitro_y, "total": dt, "pct": round(nitro_y / dt * 100, 1) if dt else 0},
        "PermaPlate": {"yes": perma_y, "total": dt, "pct": round(perma_y / dt * 100, 1) if dt else 0},
        "Warranty": {"yes": warranty_y, "total": dt, "pct": round(warranty_y / dt * 100, 1) if dt else 0},
        "Finance": {"yes": finance_y, "total": dt, "pct": round(finance_y / dt * 100, 1) if dt else 0},
        "Tire & Wheel": {"yes": tw_y, "total": dt, "pct": round(tw_y / dt * 100, 1) if dt else 0},
        "Aim": {"yes": aim_y, "total": aim_y + aim_n, "pct": round(aim_y / (aim_y + aim_n) * 100, 1) if (aim_y + aim_n) else 0},
    }

    # Previous month per-user (for +/- indicators on leaderboard)
    prev_deals_all = (await db.execute(
        select(Deal).where(
            Deal.dealership_id == d_id, Deal.status == "Delivered",
            Deal.delivered_date >= ps, Deal.delivered_date < pe,
        )
    )).scalars().all()
    prev_by_user = {}
    for d in prev_deals_all:
        prev_by_user[d.user_id] = prev_by_user.get(d.user_id, 0) + 1

    # Pipeline aging
    for d in pending_all:
        d.days_pending = (today_date - d.sold_date).days if d.sold_date else 0
    aging_30_plus = sum(1 for d in pending_all if d.days_pending >= 30)
    stale_deals = sorted(
        [d for d in pending_all if d.days_pending >= 30],
        key=lambda d: d.days_pending, reverse=True
    )[:10]  # Top 10 oldest

    # Enrich stale deals with salesperson name
    team_map = {u.id: u for u in team}
    for d in stale_deals:
        d._salesperson = team_map.get(d.user_id)

    # ── Leaderboard (by user) ──
    leaderboard = []
    for u in team:
        user_deals = [d for d in delivered_mtd if d.user_id == u.id]
        u_units = len(user_deals)
        u_new = sum(1 for d in user_deals if (d.new_used or "").lower() == "new")
        u_used = sum(1 for d in user_deals if (d.new_used or "").lower() == "used")
        u_spots = sum(1 for d in user_deals if d.spot_sold)
        u_prev = prev_by_user.get(u.id, 0)
        leaderboard.append({
            "user": u,
            "units": u_units,
            "new": u_new,
            "used": u_used,
            "spots": u_spots,
            "prev_units": u_prev,
            "delta": u_units - u_prev,
        })
    leaderboard.sort(key=lambda x: x["units"], reverse=True)

    return templates.TemplateResponse("team.html", {
        "request": request, "user": user, "team": team, "invites": invites,
        "dealership": dealership, "is_admin": is_admin,
        "is_manager_or_admin": is_manager_or_admin,
        "overdue_reminders": await get_overdue_reminders(db, uid(request)),
        "has_new_posts": await get_new_community_posts(db, uid(request)),
        "tab": tab,
        # Stats data
        "month_key": month_key, "sel_y": sel_y, "sel_m": sel_m,
        "total_units": total_units, "new_count": new_count, "used_count": used_count,
        "prev_units": prev_units,
        "addon_rates": addon_rates,
        "leaderboard": leaderboard,
        "pending_count": len(pending_all), "aging_30_plus": aging_30_plus,
        "stale_deals": stale_deals,
        "ubm": ubm,
        "month_labels": ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"],
    })


@app.post("/team/invite")
async def team_invite(
    request: Request,
    db: AsyncSession = Depends(get_db),
    email: str = Form(""),
    role: str = Form("salesperson"),
):
    """Create an invite link for a new team member."""
    _require_admin(request)
    d_id = user_dealership_id(request)
    if not d_id:
        return RedirectResponse(url="/team", status_code=303)

    if role not in ("salesperson", "manager"):
        role = "salesperson"

    # Check user count limit
    dealership = (await db.execute(select(Dealership).where(Dealership.id == d_id))).scalar_one_or_none()
    if dealership:
        current_count = (await db.execute(
            select(func.count()).where(User.dealership_id == d_id)
        )).scalar() or 0
        if current_count >= dealership.max_users:
            return RedirectResponse(url="/team?error=limit", status_code=303)

    invite_token = secrets.token_urlsafe(32)
    invite = Invite(
        token=invite_token,
        dealership_id=d_id,
        email=email.strip().lower() if email.strip() else None,
        role=role,
        created_by=uid(request),
        expires_at=_utcnow() + timedelta(days=7),
    )
    db.add(invite)
    await db.commit()

    return RedirectResponse(url="/team", status_code=303)


@app.get("/join/{invite_token}", response_class=HTMLResponse)
async def join_page(invite_token: str, request: Request, db: AsyncSession = Depends(get_db)):
    """Page shown when someone clicks an invite link."""
    invite = (await db.execute(
        select(Invite).where(Invite.token == invite_token, Invite.used == False)
    )).scalar_one_or_none()

    if not invite or invite.expires_at < _utcnow():
        return HTMLResponse(
            """<!DOCTYPE html><html><head><title>Invalid Invite</title>
            <style>body{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f8fafc}
            .box{text-align:center;padding:2rem;max-width:400px}h1{font-size:1.5rem;color:#0f172a}
            p{color:#64748b}a{color:#6366f1;text-decoration:none}</style></head>
            <body><div class="box"><h1>Invite Expired or Invalid</h1>
            <p>This invite link is no longer valid. Ask your manager to send a new one.</p>
            <p style="margin-top:1.5rem"><a href="/login">← Sign In</a></p></div></body></html>""",
            status_code=404,
        )

    dealership = (await db.execute(
        select(Dealership).where(Dealership.id == invite.dealership_id)
    )).scalar_one_or_none()

    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": "",
        "success": f"You've been invited to join {dealership.name if dealership else 'a dealership'}!",
        "mode": "register",
        "supabase_enabled": SUPABASE_ENABLED,
        "next": "/",
        "invite_token": invite_token,
    })


@app.post("/join/{invite_token}")
async def join_accept(
    invite_token: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    email: str = Form(""),
    username: str = Form(""),
    display_name: str = Form(""),
    password: str = Form(...),
    password2: str = Form(...),
):
    """Accept an invite — create account and join the dealership."""
    invite = (await db.execute(
        select(Invite).where(Invite.token == invite_token, Invite.used == False)
    )).scalar_one_or_none()

    if not invite or invite.expires_at < _utcnow():
        return RedirectResponse(url=f"/join/{invite_token}", status_code=303)

    error_ctx = {
        "request": request, "mode": "register", "success": "",
        "supabase_enabled": SUPABASE_ENABLED, "next": "/",
        "invite_token": invite_token,
    }

    errors = []
    if password != password2:
        errors.append("Passwords don't match.")
    if len(password) < 6:
        errors.append("Password must be at least 6 characters.")

    if SUPABASE_ENABLED:
        reg_email = email.strip().lower()
        if not reg_email or "@" not in reg_email:
            errors.append("A valid email address is required.")
        if errors:
            return templates.TemplateResponse("login.html", {**error_ctx, "error": " ".join(errors)})

        result = await supabase_sign_up(reg_email, password)
        if "error" in result:
            return templates.TemplateResponse("login.html", {**error_ctx, "error": result["error"]})

        sb_user = result.get("user") or {}
        local_user = await get_or_create_user_from_supabase(
            db, sb_user, display_name=display_name.strip() or reg_email.split("@")[0]
        )
    else:
        uname = (username or email).strip().lower()
        if len(uname) < 3:
            errors.append("Username must be at least 3 characters.")
        existing = (await db.execute(select(User).where(User.username == uname))).scalar_one_or_none()
        if existing:
            errors.append("Username already taken.")
        if errors:
            return templates.TemplateResponse("login.html", {**error_ctx, "error": " ".join(errors)})

        pw_hash, pw_salt = hash_password(password)
        local_user = User(
            username=uname,
            display_name=(display_name.strip() or uname),
            password_hash=pw_hash,
            password_salt=pw_salt,
            created_at=_utcnow().isoformat(),
        )
        db.add(local_user)
        await db.commit()
        await db.refresh(local_user)

    # Assign user to the dealership from the invite
    local_user.dealership_id = invite.dealership_id
    local_user.role = invite.role

    # Mark invite as used
    invite.used = True
    invite.used_by = local_user.id
    await db.commit()

    await get_or_create_settings(db, local_user.id, local_user.dealership_id)
    token = await create_session(db, local_user.id, remember_me=False, request=request)
    resp = RedirectResponse(url="/", status_code=303)
    _set_session_cookie(resp, token, False)
    return resp


@app.post("/team/{user_id}/role")
async def team_change_role(
    user_id: int, request: Request, db: AsyncSession = Depends(get_db),
    role: str = Form(...),
):
    """Change a team member's role. Admin only."""
    _require_admin(request)
    if role not in ("salesperson", "manager", "admin"):
        return RedirectResponse(url="/team", status_code=303)
    # Can't change your own role
    if user_id == uid(request):
        return RedirectResponse(url="/team", status_code=303)
    d_id = user_dealership_id(request)
    target = (await db.execute(
        select(User).where(User.id == user_id, User.dealership_id == d_id)
    )).scalar_one_or_none()
    if target:
        target.role = role
        await db.commit()
    return RedirectResponse(url="/team", status_code=303)


@app.post("/team/{user_id}/remove")
async def team_remove_member(
    user_id: int, request: Request, db: AsyncSession = Depends(get_db),
):
    """Remove a team member from the dealership. Admin only.
    User keeps their account but is unassigned from the dealership."""
    _require_admin(request)
    if user_id == uid(request):
        return RedirectResponse(url="/team?tab=members", status_code=303)
    d_id = user_dealership_id(request)
    target = (await db.execute(
        select(User).where(User.id == user_id, User.dealership_id == d_id)
    )).scalar_one_or_none()
    if target:
        logger.info(f"Removing user {user_id} ({target.display_name}) from dealership {d_id}")
        # Use raw SQL to guarantee the update persists
        from .auth import _raw_pg_execute
        result = await _raw_pg_execute(
            "UPDATE users SET dealership_id = NULL, role = 'salesperson', "
            "is_verified = FALSE, verified_by = NULL, verified_at = NULL "
            "WHERE id = $1", user_id
        )
        if result is None:
            # Fallback to SQLAlchemy
            target.dealership_id = None
            target.role = "salesperson"
            target.is_verified = False
            target.verified_by = None
            target.verified_at = None
            await db.commit()
        # Destroy ALL their sessions in DB so they're forced to re-login
        await destroy_all_user_sessions(db, user_id)
        # Also clear local cache
        from .auth import _cache_delete_user
        _cache_delete_user(user_id)
        logger.info(f"User {user_id} removed and sessions destroyed")
    return RedirectResponse(url="/team?tab=members", status_code=303)


    return RedirectResponse(url="/team", status_code=303)
    return RedirectResponse(url="/team", status_code=303)
    return RedirectResponse(url="/team", status_code=303)


@app.post("/team/invite/{invite_id}/cancel")
async def team_cancel_invite(
    invite_id: int, request: Request, db: AsyncSession = Depends(get_db),
):
    """Cancel a pending invite. Admin only."""
    _require_admin(request)
    d_id = user_dealership_id(request)
    invite = (await db.execute(
        select(Invite).where(Invite.id == invite_id, Invite.dealership_id == d_id)
    )).scalar_one_or_none()
    if invite:
        await db.delete(invite)
        await db.commit()
    return RedirectResponse(url="/team", status_code=303)


@app.post("/team/dealership")
async def team_update_dealership(
    request: Request, db: AsyncSession = Depends(get_db),
    name: str = Form(...),
):
    """Update dealership name. Admin only."""
    _require_admin(request)
    d_id = user_dealership_id(request)
    dealership = (await db.execute(
        select(Dealership).where(Dealership.id == d_id)
    )).scalar_one_or_none()
    if dealership and name.strip():
        dealership.name = name.strip()[:200]
        await db.commit()
    return RedirectResponse(url="/team", status_code=303)


# ════════════════════════════════════════════════
# PAYCHECK — pay auditor (expected vs actual)
# ════════════════════════════════════════════════

@app.get("/paycheck", response_class=HTMLResponse)
async def paycheck_page(
    request: Request, db: AsyncSession = Depends(get_db),
    start: str = "", end: str = "",
):
    """Pay auditor — compare expected commission vs actual paid."""
    user = await _user(request, db)
    user_id = uid(request)

    # Default to current month
    td = today()
    if start:
        s_date = parse_date(start)
    else:
        s_date = td.replace(day=1)
    if end:
        e_date = parse_date(end)
    else:
        if td.month == 12:
            e_date = date(td.year + 1, 1, 1)
        else:
            e_date = date(td.year, td.month + 1, 1)

    if not s_date: s_date = td.replace(day=1)
    if not e_date: e_date = date(s_date.year, s_date.month + 1, 1) if s_date.month < 12 else date(s_date.year + 1, 1, 1)

    # Get delivered deals in range
    deals = (await db.execute(
        select(Deal).where(
            Deal.user_id == user_id,
            Deal.status == "Delivered",
            Deal.delivered_date >= s_date,
            Deal.delivered_date < e_date,
        ).order_by(Deal.delivered_date.asc())
    )).scalars().all()

    # Calculate totals
    total_expected = sum(d.expected_commission or d.total_deal_comm or 0 for d in deals)
    total_actual = sum(d.actual_paid or 0 for d in deals if d.actual_paid is not None)
    deals_with_actual = [d for d in deals if d.actual_paid is not None]
    deals_without_actual = [d for d in deals if d.actual_paid is None]
    total_difference = total_actual - total_expected if deals_with_actual else None

    # Flag discrepancies
    for d in deals:
        exp = d.expected_commission or d.total_deal_comm or 0
        if d.actual_paid is not None:
            d._diff = d.actual_paid - exp
            d._has_discrepancy = abs(d._diff) > 1.0  # more than $1 off
        else:
            d._diff = None
            d._has_discrepancy = False

    discrepancy_count = sum(1 for d in deals if d._has_discrepancy)

    return templates.TemplateResponse("paycheck.html", {
        "request": request, "user": user, "deals": deals,
        "start_date": s_date, "end_date": e_date,
        "total_expected": total_expected,
        "total_actual": total_actual,
        "total_difference": total_difference,
        "deals_with_actual": len(deals_with_actual),
        "discrepancy_count": discrepancy_count,
        "overdue_reminders": await get_overdue_reminders(db, uid(request)),
        "has_new_posts": await get_new_community_posts(db, uid(request)),
    })


@app.post("/paycheck/update")
async def paycheck_update_actual(
    request: Request, db: AsyncSession = Depends(get_db),
    deal_id: int = Form(...),
    actual_paid: str = Form(""),
    start: str = Form(""), end: str = Form(""),
):
    """Quick-update actual_paid from the paycheck view."""
    deal = (await db.execute(
        select(Deal).where(Deal.id == deal_id, Deal.user_id == uid(request))
    )).scalar_one_or_none()
    if deal and actual_paid.strip():
        try:
            deal.actual_paid = float(actual_paid.replace("$", "").replace(",", "").strip())
        except ValueError:
            pass
        await db.commit()
    redirect_url = f"/paycheck?start={start}&end={end}" if start else "/paycheck"
    return RedirectResponse(url=redirect_url, status_code=303)


# ════════════════════════════════════════════════
# ONBOARDING — post-signup setup wizard
# ════════════════════════════════════════════════

@app.get("/onboarding", response_class=HTMLResponse)
async def onboarding_page(request: Request, db: AsyncSession = Depends(get_db)):
    """Post-signup onboarding stepper."""
    user = await _user(request, db)
    d_id = user_dealership_id(request)
    dealership = None
    if d_id:
        dealership = (await db.execute(select(Dealership).where(Dealership.id == d_id))).scalar_one_or_none()

    # If already onboarded (has brand+state), just go to dashboard
    if dealership and dealership.brand and dealership.state:
        return RedirectResponse(url="/", status_code=303)

    s = await get_or_create_settings(db, uid(request), d_id)

    return templates.TemplateResponse("onboarding.html", {
        "request": request, "user": user, "dealership": dealership, "s": s,
        "auto_brands": AUTO_BRANDS, "us_states": US_STATES,
        "overdue_reminders": 0,
        "has_new_posts": False,
    })


@app.post("/onboarding")
async def onboarding_submit(
    request: Request, db: AsyncSession = Depends(get_db),
    display_name: str = Form(""),
    dealership_name: str = Form(""),
    brand: str = Form(""),
    state: str = Form(""),
    # Simplified pay plan fields
    unit_comm_le_200: str = Form(""),
    unit_comm_gt_200: str = Form(""),
    hourly_offset: str = Form(""),
    permaplate: str = Form(""),
    nitro_fill: str = Form(""),
    pulse: str = Form(""),
    finance: str = Form(""),
    warranty: str = Form(""),
    tire_wheel: str = Form(""),
):
    """Save onboarding data and redirect to dashboard."""
    user = await _user(request, db)

    # Update display name
    if display_name.strip():
        user.display_name = display_name.strip()[:120]

    # Handle dealership
    d_id = user_dealership_id(request)
    if d_id:
        dealership = (await db.execute(select(Dealership).where(Dealership.id == d_id))).scalar_one_or_none()
        if dealership:
            if dealership_name.strip():
                dealership.name = dealership_name.strip()[:200]
            if brand.strip():
                dealership.brand = brand.strip()[:80]
            if state.strip():
                dealership.state = state.strip().upper()[:2]
    elif dealership_name.strip():
        import re as _re
        base_slug = _re.sub(r'[^a-z0-9]+', '-', dealership_name.lower()).strip('-')[:60]
        slug = base_slug
        i = 1
        while (await db.execute(select(Dealership).where(Dealership.slug == slug))).scalar_one_or_none():
            slug = f"{base_slug}-{i}"
            i += 1
        dealership = Dealership(
            name=dealership_name.strip()[:200], slug=slug,
            brand=brand.strip()[:80] if brand.strip() else None,
            state=state.strip().upper()[:2] if state.strip() else None,
            subscription_status="free",
        )
        db.add(dealership)
        await db.commit()
        await db.refresh(dealership)
        user.dealership_id = dealership.id
        user.role = "admin"
        d_id = dealership.id
        from .auth import _cache_delete_user
        _cache_delete_user(user.id)

    # Update pay plan settings
    s = await get_or_create_settings(db, uid(request), d_id)

    def _flt(v):
        try: return float(v.replace("$","").replace(",","")) if v.strip() else None
        except: return None

    if _flt(unit_comm_le_200) is not None: s.unit_comm_discount_le_200 = _flt(unit_comm_le_200)
    if _flt(unit_comm_gt_200) is not None: s.unit_comm_discount_gt_200 = _flt(unit_comm_gt_200)
    if _flt(hourly_offset) is not None: s.hourly_rate_ny_offset = _flt(hourly_offset)
    if _flt(permaplate) is not None: s.permaplate = _flt(permaplate)
    if _flt(nitro_fill) is not None: s.nitro_fill = _flt(nitro_fill)
    if _flt(pulse) is not None: s.pulse = _flt(pulse)
    if _flt(finance) is not None: s.finance_non_subvented = _flt(finance)
    if _flt(warranty) is not None: s.warranty = _flt(warranty)
    if _flt(tire_wheel) is not None: s.tire_wheel = _flt(tire_wheel)

    await db.commit()
    return RedirectResponse(url="/", status_code=303)


@app.post("/api/parse-payplan")
async def api_parse_payplan(request: Request, db: AsyncSession = Depends(get_db)):
    """AI endpoint: accept a base64 image, return structured pay plan JSON."""
    try:
        body = await request.json()
        image_data = body.get("image", "")
        media_type = body.get("media_type", "image/jpeg")

        if not image_data:
            return JSONResponse({"error": "No image provided"}, status_code=400)

        # Use Anthropic API to parse the pay plan image
        import httpx
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            return JSONResponse({"error": "ANTHROPIC_API_KEY not configured"}, status_code=500)

        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": api_key,
                    "content-type": "application/json",
                    "anthropic-version": "2023-06-01",
                },
                json={
                    "model": "claude-sonnet-4-20250514",
                    "max_tokens": 1500,
                    "messages": [{
                        "role": "user",
                        "content": [
                            {
                                "type": "image",
                                "source": {"type": "base64", "media_type": media_type, "data": image_data},
                            },
                            {
                                "type": "text",
                                "text": """Analyze this car dealership pay plan document. Extract the commission structure and return ONLY a JSON object with these fields (use 0 if not found, numbers only no $ signs):

{
  "unit_comm_le_200": <per-unit commission when discount is $200 or less>,
  "unit_comm_gt_200": <per-unit commission when discount is over $200>,
  "hourly_offset": <hourly rate or NY offset amount>,
  "permaplate": <permaplate/paint protection commission per deal>,
  "nitro_fill": <nitrogen fill commission per deal>,
  "pulse": <pulse/GPS commission per deal>,
  "finance": <finance/non-subvented finance commission per deal>,
  "warranty": <extended warranty commission per deal>,
  "tire_wheel": <tire and wheel protection commission per deal>,
  "pay_type": "flat" or "gross" or "hybrid",
  "gross_percentage": <if gross-based, the percentage of gross profit>,
  "notes": "<any important details about the pay structure>"
}

Return ONLY the JSON, no explanation."""
                            },
                        ],
                    }],
                },
            )

        if resp.status_code != 200:
            return JSONResponse({"error": "AI parsing failed"}, status_code=500)

        data = resp.json()
        text = ""
        for block in data.get("content", []):
            if block.get("type") == "text":
                text += block["text"]

        # Parse JSON from response
        text = text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[-1].rsplit("```", 1)[0]
        parsed = _json.loads(text)
        return JSONResponse(parsed)

    except _json.JSONDecodeError:
        return JSONResponse({"error": "Could not parse AI response as JSON", "raw": text}, status_code=422)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


# ════════════════════════════════════════════════
# PROFILE — user settings, dealership, brand/state
# ════════════════════════════════════════════════

# Common US auto brands for the brand picker
AUTO_BRANDS = [
    "Acura","Alfa Romeo","Audi","BMW","Buick","Cadillac","Chevrolet","Chrysler",
    "Dodge","FIAT","Ford","Genesis","GMC","Honda","Hyundai","INFINITI","Jaguar",
    "Jeep","Kia","Land Rover","Lexus","Lincoln","Maserati","Mazda","Mercedes-Benz",
    "MINI","Mitsubishi","Nissan","Porsche","RAM","Rivian","Subaru","Tesla","Toyota",
    "Volkswagen","Volvo",
]

US_STATES = [
    "AL","AK","AZ","AR","CA","CO","CT","DE","FL","GA","HI","ID","IL","IN","IA",
    "KS","KY","LA","ME","MD","MA","MI","MN","MS","MO","MT","NE","NV","NH","NJ",
    "NM","NY","NC","ND","OH","OK","OR","PA","RI","SC","SD","TN","TX","UT","VT",
    "VA","WA","WV","WI","WY","DC",
]

@app.get("/profile", response_class=HTMLResponse)
async def profile_page(request: Request, db: AsyncSession = Depends(get_db)):
    """User profile — set display name, dealership, brand, state."""
    user = await _user(request, db)
    d_id = user_dealership_id(request)
    dealership = None
    if d_id:
        dealership = (await db.execute(select(Dealership).where(Dealership.id == d_id))).scalar_one_or_none()

    # Stats for the profile page
    yr = today().year
    total_deals = (await db.execute(
        select(func.count()).where(Deal.user_id == uid(request))
    )).scalar() or 0
    ytd_deals = (await db.execute(
        select(func.count()).where(
            Deal.user_id == uid(request), Deal.status == "Delivered",
            Deal.delivered_date >= date(yr, 1, 1),
        )
    )).scalar() or 0

    return templates.TemplateResponse("profile.html", {
        "request": request, "user": user,
        "dealership": dealership,
        "auto_brands": AUTO_BRANDS,
        "us_states": US_STATES,
        "total_deals": total_deals,
        "ytd_deals": ytd_deals,
        "overdue_reminders": await get_overdue_reminders(db, uid(request)),
        "has_new_posts": await get_new_community_posts(db, uid(request)),
    })


@app.post("/profile")
async def profile_update(
    request: Request, db: AsyncSession = Depends(get_db),
    display_name: str = Form(""),
    dealership_name: str = Form(""),
    brand: str = Form(""),
    state: str = Form(""),
):
    """Update user profile and dealership info."""
    user = await _user(request, db)

    # Update display name
    if display_name.strip():
        user.display_name = display_name.strip()[:120]

    # Handle dealership
    d_id = user_dealership_id(request)
    if d_id:
        dealership = (await db.execute(select(Dealership).where(Dealership.id == d_id))).scalar_one_or_none()
        if dealership:
            if dealership_name.strip():
                dealership.name = dealership_name.strip()[:200]
            dealership.brand = brand.strip()[:80] if brand.strip() else dealership.brand
            dealership.state = state.strip().upper()[:2] if state.strip() else dealership.state
    elif dealership_name.strip():
        # Create a new dealership for this user
        import re as _re
        base_slug = _re.sub(r'[^a-z0-9]+', '-', dealership_name.lower()).strip('-')[:60]
        slug = base_slug
        i = 1
        while (await db.execute(select(Dealership).where(Dealership.slug == slug))).scalar_one_or_none():
            slug = f"{base_slug}-{i}"
            i += 1
        dealership = Dealership(
            name=dealership_name.strip()[:200],
            slug=slug,
            brand=brand.strip()[:80] if brand.strip() else None,
            state=state.strip().upper()[:2] if state.strip() else None,
            subscription_status="free",
        )
        db.add(dealership)
        await db.commit()
        await db.refresh(dealership)
        user.dealership_id = dealership.id
        user.role = "admin"
        # Clear session cache so new dealership_id takes effect
        from .auth import _cache_delete_user
        _cache_delete_user(user.id)

    await db.commit()
    return RedirectResponse(url="/profile", status_code=303)


# ════════════════════════════════════════════════
# COMMUNITY — anonymous feed for salespeople
# ════════════════════════════════════════════════

import json as _json

def _post_display_name(post, dealership_map: dict) -> str:
    """Compute the display attribution for an anonymous post."""
    d = dealership_map.get(post.dealership_id)
    if post.anonymity == "dealership" and d:
        return d.name
    elif post.anonymity == "brand" and d and d.brand:
        return f"{d.brand} Dealership"
    elif post.anonymity == "brand" and d:
        # Try to extract brand from dealership name
        name = d.name or ""
        for word in ["of", "Of", "OF"]:
            if f" {word} " in name:
                return name.split(f" {word} ")[0].strip() + " Dealership"
        return "A Dealership"
    return "Anonymous Salesperson"


@app.get("/community", response_class=HTMLResponse)
async def community_feed(
    request: Request, db: AsyncSession = Depends(get_db),
    post_type: str = "", brand: str = "", state: str = "", page: int = 1,
):
    """Community feed — anonymous posts from salespeople."""
    user = await _user(request, db)
    per_page = 20
    offset = (max(1, page) - 1) * per_page

    # Build query
    q = select(Post).where(Post.is_deleted == False)
    if post_type and post_type in ("text", "payplan", "ytd", "poll"):
        q = q.where(Post.post_type == post_type)
    if brand:
        # Join with dealerships to filter by brand
        brand_ids = (await db.execute(
            select(Dealership.id).where(Dealership.brand == brand)
        )).scalars().all()
        if brand_ids:
            q = q.where(Post.dealership_id.in_(brand_ids))
        else:
            q = q.where(Post.id < 0)  # no results
    if state:
        state_ids = (await db.execute(
            select(Dealership.id).where(Dealership.state == state.upper())
        )).scalars().all()
        if state_ids:
            q = q.where(Post.dealership_id.in_(state_ids))
        else:
            q = q.where(Post.id < 0)

    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar() or 0
    posts = (await db.execute(
        q.order_by(Post.created_at.desc()).offset(offset).limit(per_page)
    )).scalars().all()

    # Enrich posts
    d_ids = {p.dealership_id for p in posts if p.dealership_id}
    dealership_map = {}
    if d_ids:
        ds = (await db.execute(select(Dealership).where(Dealership.id.in_(d_ids)))).scalars().all()
        dealership_map = {d.id: d for d in ds}

    # Check which posts current user has upvoted
    post_ids = [p.id for p in posts]
    user_upvotes = set()
    if post_ids:
        upvoted = (await db.execute(
            select(PostUpvote.post_id).where(
                PostUpvote.user_id == uid(request),
                PostUpvote.post_id.in_(post_ids),
            )
        )).scalars().all()
        user_upvotes = set(upvoted)

    # Get poll options + user votes for poll posts
    poll_data = {}
    poll_posts = [p for p in posts if p.post_type == "poll"]
    if poll_posts:
        poll_ids = [p.id for p in poll_posts]
        options = (await db.execute(
            select(PollOption).where(PollOption.post_id.in_(poll_ids)).order_by(PollOption.sort_order)
        )).scalars().all()
        user_poll_votes = (await db.execute(
            select(PollVote).where(PollVote.user_id == uid(request), PollVote.post_id.in_(poll_ids))
        )).scalars().all()
        user_vote_map = {v.post_id: v.option_id for v in user_poll_votes}
        for p in poll_posts:
            p_options = [o for o in options if o.post_id == p.id]
            total_votes = sum(o.vote_count for o in p_options)
            poll_data[p.id] = {
                "options": p_options,
                "total_votes": total_votes,
                "user_voted": user_vote_map.get(p.id),
            }

    # Enrich posts with display info
    for p in posts:
        p._display_name = _post_display_name(p, dealership_map)
        p._payload = _json.loads(p.payload) if p.payload and p.payload != "{}" else {}
        p._upvoted = p.id in user_upvotes
        p._poll = poll_data.get(p.id)

    # Get filter options
    brands = (await db.execute(
        select(Dealership.brand).where(Dealership.brand.isnot(None), Dealership.brand != "")
        .distinct().order_by(Dealership.brand)
    )).scalars().all()
    states = (await db.execute(
        select(Dealership.state).where(Dealership.state.isnot(None), Dealership.state != "")
        .distinct().order_by(Dealership.state)
    )).scalars().all()

    my_dealership = (await db.execute(
        select(Dealership).where(Dealership.id == user_dealership_id(request))
    )).scalar_one_or_none() if user_dealership_id(request) else None

    # Update last visit timestamp for notification tracking
    user.last_community_visit = _utcnow()
    await db.commit()

    return templates.TemplateResponse("community.html", {
        "request": request, "user": user, "posts": posts,
        "brands": brands, "states": states,
        "filter_type": post_type, "filter_brand": brand, "filter_state": state,
        "page": page, "total": total, "per_page": per_page,
        "my_dealership": my_dealership,
        "overdue_reminders": await get_overdue_reminders(db, uid(request)),
        "has_new_posts": await get_new_community_posts(db, uid(request)),
    })


@app.post("/community/post")
async def community_create_post(
    request: Request, db: AsyncSession = Depends(get_db),
    post_type: str = Form("text"),
    anonymity: str = Form("brand"),
    title: str = Form(""),
    body: str = Form(""),
    poll_options: str = Form(""),  # comma-separated for polls
):
    """Create a new community post."""
    if anonymity not in ("dealership", "brand", "anonymous"):
        anonymity = "brand"
    if post_type not in ("text", "payplan", "ytd", "poll"):
        post_type = "text"

    user = await _user(request, db)
    d_id = user_dealership_id(request)
    payload = "{}"

    if post_type == "payplan":
        # Auto-generate from settings + dynamic products/bonuses
        s = await get_or_create_settings(db, uid(request), d_id)
        products = (await db.execute(
            select(DealerProduct).where(DealerProduct.dealership_id == d_id, DealerProduct.is_active == True)
            .order_by(DealerProduct.sort_order)
        )).scalars().all() if d_id else []
        bonuses = (await db.execute(
            select(DealerBonus).where(DealerBonus.dealership_id == d_id, DealerBonus.is_active == True)
            .order_by(DealerBonus.category, DealerBonus.threshold_min)
        )).scalars().all() if d_id else []
        engine = CommissionEngine(s, products, bonuses)
        payload = _json.dumps(engine.share_payload())

    elif post_type == "ytd":
        # Auto-generate from deals
        yr = today().year
        yr_start = date(yr, 1, 1)
        yr_end = date(yr + 1, 1, 1)
        delivered = (await db.execute(
            select(Deal).where(
                Deal.user_id == uid(request), Deal.status == "Delivered",
                Deal.delivered_date >= yr_start, Deal.delivered_date < yr_end,
            )
        )).scalars().all()
        months = [0] * 12
        for d in delivered:
            if d.delivered_date:
                months[d.delivered_date.month - 1] += 1
        current_month = today().month
        avg = sum(months[:current_month]) / current_month if current_month else 0
        payload = _json.dumps({
            "year": yr,
            "total_units": len(delivered),
            "months": months,
            "avg_per_month": round(avg, 1),
            "new_count": sum(1 for d in delivered if (d.new_used or "").lower() == "new"),
            "used_count": sum(1 for d in delivered if (d.new_used or "").lower() == "used"),
        })

    post = Post(
        user_id=uid(request),
        dealership_id=d_id,
        post_type=post_type,
        anonymity=anonymity,
        title=title.strip()[:200],
        body=body.strip()[:2000],
        payload=payload,
    )
    db.add(post)
    await db.commit()
    await db.refresh(post)

    # Add poll options
    if post_type == "poll" and poll_options.strip():
        opts = [o.strip() for o in poll_options.split(",") if o.strip()][:8]
        for i, label in enumerate(opts):
            db.add(PollOption(post_id=post.id, label=label[:200], sort_order=i))
        await db.commit()

    return RedirectResponse(url="/community", status_code=303)


@app.post("/community/{post_id}/upvote")
async def community_upvote(post_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Toggle upvote on a post."""
    existing = (await db.execute(
        select(PostUpvote).where(PostUpvote.post_id == post_id, PostUpvote.user_id == uid(request))
    )).scalar_one_or_none()

    post = (await db.execute(select(Post).where(Post.id == post_id))).scalar_one_or_none()
    if not post:
        return RedirectResponse(url="/community", status_code=303)

    if existing:
        await db.delete(existing)
        post.upvote_count = max(0, (post.upvote_count or 0) - 1)
    else:
        db.add(PostUpvote(post_id=post_id, user_id=uid(request)))
        post.upvote_count = (post.upvote_count or 0) + 1
    await db.commit()
    return RedirectResponse(url="/community", status_code=303)


@app.post("/community/{post_id}/vote")
async def community_poll_vote(
    post_id: int, request: Request, db: AsyncSession = Depends(get_db),
    option_id: int = Form(...),
):
    """Vote on a poll option."""
    # Check user hasn't already voted
    existing = (await db.execute(
        select(PollVote).where(PollVote.post_id == post_id, PollVote.user_id == uid(request))
    )).scalar_one_or_none()
    if existing:
        return RedirectResponse(url="/community", status_code=303)

    option = (await db.execute(
        select(PollOption).where(PollOption.id == option_id, PollOption.post_id == post_id)
    )).scalar_one_or_none()
    if not option:
        return RedirectResponse(url="/community", status_code=303)

    db.add(PollVote(post_id=post_id, option_id=option_id, user_id=uid(request)))
    option.vote_count = (option.vote_count or 0) + 1
    await db.commit()
    return RedirectResponse(url="/community", status_code=303)


@app.post("/community/{post_id}/delete")
async def community_delete_post(post_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Delete your own post (or super admin can delete any)."""
    post = (await db.execute(select(Post).where(Post.id == post_id))).scalar_one_or_none()
    if not post:
        return RedirectResponse(url="/community", status_code=303)
    if post.user_id != uid(request) and not is_super_admin(request):
        return RedirectResponse(url="/community", status_code=303)
    post.is_deleted = True
    await db.commit()
    return RedirectResponse(url="/community", status_code=303)


# ════════════════════════════════════════════════
# SUPER ADMIN — Platform Management
# ════════════════════════════════════════════════

@app.post("/admin/toggle")
async def admin_toggle_mode(request: Request):
    """Toggle between platform admin view and salesperson view."""
    if not is_super_admin(request):
        return RedirectResponse(url="/", status_code=303)
    current = request.cookies.get("admin_mode") == "1"
    resp = RedirectResponse(url="/admin" if not current else "/", status_code=303)
    resp.set_cookie("admin_mode", "0" if current else "1", httponly=True, samesite="lax", max_age=60*60*24*365)
    return resp


@app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request, db: AsyncSession = Depends(get_db)):
    """Super admin platform page — all users with summary stats."""
    _require_super_admin(request)
    user = await _user(request, db)

    # All users
    all_users = (await db.execute(
        select(User).order_by(User.dealership_id.nulls_last(), User.role.asc(), User.display_name.asc())
    )).scalars().all()

    # Dealership lookup
    dealerships = (await db.execute(select(Dealership))).scalars().all()
    dealer_map = {d.id: d for d in dealerships}
    for u in all_users:
        u._dealership = dealer_map.get(u.dealership_id)

    # Deal counts per user
    deal_counts_raw = (await db.execute(
        select(Deal.user_id, func.count(Deal.id).label("cnt")).group_by(Deal.user_id)
    )).all()
    deal_counts = {row[0]: row[1] for row in deal_counts_raw}

    unaffiliated = [u for u in all_users if u.dealership_id is None]
    affiliated = [u for u in all_users if u.dealership_id is not None]

    # Summary stats
    total_deals = (await db.execute(select(func.count()).select_from(Deal))).scalar() or 0
    td = today()
    deals_mtd = (await db.execute(
        select(func.count()).where(Deal.status == "Delivered", Deal.delivered_date >= td.replace(day=1))
    )).scalar() or 0
    active_dealerships = sum(1 for d in dealerships if d.is_active)

    return templates.TemplateResponse("admin_dashboard.html", {
        "request": request, "user": user,
        "affiliated": affiliated, "unaffiliated": unaffiliated,
        "deal_counts": deal_counts,
        "dealerships": dealerships, "dealer_map": dealer_map,
        "total_users": len(all_users),
        "total_deals": total_deals,
        "deals_mtd": deals_mtd,
        "active_dealerships": active_dealerships,
        "overdue_reminders": await get_overdue_reminders(db, uid(request)),
        "has_new_posts": await get_new_community_posts(db, uid(request)),
    })


@app.post("/admin/dealership/create")
async def admin_create_dealership(
    request: Request, db: AsyncSession = Depends(get_db),
    name: str = Form(...), slug: str = Form(""),
):
    """Create a new dealership manually."""
    _require_super_admin(request)
    import re as _re
    if not slug.strip():
        slug = _re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')[:60]
    # Ensure slug is unique
    base_slug = slug
    i = 1
    while (await db.execute(select(Dealership).where(Dealership.slug == slug))).scalar_one_or_none():
        slug = f"{base_slug}-{i}"
        i += 1
    d = Dealership(name=name.strip(), slug=slug, is_active=True, subscription_status="active")
    db.add(d)
    await db.commit()
    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/dealership/{dealership_id}/toggle-active")
async def admin_toggle_dealership(dealership_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Activate/deactivate a dealership."""
    _require_super_admin(request)
    d = (await db.execute(select(Dealership).where(Dealership.id == dealership_id))).scalar_one_or_none()
    if d:
        d.is_active = not d.is_active
        await db.commit()
    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/dealership/{dealership_id}/assign-gm")
async def admin_assign_gm(
    dealership_id: int, request: Request, db: AsyncSession = Depends(get_db),
    user_id: int = Form(...),
):
    """Assign a user as the GM (admin role) of a dealership."""
    _require_super_admin(request)
    target = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if target:
        target.dealership_id = dealership_id
        target.role = "admin"
        target.is_verified = True
        await db.commit()
    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/user/{user_id}/toggle-super")
async def admin_toggle_super(user_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Toggle super admin status for a user. Can only be done by existing super admin."""
    _require_super_admin(request)
    # Can't remove your own super admin
    if user_id == uid(request):
        return RedirectResponse(url="/admin", status_code=303)
    target = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if target:
        target.is_super_admin = not target.is_super_admin
        await db.commit()
    return RedirectResponse(url="/admin", status_code=303)


@app.get("/admin/dealership/{dealership_id}", response_class=HTMLResponse)
async def admin_dealership_detail(dealership_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Drill into a specific dealership — see all users, deals, settings."""
    _require_super_admin(request)
    user = await _user(request, db)

    dealership = (await db.execute(
        select(Dealership).where(Dealership.id == dealership_id)
    )).scalar_one_or_none()
    if not dealership:
        return RedirectResponse(url="/admin", status_code=303)

    members = (await db.execute(
        select(User).where(User.dealership_id == dealership_id)
        .order_by(User.role.asc(), User.display_name.asc())
    )).scalars().all()

    # Recent deals
    recent_deals = (await db.execute(
        select(Deal).where(Deal.dealership_id == dealership_id)
        .order_by(Deal.sold_date.desc().nullslast()).limit(25)
    )).scalars().all()

    # Enrich deals with salesperson names
    user_map = {m.id: m for m in members}
    for deal in recent_deals:
        deal._salesperson = user_map.get(deal.user_id)

    # Stats
    total_deals = (await db.execute(
        select(func.count()).where(Deal.dealership_id == dealership_id)
    )).scalar() or 0

    delivered_mtd = (await db.execute(
        select(func.count()).where(
            Deal.dealership_id == dealership_id,
            Deal.status == "Delivered",
            Deal.delivered_date >= today().replace(day=1)
        )
    )).scalar() or 0

    # Get pay plan settings for this dealership (Deploy 4)
    dealership_settings = (await db.execute(
        select(Settings).where(Settings.dealership_id == dealership_id).limit(1)
    )).scalar_one_or_none()

    return templates.TemplateResponse("admin_dealership.html", {
        "request": request, "user": user, "dealership": dealership,
        "members": members, "recent_deals": recent_deals,
        "total_deals": total_deals, "delivered_mtd": delivered_mtd,
        "dealership_settings": dealership_settings,
        "overdue_reminders": await get_overdue_reminders(db, uid(request)),
        "has_new_posts": await get_new_community_posts(db, uid(request)),
    })


# ════════════════════════════════════════════════
# DEPLOY 2 — Google Places API proxy for dealership search
# ════════════════════════════════════════════════

GOOGLE_PLACES_API_KEY = os.environ.get("GOOGLE_PLACES_API_KEY", "")

@app.get("/api/places/search")
async def places_search(request: Request, q: str = ""):
    """Proxy Google Places Autocomplete for dealership search during registration.
    Returns JSON list of place predictions."""
    if not GOOGLE_PLACES_API_KEY or not q.strip():
        return JSONResponse([])
    try:
        import httpx
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(
                "https://maps.googleapis.com/maps/api/place/autocomplete/json",
                params={
                    "input": q.strip(),
                    "types": "establishment",
                    "key": GOOGLE_PLACES_API_KEY,
                },
            )
            data = r.json()
            results = []
            for p in data.get("predictions", [])[:8]:
                results.append({
                    "place_id": p.get("place_id", ""),
                    "name": p.get("structured_formatting", {}).get("main_text", ""),
                    "description": p.get("description", ""),
                })
            return JSONResponse(results)
    except Exception as e:
        logger.warning(f"Places search error: {e}")
        return JSONResponse([])


@app.get("/api/places/detail")
async def places_detail(request: Request, place_id: str = ""):
    """Proxy Google Places Detail to get address & phone for a dealership."""
    if not GOOGLE_PLACES_API_KEY or not place_id.strip():
        return JSONResponse({})
    try:
        import httpx
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(
                "https://maps.googleapis.com/maps/api/place/details/json",
                params={
                    "place_id": place_id,
                    "fields": "name,formatted_address,formatted_phone_number,place_id",
                    "key": GOOGLE_PLACES_API_KEY,
                },
            )
            data = r.json()
            result = data.get("result", {})
            return JSONResponse({
                "name": result.get("name", ""),
                "address": result.get("formatted_address", ""),
                "phone": result.get("formatted_phone_number", ""),
                "place_id": result.get("place_id", ""),
            })
    except Exception as e:
        logger.warning(f"Places detail error: {e}")
        return JSONResponse({})


# ════════════════════════════════════════════════
# DEPLOY 3 — Verification system (GM verifies salespeople)
# ════════════════════════════════════════════════

@app.post("/team/{user_id}/verify")
async def team_verify_user(
    user_id: int, request: Request, db: AsyncSession = Depends(get_db),
):
    """Verify a salesperson — confirms they work at the dealership.
    Admin/manager (GM) only."""
    _require_admin_or_manager(request)
    d_id = user_dealership_id(request)
    target = (await db.execute(
        select(User).where(User.id == user_id, User.dealership_id == d_id)
    )).scalar_one_or_none()
    if target and not target.is_verified:
        target.is_verified = True
        target.verified_by = uid(request)
        target.verified_at = _utcnow()
        await db.commit()
    if "application/json" in request.headers.get("accept", ""):
        return JSONResponse({"ok": True, "is_verified": True})
    return RedirectResponse(url="/team", status_code=303)


@app.post("/team/{user_id}/unverify")
async def team_unverify_user(
    user_id: int, request: Request, db: AsyncSession = Depends(get_db),
):
    """Remove verification from a user. Admin only."""
    _require_admin(request)
    d_id = user_dealership_id(request)
    target = (await db.execute(
        select(User).where(User.id == user_id, User.dealership_id == d_id)
    )).scalar_one_or_none()
    if target and user_id != uid(request):
        target.is_verified = False
        target.verified_by = None
        target.verified_at = None
        await db.commit()
    if "application/json" in request.headers.get("accept", ""):
        return JSONResponse({"ok": True, "is_verified": False})
    return RedirectResponse(url="/team", status_code=303)


@app.post("/admin/user/{user_id}/verify")
async def admin_verify_user(user_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Super admin can verify any user."""
    _require_super_admin(request)
    target = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if target:
        target.is_verified = not target.is_verified
        if target.is_verified:
            target.verified_by = uid(request)
            target.verified_at = _utcnow()
        else:
            target.verified_by = None
            target.verified_at = None
        await db.commit()
    # Redirect back to the dealership detail page
    if target and target.dealership_id:
        return RedirectResponse(url=f"/admin/dealership/{target.dealership_id}", status_code=303)
    return RedirectResponse(url="/admin", status_code=303)


# ════════════════════════════════════════════════
# DEPLOY 4 — Pay plan permissions (admin override)
# ════════════════════════════════════════════════

@app.post("/admin/dealership/{dealership_id}/payplan")
async def admin_override_payplan(
    dealership_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
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
):
    """Super admin can override any dealership's pay plan."""
    _require_super_admin(request)
    s = (await db.execute(
        select(Settings).where(Settings.dealership_id == dealership_id).limit(1)
    )).scalar_one_or_none()
    if not s:
        # Create settings for this dealership
        s = Settings(dealership_id=dealership_id)
        db.add(s)
    for f in ["unit_comm_discount_le_200","unit_comm_discount_gt_200","permaplate","nitro_fill","pulse",
              "finance_non_subvented","warranty","tire_wheel","hourly_rate_ny_offset",
              "new_volume_bonus_15_16","new_volume_bonus_17_18","new_volume_bonus_19_20",
              "new_volume_bonus_21_24","new_volume_bonus_25_plus",
              "used_volume_bonus_8_10","used_volume_bonus_11_12","used_volume_bonus_13_plus",
              "spot_bonus_5_9","spot_bonus_10_12","spot_bonus_13_plus",
              "quarterly_bonus_threshold_units","quarterly_bonus_amount"]:
        setattr(s, f, locals()[f])
    await db.commit()
    return RedirectResponse(url=f"/admin/dealership/{dealership_id}", status_code=303)


@app.post("/admin/dealership/{dealership_id}/approve")
async def admin_approve_dealership(dealership_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Approve a pending dealership — set is_active=True and subscription to 'active'."""
    _require_super_admin(request)
    d = (await db.execute(select(Dealership).where(Dealership.id == dealership_id))).scalar_one_or_none()
    if d:
        d.is_active = True
        if d.subscription_status == "pending":
            d.subscription_status = "active"
        await db.commit()
    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/dealership/{dealership_id}/delete")
async def admin_delete_dealership(dealership_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Permanently delete a dealership. Users are unassigned (not deleted).
    Deals, goals, reminders, settings, and invites for this dealership are deleted."""
    _require_super_admin(request)
    d = (await db.execute(select(Dealership).where(Dealership.id == dealership_id))).scalar_one_or_none()
    if not d:
        return RedirectResponse(url="/admin", status_code=303)

    # Unassign all users from this dealership (they become unaffiliated, not deleted)
    users_in_dealer = (await db.execute(
        select(User).where(User.dealership_id == dealership_id)
    )).scalars().all()
    for u in users_in_dealer:
        u.dealership_id = None
        u.role = "salesperson"
        u.is_verified = False
        u.verified_by = None
        u.verified_at = None

    # Delete all data belonging to this dealership
    for tbl_class in (Deal, Goal, Reminder, Settings, Invite):
        rows = (await db.execute(
            select(tbl_class).where(tbl_class.dealership_id == dealership_id)
        )).scalars().all()
        for row in rows:
            await db.delete(row)

    # Delete the dealership itself
    await db.delete(d)
    await db.commit()

    # Clear session cache for affected users
    from .auth import _cache_delete_user
    for u in users_in_dealer:
        _cache_delete_user(u.id)

    logger.info(f"Deleted dealership '{d.name}' (id={dealership_id}), unassigned {len(users_in_dealer)} user(s)")
    return RedirectResponse(url="/admin", status_code=303)


@app.get("/admin/users")
async def admin_all_users_redirect(request: Request):
    return RedirectResponse(url="/admin", status_code=307)


@app.post("/admin/user/{user_id}/assign-dealership")
async def admin_assign_user_to_dealership(
    user_id: int, request: Request, db: AsyncSession = Depends(get_db),
    dealership_id: int = Form(...), role: str = Form("salesperson"),
):
    """Assign an unaffiliated user to a dealership."""
    _require_super_admin(request)
    target = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if target and role in ("salesperson", "manager", "admin"):
        target.dealership_id = dealership_id
        target.role = role
        await db.commit()
        from .auth import _cache_delete_user
        _cache_delete_user(user_id)
    return RedirectResponse(url="/admin/users", status_code=303)


# ════════════════════════════════════════════════
# SEED — Pre-populate community with realistic content
# ════════════════════════════════════════════════

import random as _random

SEED_PAY_PLANS = {
    "Toyota": {"unit_le": 200, "unit_gt": 150, "hourly": 16, "perma": 40, "nitro": 40, "pulse": 40, "finance": 50, "warranty": 25, "tw": 25, "nv1516": 1000, "nv1718": 1250, "nv1920": 1500, "nv2124": 2000, "nv25": 3000, "uv810": 350, "uv1112": 500, "uv13": 1000, "qt": 60, "qa": 1200},
    "Honda": {"unit_le": 175, "unit_gt": 125, "hourly": 15, "perma": 35, "nitro": 35, "pulse": 35, "finance": 40, "warranty": 25, "tw": 20, "nv1516": 800, "nv1718": 1000, "nv1920": 1200, "nv2124": 1600, "nv25": 2200, "uv810": 300, "uv1112": 450, "uv13": 800, "qt": 55, "qa": 1000},
    "Ford": {"unit_le": 225, "unit_gt": 175, "hourly": 15, "perma": 50, "nitro": 45, "pulse": 45, "finance": 50, "warranty": 30, "tw": 30, "nv1516": 1200, "nv1718": 1500, "nv1920": 1800, "nv2124": 2500, "nv25": 3500, "uv810": 400, "uv1112": 600, "uv13": 1200, "qt": 55, "qa": 1500},
    "Chevrolet": {"unit_le": 190, "unit_gt": 140, "hourly": 14, "perma": 40, "nitro": 40, "pulse": 35, "finance": 45, "warranty": 25, "tw": 25, "nv1516": 900, "nv1718": 1100, "nv1920": 1400, "nv2124": 1800, "nv25": 2600, "uv810": 350, "uv1112": 500, "uv13": 900, "qt": 60, "qa": 1100},
    "Hyundai": {"unit_le": 160, "unit_gt": 110, "hourly": 14, "perma": 30, "nitro": 30, "pulse": 30, "finance": 35, "warranty": 20, "tw": 20, "nv1516": 700, "nv1718": 900, "nv1920": 1100, "nv2124": 1400, "nv25": 2000, "uv810": 250, "uv1112": 400, "uv13": 700, "qt": 50, "qa": 900},
    "Kia": {"unit_le": 155, "unit_gt": 105, "hourly": 14, "perma": 30, "nitro": 30, "pulse": 25, "finance": 35, "warranty": 20, "tw": 20, "nv1516": 650, "nv1718": 850, "nv1920": 1050, "nv2124": 1300, "nv25": 1800, "uv810": 250, "uv1112": 375, "uv13": 650, "qt": 50, "qa": 800},
    "Nissan": {"unit_le": 170, "unit_gt": 120, "hourly": 14, "perma": 35, "nitro": 35, "pulse": 30, "finance": 40, "warranty": 20, "tw": 20, "nv1516": 750, "nv1718": 950, "nv1920": 1150, "nv2124": 1500, "nv25": 2100, "uv810": 300, "uv1112": 425, "uv13": 750, "qt": 55, "qa": 950},
    "BMW": {"unit_le": 300, "unit_gt": 250, "hourly": 18, "perma": 50, "nitro": 50, "pulse": 50, "finance": 75, "warranty": 50, "tw": 40, "nv1516": 1500, "nv1718": 2000, "nv1920": 2500, "nv2124": 3500, "nv25": 5000, "uv810": 500, "uv1112": 750, "uv13": 1500, "qt": 45, "qa": 2000},
    "Subaru": {"unit_le": 165, "unit_gt": 115, "hourly": 15, "perma": 35, "nitro": 30, "pulse": 30, "finance": 35, "warranty": 25, "tw": 20, "nv1516": 750, "nv1718": 950, "nv1920": 1200, "nv2124": 1500, "nv25": 2000, "uv810": 275, "uv1112": 400, "uv13": 700, "qt": 50, "qa": 900},
    "Jeep": {"unit_le": 210, "unit_gt": 160, "hourly": 15, "perma": 45, "nitro": 40, "pulse": 40, "finance": 50, "warranty": 30, "tw": 30, "nv1516": 1100, "nv1718": 1400, "nv1920": 1700, "nv2124": 2200, "nv25": 3000, "uv810": 375, "uv1112": 550, "uv13": 1000, "qt": 55, "qa": 1300},
}

SEED_CITIES = [
    ("NY", "Wappinger Falls"), ("NY", "Poughkeepsie"), ("NJ", "Paramus"), ("NJ", "Hackensack"),
    ("CT", "Danbury"), ("PA", "Philadelphia"), ("CA", "Torrance"), ("CA", "Fremont"),
    ("TX", "Plano"), ("TX", "Houston"), ("FL", "Orlando"), ("FL", "Tampa"),
    ("IL", "Naperville"), ("OH", "Dublin"), ("GA", "Marietta"), ("VA", "Tysons"),
]

SEED_TEXT_POSTS = [
    ("Is anyone else getting crushed on used car inventory?", "My lot has maybe 30 pre-owned units and half of them are over 80k miles. Meanwhile new is flowing in but the margins are trash. Anyone else dealing with this?"),
    ("Just hit 20 units for the first time", "Been grinding for 8 months at this store. Finally broke 20 this month — 14 new 6 used. The volume bonus really kicks in at this level."),
    ("How do you handle the 'I need to think about it' objection?", "Serious question. I lose at least 3-4 deals a month to this. What's your go-to response?"),
    ("F&I is killing my deals", "My finance manager pushes so hard on products that customers get buyer's remorse and back out. Lost two deliveries last week because of this. Anyone else?"),
    ("What CRM does your store use?", "We're on DealerSocket and it's painful. Curious what everyone else is using and if it's any better."),
    ("Saturday hours are brutal", "12 hour shifts every Saturday. No rotating schedule. Manager says 'that's the car business.' Is this normal everywhere?"),
    ("Thinking about switching to a luxury brand", "Been at a volume store doing 18-20 units/month. BMW dealer down the road is hiring. Less units but bigger grosses. Anyone made this switch?"),
    ("Tips for working internet leads", "I get about 40 internet leads a month and my close rate is maybe 8%. The good salespeople here are at 15%+. What am I doing wrong?"),
    ("New guy here — what should I know?", "Just got hired at my first dealership. Any advice for a green pea? What do you wish someone told you on day one?"),
    ("Pay plan just changed and I'm making less", "They restructured our commission and now the per-unit flat is $50 less. They say the volume bonuses make up for it but you'd need 20+ units to break even. Shady."),
    ("How many hours do you actually work per week?", "I'm at about 55 hours and my manager acts like I'm part-time. What's normal in this industry?"),
    ("Best month of my career", "26 units, mix of new and used. Some luck with walk-ins but mostly internet leads I've been nurturing for months. Just wanted to share the win."),
]

SEED_POLLS = [
    ("How many units do you average per month?", ["Under 10", "10-14", "15-19", "20-24", "25+"]),
    ("How long have you been in car sales?", ["Under 1 year", "1-3 years", "3-5 years", "5-10 years", "10+ years"]),
    ("What's your biggest source of deals?", ["Walk-ins", "Internet leads", "Phone ups", "Referrals/Repeats", "Service drive"]),
    ("Are you happy with your pay plan?", ["Yes, it's fair", "It's okay", "No, it's below average", "It's terrible"]),
    ("Do you work a 5 or 6 day week?", ["5 days", "5.5 days", "6 days", "Varies"]),
    ("Would you recommend car sales to a friend?", ["Absolutely", "Maybe", "Probably not", "Never"]),
]


@app.get("/admin/seed", response_class=HTMLResponse)
async def admin_seed_page(request: Request, db: AsyncSession = Depends(get_db)):
    """Show the seed community page."""
    _require_super_admin(request)
    user = await _user(request, db)
    post_count = (await db.execute(select(func.count()).where(Post.is_deleted == False))).scalar() or 0
    return templates.TemplateResponse("admin_seed.html", {
        "request": request, "user": user, "post_count": post_count,
        "overdue_reminders": await get_overdue_reminders(db, uid(request)),
        "has_new_posts": await get_new_community_posts(db, uid(request)),
    })


@app.post("/admin/seed")
async def admin_seed_execute(request: Request, db: AsyncSession = Depends(get_db)):
    """Generate seed content for the community."""
    _require_super_admin(request)

    # Create seed dealerships (one per brand/city combo)
    seed_dealerships = []
    for brand, pp in SEED_PAY_PLANS.items():
        state, city = _random.choice(SEED_CITIES)
        name = f"{brand} of {city}"
        slug = f"seed-{brand.lower()}-{city.lower().replace(' ', '-')}"

        existing = (await db.execute(select(Dealership).where(Dealership.slug == slug))).scalar_one_or_none()
        if existing:
            seed_dealerships.append(existing)
            continue

        d = Dealership(
            name=name, slug=slug, brand=brand, state=state,
            subscription_status="free", is_active=True,
        )
        db.add(d)
        await db.commit()
        await db.refresh(d)
        seed_dealerships.append(d)

    # Create pay plan posts (one per brand)
    for d in seed_dealerships:
        brand = d.brand
        pp = SEED_PAY_PLANS.get(brand, {})
        if not pp:
            continue

        # Check if we already seeded a pay plan for this dealership
        existing = (await db.execute(
            select(Post).where(Post.dealership_id == d.id, Post.post_type == "payplan", Post.is_deleted == False)
        )).scalar_one_or_none()
        if existing:
            continue

        payload = _json.dumps({
            "unit_comm_le_200": pp["unit_le"], "unit_comm_gt_200": pp["unit_gt"],
            "hourly_offset": pp["hourly"],
            "permaplate": pp["perma"], "nitro_fill": pp["nitro"], "pulse": pp["pulse"],
            "finance": pp["finance"], "warranty": pp["warranty"], "tire_wheel": pp["tw"],
            "new_vol_15_16": pp["nv1516"], "new_vol_17_18": pp["nv1718"],
            "new_vol_19_20": pp["nv1920"], "new_vol_21_24": pp["nv2124"],
            "new_vol_25_plus": pp["nv25"],
            "used_vol_8_10": pp["uv810"], "used_vol_11_12": pp["uv1112"],
            "used_vol_13_plus": pp["uv13"],
            "quarterly_threshold": pp["qt"], "quarterly_amount": pp["qa"],
        })
        comments = [
            f"Current {brand} pay plan as of this year. Volume bonuses are decent if you can push past 15.",
            f"Our {brand} store's commission structure. Add-ons are where the real money is.",
            f"Sharing our {brand} pay plan for transparency. Unit flat is solid but used bonus tiers are weak.",
        ]
        post = Post(
            user_id=uid(request), dealership_id=d.id, post_type="payplan",
            anonymity="brand", title=f"{brand} Pay Plan",
            body=_random.choice(comments), payload=payload,
            upvote_count=_random.randint(3, 25),
            created_at=_utcnow() - timedelta(days=_random.randint(0, 14)),
        )
        db.add(post)

    # Create YTD posts
    for d in _random.sample(seed_dealerships, min(5, len(seed_dealerships))):
        existing = (await db.execute(
            select(Post).where(Post.dealership_id == d.id, Post.post_type == "ytd", Post.is_deleted == False)
        )).scalar_one_or_none()
        if existing:
            continue

        yr = today().year
        mo = today().month
        months = [0] * 12
        total = 0
        for i in range(mo):
            m_units = _random.randint(10, 28)
            months[i] = m_units
            total += m_units
        avg = total / mo if mo else 0
        new_pct = _random.uniform(0.5, 0.75)
        payload = _json.dumps({
            "year": yr, "total_units": total, "months": months,
            "avg_per_month": round(avg, 1),
            "new_count": int(total * new_pct), "used_count": total - int(total * new_pct),
        })
        comments = [
            "Sharing my numbers. February was slow but picking back up.",
            "YTD so far. Trying to hit 250 by end of year.",
            "Not my best start but grinding it out.",
        ]
        post = Post(
            user_id=uid(request), dealership_id=d.id, post_type="ytd",
            anonymity=_random.choice(["brand", "anonymous"]),
            title="My YTD Numbers", body=_random.choice(comments),
            payload=payload, upvote_count=_random.randint(2, 18),
            created_at=_utcnow() - timedelta(days=_random.randint(0, 7)),
        )
        db.add(post)

    # Create text posts
    for title, body in SEED_TEXT_POSTS:
        existing = (await db.execute(
            select(Post).where(Post.title == title, Post.is_deleted == False)
        )).scalar_one_or_none()
        if existing:
            continue

        d = _random.choice(seed_dealerships)
        post = Post(
            user_id=uid(request), dealership_id=d.id, post_type="text",
            anonymity=_random.choice(["brand", "anonymous", "anonymous"]),
            title=title, body=body,
            upvote_count=_random.randint(1, 40),
            created_at=_utcnow() - timedelta(days=_random.randint(0, 21)),
        )
        db.add(post)

    # Create polls
    for question, options in SEED_POLLS:
        existing = (await db.execute(
            select(Post).where(Post.title == question, Post.is_deleted == False)
        )).scalar_one_or_none()
        if existing:
            continue

        d = _random.choice(seed_dealerships)
        post = Post(
            user_id=uid(request), dealership_id=d.id, post_type="poll",
            anonymity="anonymous", title=question, body="",
            upvote_count=_random.randint(5, 30),
            created_at=_utcnow() - timedelta(days=_random.randint(0, 14)),
        )
        db.add(post)
        await db.commit()
        await db.refresh(post)

        total_votes = _random.randint(20, 80)
        weights = [_random.random() for _ in options]
        weight_sum = sum(weights)
        for i, label in enumerate(options):
            votes = int(total_votes * weights[i] / weight_sum)
            db.add(PollOption(post_id=post.id, label=label, vote_count=votes, sort_order=i))

    await db.commit()
    return RedirectResponse(url="/admin/seed", status_code=303)
