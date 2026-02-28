import logging
import os
import io
import secrets
import csv
import ssl
import re
import urllib.parse
import calendar
import traceback
from datetime import date, datetime, timedelta

from fastapi import FastAPI, Request, Form, Depends, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import NullPool
from sqlalchemy import select, func, or_, and_

from .models import Base, User, Deal, Settings, Goal, UserSession, PasswordResetToken
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
    _ssl_ctx = ssl.create_default_context()
    _ssl_ctx.check_hostname = False
    _ssl_ctx.verify_mode = ssl.CERT_NONE
    connect_args = {
        "ssl": _ssl_ctx,
        "statement_cache_size": 0,
        "prepared_statement_cache_size": 0,
    }

engine = create_async_engine(
    db_url, echo=False, future=True,
    connect_args=connect_args,
    poolclass=NullPool,
)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)


# ─── App setup ───
app = FastAPI(title="Commission Tracker")
templates = Jinja2Templates(directory="app/templates")

templates.env.filters["md"] = lambda v: f"{v.month}/{v.day}" if v else ""
templates.env.globals["today"] = today
templates.env.globals["current_month"] = lambda: today().strftime("%Y-%m")

static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.exception_handler(Exception)
async def _exc(request: Request, exc: Exception):
    return HTMLResponse(
        f"<h1>Server Error</h1><p>{request.url}</p><pre style='white-space:pre-wrap'>{traceback.format_exc()}</pre>",
        status_code=500,
    )

async def get_db():
    async with SessionLocal() as session:
        yield session


# ─── Auth helpers ───
PUBLIC_PATHS = {"/login", "/register", "/forgot-password", "/auth/reset-confirm"}

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
    response = await call_next(request)
    # Piggyback probabilistic session cleanup (Vercel serverless-safe)
    asyncio.create_task(maybe_cleanup_sessions())
    return response


def uid(request: Request) -> int:
    return request.state.user_id

async def _user(request: Request, db: AsyncSession) -> User:
    return (await db.execute(select(User).where(User.id == uid(request)))).scalar_one()


# ─── Startup / Migrations ───
# We use raw asyncpg for DDL because SQLAlchemy's asyncpg dialect
# calls prepare() during initialization, which pgBouncer rejects.
@app.on_event("startup")
async def startup():
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
    finally:
        # Clean up expired sessions via raw asyncpg (avoids pgBouncer prepared stmt issue)
        try:
            await conn.execute("DELETE FROM user_sessions WHERE expires_at <= NOW()")
            await conn.execute("DELETE FROM password_reset_tokens WHERE expires_at <= NOW()")
        except Exception as e:
            pass
        await conn.close()


import asyncio
import random

# Vercel is serverless — no persistent background tasks.
# Instead, we piggyback cleanup on ~1% of incoming requests.
_cleanup_counter = 0

async def maybe_cleanup_sessions():
    """Probabilistic cleanup: runs on roughly 1 in 100 requests."""
    if not _is_pg:
        return
    if random.randint(1, 100) != 1:
        return
    try:
        raw_dsn = DATABASE_URL.strip().split("?")[0]
        c = await _asyncpg.connect(dsn=raw_dsn, ssl=_ssl_ctx, statement_cache_size=0)
        try:
            await c.execute("DELETE FROM user_sessions WHERE expires_at <= NOW()")
            await c.execute("DELETE FROM password_reset_tokens WHERE expires_at <= NOW()")
        finally:
            await c.close()
    except Exception as e:
        logger.warning(f"Session cleanup error: {e}")


# ─── Utility functions ───
def month_bounds(d: date):
    start = date(d.year, d.month, 1)
    end = date(d.year + 1, 1, 1) if d.month == 12 else date(d.year, d.month + 1, 1)
    return start, end

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

def _set_session_cookie(resp, token: str, remember_me: bool):
    """Set the session cookie with appropriate TTL."""
    max_age = 60 * 60 * 24 * 30 if remember_me else None  # 30 days or session cookie
    resp.set_cookie(
        "ct_session", token,
        httponly=True,
        samesite="lax",
        secure=True,
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
    redirect_to = next if next.startswith("/") else "/"
    error_ctx = {
        "request": request, "mode": "login", "success": "",
        "supabase_enabled": SUPABASE_ENABLED, "next": redirect_to,
    }

    if SUPABASE_ENABLED:
        # ── Supabase path ──
        login_email = (email or username).strip().lower()
        if not login_email or not password:
            return templates.TemplateResponse("login.html", {
                **error_ctx, "error": "Please enter your email and password."
            })
        result = await supabase_sign_in(login_email, password)
        if "error" in result:
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
        user = (await db.execute(select(User).where(User.username == uname))).scalar_one_or_none()
        if not user or not verify_password(password, user.password_hash, user.password_salt):
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
            created_at=datetime.utcnow().isoformat(),
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
            logger.info(f"Password reset link for {email}: {reset_url}")
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
        from sqlalchemy import select
        from .models import PasswordResetToken
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


# ════════════════════════════════════════════════
# DASHBOARD
# ════════════════════════════════════════════════
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

    deals = (await db.execute(
        select(Deal).where(Deal.user_id == user_id)
        .order_by(Deal.delivered_date.desc().nullslast(), Deal.sold_date.desc().nullslast())
    )).scalars().all()

    today_date = today()

    # Parse month/year
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

    delivered_mtd = [d for d in deals if d.status == "Delivered" and d.delivered_date and start_m <= d.delivered_date < end_m]

    # Previous month
    py, pm = (sel_y - 1, 12) if sel_m == 1 else (sel_y, sel_m - 1)
    ps, pe = month_bounds(date(py, pm, 1))
    prev_del = [d for d in deals if d.status == "Delivered" and d.delivered_date and ps <= d.delivered_date < pe]

    # Stats
    units_mtd = len(delivered_mtd)
    comm_mtd = sum((d.total_deal_comm or 0) for d in delivered_mtd)
    paid_comm = sum((d.total_deal_comm or 0) for d in delivered_mtd if d.is_paid)
    new_mtd = len([d for d in delivered_mtd if (d.new_used or "").lower() == "new"])
    used_mtd = len([d for d in delivered_mtd if (d.new_used or "").lower() == "used"])
    avg_deal = comm_mtd / units_mtd if units_mtd else 0.0

    # Closing rates
    dt = len(delivered_mtd)
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

    # Bonus tiers
    vol_tiers = [(25,None,float(s.new_volume_bonus_25_plus)),(21,24,float(s.new_volume_bonus_21_24)),
                 (19,20,float(s.new_volume_bonus_19_20)),(17,18,float(s.new_volume_bonus_17_18)),(15,16,float(s.new_volume_bonus_15_16))]
    used_tiers = [(13,None,float(s.used_volume_bonus_13_plus)),(11,12,float(s.used_volume_bonus_11_12)),(8,10,float(s.used_volume_bonus_8_10))]
    spot_tiers = [(13,None,float(s.spot_bonus_13_plus)),(10,12,float(s.spot_bonus_10_12)),(5,9,float(s.spot_bonus_5_9))]

    vol_amt, vol_tier = _tiered(units_mtd, vol_tiers)
    used_amt, used_tier = _tiered(used_mtd, used_tiers)
    spots = sum(1 for d in delivered_mtd if d.spot_sold)
    spot_total, spot_per, spot_tier = _tiered_spot(spots, spot_tiers)

    qs, qe = quarter_bounds(d0)
    qtd = [d for d in deals if d.status == "Delivered" and d.delivered_date and qs <= d.delivered_date < qe]
    q_hit = len(qtd) >= int(s.quarterly_bonus_threshold_units or 0)
    q_bonus = float(s.quarterly_bonus_amount) if q_hit else 0.0
    bonus_total = float(vol_amt) + float(used_amt) + float(spot_total) + q_bonus

    # Projections
    pending_all = [d for d in deals if d.status == "Pending"]
    pend_month = [d for d in pending_all if d.sold_date and start_m <= d.sold_date < end_m]
    proj_units = units_mtd + len(pend_month)
    proj_comm = comm_mtd + sum((d.total_deal_comm or 0) for d in pend_month)
    proj_used = used_mtd + len([d for d in pend_month if (d.new_used or "").lower() == "used"])
    pv, _ = _tiered(proj_units, vol_tiers)
    pu, _ = _tiered(proj_used, used_tiers)
    proj_bonus = float(pv) + float(pu) + float(spot_total) + q_bonus

    bonus_breakdown = {
        "volume": {"units": units_mtd, "new_units": new_mtd, "used_units": used_mtd, "tier": vol_tier, "amount": float(vol_amt), "next": _next_tier(units_mtd, vol_tiers)},
        "used": {"units": used_mtd, "tier": used_tier, "amount": float(used_amt), "next": _next_tier(used_mtd, used_tiers)},
        "spot": {"spots": spots, "tier": spot_tier, "per": float(spot_per), "amount": float(spot_total), "next": _next_spot(spots, spot_tiers)},
        "quarterly": {"units_qtd": len(qtd), "threshold": int(s.quarterly_bonus_threshold_units or 0), "hit": q_hit, "amount": q_bonus,
                       "q_label": f"Q{((sel_m-1)//3)+1}", "next": {"tier": "Hit" if q_hit else f"{int(s.quarterly_bonus_threshold_units or 0)} units",
                       "need": 0 if q_hit else max(0, int(s.quarterly_bonus_threshold_units or 0) - len(qtd)), "amount": float(s.quarterly_bonus_amount or 0)}},
        "total": bonus_total,
    }

    # Year trend
    yr_del = [d for d in deals if d.status == "Delivered" and d.delivered_date and d.delivered_date.year == sel_y]
    ubm = [0]*12; cbm = [0.0]*12
    for d in yr_del:
        ubm[d.delivered_date.month-1] += 1
        cbm[d.delivered_date.month-1] += (d.total_deal_comm or 0)

    # Pending
    for d in pending_all:
        d.days_pending = (today_date - d.sold_date).days if d.sold_date else 0
    pending_all.sort(key=lambda x: x.sold_date or date.max)

    # Milestones
    milestones = []
    if vol_amt > 0: milestones.append(f"Volume Bonus unlocked — ${vol_amt:,.0f}")
    if used_amt > 0: milestones.append(f"Used Bonus unlocked — ${used_amt:,.0f}")
    if spot_total > 0: milestones.append(f"Spot Bonus active — ${spot_total:,.0f}")
    if q_hit: milestones.append(f"Quarterly target hit — ${q_bonus:,.0f}")

    # Goals
    goal = (await db.execute(select(Goal).where(Goal.user_id == user_id, Goal.year == sel_y, Goal.month == sel_m).limit(1))).scalar_one_or_none()
    goals = {"unit_goal": goal.unit_goal if goal else 20, "commission_goal": goal.commission_goal if goal else 8000.0, "has_custom": goal is not None}

    # Today's deliveries
    todays = [d for d in deals if d.status not in ("Delivered","Dead") and d.scheduled_date == today_date]

    years = sorted({today_date.year} | {d.delivered_date.year for d in deals if d.delivered_date} | {d.sold_date.year for d in deals if d.sold_date}, reverse=True)

    resp = templates.TemplateResponse("dashboard.html", {
        "request": request, "user": user,
        "month": month_key, "selected_year": sel_y, "selected_month": sel_m,
        "year_options": years, "month_options": [{"num": i, "label": calendar.month_name[i]} for i in range(1,13)],
        "units_mtd": units_mtd, "closing_rates": closing_rates,
        "comm_mtd": comm_mtd, "paid_comm_mtd": paid_comm, "pending_comm_mtd": comm_mtd - paid_comm,
        "new_mtd": new_mtd, "used_mtd": used_mtd, "avg_per_deal": avg_deal,
        "current_bonus_total": bonus_total, "bonus_breakdown": bonus_breakdown,
        "units_ytd": len(yr_del), "comm_ytd": sum((d.total_deal_comm or 0) for d in yr_del),
        "pending": len(pending_all), "pending_deals": pending_all[:15], "pending_deals_all": pending_all,
        "year": sel_y, "month_labels": ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"],
        "units_by_month": ubm, "comm_by_month": cbm,
        "prev_units": len(prev_del), "prev_comm": sum((d.total_deal_comm or 0) for d in prev_del),
        "units_diff": units_mtd - len(prev_del), "comm_diff": comm_mtd - sum((d.total_deal_comm or 0) for d in prev_del),
        "proj_units": proj_units, "proj_comm": proj_comm,
        "proj_bonus_total": proj_bonus, "bonus_uplift": proj_bonus - bonus_total,
        "pending_in_month_count": len(pend_month),
        "goals": goals, "milestones": milestones, "todays_deliveries": todays,
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
    goal = (await db.execute(select(Goal).where(Goal.user_id == user_id, Goal.year == y, Goal.month == m).limit(1))).scalar_one_or_none()
    if goal:
        goal.unit_goal = unit_goal; goal.commission_goal = commission_goal
    else:
        db.add(Goal(user_id=user_id, year=y, month=m, unit_goal=unit_goal, commission_goal=commission_goal))
    await db.commit()
    return RedirectResponse(url=f"/?year={y}&month={m}", status_code=303)


# ════════════════════════════════════════════════
# DEALS LIST
# ════════════════════════════════════════════════
@app.get("/deals", response_class=HTMLResponse)
async def deals_list(request: Request, q: str | None = None, status: str | None = None, paid: str | None = None, db: AsyncSession = Depends(get_db)):
    user_id = uid(request)
    td = today()
    try: y = int(request.cookies.get("ct_year") or td.year)
    except: y = td.year
    try: m = int(request.cookies.get("ct_month") or td.month)
    except: m = td.month
    start_sel, end_sel = month_bounds(date(y, max(1,min(12,m)), 1))

    stmt = select(Deal).where(Deal.user_id == user_id).order_by(Deal.delivered_date.desc().nullslast(), Deal.sold_date.desc().nullslast())
    carry = ["inbound", "fo"]
    stmt = stmt.where(or_(
        and_(Deal.sold_date.is_not(None), Deal.sold_date >= start_sel, Deal.sold_date < end_sel),
        and_(func.lower(func.coalesce(Deal.tag, "")).in_(carry), Deal.status != "Delivered"),
    ))
    if status and status != "All": stmt = stmt.where(Deal.status == status)
    if paid == "Paid": stmt = stmt.where(Deal.is_paid.is_(True))
    elif paid == "Pending": stmt = stmt.where(Deal.is_paid.is_(False))
    if q and q.strip():
        like = f"%{q.strip()}%"
        stmt = stmt.where((Deal.customer.ilike(like)) | (Deal.stock_num.ilike(like)) | (Deal.model.ilike(like)))

    deals = (await db.execute(stmt)).scalars().all()
    user = await _user(request, db)
    return templates.TemplateResponse("deals.html", {
        "request": request, "user": user, "deals": deals, "q": q or "", "status": status or "All", "paid": paid or "All",
        "selected_year": y, "selected_month": m,
    })


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
        existing = (await db.execute(select(Deal).where(Deal.id == deal_id, Deal.user_id == user_id))).scalar_one()
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
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id, Deal.user_id == uid(request)))).scalar_one()
    deal.is_paid = not deal.is_paid
    if deal.is_paid and not deal.pay_date: deal.pay_date = today()
    await db.commit()
    return RedirectResponse(url=(next or "/deals"), status_code=303)

@app.post("/deals/{deal_id}/mark_delivered")
async def mark_delivered(deal_id: int, request: Request, redirect: str | None = Form(None), month: str | None = Form(None), db: AsyncSession = Depends(get_db)):
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id, Deal.user_id == uid(request)))).scalar_one()
    deal.status = "Delivered"; deal.delivered_date = today()
    await db.commit()
    return RedirectResponse(url=(redirect or (f"/?month={month}" if month else "/")), status_code=303)

@app.post("/deals/{deal_id}/mark_dead")
async def mark_dead(deal_id: int, request: Request, redirect: str | None = Form(None), month: str | None = Form(None), db: AsyncSession = Depends(get_db)):
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id, Deal.user_id == uid(request)))).scalar_one()
    deal.status = "Dead"
    await db.commit()
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
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id, Deal.user_id == uid(request)))).scalar_one()
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
    return templates.TemplateResponse("delivery_board.html", {"request": request, "user": user, "prep": prep, "ready": ready, "delivered": delivered, "total": len(prep)+len(ready)})

@app.post("/delivery/{deal_id}/toggle")
async def delivery_toggle(deal_id: int, request: Request, field: str = Form(...), db: AsyncSession = Depends(get_db)):
    if field not in {"gas_ready","inspection_ready","insurance_ready"}: return RedirectResponse(url="/delivery", status_code=303)
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id, Deal.user_id == uid(request)))).scalar_one()
    setattr(deal, field, not getattr(deal, field)); await db.commit()
    return RedirectResponse(url="/delivery", status_code=303)

@app.post("/delivery/{deal_id}/deliver")
async def delivery_deliver(deal_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id, Deal.user_id == uid(request)))).scalar_one()
    deal.status = "Delivered"; deal.delivered_date = today(); await db.commit()
    return RedirectResponse(url="/delivery", status_code=303)

@app.post("/delivery/{deal_id}/remove")
async def delivery_remove(deal_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id, Deal.user_id == uid(request)))).scalar_one()
    deal.on_delivery_board = False; deal.gas_ready = False; deal.inspection_ready = False; deal.insurance_ready = False
    await db.commit()
    return RedirectResponse(url="/delivery", status_code=303)

@app.post("/delivery/{deal_id}/push")
async def delivery_push(deal_id: int, request: Request, next: str | None = Form(None), db: AsyncSession = Depends(get_db)):
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id, Deal.user_id == uid(request)))).scalar_one()
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
    import difflib
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
    import json
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
    import base64
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
    import base64, json as _json
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
    import base64, json as _json
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

    import_batch_id = f"imp_{secrets.token_hex(8)}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    imported = skipped = 0
    errors = []

    for i, row in enumerate(rows):
        if i in skip_indices:
            skipped += 1
            continue
        try:
            deal_in = _parse_row(row, mapping, settings)
            if deal_in is None:
                skipped += 1
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
    from sqlalchemy import func as sqlfunc
    rows = (await db.execute(
        select(
            Deal.import_batch_id,
            sqlfunc.count(Deal.id).label("count"),
            sqlfunc.min(Deal.sold_date).label("earliest"),
            sqlfunc.max(Deal.sold_date).label("latest"),
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
# PAY PLAN
# ════════════════════════════════════════════════
@app.get("/payplan", response_class=HTMLResponse)
async def payplan_get(request: Request, db: AsyncSession = Depends(get_db)):
    s = await get_or_create_settings(db, uid(request))
    user = await _user(request, db)
    return templates.TemplateResponse("payplan.html", {"request": request, "user": user, "s": s})

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
