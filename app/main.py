import os
import io
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

from .models import Base, User, Deal, Settings, Goal
from .schemas import DealIn
from .payplan import calc_commission
from .utils import parse_date, today
from .auth import (
    hash_password, verify_password,
    create_session, get_user_id_from_session, destroy_session,
    get_session_token, get_current_user, get_or_create_settings,
)


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
if "asyncpg" in db_url:
    _ssl = ssl.create_default_context()
    _ssl.check_hostname = False
    _ssl.verify_mode = ssl.CERT_NONE
    connect_args = {"ssl": _ssl, "statement_cache_size": 0, "prepared_statement_cache_size": 0}

engine = create_async_engine(db_url, echo=False, future=True, connect_args=connect_args, poolclass=NullPool)
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
PUBLIC_PATHS = {"/login", "/register"}

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if path in PUBLIC_PATHS or path.startswith("/static"):
        return await call_next(request)
    token = get_session_token(request)
    uid = get_user_id_from_session(token)
    if uid is None:
        return RedirectResponse(url="/login", status_code=303)
    request.state.user_id = uid
    return await call_next(request)


def uid(request: Request) -> int:
    return request.state.user_id

async def _user(request: Request, db: AsyncSession) -> User:
    return (await db.execute(select(User).where(User.id == uid(request)))).scalar_one()


# ─── Startup / Migrations ───
@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Add user_id columns to existing tables (backward compat migration)
        for tbl in ("deals", "settings", "goals"):
            try:
                await conn.exec_driver_sql(f"ALTER TABLE {tbl} ADD COLUMN user_id INTEGER REFERENCES users(id)")
            except Exception:
                try:
                    await conn.exec_driver_sql(f"ALTER TABLE {tbl} ADD COLUMN IF NOT EXISTS user_id INTEGER REFERENCES users(id)")
                except Exception:
                    pass
        # Legacy column migrations
        for col, typ, dflt in [
            ("scheduled_date", "DATE", "NULL"),
            ("on_delivery_board", "BOOLEAN", "false"),
            ("gas_ready", "BOOLEAN", "false"),
            ("inspection_ready", "BOOLEAN", "false"),
            ("insurance_ready", "BOOLEAN", "false"),
        ]:
            try:
                await conn.exec_driver_sql(f"ALTER TABLE deals ADD COLUMN IF NOT EXISTS {col} {typ} DEFAULT {dflt}")
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
                await conn.exec_driver_sql(f"ALTER TABLE settings ADD COLUMN IF NOT EXISTS {col} {typ} DEFAULT {dflt}")
            except Exception:
                pass


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
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = ""):
    return templates.TemplateResponse("login.html", {"request": request, "error": error, "mode": "login"})

@app.post("/login")
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    username = username.strip().lower()
    user = (await db.execute(select(User).where(User.username == username))).scalar_one_or_none()
    if not user or not verify_password(password, user.password_hash, user.password_salt):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid username or password",
            "mode": "login",
        })
    token = create_session(user.id)
    resp = RedirectResponse(url="/", status_code=303)
    resp.set_cookie("ct_session", token, httponly=True, samesite="lax", max_age=60*60*24*30)
    return resp

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request, error: str = ""):
    return templates.TemplateResponse("login.html", {"request": request, "error": error, "mode": "register"})

@app.post("/register")
async def register_post(
    request: Request,
    username: str = Form(...),
    display_name: str = Form(""),
    password: str = Form(...),
    password2: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    username = username.strip().lower()
    errors = []
    if len(username) < 3:
        errors.append("Username must be at least 3 characters")
    if len(password) < 6:
        errors.append("Password must be at least 6 characters")
    if password != password2:
        errors.append("Passwords don't match")
    existing = (await db.execute(select(User).where(User.username == username))).scalar_one_or_none()
    if existing:
        errors.append("Username already taken")
    if errors:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": ". ".join(errors),
            "mode": "register",
        })
    pw_hash, pw_salt = hash_password(password)
    user = User(
        username=username,
        display_name=(display_name.strip() or username),
        password_hash=pw_hash,
        password_salt=pw_salt,
        created_at=datetime.utcnow().isoformat(),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    # Auto-create settings for the new user
    await get_or_create_settings(db, user.id)
    token = create_session(user.id)
    resp = RedirectResponse(url="/", status_code=303)
    resp.set_cookie("ct_session", token, httponly=True, samesite="lax", max_age=60*60*24*30)
    return resp

@app.get("/logout")
async def logout(request: Request):
    destroy_session(get_session_token(request))
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
    discount_gt_200: str = Form("No"), aim_presentation: str = Form("X"),
    permaplate: int = Form(0), nitro_fill: int = Form(0), pulse: int = Form(0),
    finance_non_subvented: int = Form(0), warranty: int = Form(0), tire_wheel: int = Form(0),
    hold_amount: float = Form(0.0), aim_amount: float = Form(0.0), fi_pvr: float = Form(0.0),
    notes: str | None = Form(None), pay_date: str | None = Form(None), is_paid: int = Form(0),
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
        spot_sold=bool(spot_sold), discount_gt_200=(discount_gt_200 or "No"),
        aim_presentation=(aim_presentation or "X"),
        permaplate=bool(permaplate), nitro_fill=bool(nitro_fill), pulse=bool(pulse),
        finance_non_subvented=bool(dt in ("Finance","Lease") or finance_non_subvented),
        warranty=bool(warranty), tire_wheel=bool(tire_wheel),
        hold_amount=float(hold_amount or 0), aim_amount=float(aim_amount or 0), fi_pvr=float(fi_pvr or 0),
        notes=notes or "", pay_date=pay, is_paid=bool(is_paid),
    )
    uc, ao, th, tot = calc_commission(deal_in, settings)

    if deal_id:
        for k, v in deal_in.model_dump().items(): setattr(existing, k, v)
        existing.unit_comm = uc; existing.add_ons = ao; existing.trade_hold_comm = th; existing.total_deal_comm = tot
    else:
        deal = Deal(**deal_in.model_dump(), user_id=user_id, unit_comm=uc, add_ons=ao, trade_hold_comm=th, total_deal_comm=tot)
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
# CSV IMPORT
# ════════════════════════════════════════════════
@app.get("/import", response_class=HTMLResponse)
async def import_page(request: Request, db: AsyncSession = Depends(get_db)):
    user = await _user(request, db)
    return templates.TemplateResponse("import.html", {"request": request, "user": user, "result": None})

@app.post("/import", response_class=HTMLResponse)
async def import_csv(request: Request, file: UploadFile = File(...), db: AsyncSession = Depends(get_db)):
    user_id = uid(request)
    settings = await get_or_create_settings(db, user_id)
    text = (await file.read()).decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(text))
    imported = skipped = 0; errors = []

    def _yn(val): return (val or "").strip().lower() in ("y","yes","1","true")

    for i, row in enumerate(reader, start=2):
        try:
            cust = (row.get("Customer") or row.get("customer") or "").strip()
            if not cust: skipped += 1; continue
            sold = parse_date(row.get("Sold Date") or row.get("sold_date") or "")
            delivered = parse_date(row.get("Delivered Date") or row.get("delivered_date") or "")
            sched = parse_date(row.get("Scheduled Date") or row.get("scheduled_date") or "")
            st = (row.get("Status") or "Pending").strip()
            if st.lower() in ("delivered","d"): st = "Delivered"
            elif st.lower() in ("dead","x"): st = "Dead"
            elif st.lower() in ("scheduled","sched"): st = "Scheduled"
            else: st = "Pending"
            nu = (row.get("New/Used") or "").strip()
            if nu.lower() in ("n","new"): nu = "New"
            elif nu.lower() in ("u","used"): nu = "Used"
            dt = (row.get("F/C/L") or "").strip()
            if dt.lower() in ("f","finance"): dt = "Finance"
            elif dt.lower() in ("c","cash","cash/sub-vented"): dt = "Cash/Sub-Vented"
            elif dt.lower() in ("l","lease"): dt = "Lease"
            try: hold = float(row.get("Hold Amount") or "0")
            except: hold = 0.0
            aim = (row.get("Aim") or "X").strip()
            if aim.lower() in ("y","yes"): aim = "Yes"
            elif aim.lower() in ("n","no"): aim = "No"
            else: aim = "X"
            fin = _yn(row.get("Finance") or "")
            if not fin and dt in ("Finance","Lease"): fin = True

            deal_in = DealIn(
                sold_date=sold, delivered_date=delivered, scheduled_date=sched, status=st,
                tag=(row.get("Tag") or "").strip(), customer=cust,
                stock_num=(row.get("Stock #") or "").strip(), model=(row.get("Model") or "").strip(),
                new_used=nu, deal_type=dt, business_manager=(row.get("F&I") or "").strip(),
                spot_sold=_yn(row.get("Spot") or ""),
                discount_gt_200="Yes" if _yn(row.get("Discount>200") or "") else "No",
                aim_presentation=aim,
                permaplate=_yn(row.get("PermaPlate") or ""), nitro_fill=_yn(row.get("Nitro Fill") or ""),
                pulse=_yn(row.get("Pulse") or ""), finance_non_subvented=fin,
                warranty=_yn(row.get("Warranty") or ""), tire_wheel=_yn(row.get("Tire&Wheel") or ""),
                hold_amount=hold, notes=(row.get("Notes") or "").strip(),
                pay_date=parse_date(row.get("Pay Date") or ""), is_paid=_yn(row.get("Paid") or ""),
            )
            uc, ao, th, tot = calc_commission(deal_in, settings)
            db.add(Deal(**deal_in.model_dump(), user_id=user_id, unit_comm=uc, add_ons=ao, trade_hold_comm=th, total_deal_comm=tot))
            imported += 1
        except Exception as e:
            errors.append(f"Row {i}: {e}")
    await db.commit()
    user = await _user(request, db)
    return templates.TemplateResponse("import.html", {"request": request, "user": user, "result": {"imported": imported, "skipped": skipped, "errors": errors}})


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
