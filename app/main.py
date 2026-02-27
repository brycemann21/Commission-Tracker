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
from sqlalchemy import select, func, or_, and_

from .models import Base, Deal, Settings, Goal
from .schemas import DealIn
from .payplan import calc_commission
from .utils import parse_date, today


# -----------------------------
# DB setup
# -----------------------------
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite+aiosqlite:////tmp/commission.db")

def sanitize_db_url(url: str) -> str:
    """Remove libpq-only query params (e.g. sslmode) that asyncpg doesn't accept."""
    try:
        parsed = urllib.parse.urlsplit(url)
        qs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        qs = [(k, v) for (k, v) in qs if k.lower() not in {"sslmode", "sslrootcert", "sslcert", "sslkey"}]
        new_query = urllib.parse.urlencode(qs)
        return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment))
    except Exception:
        return url

SSL_CONTEXT = ssl.create_default_context()
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode = ssl.CERT_NONE

db_url = sanitize_db_url(DATABASE_URL)
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql+asyncpg://", 1)
elif db_url.startswith("postgresql://"):
    db_url = db_url.replace("postgresql://", "postgresql+asyncpg://", 1)

connect_args = {}
if db_url.startswith("postgresql+asyncpg://"):
    connect_args = {"ssl": SSL_CONTEXT, "statement_cache_size": 0, "prepared_statement_cache_size": 0}

from sqlalchemy.pool import NullPool

engine = create_async_engine(
    db_url,
    echo=False,
    future=True,
    connect_args=connect_args,
    poolclass=NullPool,
)
from sqlalchemy.ext.asyncio import async_sessionmaker

SessionLocal = async_sessionmaker(
    engine,
    expire_on_commit=False
)


# -----------------------------
# App setup
# -----------------------------
app = FastAPI(title="Commission Tracker")
templates = Jinja2Templates(directory="app/templates")

def _md_date(value):
    try:
        if value is None:
            return ""
        return f"{value.month}/{value.day}"
    except Exception:
        return ""

templates.env.filters["md"] = _md_date
templates.env.globals["today"] = today
templates.env.globals["current_month"] = lambda: today().strftime("%Y-%m")

static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.exception_handler(Exception)
async def _unhandled_exception_handler(request: Request, exc: Exception):
    tb = traceback.format_exc()
    return HTMLResponse(
        f"<h1>Internal Server Error</h1>"
        f"<p><b>URL:</b> {request.url}</p>"
        f"<pre style='white-space:pre-wrap'>{tb}</pre>",
        status_code=500,
    )


async def get_db():
    async with SessionLocal() as session:
        yield session


def month_bounds(d: date):
    start = date(d.year, d.month, 1)
    if d.month == 12:
        end = date(d.year + 1, 1, 1)
    else:
        end = date(d.year, d.month + 1, 1)
    return start, end


def quarter_bounds(d: date) -> tuple[date, date]:
    q_start_month = ((d.month - 1) // 3) * 3 + 1
    start = date(d.year, q_start_month, 1)
    if q_start_month == 10:
        end = date(d.year + 1, 1, 1)
    else:
        end = date(d.year, q_start_month + 3, 1)
    return start, end


def _tiered_volume_bonus(count: int, tiers: list[tuple[int, int | None, float]]) -> tuple[float, str]:
    for mn, mx, amt in tiers:
        if count >= mn and (mx is None or count <= mx):
            if mx is None:
                return amt, f"{mn}+"
            return amt, f"{mn}-{mx}"
    return 0.0, "--"


def _tiered_spot_bonus(count: int, tiers: list[tuple[int, int | None, float]]) -> tuple[float, float, str]:
    for mn, mx, per in tiers:
        if count >= mn and (mx is None or count <= mx):
            label = f"{mn}+" if mx is None else f"{mn}-{mx}"
            return float(count) * float(per), float(per), label
    return 0.0, 0.0, "--"


def get_selected_month_year(request: Request) -> tuple[int, int]:
    td = today()
    try:
        y = int(request.cookies.get("ct_year") or td.year)
    except Exception:
        y = td.year
    try:
        m = int(request.cookies.get("ct_month") or td.month)
    except Exception:
        m = td.month
    if m < 1:
        m = 1
    if m > 12:
        m = 12
    return y, m


@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

        try:
            await conn.exec_driver_sql("ALTER TABLE deals ADD COLUMN scheduled_date DATE")
        except Exception:
            try:
                await conn.exec_driver_sql("ALTER TABLE deals ADD COLUMN IF NOT EXISTS scheduled_date DATE")
            except Exception:
                pass

        # Delivery board columns
        delivery_cols = [
            ("on_delivery_board", "BOOLEAN", "0"),
            ("gas_ready", "BOOLEAN", "0"),
            ("inspection_ready", "BOOLEAN", "0"),
            ("insurance_ready", "BOOLEAN", "0"),
        ]
        for col, typ, default in delivery_cols:
            try:
                await conn.exec_driver_sql(
                    f"ALTER TABLE deals ADD COLUMN {col} {typ} DEFAULT {default}"
                )
            except Exception:
                try:
                    await conn.exec_driver_sql(
                        f"ALTER TABLE deals ADD COLUMN IF NOT EXISTS {col} {typ} DEFAULT {default}"
                    )
                except Exception:
                    pass

        settings_cols = [
            ("hourly_rate_ny_offset", "FLOAT", "15.0"),
            ("new_volume_bonus_15_16", "FLOAT", "1000.0"),
            ("new_volume_bonus_17_18", "FLOAT", "1200.0"),
            ("new_volume_bonus_19_20", "FLOAT", "1500.0"),
            ("new_volume_bonus_21_24", "FLOAT", "2000.0"),
            ("new_volume_bonus_25_plus", "FLOAT", "2800.0"),
            ("used_volume_bonus_8_10", "FLOAT", "350.0"),
            ("used_volume_bonus_11_12", "FLOAT", "500.0"),
            ("used_volume_bonus_13_plus", "FLOAT", "1000.0"),
            ("spot_bonus_5_9", "FLOAT", "50.0"),
            ("spot_bonus_10_12", "FLOAT", "80.0"),
            ("spot_bonus_13_plus", "FLOAT", "100.0"),
            ("quarterly_bonus_threshold_units", "INTEGER", "60"),
            ("quarterly_bonus_amount", "FLOAT", "1200.0"),
        ]

        for col, typ, default in settings_cols:
            try:
                await conn.exec_driver_sql(
                    f"ALTER TABLE settings ADD COLUMN {col} {typ} DEFAULT {default}"
                )
            except Exception:
                try:
                    await conn.exec_driver_sql(
                        f"ALTER TABLE settings ADD COLUMN IF NOT EXISTS {col} {typ} DEFAULT {default}"
                    )
                except Exception:
                    pass

    async with SessionLocal() as session:
        res = await session.execute(select(Settings).limit(1))
        s = res.scalar_one_or_none()
        if not s:
            s = Settings(
                unit_comm_discount_le_200=190.0,
                unit_comm_discount_gt_200=140.0,
                permaplate=40.0,
                nitro_fill=40.0,
                pulse=40.0,
                finance_non_subvented=40.0,
                warranty=25.0,
                tire_wheel=25.0,
                hourly_rate_ny_offset=15.0,
                new_volume_bonus_15_16=1000.0,
                new_volume_bonus_17_18=1200.0,
                new_volume_bonus_19_20=1500.0,
                new_volume_bonus_21_24=2000.0,
                new_volume_bonus_25_plus=2800.0,
                used_volume_bonus_8_10=350.0,
                used_volume_bonus_11_12=500.0,
                used_volume_bonus_13_plus=1000.0,
                spot_bonus_5_9=50.0,
                spot_bonus_10_12=80.0,
                spot_bonus_13_plus=100.0,
                quarterly_bonus_threshold_units=60,
                quarterly_bonus_amount=1200.0,
            )
            session.add(s)
            await session.commit()


# =============================================
# Dashboard
# =============================================
@app.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    month: str | None = None,
    year: int | None = None,
    db: AsyncSession = Depends(get_db),
):
    s = (await db.execute(select(Settings).limit(1))).scalar_one()

    deals = (
        await db.execute(
            select(Deal).order_by(
                Deal.delivered_date.desc().nullslast(),
                Deal.sold_date.desc().nullslast(),
            )
        )
    ).scalars().all()

    today_date = today()
    selected_year: int
    selected_month: int

    month_str = (month or "").strip() if month else ""
    if year is not None and month_str and month_str.isdigit():
        selected_year = int(year)
        selected_month = int(month_str)
    else:
        m = re.fullmatch(r"(\d{4})-(\d{1,2})", month_str)
        if m:
            selected_year = int(m.group(1))
            selected_month = int(m.group(2))
        else:
            selected_year = int(year) if year is not None else today_date.year
            selected_month = today_date.month

    if selected_month < 1:
        selected_month = 1
    if selected_month > 12:
        selected_month = 12

    d0 = date(selected_year, selected_month, 1)
    start_m, end_m = month_bounds(d0)
    month_key = f"{selected_year:04d}-{selected_month:02d}"

    delivered_mtd = [
        d for d in deals
        if d.status == "Delivered"
        and d.delivered_date
        and start_m <= d.delivered_date < end_m
    ]

    # --- Previous month for comparison ---
    if selected_month == 1:
        prev_year, prev_month = selected_year - 1, 12
    else:
        prev_year, prev_month = selected_year, selected_month - 1
    prev_d0 = date(prev_year, prev_month, 1)
    prev_start, prev_end = month_bounds(prev_d0)
    prev_delivered = [
        d for d in deals
        if d.status == "Delivered"
        and d.delivered_date
        and prev_start <= d.delivered_date < prev_end
    ]
    prev_units = len(prev_delivered)
    prev_comm = sum((d.total_deal_comm or 0) for d in prev_delivered)

    # --- Closing rates ---
    delivered_total = len(delivered_mtd)

    def _pct(n: int, d: int) -> float | None:
        if d <= 0:
            return None
        return round((n / d) * 100.0, 1)

    pulse_yes = sum(1 for d in delivered_mtd if getattr(d, "pulse", False))
    nitro_yes = sum(1 for d in delivered_mtd if getattr(d, "nitro_fill", False))
    perma_yes = sum(1 for d in delivered_mtd if getattr(d, "permaplate", False))
    aim_yes = sum(1 for d in delivered_mtd if (getattr(d, "aim_presentation", "X") or "X") == "Yes")
    aim_no = sum(1 for d in delivered_mtd if (getattr(d, "aim_presentation", "X") or "X") == "No")
    aim_den = aim_yes + aim_no

    closing_rates = {
        "pulse": {"label": "Pulse", "yes": pulse_yes, "den": delivered_total, "pct": _pct(pulse_yes, delivered_total)},
        "nitro": {"label": "Nitro Fill", "yes": nitro_yes, "den": delivered_total, "pct": _pct(nitro_yes, delivered_total)},
        "permaplate": {"label": "PermaPlate", "yes": perma_yes, "den": delivered_total, "pct": _pct(perma_yes, delivered_total)},
        "aim": {"label": "Aim Presentation", "yes": aim_yes, "den": aim_den, "pct": _pct(aim_yes, aim_den)},
    }

    units_mtd = len(delivered_mtd)
    comm_mtd = sum((d.total_deal_comm or 0) for d in delivered_mtd)
    paid_comm_mtd = sum((d.total_deal_comm or 0) for d in delivered_mtd if getattr(d, "is_paid", False))
    pending_comm_mtd = sum((d.total_deal_comm or 0) for d in delivered_mtd if not getattr(d, "is_paid", False))
    new_mtd = len([d for d in delivered_mtd if (d.new_used or "").lower() == "new"])
    used_mtd = len([d for d in delivered_mtd if (d.new_used or "").lower() == "used"])
    avg_per_deal = (comm_mtd / units_mtd) if units_mtd > 0 else 0.0

    # --- Bonus calculation ---
    volume_units_mtd = units_mtd
    volume_tiers = [
        (25, None, float(s.new_volume_bonus_25_plus)),
        (21, 24, float(s.new_volume_bonus_21_24)),
        (19, 20, float(s.new_volume_bonus_19_20)),
        (17, 18, float(s.new_volume_bonus_17_18)),
        (15, 16, float(s.new_volume_bonus_15_16)),
    ]
    used_tiers = [
        (13, None, float(s.used_volume_bonus_13_plus)),
        (11, 12, float(s.used_volume_bonus_11_12)),
        (8, 10, float(s.used_volume_bonus_8_10)),
    ]
    spot_tiers = [
        (13, None, float(s.spot_bonus_13_plus)),
        (10, 12, float(s.spot_bonus_10_12)),
        (5, 9, float(s.spot_bonus_5_9)),
    ]

    volume_bonus_amt, volume_bonus_tier = _tiered_volume_bonus(volume_units_mtd, volume_tiers)
    used_bonus_amt, used_bonus_tier = _tiered_volume_bonus(used_mtd, used_tiers)
    spot_count_mtd = sum(1 for d in delivered_mtd if getattr(d, "spot_sold", False))
    spot_bonus_total, spot_bonus_per, spot_bonus_tier = _tiered_spot_bonus(spot_count_mtd, spot_tiers)

    q_start, q_end = quarter_bounds(date(selected_year, selected_month, 1))
    delivered_qtd = [
        d for d in deals
        if d.status == "Delivered" and d.delivered_date and q_start <= d.delivered_date < q_end
    ]
    units_qtd = len(delivered_qtd)
    quarterly_hit = units_qtd >= int(s.quarterly_bonus_threshold_units or 0)
    quarterly_bonus = float(s.quarterly_bonus_amount) if quarterly_hit else 0.0
    current_bonus_total = float(volume_bonus_amt) + float(used_bonus_amt) + float(spot_bonus_total) + float(quarterly_bonus)

    # --- Projected (delivered + pending) ---
    pending_deals_list = [d for d in deals if d.status == "Pending"]
    pending_in_month = [
        d for d in pending_deals_list
        if d.sold_date and start_m <= d.sold_date < end_m
    ]
    proj_units = units_mtd + len(pending_in_month)
    proj_comm = comm_mtd + sum((d.total_deal_comm or 0) for d in pending_in_month)
    proj_used = used_mtd + len([d for d in pending_in_month if (d.new_used or "").lower() == "used"])
    proj_vol_bonus, _ = _tiered_volume_bonus(proj_units, volume_tiers)
    proj_used_bonus, _ = _tiered_volume_bonus(proj_used, used_tiers)
    proj_bonus_total = float(proj_vol_bonus) + float(proj_used_bonus) + float(spot_bonus_total) + float(quarterly_bonus)
    bonus_uplift = proj_bonus_total - current_bonus_total

    # --- Next tier helpers ---
    def _next_volume(count: int, tiers_desc):
        asc = sorted([(mn, mx, amt) for (mn, mx, amt) in tiers_desc], key=lambda x: x[0])
        for mn, mx, amt in asc:
            if count < mn:
                return {"tier": f"{mn}+" if mx is None else f"{mn}–{mx}", "at": mn, "need": mn - count, "amount": float(amt)}
        return {"tier": "Maxed", "at": None, "need": 0, "amount": 0.0}

    def _next_spot(count: int, tiers_desc):
        asc = sorted([(mn, mx, per) for (mn, mx, per) in tiers_desc], key=lambda x: x[0])
        for mn, mx, per in asc:
            if count < mn:
                return {"tier": f"{mn}+" if mx is None else f"{mn}–{mx}", "at": mn, "need": mn - count, "per": float(per)}
        return {"tier": "Maxed", "at": None, "need": 0, "per": 0.0}

    volume_next = _next_volume(volume_units_mtd, volume_tiers)
    used_next = _next_volume(used_mtd, used_tiers)
    spot_next = _next_spot(spot_count_mtd, spot_tiers)
    quarterly_next = {
        "tier": "Hit" if quarterly_hit else f"{int(s.quarterly_bonus_threshold_units or 0)} units",
        "need": 0 if quarterly_hit else max(0, int(s.quarterly_bonus_threshold_units or 0) - units_qtd),
        "amount": float(s.quarterly_bonus_amount or 0),
    }

    bonus_breakdown = {
        "volume": {"units": volume_units_mtd, "new_units": new_mtd, "used_units": used_mtd, "tier": volume_bonus_tier, "amount": float(volume_bonus_amt), "next": volume_next},
        "used": {"units": used_mtd, "tier": used_bonus_tier, "amount": float(used_bonus_amt), "next": used_next},
        "spot": {"spots": spot_count_mtd, "tier": spot_bonus_tier, "per": float(spot_bonus_per), "amount": float(spot_bonus_total), "next": spot_next},
        "quarterly": {"units_qtd": units_qtd, "threshold": int(s.quarterly_bonus_threshold_units or 0), "hit": bool(quarterly_hit), "amount": float(quarterly_bonus), "q_label": f"Q{((selected_month - 1)//3)+1}", "next": quarterly_next},
        "total": float(current_bonus_total),
    }

    # --- Year trend ---
    delivered_year = [d for d in deals if d.status == "Delivered" and d.delivered_date and d.delivered_date.year == selected_year]
    units_by_month = [0] * 12
    comm_by_month = [0.0] * 12
    for d in delivered_year:
        units_by_month[d.delivered_date.month - 1] += 1
        comm_by_month[d.delivered_date.month - 1] += (d.total_deal_comm or 0)
    month_labels = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]

    units_ytd = len(delivered_year)
    comm_ytd = sum((d.total_deal_comm or 0) for d in delivered_year)

    # --- Pending deals ---
    for d in pending_deals_list:
        if d.sold_date:
            d.days_pending = (today_date - d.sold_date).days
        else:
            d.days_pending = 0
    pending_deals_list = sorted(pending_deals_list, key=lambda x: x.sold_date or date.max)
    pending = len(pending_deals_list)

    # --- Milestones (achievements unlocked this month) ---
    milestones = []
    if volume_bonus_amt > 0:
        milestones.append(f"Volume Bonus unlocked — ${volume_bonus_amt:,.0f}")
    if used_bonus_amt > 0:
        milestones.append(f"Used Bonus unlocked — ${used_bonus_amt:,.0f}")
    if spot_bonus_total > 0:
        milestones.append(f"Spot Bonus active — ${spot_bonus_total:,.0f}")
    if quarterly_hit:
        milestones.append(f"Quarterly target hit — ${quarterly_bonus:,.0f}")

    # --- Goals ---
    goal_row = (await db.execute(
        select(Goal).where(Goal.year == selected_year, Goal.month == selected_month).limit(1)
    )).scalar_one_or_none()
    goals = {
        "unit_goal": goal_row.unit_goal if goal_row else 20,
        "commission_goal": goal_row.commission_goal if goal_row else 8000.0,
        "has_custom": goal_row is not None,
    }

    # --- Today's deliveries (scheduled for today or on delivery board) ---
    todays_deliveries = [
        d for d in deals
        if d.status not in ("Delivered", "Dead")
        and d.scheduled_date == today_date
    ]

    # --- Year selector ---
    years = set([today_date.year])
    for d in deals:
        if d.delivered_date:
            years.add(d.delivered_date.year)
        if d.sold_date:
            years.add(d.sold_date.year)
    year_options = sorted(years, reverse=True)
    month_options = [{"num": i, "label": calendar.month_name[i]} for i in range(1, 13)]

    resp = templates.TemplateResponse("dashboard.html", {
        "request": request,
        "month": month_key,
        "selected_year": selected_year,
        "selected_month": selected_month,
        "year_options": year_options,
        "month_options": month_options,

        "units_mtd": units_mtd,
        "closing_rates": closing_rates,
        "comm_mtd": comm_mtd,
        "paid_comm_mtd": paid_comm_mtd,
        "pending_comm_mtd": pending_comm_mtd,
        "new_mtd": new_mtd,
        "used_mtd": used_mtd,
        "avg_per_deal": avg_per_deal,

        "current_bonus_total": current_bonus_total,
        "bonus_breakdown": bonus_breakdown,

        "units_ytd": units_ytd,
        "comm_ytd": comm_ytd,

        "pending": pending,
        "pending_deals": pending_deals_list[:15],
        "pending_deals_all": pending_deals_list,

        "year": selected_year,
        "month_labels": month_labels,
        "units_by_month": units_by_month,
        "comm_by_month": comm_by_month,

        # New: comparisons
        "prev_units": prev_units,
        "prev_comm": prev_comm,
        "units_diff": units_mtd - prev_units,
        "comm_diff": comm_mtd - prev_comm,

        # New: projections
        "proj_units": proj_units,
        "proj_comm": proj_comm,
        "proj_bonus_total": proj_bonus_total,
        "bonus_uplift": bonus_uplift,
        "pending_in_month_count": len(pending_in_month),

        # New: goals
        "goals": goals,

        # New: milestones
        "milestones": milestones,

        # New: today's deliveries
        "todays_deliveries": todays_deliveries,
    })

    resp.set_cookie("ct_year", str(selected_year), httponly=False, samesite="lax")
    resp.set_cookie("ct_month", str(selected_month), httponly=False, samesite="lax")
    return resp


# =============================================
# Goals
# =============================================
@app.post("/goals/save")
async def goals_save(
    request: Request,
    unit_goal: int = Form(default=20),
    commission_goal: float = Form(default=8000.0),
    db: AsyncSession = Depends(get_db),
):
    selected_year, selected_month = get_selected_month_year(request)
    goal = (await db.execute(
        select(Goal).where(Goal.year == selected_year, Goal.month == selected_month).limit(1)
    )).scalar_one_or_none()

    if goal:
        goal.unit_goal = unit_goal
        goal.commission_goal = commission_goal
    else:
        goal = Goal(year=selected_year, month=selected_month, unit_goal=unit_goal, commission_goal=commission_goal)
        db.add(goal)
    await db.commit()
    return RedirectResponse(url=f"/?year={selected_year}&month={selected_month}", status_code=303)


# =============================================
# Deals list
# =============================================
@app.get("/deals", response_class=HTMLResponse)
async def deals_list(
    request: Request,
    q: str | None = None,
    status: str | None = None,
    paid: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    selected_year, selected_month = get_selected_month_year(request)
    start_sel, end_sel = month_bounds(date(selected_year, selected_month, 1))

    stmt = select(Deal).order_by(
        Deal.delivered_date.desc().nullslast(),
        Deal.sold_date.desc().nullslast(),
    )

    carry_tags = ["inbound", "fo"]
    base_filter = or_(
        and_(
            Deal.sold_date.is_not(None),
            Deal.sold_date >= start_sel,
            Deal.sold_date < end_sel,
        ),
        and_(
            func.lower(func.coalesce(Deal.tag, "")).in_(carry_tags),
            Deal.status != "Delivered",
        ),
    )
    stmt = stmt.where(base_filter)

    if status and status != "All":
        stmt = stmt.where(Deal.status == status)
    if paid and paid != "All":
        if paid == "Paid":
            stmt = stmt.where(Deal.is_paid.is_(True))
        elif paid == "Pending":
            stmt = stmt.where(Deal.is_paid.is_(False))
    if q and q.strip():
        like = f"%{q.strip()}%"
        stmt = stmt.where(
            (Deal.customer.ilike(like)) |
            (Deal.stock_num.ilike(like)) |
            (Deal.model.ilike(like))
        )

    deals = (await db.execute(stmt)).scalars().all()

    return templates.TemplateResponse("deals.html", {
        "request": request,
        "deals": deals,
        "q": q or "",
        "status": status or "All",
        "paid": paid or "All",
        "selected_year": selected_year,
        "selected_month": selected_month,
    })


# =============================================
# Deal form
# =============================================
@app.get("/deals/new", response_class=HTMLResponse)
async def deal_new(request: Request, db: AsyncSession = Depends(get_db)):
    settings = (await db.execute(select(Settings).limit(1))).scalar_one()

    start_m, end_m = month_bounds(today())
    delivered_mtd = (
        await db.execute(
            select(Deal).where(
                Deal.status == "Delivered",
                Deal.delivered_date.is_not(None),
                Deal.delivered_date >= start_m,
                Deal.delivered_date < end_m,
            )
        )
    ).scalars().all()

    units_mtd = len(delivered_mtd)
    comm_mtd = sum((d.total_deal_comm or 0) for d in delivered_mtd)
    avg_per_copy = (comm_mtd / units_mtd) if units_mtd else 0.0

    return templates.TemplateResponse("deal_form.html", {
        "request": request,
        "deal": None,
        "settings": settings,
        "next_url": request.query_params.get("next") or "",
        "mtd": {
            "units": units_mtd,
            "comm": comm_mtd,
            "avg": avg_per_copy,
            "month_label": today().strftime("%B %Y"),
        },
    })


@app.get("/deals/{deal_id}/edit", response_class=HTMLResponse)
async def deal_edit(deal_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    try:
        deal = (await db.execute(select(Deal).where(Deal.id == deal_id))).scalar_one_or_none()
        if deal is None:
            return RedirectResponse(url="/deals", status_code=303)
        settings = (await db.execute(select(Settings).limit(1))).scalar_one_or_none()
        if settings is None:
            return HTMLResponse("<h1>Missing settings</h1>", status_code=500)
    except Exception as e:
        return HTMLResponse(
            f"<h1>Internal Server Error</h1><pre>{str(e)}</pre>", status_code=500,
        )

    embed = (request.query_params.get("embed") == "1")

    start_m, end_m = month_bounds(today())
    delivered_mtd = (
        await db.execute(
            select(Deal).where(
                Deal.status == "Delivered",
                Deal.delivered_date.is_not(None),
                Deal.delivered_date >= start_m,
                Deal.delivered_date < end_m,
            )
        )
    ).scalars().all()

    units_mtd = len(delivered_mtd)
    comm_mtd = sum((d.total_deal_comm or 0) for d in delivered_mtd)
    avg_per_copy = (comm_mtd / units_mtd) if units_mtd else 0.0

    try:
        return templates.TemplateResponse("deal_form.html", {
            "request": request,
            "deal": deal,
            "settings": settings,
            "next_url": request.query_params.get("next") or "",
            "embed": embed,
            "mtd": {
                "units": units_mtd,
                "comm": comm_mtd,
                "avg": avg_per_copy,
                "month_label": today().strftime("%B %Y"),
            },
        })
    except Exception:
        return HTMLResponse(
            f"<h1>Internal Server Error</h1><pre style='white-space:pre-wrap'>{traceback.format_exc()}</pre>",
            status_code=500,
        )


@app.post("/deals/save")
async def deal_save(
    deal_id: int | None = Form(default=None),
    sold_date: str | None = Form(default=None),
    delivered_date: str | None = Form(default=None),
    scheduled_date: str | None = Form(default=None),
    status: str = Form(default="Pending"),
    tag: str = Form(default=""),
    customer: str = Form(default=""),
    stock_num: str | None = Form(default=None),
    model: str | None = Form(default=None),
    new_used: str | None = Form(default=None),
    deal_type: str | None = Form(default=None),
    business_manager: str | None = Form(default=None),
    spot_sold: int = Form(default=0),
    discount_gt_200: str = Form(default="No"),
    aim_presentation: str = Form(default="X"),
    permaplate: int = Form(default=0),
    nitro_fill: int = Form(default=0),
    pulse: int = Form(default=0),
    finance_non_subvented: int = Form(default=0),
    warranty: int = Form(default=0),
    tire_wheel: int = Form(default=0),
    hold_amount: float = Form(default=0.0),
    aim_amount: float = Form(default=0.0),
    fi_pvr: float = Form(default=0.0),
    notes: str | None = Form(default=None),
    pay_date: str | None = Form(default=None),
    is_paid: int = Form(default=0),
    next: str | None = Form(default=None),
    db: AsyncSession = Depends(get_db),
):
    settings = (await db.execute(select(Settings).limit(1))).scalar_one()

    sold = parse_date(sold_date)
    if sold is None and not deal_id:
        sold = today()

    delivered = None
    if bool(spot_sold):
        delivered = today()
    else:
        delivered = parse_date(delivered_date)
    pay = parse_date(pay_date)

    sched = parse_date(scheduled_date)
    if (status or "").strip() == "Scheduled" and sched is None:
        sched = today()
    if (status or "").strip() != "Scheduled":
        sched = None

    if bool(is_paid) and pay is None:
        pay = today()

    dt = (deal_type or "").strip()
    if dt in ("F", "f"):
        dt = "Finance"
    elif dt in ("C", "c"):
        dt = "Cash/Sub-Vented"
    elif dt in ("L", "l"):
        dt = "Lease"

    auto_fin_non_sub = (dt in ("Finance", "Lease"))

    if bool(spot_sold):
        status = "Delivered"

    existing_deal = None
    if deal_id:
        existing_deal = (await db.execute(select(Deal).where(Deal.id == deal_id))).scalar_one()
        if delivered is None:
            delivered = existing_deal.delivered_date

    deal_in = DealIn(
        sold_date=sold,
        delivered_date=delivered,
        scheduled_date=sched,
        status=status,
        tag=(tag or "").strip(),
        customer=customer.strip(),
        stock_num=(stock_num or "").strip(),
        model=(model or "").strip(),
        new_used=new_used or "",
        deal_type=dt,
        business_manager=(business_manager or ""),
        spot_sold=bool(spot_sold),
        discount_gt_200=(discount_gt_200 or "No"),
        aim_presentation=(aim_presentation or "X"),
        permaplate=bool(permaplate),
        nitro_fill=bool(nitro_fill),
        pulse=bool(pulse),
        finance_non_subvented=bool(auto_fin_non_sub or finance_non_subvented),
        warranty=bool(warranty),
        tire_wheel=bool(tire_wheel),
        hold_amount=float(hold_amount or 0),
        aim_amount=float(aim_amount or 0),
        fi_pvr=float(fi_pvr or 0),
        notes=notes or "",
        pay_date=pay,
        is_paid=bool(is_paid),
    )

    unit_comm, addons, trade_hold, total = calc_commission(deal_in, settings)

    if deal_id:
        deal = existing_deal
        for k, v in deal_in.model_dump().items():
            setattr(deal, k, v)
        deal.unit_comm = unit_comm
        deal.add_ons = addons
        deal.trade_hold_comm = trade_hold
        deal.total_deal_comm = total
    else:
        deal = Deal(
            **deal_in.model_dump(),
            unit_comm=unit_comm,
            add_ons=addons,
            trade_hold_comm=trade_hold,
            total_deal_comm=total,
        )
        db.add(deal)

    await db.commit()
    return RedirectResponse(url=(next or "/deals"), status_code=303)


@app.post("/deals/{deal_id}/toggle_paid")
async def toggle_paid(
    deal_id: int,
    next: str | None = Form(default=None),
    db: AsyncSession = Depends(get_db),
):
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id))).scalar_one()
    deal.is_paid = not bool(deal.is_paid)
    if deal.is_paid and deal.pay_date is None:
        deal.pay_date = today()
    await db.commit()
    return RedirectResponse(url=(next or "/deals"), status_code=303)


# Fixed: routes now match template action paths
@app.post("/deals/{deal_id}/mark_delivered")
async def mark_delivered(
    deal_id: int,
    redirect: str | None = Form(default=None),
    month: str | None = Form(default=None),
    db: AsyncSession = Depends(get_db),
):
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id))).scalar_one()
    deal.status = "Delivered"
    deal.delivered_date = today()
    await db.commit()
    if redirect:
        return RedirectResponse(url=redirect, status_code=303)
    redirect_url = f"/?month={month}" if month else "/"
    return RedirectResponse(url=redirect_url, status_code=303)


@app.post("/deals/{deal_id}/mark_dead")
async def mark_dead(
    deal_id: int,
    redirect: str | None = Form(default=None),
    month: str | None = Form(default=None),
    db: AsyncSession = Depends(get_db),
):
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id))).scalar_one()
    deal.status = "Dead"
    await db.commit()
    if redirect:
        return RedirectResponse(url=redirect, status_code=303)
    redirect_url = f"/?month={month}" if month else "/"
    return RedirectResponse(url=redirect_url, status_code=303)


# Keep old routes as aliases for backwards compat
@app.post("/deals/{deal_id}/deliver")
async def mark_delivered_old(deal_id: int, month: str | None = Form(default=None), db: AsyncSession = Depends(get_db)):
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id))).scalar_one()
    deal.status = "Delivered"
    deal.delivered_date = today()
    await db.commit()
    return RedirectResponse(url=f"/?month={month}" if month else "/", status_code=303)


@app.post("/deals/{deal_id}/dead")
async def mark_dead_old(deal_id: int, month: str | None = Form(default=None), db: AsyncSession = Depends(get_db)):
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id))).scalar_one()
    deal.status = "Dead"
    await db.commit()
    return RedirectResponse(url=f"/?month={month}" if month else "/", status_code=303)


@app.post("/deals/{deal_id}/delete")
async def deal_delete(deal_id: int, db: AsyncSession = Depends(get_db)):
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id))).scalar_one()
    await db.delete(deal)
    await db.commit()
    return RedirectResponse(url="/deals", status_code=303)


# =============================================
# Delivery Board
# =============================================
@app.get("/delivery", response_class=HTMLResponse)
async def delivery_board(request: Request, db: AsyncSession = Depends(get_db)):
    stmt = (
        select(Deal)
        .where(Deal.on_delivery_board == True)
        .where(Deal.status != "Delivered")
        .where(Deal.status != "Dead")
        .order_by(Deal.scheduled_date.asc().nullslast(), Deal.sold_date.asc().nullslast())
    )
    all_board_deals = (await db.execute(stmt)).scalars().all()

    prep = []
    ready = []
    for d in all_board_deals:
        if d.gas_ready and d.inspection_ready and d.insurance_ready:
            ready.append(d)
        else:
            prep.append(d)

    # Also fetch recently delivered from the board (last 7 days) for the "Delivered" column
    week_ago = today() - timedelta(days=7)
    delivered_stmt = (
        select(Deal)
        .where(Deal.on_delivery_board == True)
        .where(Deal.status == "Delivered")
        .where(Deal.delivered_date >= week_ago)
        .order_by(Deal.delivered_date.desc())
    )
    delivered = (await db.execute(delivered_stmt)).scalars().all()

    return templates.TemplateResponse("delivery_board.html", {
        "request": request,
        "prep": prep,
        "ready": ready,
        "delivered": delivered,
        "total": len(prep) + len(ready),
    })


@app.post("/delivery/{deal_id}/toggle")
async def delivery_toggle_check(
    deal_id: int,
    field: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    """Toggle a single prep checkbox (gas_ready, inspection_ready, insurance_ready)."""
    allowed = {"gas_ready", "inspection_ready", "insurance_ready"}
    if field not in allowed:
        return RedirectResponse(url="/delivery", status_code=303)

    deal = (await db.execute(select(Deal).where(Deal.id == deal_id))).scalar_one()
    setattr(deal, field, not getattr(deal, field))
    await db.commit()
    return RedirectResponse(url="/delivery", status_code=303)


@app.post("/delivery/{deal_id}/deliver")
async def delivery_board_deliver(
    deal_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Mark a deal as Delivered from the delivery board."""
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id))).scalar_one()
    deal.status = "Delivered"
    deal.delivered_date = today()
    await db.commit()
    return RedirectResponse(url="/delivery", status_code=303)


@app.post("/delivery/{deal_id}/remove")
async def delivery_board_remove(
    deal_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Remove a deal from the delivery board (doesn't delete it)."""
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id))).scalar_one()
    deal.on_delivery_board = False
    deal.gas_ready = False
    deal.inspection_ready = False
    deal.insurance_ready = False
    await db.commit()
    return RedirectResponse(url="/delivery", status_code=303)


@app.post("/delivery/{deal_id}/push")
async def push_to_delivery_board(
    deal_id: int,
    next: str | None = Form(default=None),
    db: AsyncSession = Depends(get_db),
):
    """Push a deal onto the delivery board from the deals list or form."""
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id))).scalar_one()
    deal.on_delivery_board = True
    await db.commit()
    return RedirectResponse(url=(next or "/delivery"), status_code=303)


# =============================================
# CSV Export
# =============================================
@app.get("/reports/export")
async def export_csv(
    request: Request,
    month: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Deal).order_by(Deal.sold_date.desc().nullslast())
    if month:
        try:
            y, m = month.split("-")
            d0 = date(int(y), int(m), 1)
            start_m, end_m = month_bounds(d0)
            stmt = stmt.where(
                or_(
                    and_(Deal.sold_date.is_not(None), Deal.sold_date >= start_m, Deal.sold_date < end_m),
                    and_(Deal.delivered_date.is_not(None), Deal.delivered_date >= start_m, Deal.delivered_date < end_m),
                )
            )
        except Exception:
            pass

    deals = (await db.execute(stmt)).scalars().all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Sold Date", "Delivered Date", "Customer", "Stock #", "Model", "New/Used",
        "F/C/L", "F&I", "Status", "Tag", "Spot", "Discount>200",
        "PermaPlate", "Nitro Fill", "Pulse", "Finance", "Warranty", "Tire&Wheel",
        "Aim", "Hold Amount", "Unit Comm", "Add-ons", "Trade Hold", "Total Comm",
        "Paid", "Pay Date", "Notes",
    ])
    for d in deals:
        writer.writerow([
            d.sold_date or "", d.delivered_date or "", d.customer, d.stock_num, d.model,
            d.new_used, d.deal_type, d.business_manager, d.status, d.tag,
            "Y" if d.spot_sold else "N", d.discount_gt_200,
            "Y" if d.permaplate else "N", "Y" if d.nitro_fill else "N",
            "Y" if d.pulse else "N", "Y" if d.finance_non_subvented else "N",
            "Y" if d.warranty else "N", "Y" if d.tire_wheel else "N",
            d.aim_presentation, d.hold_amount,
            f"{d.unit_comm:.2f}", f"{d.add_ons:.2f}", f"{d.trade_hold_comm:.2f}", f"{d.total_deal_comm:.2f}",
            "Y" if d.is_paid else "N", d.pay_date or "", d.notes or "",
        ])

    output.seek(0)
    filename = f"commission-export-{month or 'all'}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# =============================================
# CSV Import (Bulk Upload)
# =============================================
@app.get("/import", response_class=HTMLResponse)
async def import_page(request: Request):
    return templates.TemplateResponse("import.html", {
        "request": request,
        "result": None,
    })


@app.post("/import", response_class=HTMLResponse)
async def import_csv(
    request: Request,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    settings = (await db.execute(select(Settings).limit(1))).scalar_one()

    content = await file.read()
    text = content.decode("utf-8-sig")  # handles BOM from Excel
    reader = csv.DictReader(io.StringIO(text))

    imported = 0
    skipped = 0
    errors = []

    for i, row in enumerate(reader, start=2):  # row 2 = first data row
        try:
            customer = (row.get("Customer") or row.get("customer") or "").strip()
            if not customer:
                skipped += 1
                continue

            sold = parse_date(row.get("Sold Date") or row.get("sold_date") or "")
            delivered = parse_date(row.get("Delivered Date") or row.get("delivered_date") or "")
            sched = parse_date(row.get("Scheduled Date") or row.get("scheduled_date") or "")

            status_raw = (row.get("Status") or row.get("status") or "Pending").strip()
            if status_raw.lower() in ("delivered", "d"):
                status_val = "Delivered"
            elif status_raw.lower() in ("dead", "x"):
                status_val = "Dead"
            elif status_raw.lower() in ("scheduled", "sched"):
                status_val = "Scheduled"
            else:
                status_val = "Pending"

            nu = (row.get("New/Used") or row.get("new_used") or "").strip()
            if nu.lower() in ("n", "new"):
                nu = "New"
            elif nu.lower() in ("u", "used"):
                nu = "Used"

            dt = (row.get("F/C/L") or row.get("deal_type") or "").strip()
            if dt.lower() in ("f", "finance"):
                dt = "Finance"
            elif dt.lower() in ("c", "cash", "cash/sub-vented"):
                dt = "Cash/Sub-Vented"
            elif dt.lower() in ("l", "lease"):
                dt = "Lease"

            def _yn(val):
                return (val or "").strip().lower() in ("y", "yes", "1", "true")

            spot = _yn(row.get("Spot") or row.get("spot_sold") or "")
            disc = "Yes" if _yn(row.get("Discount>200") or row.get("discount_gt_200") or "") else "No"
            aim = (row.get("Aim") or row.get("aim_presentation") or "X").strip()
            if aim.lower() in ("y", "yes"):
                aim = "Yes"
            elif aim.lower() in ("n", "no"):
                aim = "No"
            else:
                aim = "X"

            permaplate = _yn(row.get("PermaPlate") or row.get("permaplate") or "")
            nitro = _yn(row.get("Nitro Fill") or row.get("nitro_fill") or "")
            pulse_v = _yn(row.get("Pulse") or row.get("pulse") or "")
            finance_ns = _yn(row.get("Finance") or row.get("finance_non_subvented") or "")
            warranty = _yn(row.get("Warranty") or row.get("warranty") or "")
            tire = _yn(row.get("Tire&Wheel") or row.get("tire_wheel") or "")

            # Auto-detect finance_non_subvented from deal_type if not explicitly set
            if not finance_ns and dt in ("Finance", "Lease"):
                finance_ns = True

            hold = 0.0
            try:
                hold = float(row.get("Hold Amount") or row.get("hold_amount") or "0")
            except ValueError:
                pass

            pay = parse_date(row.get("Pay Date") or row.get("pay_date") or "")
            is_paid = _yn(row.get("Paid") or row.get("is_paid") or "")

            deal_in = DealIn(
                sold_date=sold,
                delivered_date=delivered,
                scheduled_date=sched,
                status=status_val,
                tag=(row.get("Tag") or row.get("tag") or "").strip(),
                customer=customer,
                stock_num=(row.get("Stock #") or row.get("stock_num") or "").strip(),
                model=(row.get("Model") or row.get("model") or "").strip(),
                new_used=nu,
                deal_type=dt,
                business_manager=(row.get("F&I") or row.get("business_manager") or "").strip(),
                spot_sold=spot,
                discount_gt_200=disc,
                aim_presentation=aim,
                permaplate=permaplate,
                nitro_fill=nitro,
                pulse=pulse_v,
                finance_non_subvented=finance_ns,
                warranty=warranty,
                tire_wheel=tire,
                hold_amount=hold,
                notes=(row.get("Notes") or row.get("notes") or "").strip(),
                pay_date=pay,
                is_paid=is_paid,
            )

            unit_comm, addons, trade_hold, total = calc_commission(deal_in, settings)

            deal = Deal(
                **deal_in.model_dump(),
                unit_comm=unit_comm,
                add_ons=addons,
                trade_hold_comm=trade_hold,
                total_deal_comm=total,
            )
            db.add(deal)
            imported += 1

        except Exception as e:
            errors.append(f"Row {i}: {str(e)}")

    await db.commit()

    return templates.TemplateResponse("import.html", {
        "request": request,
        "result": {
            "imported": imported,
            "skipped": skipped,
            "errors": errors,
        },
    })


# =============================================
# Pay Plan
# =============================================
@app.get("/payplan", response_class=HTMLResponse)
async def payplan_get(request: Request, db: AsyncSession = Depends(get_db)):
    s = (await db.execute(select(Settings).limit(1))).scalar_one()
    return templates.TemplateResponse("payplan.html", {"request": request, "s": s})


@app.post("/payplan")
async def payplan_post(
    unit_comm_discount_le_200: float = Form(...),
    unit_comm_discount_gt_200: float = Form(...),
    permaplate: float = Form(...),
    nitro_fill: float = Form(...),
    pulse: float = Form(...),
    finance_non_subvented: float = Form(...),
    warranty: float = Form(...),
    tire_wheel: float = Form(...),
    hourly_rate_ny_offset: float = Form(...),
    new_volume_bonus_15_16: float = Form(...),
    new_volume_bonus_17_18: float = Form(...),
    new_volume_bonus_19_20: float = Form(...),
    new_volume_bonus_21_24: float = Form(...),
    new_volume_bonus_25_plus: float = Form(...),
    used_volume_bonus_8_10: float = Form(...),
    used_volume_bonus_11_12: float = Form(...),
    used_volume_bonus_13_plus: float = Form(...),
    spot_bonus_5_9: float = Form(...),
    spot_bonus_10_12: float = Form(...),
    spot_bonus_13_plus: float = Form(...),
    quarterly_bonus_threshold_units: int = Form(...),
    quarterly_bonus_amount: float = Form(...),
    db: AsyncSession = Depends(get_db),
):
    s = (await db.execute(select(Settings).limit(1))).scalar_one()
    for field in [
        "unit_comm_discount_le_200", "unit_comm_discount_gt_200", "permaplate", "nitro_fill",
        "pulse", "finance_non_subvented", "warranty", "tire_wheel", "hourly_rate_ny_offset",
        "new_volume_bonus_15_16", "new_volume_bonus_17_18", "new_volume_bonus_19_20",
        "new_volume_bonus_21_24", "new_volume_bonus_25_plus",
        "used_volume_bonus_8_10", "used_volume_bonus_11_12", "used_volume_bonus_13_plus",
        "spot_bonus_5_9", "spot_bonus_10_12", "spot_bonus_13_plus",
        "quarterly_bonus_threshold_units", "quarterly_bonus_amount",
    ]:
        setattr(s, field, locals()[field])
    await db.commit()
    return RedirectResponse(url="/payplan", status_code=303)


# Backwards compatibility
@app.get("/settings")
async def settings_redirect_get():
    return RedirectResponse(url="/payplan", status_code=307)

@app.post("/settings")
async def settings_redirect_post(request: Request):
    return RedirectResponse(url="/payplan", status_code=303)
