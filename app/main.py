import os
import ssl
import re
import calendar
from datetime import date, datetime, timedelta

from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy import select, func

from .models import Base, Deal, Settings
from .schemas import DealIn
from .payplan import calc_commission
from .utils import parse_date, today


# -----------------------------
# DB setup
# -----------------------------
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite+aiosqlite:////tmp/commission.db")

# Supabase transaction pooler requires TLS; asyncpg uses an SSL context.
SSL_CONTEXT = ssl.create_default_context()
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode = ssl.CERT_NONE

db_url = DATABASE_URL
# Convert postgres URL to SQLAlchemy asyncpg driver if needed
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql+asyncpg://", 1)
elif db_url.startswith("postgresql://"):
    db_url = db_url.replace("postgresql://", "postgresql+asyncpg://", 1)

connect_args = {}
if db_url.startswith("postgresql+asyncpg://"):
    connect_args = {"ssl": SSL_CONTEXT}

engine = create_async_engine(db_url, echo=False, future=True, connect_args=connect_args)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)


# -----------------------------
# App setup
# -----------------------------
app = FastAPI(title="Commission Tracker")
templates = Jinja2Templates(directory="app/templates")
templates.env.globals["today"] = today
templates.env.globals["current_month"] = lambda: today().strftime("%Y-%m")
templates.env.globals["today"] = today

static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


async def get_db():
    async with SessionLocal() as session:
        yield session


def month_bounds(d: date):
    """Return [start, end) bounds for the month that contains date d."""
    start = date(d.year, d.month, 1)
    if d.month == 12:
        end = date(d.year + 1, 1, 1)
    else:
        end = date(d.year, d.month + 1, 1)
    return start, end


@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # seed settings if empty
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
            )
            session.add(s)
            await session.commit()


# -----------------------------
# Dashboard
# -----------------------------
@app.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    month: str | None = None,
    year: int | None = None,
    db: AsyncSession = Depends(get_db),
):
    deals = (
        await db.execute(
            select(Deal).order_by(
                Deal.delivered_date.desc().nullslast(),
                Deal.sold_date.desc().nullslast(),
            )
        )
    ).scalars().all()

    # -----------------------------
    # Month/Year Selection
    # Supports:
    #   /?year=2026&month=2
    #   /?month=2026-02   (backwards compatible)
    # Default = current month/year
    # -----------------------------
    today_date = today()

    selected_year: int
    selected_month: int

    month_str = (month or "").strip() if month else ""

    # Case 1: explicit year + numeric month in query
    if year is not None and month_str and month_str.isdigit():
        selected_year = int(year)
        selected_month = int(month_str)
    else:
        # Case 2: backwards compatible month=YYYY-MM
        m = re.fullmatch(r"(\d{4})-(\d{1,2})", month_str)
        if m:
            selected_year = int(m.group(1))
            selected_month = int(m.group(2))
        else:
            # Default
            selected_year = int(year) if year is not None else today_date.year
            selected_month = today_date.month

    # Clamp month into 1..12
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

    
    # -----------------------------
    # Closing % (Delivered deals in selected month)
    # -----------------------------
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

    # Paid vs Pending Commission (MTD)
    paid_comm_mtd = sum((d.total_deal_comm or 0) for d in delivered_mtd if getattr(d, "is_paid", False))
    pending_comm_mtd = sum((d.total_deal_comm or 0) for d in delivered_mtd if not getattr(d, "is_paid", False))

    new_mtd = len([d for d in delivered_mtd if (d.new_used or "").lower() == "new"])
    used_mtd = len([d for d in delivered_mtd if (d.new_used or "").lower() == "used"])

    # -----------------------------
    # Year Trend (Delivered Units per Month)
    # -----------------------------
    delivered_year = [
        d for d in deals
        if d.status == "Delivered"
        and d.delivered_date
        and d.delivered_date.year == selected_year
    ]

    units_by_month = [0] * 12
    for d in delivered_year:
        units_by_month[d.delivered_date.month - 1] += 1

    month_labels = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]

    # -----------------------------
    # YTD (Delivered)
    # -----------------------------
    units_ytd = len(delivered_year)
    comm_ytd = sum((d.total_deal_comm or 0) for d in delivered_year)

    # -----------------------------
    # Pending Deals
    # -----------------------------
    pending_deals = [d for d in deals if d.status == "Pending"]
    for d in pending_deals:
        if d.sold_date:
            d.days_pending = (today_date - d.sold_date).days
        else:
            d.days_pending = 0

    pending_deals = sorted(
        pending_deals,
        key=lambda x: x.sold_date or date.max
    )
    pending = len(pending_deals)

    # -----------------------------
    # Selector options
    # Years are derived from your data (delivered_date/sold_date), plus current year.
    # -----------------------------
    years = set([today_date.year])
    for d in deals:
        if d.delivered_date:
            years.add(d.delivered_date.year)
        if d.sold_date:
            years.add(d.sold_date.year)
    year_options = sorted(years, reverse=True)

    month_options = [
        {"num": i, "label": calendar.month_name[i]}
        for i in range(1, 13)
    ]

    return templates.TemplateResponse("dashboard.html", {
        "request": request,

        # For redirects/actions (keeps old behavior)
        "month": month_key,

        # Selector state/options
        "selected_year": selected_year,
        "selected_month": selected_month,
        "year_options": year_options,
        "month_options": month_options,

        # MTD
        "units_mtd": units_mtd,
        "closing_rates": closing_rates,
        "comm_mtd": comm_mtd,
        "paid_comm_mtd": paid_comm_mtd,
        "pending_comm_mtd": pending_comm_mtd,
        "new_mtd": new_mtd,
        "used_mtd": used_mtd,

        # YTD
        "units_ytd": units_ytd,
        "comm_ytd": comm_ytd,

        # Pending
        "pending": pending,
        "pending_deals": pending_deals[:15],

        # Trend
        "year": selected_year,
        "month_labels": month_labels,
        "units_by_month": units_by_month,
    })

@app.get("/deals", response_class=HTMLResponse)
async def deals_list(
    request: Request,
    q: str | None = None,
    status: str | None = None,
    paid: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Deal).order_by(
        Deal.delivered_date.desc().nullslast(),
        Deal.sold_date.desc().nullslast(),
    )

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
    })


@app.get("/deals/new", response_class=HTMLResponse)
async def deal_new(request: Request, db: AsyncSession = Depends(get_db)):
    settings = (await db.execute(select(Settings).limit(1))).scalar_one()
    return templates.TemplateResponse("deal_form.html", {
        "request": request,
        "deal": None,
        "settings": settings,
    })


@app.get("/deals/{deal_id}/edit", response_class=HTMLResponse)
async def deal_edit(deal_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id))).scalar_one()
    settings = (await db.execute(select(Settings).limit(1))).scalar_one()
    return templates.TemplateResponse("deal_form.html", {
        "request": request,
        "deal": deal,
        "settings": settings,
    })


@app.post("/deals/save")
async def deal_save(
    deal_id: int | None = Form(default=None),
    sold_date: str | None = Form(default=None),
    delivered_date: str | None = Form(default=None),
    status: str = Form(default="Pending"),
    tag: str = Form(default="Shop"),
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
    db: AsyncSession = Depends(get_db),
):

    settings = (await db.execute(select(Settings).limit(1))).scalar_one()

    sold = parse_date(sold_date)
    delivered = parse_date(delivered_date)
    pay = parse_date(pay_date)


    # If marked paid but no pay date provided, default to today
    if bool(is_paid) and pay is None:
        pay = today()

    deal_in = DealIn(
        sold_date=sold,
        delivered_date=delivered,
        status=status,
        tag=tag,
        customer=customer.strip(),
        stock_num=(stock_num or "").strip(),
        model=(model or "").strip(),
        new_used=new_used or "",
        deal_type=deal_type or "",
        business_manager=business_manager or "",
        spot_sold=bool(spot_sold),
        discount_gt_200=(discount_gt_200 or "No"),
        aim_presentation=(aim_presentation or "X"),
        permaplate=bool(permaplate),
        nitro_fill=bool(nitro_fill),
        pulse=bool(pulse),
        finance_non_subvented=bool(finance_non_subvented),
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
        deal = (await db.execute(select(Deal).where(Deal.id == deal_id))).scalar_one()
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
    return RedirectResponse(url="/deals", status_code=303)
    

@app.post("/deals/{deal_id}/toggle_paid")
async def toggle_paid(
    deal_id: int,
    next: str | None = Form(default=None),
    db: AsyncSession = Depends(get_db),
):
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id))).scalar_one()
    deal.is_paid = not bool(deal.is_paid)

    # If marking paid and no pay date set, default pay_date to today.
    if deal.is_paid and deal.pay_date is None:
        deal.pay_date = today()

    await db.commit()

    return RedirectResponse(url=(next or "/deals"), status_code=303)


@app.post("/deals/{deal_id}/deliver")
async def mark_delivered(
    deal_id: int,
    month: str | None = Form(default=None),
    db: AsyncSession = Depends(get_db),
):
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id))).scalar_one()

    deal.status = "Delivered"
    deal.delivered_date = today()

    await db.commit()

    redirect_url = "/"
    if month:
        redirect_url = f"/?month={month}"

    return RedirectResponse(url=redirect_url, status_code=303)

@app.post("/deals/{deal_id}/dead")
async def mark_dead(
    deal_id: int,
    month: str | None = Form(default=None),
    db: AsyncSession = Depends(get_db),
):
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id))).scalar_one()
    deal.status = "Dead"
    await db.commit()

    redirect_url = "/"
    if month:
        redirect_url = f"/?month={month}"
    return RedirectResponse(url=redirect_url, status_code=303)
    
@app.post("/deals/{deal_id}/delete")
async def deal_delete(deal_id: int, db: AsyncSession = Depends(get_db)):
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id))).scalar_one()
    await db.delete(deal)
    await db.commit()
    return RedirectResponse(url="/deals", status_code=303)


# -----------------------------
# Pending deals (sort/prioritize)
# -----------------------------
@app.get("/pending", response_class=HTMLResponse)
async def pending_view(
    request: Request,
    q: str | None = None,
    older_than: int | None = None,  # days
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Deal).where(Deal.status == "Pending")

    if q and q.strip():
        like = f"%{q.strip()}%"
        stmt = stmt.where(
            (Deal.customer.ilike(like)) |
            (Deal.stock_num.ilike(like)) |
            (Deal.model.ilike(like))
        )

    # Oldest sold date first (best chase list)
    stmt = stmt.order_by(Deal.sold_date.asc().nullslast())

    deals = (await db.execute(stmt)).scalars().all()

    if older_than is not None:
        cutoff = today() - timedelta(days=int(older_than))
        deals = [d for d in deals if d.sold_date and d.sold_date <= cutoff]

    return templates.TemplateResponse("pending.html", {
        "request": request,
        "deals": deals,
        "q": q or "",
        "older_than": older_than or "",
        "today": today(),
    })


# -----------------------------
# Current month view (Delivered MTD)
# -----------------------------
@app.get("/month", response_class=HTMLResponse)
async def month_view(
    request: Request,
    month: str | None = None,  # "YYYY-MM"
    db: AsyncSession = Depends(get_db),
):
    if month:
        y, m = month.split("-")
        d0 = date(int(y), int(m), 1)
    else:
        d0 = today()
        month = f"{d0.year:04d}-{d0.month:02d}"

    start_m, end_m = month_bounds(d0)

    stmt = (
        select(Deal)
        .where(Deal.status == "Delivered")
        .where(Deal.delivered_date != None)
        .where(Deal.delivered_date >= start_m)
        .where(Deal.delivered_date < end_m)
        .order_by(Deal.delivered_date.desc())
    )

    deals = (await db.execute(stmt)).scalars().all()

    units = len(deals)
    total_comm = sum((x.total_deal_comm or 0) for x in deals)
    addons_total = sum((x.add_ons or 0) for x in deals)
    unit_comm_total = sum((x.unit_comm or 0) for x in deals)
    trade_hold_total = sum((x.trade_hold_comm or 0) for x in deals)

    return templates.TemplateResponse("month.html", {
        "request": request,
        "month": month,
        "start": start_m,
        "end": end_m,
        "deals": deals,
        "units": units,
        "total_comm": total_comm,
        "addons_total": addons_total,
        "unit_comm_total": unit_comm_total,
        "trade_hold_total": trade_hold_total,
    })


# -----------------------------
# Customer summary
# -----------------------------
@app.get("/customers", response_class=HTMLResponse)
async def customer_summary(
    request: Request,
    q: str | None = None,
    month: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(
        Deal.customer.label("customer"),
        func.count(Deal.id).label("deals"),
        func.sum(func.coalesce(Deal.total_deal_comm, 0)).label("total_comm"),
        func.max(Deal.delivered_date).label("last_delivered"),
    ).where(Deal.customer != "")

    if month:
        y, m = month.split("-")
        d0 = date(int(y), int(m), 1)
        start_m, end_m = month_bounds(d0)
        stmt = (
            stmt.where(Deal.delivered_date != None)
            .where(Deal.delivered_date >= start_m)
            .where(Deal.delivered_date < end_m)
        )

    if q and q.strip():
        like = f"%{q.strip()}%"
        stmt = stmt.where(Deal.customer.ilike(like))

    stmt = stmt.group_by(Deal.customer).order_by(
        func.sum(func.coalesce(Deal.total_deal_comm, 0)).desc()
    )

    result = await db.execute(stmt)
    raw = result.all()

    rows = []
    for r in raw:
        rows.append({
            "customer": r[0],
            "deals": int(r[1] or 0),
            "total_comm": float(r[2] or 0),
            "last_delivered": r[3],
        })

    return templates.TemplateResponse("customers.html", {
        "request": request,
        "rows": rows,
        "q": q or "",
        "month": month or "",
    })

# -----------------------------
# End of month report
# -----------------------------
@app.get("/reports/eom", response_class=HTMLResponse)
async def end_of_month_report(
    request: Request,
    month: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    if not month:
        month = today().strftime("%Y-%m")
    y, m = month.split("-")
    d0 = date(int(y), int(m), 1)
    start_m, end_m = month_bounds(d0)

    stmt = (
        select(Deal)
        .where(Deal.status == "Delivered")
        .where(Deal.delivered_date != None)
        .where(Deal.delivered_date >= start_m)
        .where(Deal.delivered_date < end_m)
        .order_by(Deal.delivered_date.asc())
    )
    deals = (await db.execute(stmt)).scalars().all()

    units = len(deals)
    total_comm = sum((x.total_deal_comm or 0) for x in deals)
    unit_comm_total = sum((x.unit_comm or 0) for x in deals)
    addons_total = sum((x.add_ons or 0) for x in deals)
    trade_hold_total = sum((x.trade_hold_comm or 0) for x in deals)

    return templates.TemplateResponse("eom_report.html", {
        "request": request,
        "month": month,
        "start": start_m,
        "end": end_m,
        "deals": deals,
        "units": units,
        "total_comm": total_comm,
        "unit_comm_total": unit_comm_total,
        "addons_total": addons_total,
        "trade_hold_total": trade_hold_total,
    })


# -----------------------------
# Paycheck report (existing)
# -----------------------------
@app.get("/reports/paycheck", response_class=HTMLResponse)
async def paycheck_report(
    request: Request,
    start: str | None = None,
    end: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    start_d = parse_date(start) if start else None
    end_d = parse_date(end) if end else None

    stmt = select(Deal).where(Deal.status == "Delivered")
    if start_d:
        stmt = stmt.where(Deal.pay_date != None).where(Deal.pay_date >= start_d)
    if end_d:
        stmt = stmt.where(Deal.pay_date != None).where(Deal.pay_date <= end_d)

    deals = (await db.execute(stmt.order_by(Deal.pay_date.desc().nullslast()))).scalars().all()
    total = sum((d.total_deal_comm or 0) for d in deals)

    return templates.TemplateResponse("paycheck.html", {
        "request": request,
        "start": start or "",
        "end": end or "",
        "deals": deals,
        "total": total,
    })


# -----------------------------
# Settings (existing)
# -----------------------------
@app.get("/settings", response_class=HTMLResponse)
async def settings_get(request: Request, db: AsyncSession = Depends(get_db)):
    s = (await db.execute(select(Settings).limit(1))).scalar_one()
    return templates.TemplateResponse("settings.html", {"request": request, "s": s})


@app.post("/settings")
async def settings_post(
    unit_comm_discount_le_200: float = Form(...),
    unit_comm_discount_gt_200: float = Form(...),
    permaplate: float = Form(...),
    nitro_fill: float = Form(...),
    pulse: float = Form(...),
    finance_non_subvented: float = Form(...),
    warranty: float = Form(...),
    tire_wheel: float = Form(...),
    db: AsyncSession = Depends(get_db),
):
    s = (await db.execute(select(Settings).limit(1))).scalar_one()
    s.unit_comm_discount_le_200 = float(unit_comm_discount_le_200)
    s.unit_comm_discount_gt_200 = float(unit_comm_discount_gt_200)
    s.permaplate = float(permaplate)
    s.nitro_fill = float(nitro_fill)
    s.pulse = float(pulse)
    s.finance_non_subvented = float(finance_non_subvented)
    s.warranty = float(warranty)
    s.tire_wheel = float(tire_wheel)
    await db.commit()
    return RedirectResponse(url="/settings", status_code=303)
