import os
import ssl
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
async def dashboard(request: Request, month: str | None = None, db: AsyncSession = Depends(get_db)):
    # Load all deals for recent list
    deals = (
        await db.execute(
            select(Deal).order_by(
                Deal.delivered_date.desc().nullslast(),
                Deal.sold_date.desc().nullslast(),
            )
        )
    ).scalars().all()

    # YTD metrics based on delivered date if available else sold date
    year = today().year
    start_ytd = date(year, 1, 1)

    def deal_anchor(d: Deal):
        return d.delivered_date or d.sold_date

    ytd_deals = [d for d in deals if deal_anchor(d) and deal_anchor(d) >= start_ytd]
    units_ytd = len([d for d in ytd_deals if d.status != "Dead"])
    comm_ytd = sum((d.total_deal_comm or 0) for d in ytd_deals if d.status != "Dead")

    pending = len([d for d in deals if d.status == "Pending"])
    delivered = len([d for d in deals if d.status == "Delivered"])

    # Optional: MTD metrics when month=YYYY-MM
    mtd_units = None
    mtd_comm = None
    mtd_label = None
    if month:
        y, m = month.split("-")
        d0 = date(int(y), int(m), 1)
        start_m, end_m = month_bounds(d0)
        mtd_label = month
        mtd = [
            d for d in deals
            if d.status == "Delivered"
            and d.delivered_date
            and start_m <= d.delivered_date < end_m
        ]
        mtd_units = len(mtd)
        mtd_comm = sum((d.total_deal_comm or 0) for d in mtd)

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "units_ytd": units_ytd,
        "comm_ytd": comm_ytd,
        "pending": pending,
        "delivered": delivered,
        "recent": deals[:15],
        "year": year,
        "mtd_units": mtd_units,
        "mtd_comm": mtd_comm,
        "mtd_label": mtd_label,
    })


# -----------------------------
# Sales Entry
# -----------------------------
@app.get("/deals", response_class=HTMLResponse)
async def deals_list(
    request: Request,
    q: str | None = None,
    status: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Deal).order_by(
        Deal.delivered_date.desc().nullslast(),
        Deal.sold_date.desc().nullslast(),
    )

    if status and status != "All":
        stmt = stmt.where(Deal.status == status)

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
    customer: str = Form(default=""),
    stock_num: str | None = Form(default=None),
    model: str | None = Form(default=None),
    new_used: str | None = Form(default=None),
    deal_type: str | None = Form(default=None),
    business_manager: str | None = Form(default=None),
    spot_sold: int = Form(default=0),
    discount_gt_200: str = Form(default="No"),
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
    db: AsyncSession = Depends(get_db),
):
    settings = (await db.execute(select(Settings).limit(1))).scalar_one()

    sold = parse_date(sold_date)
    delivered = parse_date(delivered_date)
    pay = parse_date(pay_date)

    deal_in = DealIn(
        sold_date=sold,
        delivered_date=delivered,
        status=status,
        customer=customer.strip(),
        stock_num=(stock_num or "").strip(),
        model=(model or "").strip(),
        new_used=new_used or "",
        deal_type=deal_type or "",
        business_manager=business_manager or "",
        spot_sold=bool(spot_sold),
        discount_gt_200=(discount_gt_200 or "No"),
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
    month: str | None = None,  # optional YYYY-MM filter on delivered month
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
    month: str,  # required YYYY-MM
    db: AsyncSession = Depends(get_db),
):
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
