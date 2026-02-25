import os
import ssl
from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy import select, func
from datetime import date, datetime
from .models import Base, Deal, Settings
from .schemas import DealIn
from .payplan import calc_commission
from .utils import parse_date, today

from fastapi.templating import Jinja2Templates

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite+aiosqlite:///./commission.db")
# Supabase transaction pooler requires TLS; asyncpg uses an SSL context.
SSL_CONTEXT = ssl.create_default_context()
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode = ssl.CERT_NONE
db_url = DATABASE_URL
# If you provide a Supabase Postgres URL like postgres://..., convert it for SQLAlchemy asyncpg.
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql+asyncpg://", 1)
elif db_url.startswith("postgresql://"):
    db_url = db_url.replace("postgresql://", "postgresql+asyncpg://", 1)

connect_args = {}
if db_url.startswith("postgresql+asyncpg://"):
    connect_args = {"ssl": SSL_CONTEXT}

engine = create_async_engine(db_url, echo=False, future=True, connect_args=connect_args)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)

app = FastAPI(title="Commission Tracker")
templates = Jinja2Templates(directory="app/templates")

import os

static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


async def get_db():
    async with SessionLocal() as session:
        yield session


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


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, db: AsyncSession = Depends(get_db)):
    # YTD metrics based on delivered date if available else sold date
    year = today().year
    start = date(year, 1, 1)

    deals = (await db.execute(
        select(Deal).order_by(Deal.delivered_date.desc().nullslast(), Deal.sold_date.desc().nullslast())
    )).scalars().all()

    ytd_deals = [d for d in deals if (d.delivered_date or d.sold_date) and (d.delivered_date or d.sold_date) >= start]
    units_ytd = len([d for d in ytd_deals if d.status != "Dead"])
    comm_ytd = sum((d.total_deal_comm or 0) for d in ytd_deals if d.status != "Dead")

    pending = len([d for d in deals if d.status == "Pending"])
    delivered = len([d for d in deals if d.status == "Delivered"])

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "units_ytd": units_ytd,
        "comm_ytd": comm_ytd,
        "pending": pending,
        "delivered": delivered,
        "recent": deals[:15],
        "year": year,
    })


@app.get("/deals", response_class=HTMLResponse)
async def deals_list(request: Request, q: str | None = None, status: str | None = None, db: AsyncSession = Depends(get_db)):
    stmt = select(Deal).order_by(Deal.delivered_date.desc().nullslast(), Deal.sold_date.desc().nullslast())
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
    return templates.TemplateResponse("deals.html", {"request": request, "deals": deals, "q": q or "", "status": status or "All"})


@app.get("/deals/new", response_class=HTMLResponse)
async def deal_new(request: Request, db: AsyncSession = Depends(get_db)):
    settings = (await db.execute(select(Settings).limit(1))).scalar_one()
    return templates.TemplateResponse("deal_form.html", {"request": request, "deal": None, "settings": settings})


@app.get("/deals/{deal_id}/edit", response_class=HTMLResponse)
async def deal_edit(deal_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id))).scalar_one()
    settings = (await db.execute(select(Settings).limit(1))).scalar_one()
    return templates.TemplateResponse("deal_form.html", {"request": request, "deal": deal, "settings": settings})


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
        deal = Deal(**deal_in.model_dump(),
                    unit_comm=unit_comm,
                    add_ons=addons,
                    trade_hold_comm=trade_hold,
                    total_deal_comm=total)
        db.add(deal)

    await db.commit()
    return RedirectResponse(url="/deals", status_code=303)


@app.post("/deals/{deal_id}/delete")
async def deal_delete(deal_id: int, db: AsyncSession = Depends(get_db)):
    deal = (await db.execute(select(Deal).where(Deal.id == deal_id))).scalar_one()
    await db.delete(deal)
    await db.commit()
    return RedirectResponse(url="/deals", status_code=303)


@app.get("/reports/paycheck", response_class=HTMLResponse)
async def paycheck_report(request: Request, start: str | None = None, end: str | None = None, db: AsyncSession = Depends(get_db)):
    start_d = parse_date(start) if start else None
    end_d = parse_date(end) if end else None

    stmt = select(Deal).where(Deal.status == "Delivered")
    # If you prefer Paid-only logic later, we can add a Paid status.
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
