from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, Integer, Float, Date, Boolean, Text

class Base(DeclarativeBase):
    pass

class Settings(Base):
    __tablename__ = "settings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    unit_comm_discount_le_200: Mapped[float] = mapped_column(Float, default=190.0)
    unit_comm_discount_gt_200: Mapped[float] = mapped_column(Float, default=140.0)

    permaplate: Mapped[float] = mapped_column(Float, default=40.0)
    nitro_fill: Mapped[float] = mapped_column(Float, default=40.0)
    pulse: Mapped[float] = mapped_column(Float, default=40.0)
    finance_non_subvented: Mapped[float] = mapped_column(Float, default=40.0)
    warranty: Mapped[float] = mapped_column(Float, default=25.0)
    tire_wheel: Mapped[float] = mapped_column(Float, default=25.0)

class Deal(Base):
    __tablename__ = "deals"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    sold_date: Mapped[Date | None] = mapped_column(Date, nullable=True)
    delivered_date: Mapped[Date | None] = mapped_column(Date, nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="Pending")
    tag: Mapped[str] = mapped_column(String(24), default="Inbound")

    customer: Mapped[str] = mapped_column(String(120), default="")
    stock_num: Mapped[str] = mapped_column(String(40), default="")
    model: Mapped[str] = mapped_column(String(120), default="")
    new_used: Mapped[str] = mapped_column(String(16), default="")
    deal_type: Mapped[str] = mapped_column(String(8), default="")
    business_manager: Mapped[str] = mapped_column(String(80), default="")

    spot_sold: Mapped[bool] = mapped_column(Boolean, default=False)
    discount_gt_200: Mapped[str] = mapped_column(String(8), default="No")

    permaplate: Mapped[bool] = mapped_column(Boolean, default=False)
    nitro_fill: Mapped[bool] = mapped_column(Boolean, default=False)
    pulse: Mapped[bool] = mapped_column(Boolean, default=False)
    finance_non_subvented: Mapped[bool] = mapped_column(Boolean, default=False)
    warranty: Mapped[bool] = mapped_column(Boolean, default=False)
    tire_wheel: Mapped[bool] = mapped_column(Boolean, default=False)

    hold_amount: Mapped[float] = mapped_column(Float, default=0.0)
    aim_amount: Mapped[float] = mapped_column(Float, default=0.0)
    fi_pvr: Mapped[float] = mapped_column(Float, default=0.0)

    notes: Mapped[str] = mapped_column(Text, default="")

    unit_comm: Mapped[float] = mapped_column(Float, default=0.0)
    add_ons: Mapped[float] = mapped_column(Float, default=0.0)
    trade_hold_comm: Mapped[float] = mapped_column(Float, default=0.0)
    total_deal_comm: Mapped[float] = mapped_column(Float, default=0.0)

    pay_date: Mapped[Date | None] = mapped_column(Date, nullable=True)

    # Paid status (used for Paid vs Pending Commission)
    is_paid: Mapped[bool] = mapped_column(Boolean, default=False)
