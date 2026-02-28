from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, Integer, Float, Date, Boolean, Text, DateTime
from datetime import datetime

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    email: Mapped[str | None] = mapped_column(String(254), unique=True, nullable=True)
    display_name: Mapped[str] = mapped_column(String(120), default="")
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    password_salt: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    supabase_id: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[str] = mapped_column(String(32), default="")

class UserSession(Base):
    """Persistent sessions stored in DB — survives server restarts."""
    __tablename__ = "user_sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    token: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    remember_me: Mapped[bool] = mapped_column(Boolean, default=False)
    user_agent: Mapped[str | None] = mapped_column(String(256), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)

class PasswordResetToken(Base):
    """Single-use password reset tokens."""
    __tablename__ = "password_reset_tokens"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    token: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, default=False)

class Settings(Base):
    __tablename__ = "settings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    unit_comm_discount_le_200: Mapped[float] = mapped_column(Float, default=190.0)
    unit_comm_discount_gt_200: Mapped[float] = mapped_column(Float, default=140.0)
    permaplate: Mapped[float] = mapped_column(Float, default=40.0)
    nitro_fill: Mapped[float] = mapped_column(Float, default=40.0)
    pulse: Mapped[float] = mapped_column(Float, default=40.0)
    finance_non_subvented: Mapped[float] = mapped_column(Float, default=40.0)
    warranty: Mapped[float] = mapped_column(Float, default=25.0)
    tire_wheel: Mapped[float] = mapped_column(Float, default=25.0)
    hourly_rate_ny_offset: Mapped[float] = mapped_column(Float, default=15.0)
    new_volume_bonus_15_16: Mapped[float] = mapped_column(Float, default=1000.0)
    new_volume_bonus_17_18: Mapped[float] = mapped_column(Float, default=1200.0)
    new_volume_bonus_19_20: Mapped[float] = mapped_column(Float, default=1500.0)
    new_volume_bonus_21_24: Mapped[float] = mapped_column(Float, default=2000.0)
    new_volume_bonus_25_plus: Mapped[float] = mapped_column(Float, default=2800.0)
    used_volume_bonus_8_10: Mapped[float] = mapped_column(Float, default=350.0)
    used_volume_bonus_11_12: Mapped[float] = mapped_column(Float, default=500.0)
    used_volume_bonus_13_plus: Mapped[float] = mapped_column(Float, default=1000.0)
    spot_bonus_5_9: Mapped[float] = mapped_column(Float, default=50.0)
    spot_bonus_10_12: Mapped[float] = mapped_column(Float, default=80.0)
    spot_bonus_13_plus: Mapped[float] = mapped_column(Float, default=100.0)
    quarterly_bonus_threshold_units: Mapped[int] = mapped_column(Integer, default=60)
    quarterly_bonus_amount: Mapped[float] = mapped_column(Float, default=1200.0)

class Goal(Base):
    __tablename__ = "goals"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    year: Mapped[int] = mapped_column(Integer, nullable=False)
    month: Mapped[int] = mapped_column(Integer, nullable=False)
    unit_goal: Mapped[int] = mapped_column(Integer, default=20)
    commission_goal: Mapped[float] = mapped_column(Float, default=8000.0)

class Deal(Base):
    __tablename__ = "deals"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sold_date: Mapped[Date | None] = mapped_column(Date, nullable=True)
    delivered_date: Mapped[Date | None] = mapped_column(Date, nullable=True)
    scheduled_date: Mapped[Date | None] = mapped_column(Date, nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="Pending")
    tag: Mapped[str] = mapped_column(String(24), default="")
    customer: Mapped[str] = mapped_column(String(120), default="")
    stock_num: Mapped[str] = mapped_column(String(40), default="")
    model: Mapped[str] = mapped_column(String(120), default="")
    new_used: Mapped[str] = mapped_column(String(16), default="")
    deal_type: Mapped[str] = mapped_column(String(32), default="")
    business_manager: Mapped[str] = mapped_column(String(80), default="")
    spot_sold: Mapped[bool] = mapped_column(Boolean, default=False)
    discount_gt_200: Mapped[str] = mapped_column(String(8), default="No")
    aim_presentation: Mapped[str] = mapped_column(String(3), default="X")
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
    is_paid: Mapped[bool] = mapped_column(Boolean, default=False)
    on_delivery_board: Mapped[bool] = mapped_column(Boolean, default=False)
    gas_ready: Mapped[bool] = mapped_column(Boolean, default=False)
    inspection_ready: Mapped[bool] = mapped_column(Boolean, default=False)
    insurance_ready: Mapped[bool] = mapped_column(Boolean, default=False)
