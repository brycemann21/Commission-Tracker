from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, Integer, Float, Date, Boolean, Text, DateTime
from datetime import datetime, timezone

def _utcnow() -> datetime:
    """Naive UTC now — for TIMESTAMP columns (not TIMESTAMPTZ)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)

class Base(DeclarativeBase):
    pass


# ════════════════════════════════════════════════
# DEALERSHIP — the organizational unit
# ════════════════════════════════════════════════
class Dealership(Base):
    """A dealership is the top-level tenant. Every user, deal, setting, and goal
    belongs to exactly one dealership. The pay plan (Settings) is per-dealership,
    not per-user — the dealer sets the commission structure for all salespeople."""
    __tablename__ = "dealerships"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    timezone: Mapped[str] = mapped_column(String(64), default="America/New_York")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    # Google Places integration (Deploy 2)
    google_place_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    address: Mapped[str | None] = mapped_column(String(300), nullable=True)
    phone: Mapped[str | None] = mapped_column(String(30), nullable=True)

    # Subscription fields (Phase 4 — Stripe integration)
    # Placeholder columns so we don't need another migration later
    stripe_customer_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    stripe_subscription_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    subscription_status: Mapped[str] = mapped_column(String(32), default="trialing")
    # trialing | active | past_due | canceled | free (for your own dealership)
    max_users: Mapped[int] = mapped_column(Integer, default=5)


# ════════════════════════════════════════════════
# USER — now belongs to a dealership with a role
# ════════════════════════════════════════════════
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

    # ── Multi-tenancy fields ──
    dealership_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    role: Mapped[str] = mapped_column(String(24), default="salesperson")
    # Roles: "admin" — dealership admin, manages pay plan, invites users
    #        "manager" — can view all salespeople in their dealership
    #        "salesperson" — can only see their own data (default)
    is_super_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    # Super admin: platform owner (you) — sits above all dealerships
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    # Verified: GM has confirmed this person works at the dealership
    verified_by: Mapped[int | None] = mapped_column(Integer, nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


# ════════════════════════════════════════════════
# INVITE — for adding salespeople to a dealership
# ════════════════════════════════════════════════
class Invite(Base):
    """An invite token that an admin/manager sends to a salesperson to join
    their dealership. Single-use, expires after 7 days."""
    __tablename__ = "invites"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    token: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    dealership_id: Mapped[int] = mapped_column(Integer, nullable=False)
    email: Mapped[str | None] = mapped_column(String(254), nullable=True)
    role: Mapped[str] = mapped_column(String(24), default="salesperson")
    created_by: Mapped[int] = mapped_column(Integer, nullable=False)  # user_id of inviter
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    used_by: Mapped[int | None] = mapped_column(Integer, nullable=True)


# ════════════════════════════════════════════════
# SESSION / AUTH (unchanged)
# ════════════════════════════════════════════════
class UserSession(Base):
    """Persistent sessions stored in DB — survives server restarts."""
    __tablename__ = "user_sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    token: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
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
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, default=False)


# ════════════════════════════════════════════════
# SETTINGS — now per-DEALERSHIP (not per-user)
# The pay plan is set by the dealership, applies to all salespeople.
# ════════════════════════════════════════════════
class Settings(Base):
    __tablename__ = "settings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # DEPRECATED: user_id kept for backward compat during migration — new code uses dealership_id
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dealership_id: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Commission per unit
    unit_comm_discount_le_200: Mapped[float] = mapped_column(Float, default=190.0)
    unit_comm_discount_gt_200: Mapped[float] = mapped_column(Float, default=140.0)

    # Add-on commissions
    permaplate: Mapped[float] = mapped_column(Float, default=40.0)
    nitro_fill: Mapped[float] = mapped_column(Float, default=40.0)
    pulse: Mapped[float] = mapped_column(Float, default=40.0)
    finance_non_subvented: Mapped[float] = mapped_column(Float, default=40.0)
    warranty: Mapped[float] = mapped_column(Float, default=25.0)
    tire_wheel: Mapped[float] = mapped_column(Float, default=25.0)
    hourly_rate_ny_offset: Mapped[float] = mapped_column(Float, default=15.0)

    # Volume bonuses (new units)
    new_volume_bonus_15_16: Mapped[float] = mapped_column(Float, default=1000.0)
    new_volume_bonus_17_18: Mapped[float] = mapped_column(Float, default=1200.0)
    new_volume_bonus_19_20: Mapped[float] = mapped_column(Float, default=1500.0)
    new_volume_bonus_21_24: Mapped[float] = mapped_column(Float, default=2000.0)
    new_volume_bonus_25_plus: Mapped[float] = mapped_column(Float, default=2800.0)

    # Volume bonuses (used units)
    used_volume_bonus_8_10: Mapped[float] = mapped_column(Float, default=350.0)
    used_volume_bonus_11_12: Mapped[float] = mapped_column(Float, default=500.0)
    used_volume_bonus_13_plus: Mapped[float] = mapped_column(Float, default=1000.0)

    # Spot bonuses
    spot_bonus_5_9: Mapped[float] = mapped_column(Float, default=50.0)
    spot_bonus_10_12: Mapped[float] = mapped_column(Float, default=80.0)
    spot_bonus_13_plus: Mapped[float] = mapped_column(Float, default=100.0)

    # Quarterly bonus
    quarterly_bonus_threshold_units: Mapped[int] = mapped_column(Integer, default=60)
    quarterly_bonus_amount: Mapped[float] = mapped_column(Float, default=1200.0)


# ════════════════════════════════════════════════
# GOAL — per-user per-month (within a dealership)
# ════════════════════════════════════════════════
class Goal(Base):
    __tablename__ = "goals"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dealership_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    year: Mapped[int] = mapped_column(Integer, nullable=False)
    month: Mapped[int] = mapped_column(Integer, nullable=False)
    unit_goal: Mapped[int] = mapped_column(Integer, default=20)
    commission_goal: Mapped[float] = mapped_column(Float, default=8000.0)


# ════════════════════════════════════════════════
# DEAL — per-user (within a dealership)
# ════════════════════════════════════════════════
class Deal(Base):
    __tablename__ = "deals"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dealership_id: Mapped[int | None] = mapped_column(Integer, nullable=True)

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
    discount_gt_200: Mapped[bool] = mapped_column(Boolean, default=False)
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
    import_batch_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    commission_override: Mapped[float | None] = mapped_column(Float, nullable=True)
    on_delivery_board: Mapped[bool] = mapped_column(Boolean, default=False)
    gas_ready: Mapped[bool] = mapped_column(Boolean, default=False)
    inspection_ready: Mapped[bool] = mapped_column(Boolean, default=False)
    insurance_ready: Mapped[bool] = mapped_column(Boolean, default=False)


# ════════════════════════════════════════════════
# REMINDER — per-user (within a dealership)
# ════════════════════════════════════════════════
class Reminder(Base):
    __tablename__ = "reminders"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False)
    dealership_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    body: Mapped[str] = mapped_column(Text, default="")
    due_date: Mapped[Date | None] = mapped_column(Date, nullable=True)
    is_done: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
