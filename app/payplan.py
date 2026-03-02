"""Unified commission engine.

Handles all three pay types (flat, gross, hybrid), dynamic product-based
add-ons via DealerProduct/DealProduct, and flexible bonus tiers via
DealerBonus.  This replaces the old payplan.py which only handled hardcoded
product booleans and the separate bonus branches in the dashboard.

Usage:
    engine = CommissionEngine(settings, products, bonuses)

    # Per-deal
    result = engine.calc_deal(deal_in, attached_product_ids)

    # Monthly bonuses
    bonus = engine.calc_bonuses(stats)

    # Dynamic closing rates for all products
    rates = engine.calc_closing_rates(delivered_deals, deal_product_map)
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


# ── Result containers ────────────────────────────────────────────────────────

@dataclass
class DealCommission:
    unit_comm: float = 0.0
    addon_comm: float = 0.0
    trade_hold_comm: float = 0.0
    total: float = 0.0


@dataclass
class BonusTier:
    """Result for a single bonus tier."""
    name: str = ""
    category: str = ""
    range_label: str = ""
    amount_per: float = 0.0       # the configured $ amount
    earned: float = 0.0           # what was actually earned
    hit: bool = False
    need: int = 0                 # units needed to reach threshold
    count: int = 0                # current count
    period: str = "monthly"
    projected_earned: float = 0.0


@dataclass
class BonusResult:
    total: float = 0.0
    projected_total: float = 0.0
    tiers: list[BonusTier] = field(default_factory=list)


@dataclass
class ClosingRate:
    label: str = ""
    product_id: int | None = None
    yes: int = 0
    den: int = 0
    pct: float | None = None


@dataclass
class MonthStats:
    """All the counts the bonus engine needs."""
    units_mtd: int = 0
    new_mtd: int = 0
    used_mtd: int = 0
    spots: int = 0
    qtd_count: int = 0
    ytd_units: int = 0
    # Projected (including pending)
    proj_units: int = 0
    proj_used: int = 0


# ── Helpers ──────────────────────────────────────────────────────────────────

def _pct(n: int, d: int) -> float | None:
    return round((n / d) * 100.0, 1) if d > 0 else None


# ── Engine ───────────────────────────────────────────────────────────────────

class CommissionEngine:
    """Unified commission + bonus + closing-rate calculator.

    Parameters
    ----------
    settings : Settings ORM object (or any object with the needed attributes)
    products : list of DealerProduct ORM objects for this dealership
    bonuses  : list of DealerBonus  ORM objects for this dealership
    """

    def __init__(self, settings, products: list = None, bonuses: list = None):
        self.settings = settings
        self.products = products or []
        self.bonuses = bonuses or []
        # Build a fast lookup: product_id -> commission
        self._product_comm = {p.id: p.commission for p in self.products}
        self._product_name = {p.id: p.name for p in self.products}

    # ── Per-deal commission ──────────────────────────────────────────────────

    def calc_deal(
        self,
        deal,
        attached_product_ids: set[int] | None = None,
        product_overrides: dict[int, float] | None = None,
    ) -> DealCommission:
        """Calculate commission for a single deal.

        Parameters
        ----------
        deal : DealIn (Pydantic) or Deal (ORM) — needs .customer, .discount_gt_200,
               .hold_amount, .front_gross, .back_gross
        attached_product_ids : set of DealerProduct IDs attached to this deal
        product_overrides : optional {product_id: override_amount} for per-deal overrides
        """
        if not getattr(deal, "customer", ""):
            return DealCommission()

        s = self.settings
        pay_type = getattr(s, "pay_type", "flat") or "flat"

        if pay_type == "gross":
            unit_comm = self._gross_unit(deal)
        elif pay_type == "hybrid":
            unit_comm = self._hybrid_unit(deal)
        else:
            unit_comm = self._flat_unit(deal)

        # Add-on commission from dynamic products
        addon_comm = 0.0
        if attached_product_ids:
            overrides = product_overrides or {}
            for pid in attached_product_ids:
                if pid in overrides:
                    addon_comm += overrides[pid]
                elif pid in self._product_comm:
                    addon_comm += self._product_comm[pid]

        # Trade hold
        trade_hold = int((getattr(deal, "hold_amount", 0.0) or 0.0) // 1000) * 100.0

        total = float(unit_comm + addon_comm + trade_hold)

        return DealCommission(
            unit_comm=float(unit_comm),
            addon_comm=float(addon_comm),
            trade_hold_comm=float(trade_hold),
            total=total,
        )

    def _flat_unit(self, deal) -> float:
        s = self.settings
        disc = getattr(deal, "discount_gt_200", False)
        return float(s.unit_comm_discount_gt_200 if disc else s.unit_comm_discount_le_200)

    def _gross_unit(self, deal) -> float:
        s = self.settings
        front = getattr(deal, "front_gross", 0.0) or 0.0
        back = getattr(deal, "back_gross", 0.0) or 0.0
        pack = getattr(s, "pack_deduction", 0.0) or 0.0
        front_pct = getattr(s, "gross_front_pct", 0.0) or 0.0
        back_pct = getattr(s, "gross_back_pct", 0.0) or 0.0
        mini = getattr(s, "mini_deal", 0.0) or 0.0

        front_comm = max(0, (front - pack)) * (front_pct / 100.0)
        back_comm = back * (back_pct / 100.0)
        total = front_comm + back_comm

        if mini > 0 and total < mini and (front > 0 or back > 0):
            total = mini

        return float(total)

    def _hybrid_unit(self, deal) -> float:
        flat = self._flat_unit(deal)
        back = getattr(deal, "back_gross", 0.0) or 0.0
        back_pct = getattr(self.settings, "gross_back_pct", 0.0) or 0.0
        return flat + back * (back_pct / 100.0)

    # ── Bonus calculation ────────────────────────────────────────────────────

    def calc_bonuses(self, stats: MonthStats) -> BonusResult:
        """Calculate all bonus tiers from DealerBonus rows."""
        result = BonusResult()

        for b in self.bonuses:
            count = self._bonus_count(b, stats)
            proj_count = self._bonus_proj_count(b, stats)

            in_range = count >= b.threshold_min and (
                b.threshold_max is None or count <= b.threshold_max
            )
            proj_in_range = proj_count >= b.threshold_min and (
                b.threshold_max is None or proj_count <= b.threshold_max
            )

            # Spot bonuses multiply: $X per spot
            if b.category == "spot" and in_range:
                earned = b.amount * count
            elif in_range:
                earned = b.amount
            else:
                earned = 0.0

            if b.category == "spot" and proj_in_range:
                proj_earned = b.amount * proj_count
            elif proj_in_range:
                proj_earned = b.amount
            else:
                proj_earned = 0.0

            need = max(0, b.threshold_min - count) if not in_range else 0
            range_label = f"{b.threshold_min}{'–' + str(b.threshold_max) if b.threshold_max else '+'}"

            tier = BonusTier(
                name=b.name,
                category=b.category,
                range_label=range_label,
                amount_per=b.amount,
                earned=earned,
                hit=in_range,
                need=need,
                count=count,
                period=b.period,
                projected_earned=proj_earned,
            )
            result.tiers.append(tier)
            result.total += earned
            result.projected_total += proj_earned

        return result

    def _bonus_count(self, bonus, stats: MonthStats) -> int:
        cat = bonus.category
        period = bonus.period
        if cat == "volume_new":
            return stats.new_mtd if period == "monthly" else stats.qtd_count
        elif cat == "volume_used":
            return stats.used_mtd if period == "monthly" else stats.qtd_count
        elif cat == "spot":
            return stats.spots
        elif cat == "quarterly":
            return stats.qtd_count
        else:
            if period == "monthly":
                return stats.units_mtd
            elif period == "quarterly":
                return stats.qtd_count
            else:
                return stats.ytd_units

    def _bonus_proj_count(self, bonus, stats: MonthStats) -> int:
        cat = bonus.category
        if cat == "volume_new":
            return stats.proj_units
        elif cat == "volume_used":
            return stats.proj_used
        elif cat == "spot":
            return stats.spots
        elif cat == "quarterly":
            return stats.qtd_count
        else:
            return stats.proj_units

    # ── Dynamic closing rates ────────────────────────────────────────────────

    def calc_closing_rates(
        self,
        delivered_deals: list,
        deal_product_map: dict[int, set[int]],
    ) -> list[ClosingRate]:
        """Calculate closing rates for ALL active products + Aim.

        Parameters
        ----------
        delivered_deals : list of Deal ORM objects for the month
        deal_product_map : {deal_id: set_of_product_ids}
        """
        total = len(delivered_deals)
        rates = []

        for p in self.products:
            yes = sum(
                1 for d in delivered_deals
                if p.id in deal_product_map.get(d.id, set())
            )
            rates.append(ClosingRate(
                label=p.name,
                product_id=p.id,
                yes=yes,
                den=total,
                pct=_pct(yes, total),
            ))

        # Aim is a presentation metric, not a product
        aim_y = sum(1 for d in delivered_deals if (getattr(d, "aim_presentation", "X") or "X") == "Yes")
        aim_n = sum(1 for d in delivered_deals if (getattr(d, "aim_presentation", "X") or "X") == "No")
        rates.append(ClosingRate(
            label="Aim",
            product_id=None,
            yes=aim_y,
            den=aim_y + aim_n,
            pct=_pct(aim_y, aim_y + aim_n),
        ))

        return rates

    # ── Milestones ───────────────────────────────────────────────────────────

    def milestones(self, bonus_result: BonusResult) -> list[str]:
        """Build milestone strings from bonus results."""
        return [
            f"{t.name} unlocked — ${t.earned:,.0f}"
            for t in bonus_result.tiers if t.earned > 0
        ]

    # ── Community payplan sharing payload ────────────────────────────────────

    def share_payload(self) -> dict[str, Any]:
        """Build a JSON-friendly payload for community payplan sharing."""
        s = self.settings
        pay = {
            "pay_type": getattr(s, "pay_type", "flat") or "flat",
            "unit_comm_le_200": s.unit_comm_discount_le_200,
            "unit_comm_gt_200": s.unit_comm_discount_gt_200,
            "hourly_offset": getattr(s, "hourly_rate_ny_offset", 0),
        }
        if pay["pay_type"] in ("gross", "hybrid"):
            pay["gross_front_pct"] = getattr(s, "gross_front_pct", 0)
            pay["gross_back_pct"] = getattr(s, "gross_back_pct", 0)
            pay["mini_deal"] = getattr(s, "mini_deal", 0)
            pay["pack_deduction"] = getattr(s, "pack_deduction", 0)

        pay["products"] = [
            {"name": p.name, "commission": p.commission}
            for p in self.products
        ]
        pay["bonuses"] = [
            {"name": b.name, "category": b.category,
             "min": b.threshold_min, "max": b.threshold_max,
             "amount": b.amount, "period": b.period}
            for b in self.bonuses
        ]
        return pay
