from .schemas import DealIn
from .models import Settings


def calc_commission(deal: DealIn, settings: Settings):
    """Calculate commission breakdown for a single deal.

    Returns (unit_comm, add_ons, trade_hold_comm, total_deal_comm).

    Handles three pay types:
    - flat: per-unit flat + add-ons (original model)
    - gross: percentage of front/back gross profit
    - hybrid: flat per-unit + percentage of back gross
    """
    if not deal.customer:
        return 0.0, 0.0, 0.0, 0.0

    pay_type = getattr(settings, "pay_type", "flat") or "flat"

    if pay_type == "gross":
        return _calc_gross(deal, settings)
    elif pay_type == "hybrid":
        return _calc_hybrid(deal, settings)
    else:
        return _calc_flat(deal, settings)


def _calc_flat(deal: DealIn, settings: Settings):
    """Original flat per-unit + add-ons calculation."""
    unit = settings.unit_comm_discount_gt_200 if deal.discount_gt_200 else settings.unit_comm_discount_le_200

    addons = sum(
        getattr(settings, field) for field, flag in [
            ("permaplate", deal.permaplate),
            ("nitro_fill", deal.nitro_fill),
            ("pulse", deal.pulse),
            ("finance_non_subvented", deal.finance_non_subvented),
            ("warranty", deal.warranty),
            ("tire_wheel", deal.tire_wheel),
        ] if flag
    )

    # Trade hold: $100 for every full $1,000 of hold amount
    trade_hold = int((deal.hold_amount or 0.0) // 1000) * 100.0

    total = float(unit + addons + trade_hold)
    return float(unit), float(addons), float(trade_hold), total


def _calc_gross(deal: DealIn, settings: Settings):
    """Gross-percentage-based calculation.

    Commission = (front_gross - pack) * front_pct% + back_gross * back_pct%
    With a mini deal floor.
    """
    front = getattr(deal, "front_gross", 0.0) or 0.0
    back = getattr(deal, "back_gross", 0.0) or 0.0
    pack = getattr(settings, "pack_deduction", 0.0) or 0.0
    front_pct = getattr(settings, "gross_front_pct", 0.0) or 0.0
    back_pct = getattr(settings, "gross_back_pct", 0.0) or 0.0
    mini = getattr(settings, "mini_deal", 0.0) or 0.0

    front_comm = max(0, (front - pack)) * (front_pct / 100.0)
    back_comm = back * (back_pct / 100.0)
    gross_total = front_comm + back_comm

    # Apply mini deal floor
    if mini > 0 and gross_total < mini and (front > 0 or back > 0):
        gross_total = mini

    # Add-ons still apply on top for gross plans (some stores do this)
    addons = sum(
        getattr(settings, field) for field, flag in [
            ("permaplate", deal.permaplate),
            ("nitro_fill", deal.nitro_fill),
            ("pulse", deal.pulse),
            ("finance_non_subvented", deal.finance_non_subvented),
            ("warranty", deal.warranty),
            ("tire_wheel", deal.tire_wheel),
        ] if flag
    )

    total = float(gross_total + addons)
    return float(gross_total), float(addons), 0.0, total


def _calc_hybrid(deal: DealIn, settings: Settings):
    """Hybrid: flat per-unit + percentage of back-end gross."""
    unit = settings.unit_comm_discount_gt_200 if deal.discount_gt_200 else settings.unit_comm_discount_le_200

    back = getattr(deal, "back_gross", 0.0) or 0.0
    back_pct = getattr(settings, "gross_back_pct", 0.0) or 0.0
    back_comm = back * (back_pct / 100.0)

    addons = sum(
        getattr(settings, field) for field, flag in [
            ("permaplate", deal.permaplate),
            ("nitro_fill", deal.nitro_fill),
            ("pulse", deal.pulse),
            ("finance_non_subvented", deal.finance_non_subvented),
            ("warranty", deal.warranty),
            ("tire_wheel", deal.tire_wheel),
        ] if flag
    )

    trade_hold = int((deal.hold_amount or 0.0) // 1000) * 100.0
    total = float(unit + back_comm + addons + trade_hold)
    return float(unit + back_comm), float(addons), float(trade_hold), total
