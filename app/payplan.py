from .schemas import DealIn
from .models import Settings


def calc_commission(deal: DealIn, settings: Settings):
    """Calculate commission breakdown for a single deal.

    Returns (unit_comm, add_ons, trade_hold_comm, total_deal_comm).

    Pay structure: $150 flat per New & Used unit sold
                 + 7% of back-end F&I gross on each unit sold
                 + add-on product commissions
                 + trade hold commission (10% of hold amount)
    """
    if not deal.customer:
        return 0.0, 0.0, 0.0, 0.0

    # Flat per-unit commission ($150 for all units)
    unit = float(settings.unit_comm_discount_le_200 or 150.0)

    # Back-end F&I gross percentage (7%)
    back = getattr(deal, "back_gross", 0.0) or 0.0
    back_pct = getattr(settings, "gross_back_pct", 7.0) or 0.0
    back_comm = back * (back_pct / 100.0)

    # Legacy add-on commissions (kept for backward compat, but custom products are primary)
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

    # Trade hold: 10% of hold amount
    trade_hold = (deal.hold_amount or 0.0) * 0.10

    unit_plus_back = float(unit + back_comm)
    total = float(unit_plus_back + addons + trade_hold)
    return unit_plus_back, float(addons), float(trade_hold), total
