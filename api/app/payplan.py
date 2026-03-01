from .schemas import DealIn
from .models import Settings


def calc_commission(deal: DealIn, settings: Settings):
    """Calculate commission breakdown for a single deal.

    Returns (unit_comm, add_ons, trade_hold_comm, total_deal_comm).
    """
    if not deal.customer:
        return 0.0, 0.0, 0.0, 0.0

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
