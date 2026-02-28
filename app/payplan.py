import math
from .schemas import DealIn
from .models import Settings

def calc_commission(deal: DealIn, settings: Settings):
    if not deal.customer:
        return 0.0, 0.0, 0.0, 0.0

    unit = settings.unit_comm_discount_gt_200 if deal.discount_gt_200 else settings.unit_comm_discount_le_200

    addons = 0.0
    addons += (1 if deal.permaplate else 0) * settings.permaplate
    addons += (1 if deal.nitro_fill else 0) * settings.nitro_fill
    addons += (1 if deal.pulse else 0) * settings.pulse
    addons += (1 if deal.finance_non_subvented else 0) * settings.finance_non_subvented
    addons += (1 if deal.warranty else 0) * settings.warranty
    addons += (1 if deal.tire_wheel else 0) * settings.tire_wheel

    trade_hold = math.floor((deal.hold_amount or 0.0) / 1000.0) * 100.0
    total = float(unit + addons + trade_hold)
    return float(unit), float(addons), float(trade_hold), total
