import math
from .schemas import DealIn
from .models import Settings

def calc_commission(deal: DealIn, settings: Settings):
    """
    Mirrors the key formulas in your Excel:
    Unit Comm = IF(Discount>200, Config!B5, Config!B4)
    Add-ons = sum(1/0 flags * config values)
    Trade Hold Comm = INT(Hold/1000) * 100
    Total = Unit + Add-ons + TradeHold
    """
    if not deal.customer:
        return 0.0, 0.0, 0.0, 0.0

    disc = (deal.discount_gt_200 or "No").strip().lower()
    unit = settings.unit_comm_discount_gt_200 if disc in ("yes","y","true","1") else settings.unit_comm_discount_le_200

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
