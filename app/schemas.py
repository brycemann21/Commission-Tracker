from pydantic import BaseModel
from datetime import date

class DealIn(BaseModel):
    sold_date: date | None = None
    delivered_date: date | None = None
    status: str = "Pending"
    tag: str = "Shop"

    customer: str = ""
    stock_num: str = ""
    model: str = ""
    new_used: str = ""
    deal_type: str = ""
    business_manager: str = ""

    spot_sold: bool = False
    discount_gt_200: str = "No"

    aim_presentation: str = "X"

    permaplate: bool = False
    nitro_fill: bool = False
    pulse: bool = False
    finance_non_subvented: bool = False
    warranty: bool = False
    tire_wheel: bool = False

    hold_amount: float = 0.0
    aim_amount: float = 0.0
    fi_pvr: float = 0.0

    notes: str = ""
    pay_date: date | None = None
    is_paid: bool = False
