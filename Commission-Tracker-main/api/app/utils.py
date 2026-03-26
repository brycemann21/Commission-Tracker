from datetime import date, datetime

def parse_date(s: str | None):
    if not s:
        return None
    s = s.strip()
    if not s:
        return None
    for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%m-%d-%Y"):
        try:
            return datetime.strptime(s, fmt).date()
        except ValueError:
            continue
    return None

def today():
    return date.today()

def money(v):
    try:
        return f"${float(v):,.0f}"
    except Exception:
        return "$0"
