from datetime import timedelta, datetime, time
from zoneinfo import ZoneInfo
from django.db.models import Count
from django.utils import timezone
from .models import IpLookup, DomainLookup, UrlLookup, UserAgentLookup, HashLookup

MODEL_MAP = {
    "ip": IpLookup,
    "domain": DomainLookup,
    "url": UrlLookup,
    "ua": UserAgentLookup,
    "hash": HashLookup,
}

def calendar_bounds(period: str, tz_str="Asia/Jerusalem"):
    tz = ZoneInfo(tz_str)
    now = timezone.now().astimezone(tz)
    if period == "day":
        start = datetime.combine(now.date(), time.min, tzinfo=tz)
        end   = datetime.combine(now.date(), time.max, tzinfo=tz)
    elif period == "week":
        # Monday as start of week; adjust if you prefer Sunday
        start = datetime.combine((now - timedelta(days=now.weekday())).date(), time.min, tzinfo=tz)
        end   = datetime.combine((start.date() + timedelta(days=6)), time.max, tzinfo=tz)
    elif period == "month":
        start = datetime(now.year, now.month, 1, tzinfo=tz)
        # next month start minus 1 microsecond
        if now.month == 12:
            end = datetime(now.year + 1, 1, 1, tzinfo=tz) - timedelta(microseconds=1)
        else:
            end = datetime(now.year, now.month + 1, 1, tzinfo=tz) - timedelta(microseconds=1)
    else:
        raise ValueError("period must be day|week|month")
    return start, end

def leaderboard(entity: str, period: str, limit: int = 20):
    model = MODEL_MAP[entity]
    start, end = calendar_bounds(period)
    return (model.objects
            .filter(created_at__gte=start, created_at__lte=end)
            .values("value")
            .annotate(count=Count("id"))
            .order_by("-count")[:limit])
