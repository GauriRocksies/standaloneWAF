"""
statistics.py

Pure query functions over the WAF database. Every function here does
ONLY data retrieval/aggregation and returns plain Python data
(int, list[dict], dict) — no HTML, no rendering, no request/response
handling. dashboard/views.py and dashboard/charts.py build on top of
these; they should never need to write a raw queryset themselves.
"""

from datetime import timedelta
from typing import Any

from django.db.models import Count, Q
from django.db.models.functions import TruncDate
from django.utils import timezone

from waf.models import AttackLog, BlockedIP, RuleStats, DetectorStats


# ---------------------------------------------------------------------
# Headline counters (dashboard cards)
# ---------------------------------------------------------------------

def total_attacks() -> int:
    """Total number of attacks ever logged."""
    return AttackLog.objects.count()


def attacks_today() -> int:
    """Number of attacks logged today (local date)."""
    today = timezone.localdate()
    return AttackLog.objects.filter(timestamp__date=today).count()


def blocked_attacks_count() -> int:
    """Number of attacks the decision engine blocked."""
    return AttackLog.objects.filter(blocked=True).count()


def allowed_attacks_count() -> int:
    """Number of detected attacks that were NOT blocked (logged only)."""
    return AttackLog.objects.filter(blocked=False).count()


def active_blocked_ips_count() -> int:
    """Number of IPs currently under an active block."""
    now = timezone.now()
    return BlockedIP.objects.filter(is_active=True).filter(
        Q(expires_at__isnull=True) | Q(expires_at__gt=now)
    ).count()


# ---------------------------------------------------------------------
# Distributions
# ---------------------------------------------------------------------

def attack_distribution() -> list[dict[str, Any]]:
    """
    Count and percentage share of each attack_type, for the dashboard's
    attack distribution pie chart.

    Returns:
        [{'attack_type': 'sql_injection', 'count': 42, 'percentage': 55.3}, ...]
        sorted by count descending. Empty list if there is no data yet.
    """
    total = total_attacks()
    if total == 0:
        return []

    rows = (
        AttackLog.objects
        .values('attack_type')
        .annotate(count=Count('id'))
        .order_by('-count')
    )
    return [
        {
            'attack_type': row['attack_type'],
            'count': row['count'],
            'percentage': round((row['count'] / total) * 100, 1),
        }
        for row in rows
    ]


def severity_distribution() -> list[dict[str, Any]]:
    """
    Count of attacks per severity level.

    Returns:
        [{'severity': 'high', 'count': 12}, ...] sorted by count descending.
    """
    rows = (
        AttackLog.objects
        .values('severity')
        .annotate(count=Count('id'))
        .order_by('-count')
    )
    return list(rows)


# ---------------------------------------------------------------------
# "Top N" leaderboards
# ---------------------------------------------------------------------

def top_attacker_ips(limit: int = 10) -> list[dict[str, Any]]:
    """
    Most active attacking IP addresses.

    Returns:
        [{'ip_address': '10.0.0.7', 'count': 8}, ...] sorted by count descending.
    """
    rows = (
        AttackLog.objects
        .values('ip_address')
        .annotate(count=Count('id'))
        .order_by('-count')[:limit]
    )
    return list(rows)


def top_attack_types(limit: int = 10) -> list[dict[str, Any]]:
    """
    Most frequent attack types (counts only, no percentage — see
    attack_distribution() if percentages are needed).

    Returns:
        [{'attack_type': 'sql_injection', 'count': 42}, ...] sorted descending.
    """
    rows = (
        AttackLog.objects
        .values('attack_type')
        .annotate(count=Count('id'))
        .order_by('-count')[:limit]
    )
    return list(rows)


def top_detectors(limit: int = 10) -> list[dict[str, Any]]:
    """
    Detectors with the most detections, from the DetectorStats
    aggregate table (Step 3/4) rather than re-scanning AttackLog.

    Returns:
        [{'detector_name': 'sqli_detector', 'detection_count': 42,
          'false_positive_count': 2, 'last_detection': datetime}, ...]
    """
    rows = DetectorStats.objects.order_by('-detection_count')[:limit].values(
        'detector_name', 'detection_count', 'false_positive_count', 'last_detection'
    )
    return list(rows)


def top_triggered_rules(limit: int = 10) -> list[dict[str, Any]]:
    """
    Rules with the most triggers, from the RuleStats aggregate table.

    Returns:
        [{'rule_name': 'SQLI-001', 'trigger_count': 42, 'last_triggered': datetime}, ...]
    """
    rows = RuleStats.objects.order_by('-trigger_count')[:limit].values(
        'rule_name', 'trigger_count', 'last_triggered'
    )
    return list(rows)


# ---------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------

def attack_timeline(days: int = 7) -> list[dict[str, Any]]:
    """
    Daily attack counts for the last `days` days, including days with
    zero attacks (so the line chart doesn't skip gaps).

    Returns:
        [{'date': date(2026, 7, 20), 'count': 3}, ...] oldest to newest.
    """
    today = timezone.localdate()
    start_date = today - timedelta(days=days - 1)

    rows = (
        AttackLog.objects
        .filter(timestamp__date__gte=start_date)
        .annotate(day=TruncDate('timestamp'))
        .values('day')
        .annotate(count=Count('id'))
        .order_by('day')
    )
    counts_by_day = {row['day']: row['count'] for row in rows}

    return [
        {
            'date': start_date + timedelta(days=offset),
            'count': counts_by_day.get(start_date + timedelta(days=offset), 0),
        }
        for offset in range(days)
    ]


# ---------------------------------------------------------------------
# Recent activity
# ---------------------------------------------------------------------

def latest_attacks(limit: int = 20) -> list[dict[str, Any]]:
    """
    Most recent attacks, for the dashboard's "Recent Attacks" table.

    Returns:
        [{'timestamp': ..., 'ip_address': ..., 'url': ..., 'method': ...,
          'attack_type': ..., 'severity': ..., 'risk_score': ...,
          'blocked': ...}, ...] newest first.
    """
    rows = AttackLog.objects.order_by('-timestamp')[:limit].values(
        'id', 'timestamp', 'ip_address', 'url', 'method',
        'attack_type', 'severity', 'risk_score', 'blocked',
    )
    return list(rows)