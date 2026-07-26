"""
dashboard/views.py

Renders the WAF dashboard, blocked-IP page, and statistics page.
All heavy lifting (queries, chart-building) happens in statistics.py
and charts.py (Steps 5-6) — these views only assemble context and
pick a template. Access is restricted to staff accounts, same as the
Django admin, since this exposes raw request payloads/headers.
"""

from django.contrib.admin.views.decorators import staff_member_required
from django.shortcuts import render

from waf.dashboard import charts
from waf.dashboard import statistics as stats
from waf.models import BlockedIP


@staff_member_required
def dashboard_home(request):
    """Main WAF dashboard: headline cards, charts, recent attacks table."""
    context = {
        'active_nav': 'dashboard',
        'total_attacks': stats.total_attacks(),
        'attacks_today': stats.attacks_today(),
        'blocked_count': stats.blocked_attacks_count(),
        'allowed_count': stats.allowed_attacks_count(),
        'recent_attacks': stats.latest_attacks(limit=15),
        'pie_chart': charts.attack_distribution_pie_chart(),
        'timeline_chart': charts.attack_timeline_line_chart(days=7),
        'rules_chart': charts.top_rules_bar_chart(limit=8),
        'detectors_chart': charts.top_detectors_bar_chart(limit=8),
    }
    return render(request, 'waf/dashboard.html', context)


@staff_member_required
def blocked_ips_view(request):
    """Blocked IP page: every IP the WAF has blocked, active or not."""
    context = {
        'active_nav': 'blocked_ips',
        'blocked_ips': BlockedIP.objects.all(),
        'active_count': stats.active_blocked_ips_count(),
    }
    return render(request, 'waf/blocked_ips.html', context)


@staff_member_required
def statistics_view(request):
    """Statistics page: severity breakdown + full leaderboards."""
    context = {
        'active_nav': 'statistics',
        'severity_chart': charts.severity_chart(),
        'top_ips': stats.top_attacker_ips(limit=10),
        'top_types': stats.top_attack_types(limit=10),
        'top_rules': stats.top_triggered_rules(limit=10),
        'top_detectors': stats.top_detectors(limit=10),
    }
    return render(request, 'waf/statistics.html', context)