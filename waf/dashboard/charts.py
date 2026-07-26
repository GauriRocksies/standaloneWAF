"""
charts.py

Converts the pure data from statistics.py into Chart.js-compatible
config dicts (data + type + minimal display options). Views pass
these straight to `json.dumps` / `JsonResponse` for the frontend to
feed directly into `new Chart(ctx, config)`.

No querying happens here directly — everything is built on top of
statistics.py so there's exactly one place (statistics.py) that knows
how to talk to the database.
"""

from typing import Any

from waf.dashboard import statistics as stats

# Consistent palette reused across charts so the same attack_type or
# severity always renders in the same color everywhere on the dashboard.
ATTACK_TYPE_COLORS = {
    'sql_injection': '#e74c3c',
    'xss': '#e67e22',
    'html_injection': '#f1c40f',
    'file_upload': '#9b59b6',
    'command_injection': '#c0392b',
    'path_traversal': '#8e44ad',
    'csrf': '#2980b9',
    'other': '#7f8c8d',
}
DEFAULT_COLOR_CYCLE = [
    '#1abc9c', '#3498db', '#e74c3c', '#f1c40f',
    '#9b59b6', '#e67e22', '#2ecc71', '#34495e',
]

SEVERITY_COLORS = {
    'low': '#2ecc71',      # green
    'medium': '#f1c40f',   # yellow
    'high': '#e67e22',     # orange
    'critical': '#e74c3c', # red
}
SEVERITY_ORDER = ['low', 'medium', 'high', 'critical']


def _color_for(label: str, index: int, palette: dict[str, str]) -> str:
    """Look up a stable color for a known label, falling back to the cycle."""
    return palette.get(label, DEFAULT_COLOR_CYCLE[index % len(DEFAULT_COLOR_CYCLE)])


# ---------------------------------------------------------------------
# Pie Chart — Attack Distribution
# ---------------------------------------------------------------------

def attack_distribution_pie_chart() -> dict[str, Any]:
    """Chart.js config: share of each attack_type."""
    rows = stats.attack_distribution()
    labels = [row['attack_type'] for row in rows]
    data = [row['count'] for row in rows]
    colors = [_color_for(label, i, ATTACK_TYPE_COLORS) for i, label in enumerate(labels)]

    return {
        'type': 'pie',
        'data': {
            'labels': labels,
            'datasets': [{
                'label': 'Attack Distribution',
                'data': data,
                'backgroundColor': colors,
            }],
        },
        'options': {
            'plugins': {'legend': {'position': 'right'}},
        },
    }


# ---------------------------------------------------------------------
# Line Chart — Attack Timeline
# ---------------------------------------------------------------------

def attack_timeline_line_chart(days: int = 7) -> dict[str, Any]:
    """Chart.js config: daily attack counts over the last `days` days."""
    rows = stats.attack_timeline(days=days)
    labels = [row['date'].strftime('%b %d') for row in rows]
    data = [row['count'] for row in rows]

    return {
        'type': 'line',
        'data': {
            'labels': labels,
            'datasets': [{
                'label': 'Attacks per Day',
                'data': data,
                'borderColor': '#1abc9c',
                'backgroundColor': 'rgba(26, 188, 156, 0.2)',
                'fill': True,
                'tension': 0.3,
            }],
        },
        'options': {
            'plugins': {'legend': {'display': False}},
            'scales': {'y': {'beginAtZero': True, 'ticks': {'precision': 0}}},
        },
    }


# ---------------------------------------------------------------------
# Bar Charts — Top Rules / Top Detectors
# ---------------------------------------------------------------------

def top_rules_bar_chart(limit: int = 10) -> dict[str, Any]:
    """Chart.js config: most-triggered rules."""
    rows = stats.top_triggered_rules(limit=limit)
    labels = [row['rule_name'] for row in rows]
    data = [row['trigger_count'] for row in rows]

    return {
        'type': 'bar',
        'data': {
            'labels': labels,
            'datasets': [{
                'label': 'Rule Triggers',
                'data': data,
                'backgroundColor': '#3498db',
            }],
        },
        'options': {
            'indexAxis': 'y',
            'plugins': {'legend': {'display': False}},
            'scales': {'x': {'beginAtZero': True, 'ticks': {'precision': 0}}},
        },
    }


def top_detectors_bar_chart(limit: int = 10) -> dict[str, Any]:
    """Chart.js config: detectors with the most detections."""
    rows = stats.top_detectors(limit=limit)
    labels = [row['detector_name'] for row in rows]
    data = [row['detection_count'] for row in rows]

    return {
        'type': 'bar',
        'data': {
            'labels': labels,
            'datasets': [{
                'label': 'Detections',
                'data': data,
                'backgroundColor': '#9b59b6',
            }],
        },
        'options': {
            'indexAxis': 'y',
            'plugins': {'legend': {'display': False}},
            'scales': {'x': {'beginAtZero': True, 'ticks': {'precision': 0}}},
        },
    }


# ---------------------------------------------------------------------
# Severity Chart
# ---------------------------------------------------------------------

def severity_chart() -> dict[str, Any]:
    """
    Chart.js config: attack counts by severity, always shown in a
    fixed low -> critical order (rather than count-sorted) so the
    color ramp reads intuitively left-to-right.
    """
    rows = {row['severity']: row['count'] for row in stats.severity_distribution()}
    labels = [s for s in SEVERITY_ORDER if s in rows]
    data = [rows[s] for s in labels]
    colors = [SEVERITY_COLORS[s] for s in labels]

    return {
        'type': 'bar',
        'data': {
            'labels': [label.capitalize() for label in labels],
            'datasets': [{
                'label': 'Attacks by Severity',
                'data': data,
                'backgroundColor': colors,
            }],
        },
        'options': {
            'plugins': {'legend': {'display': False}},
            'scales': {'y': {'beginAtZero': True, 'ticks': {'precision': 0}}},
        },
    }