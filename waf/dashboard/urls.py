"""
dashboard/urls.py

URL patterns for the WAF dashboard. Mounted at /waf/ in the project's
root urls.py (vulnerablog/urls.py).
"""

from django.urls import path

from . import views

app_name = 'waf'

urlpatterns = [
    path('', views.dashboard_home, name='dashboard'),
    path('blocked-ips/', views.blocked_ips_view, name='blocked_ips'),
    path('statistics/', views.statistics_view, name='statistics'),
]