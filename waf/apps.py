"""
WAF App Configuration.

Registers the 'waf' app with Django. This app owns attack logging,
the attack/blocked-IP/statistics database, the dashboard, and the
Django admin customizations for the WAF (Member 3's module).
"""

from django.apps import AppConfig


class WafConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'waf'
    verbose_name = 'WAF Logging & Dashboard'