"""
AttackLog model.

The central record of every attack the detection/decision engine
reports. One row per detected event. This is the table the dashboard,
statistics engine, and charts all read from.
"""

from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone


class HTTPMethod(models.TextChoices):
    GET = 'GET', 'GET'
    POST = 'POST', 'POST'
    PUT = 'PUT', 'PUT'
    PATCH = 'PATCH', 'PATCH'
    DELETE = 'DELETE', 'DELETE'
    HEAD = 'HEAD', 'HEAD'
    OPTIONS = 'OPTIONS', 'OPTIONS'


class AttackType(models.TextChoices):
    """
    Suggested vocabulary for known attack types.

    NOTE: this is intentionally NOT a hard DB constraint — Django
    choices are only enforced by form/admin validation, not at the
    database level. Detectors that are still in development can send
    a custom string (e.g. an unrecognised attack_type) and the row
    will still save correctly; it just won't have a friendly display
    label in the admin dropdown until this list is extended.
    """
    SQL_INJECTION = 'sql_injection', 'SQL Injection'
    XSS = 'xss', 'Cross-Site Scripting (XSS)'
    HTML_INJECTION = 'html_injection', 'HTML Injection'
    FILE_UPLOAD = 'file_upload', 'File Upload Vulnerability'
    COMMAND_INJECTION = 'command_injection', 'Command Injection'
    PATH_TRAVERSAL = 'path_traversal', 'Path Traversal'
    CSRF = 'csrf', 'CSRF'
    OTHER = 'other', 'Other'


class Severity(models.TextChoices):
    LOW = 'low', 'Low'
    MEDIUM = 'medium', 'Medium'
    HIGH = 'high', 'High'
    CRITICAL = 'critical', 'Critical'


class AttackLog(models.Model):
    """
    A single detected attack event, as reported by the detection /
    decision engine pipeline.
    """

    ip_address = models.GenericIPAddressField(
        db_index=True,
        help_text='Source IP address of the request.'
    )
    url = models.CharField(
        max_length=2048,
        help_text='Request path/URL that triggered detection.'
    )
    method = models.CharField(
        max_length=10,
        choices=HTTPMethod.choices,
        help_text='HTTP method of the request.'
    )
    timestamp = models.DateTimeField(
        default=timezone.now,
        db_index=True,
        help_text='When the attack was detected.'
    )

    payload = models.JSONField(
        blank=True,
        null=True,
        help_text='Raw request body/params captured at detection time.'
    )
    headers = models.JSONField(
        blank=True,
        null=True,
        help_text='Request headers captured at detection time.'
    )

    attack_type = models.CharField(
        max_length=100,
        choices=AttackType.choices,
        db_index=True,
        help_text='Category of attack (see AttackType for known values).'
    )
    severity = models.CharField(
        max_length=20,
        choices=Severity.choices,
        default=Severity.LOW,
        db_index=True,
    )
    risk_score = models.PositiveSmallIntegerField(
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        help_text='Normalized risk score (0-100) assigned by the decision engine.'
    )

    rule_triggered = models.CharField(
        max_length=150,
        blank=True,
        db_index=True,
        help_text='Name/ID of the specific rule that matched.'
    )
    detector_name = models.CharField(
        max_length=150,
        blank=True,
        db_index=True,
        help_text='Which detector module flagged this request.'
    )

    user_agent = models.TextField(blank=True)

    blocked = models.BooleanField(
        default=False,
        db_index=True,
        help_text='Whether the decision engine blocked this request.'
    )
    response_code = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        help_text='HTTP status code ultimately returned to the client.'
    )

    # Optional GeoIP enrichment — safe to leave null if the pipeline
    # doesn't resolve geolocation.
    country = models.CharField(max_length=100, blank=True)
    city = models.CharField(max_length=100, blank=True)
    latitude = models.FloatField(null=True, blank=True)
    longitude = models.FloatField(null=True, blank=True)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'Attack Log'
        verbose_name_plural = 'Attack Logs'
        indexes = [
            models.Index(fields=['-timestamp']),
            models.Index(fields=['ip_address', '-timestamp']),
            models.Index(fields=['attack_type', '-timestamp']),
            models.Index(fields=['severity', '-timestamp']),
        ]

    @property
    def short_payload(self) -> str:
        """Truncated payload preview, safe for admin list_display."""
        if not self.payload:
            return ''
        text = str(self.payload)
        return text if len(text) <= 80 else f'{text[:80]}…'

    def __str__(self) -> str:
        return f'[{self.severity.upper()}] {self.attack_type} from {self.ip_address} @ {self.timestamp:%Y-%m-%d %H:%M:%S}'