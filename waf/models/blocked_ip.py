"""
BlockedIP model.

Tracks IP addresses currently (or previously) blocked by the WAF,
independent of individual AttackLog rows, so the decision engine /
middleware can do a fast "is this IP blocked?" lookup.
"""

from django.db import models
from django.db.models import F
from django.utils import timezone


class BlockedIP(models.Model):
    """A single blocked IP address and its block metadata."""

    ip_address = models.GenericIPAddressField(
        unique=True,
        db_index=True,
        help_text='The blocked IP address.'
    )
    reason = models.TextField(
        blank=True,
        help_text='Why this IP was blocked (e.g. rule name, attack type).'
    )
    blocked_at = models.DateTimeField(
        default=timezone.now,
        db_index=True,
    )
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text='When the block lifts. Leave blank for a permanent block.'
    )
    is_active = models.BooleanField(
        default=True,
        db_index=True,
        help_text='Whether this block is currently in effect.'
    )
    attack_count = models.PositiveIntegerField(
        default=1,
        help_text='Number of attacks attributed to this IP while blocked.'
    )

    class Meta:
        ordering = ['-blocked_at']
        verbose_name = 'Blocked IP'
        verbose_name_plural = 'Blocked IPs'

    @property
    def is_expired(self) -> bool:
        """True if this block has a set expiry and it has passed."""
        return bool(self.expires_at and self.expires_at <= timezone.now())

    @classmethod
    def is_blocked(cls, ip_address: str) -> bool:
        """
        Fast lookup used by middleware/decision engine to check whether
        an incoming IP should be rejected outright.
        """
        return cls.objects.filter(
            ip_address=ip_address,
            is_active=True,
        ).exclude(
            expires_at__isnull=False,
            expires_at__lte=timezone.now(),
        ).exists()

    @classmethod
    def block(
        cls,
        ip_address: str,
        reason: str = '',
        expires_at=None,
        attack_count: int | None = None,
    ) -> 'BlockedIP':
        """
        Create a new block record, or reactivate/refresh an existing one.

        For a new block, attack_count can be supplied when the caller
        already knows how many attacks caused the block. This prevents
        the initial record from incorrectly reporting only 1 attack.

        For an existing block, attack_count is incremented by one unless
        an explicit count is supplied.
        """
        if attack_count is not None and attack_count < 1:
            raise ValueError('attack_count must be at least 1')

        obj, created = cls.objects.get_or_create(
            ip_address=ip_address,
            defaults={
                'reason': reason,
                'expires_at': expires_at,
                'attack_count': attack_count if attack_count is not None else 1,
            },
        )

        if not created:
            obj.is_active = True
            obj.reason = reason or obj.reason
            obj.expires_at = expires_at

            if attack_count is None:
                obj.attack_count = F('attack_count') + 1
            else:
                obj.attack_count = attack_count

            obj.save(
                update_fields=[
                    'is_active',
                    'reason',
                    'expires_at',
                    'attack_count',
                ]
            )
            obj.refresh_from_db()

        return obj

    def __str__(self) -> str:
        status = 'active' if self.is_active and not self.is_expired else 'inactive'
        return f'{self.ip_address} ({status})'