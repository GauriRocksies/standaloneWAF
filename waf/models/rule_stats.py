"""
RuleStats model.

Aggregate counters per WAF rule, so the dashboard's "Top Rules" chart
doesn't have to run a GROUP BY over the entire AttackLog table on
every page load.
"""

from django.db import models
from django.db.models import F
from django.utils import timezone


class RuleStats(models.Model):
    """Running trigger count for a single named rule."""

    rule_name = models.CharField(
        max_length=150,
        unique=True,
        db_index=True,
    )
    trigger_count = models.PositiveIntegerField(default=0)
    last_triggered = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-trigger_count']
        verbose_name = 'Rule Statistic'
        verbose_name_plural = 'Rule Statistics'

    @classmethod
    def record_trigger(cls, rule_name: str) -> None:
        """
        Increment the trigger count for a rule, creating its row on
        first use. Called by attack_logger.py whenever an AttackLog
        entry with a non-empty rule_triggered is saved.
        """
        if not rule_name:
            return
        obj, created = cls.objects.get_or_create(rule_name=rule_name)
        if not created:
            obj.trigger_count = F('trigger_count') + 1
        else:
            obj.trigger_count = 1
        obj.last_triggered = timezone.now()
        obj.save(update_fields=['trigger_count', 'last_triggered'])

    def __str__(self) -> str:
        return f'{self.rule_name} ({self.trigger_count} triggers)'
    