"""
DetectorStats model.

Aggregate counters per detector module, including an optional
false-positive count for detectors that support marking one.
"""

from django.db import models
from django.db.models import F
from django.utils import timezone


class DetectorStats(models.Model):
    """Running detection count for a single named detector."""

    detector_name = models.CharField(
        max_length=150,
        unique=True,
        db_index=True,
    )
    detection_count = models.PositiveIntegerField(default=0)
    false_positive_count = models.PositiveIntegerField(default=0)
    last_detection = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-detection_count']
        verbose_name = 'Detector Statistic'
        verbose_name_plural = 'Detector Statistics'

    @classmethod
    def record_detection(cls, detector_name: str, is_false_positive: bool = False) -> None:
        """
        Increment detection (and optionally false-positive) counts for
        a detector, creating its row on first use. Called by
        attack_logger.py whenever an AttackLog entry with a non-empty
        detector_name is saved.
        """
        if not detector_name:
            return
        obj, created = cls.objects.get_or_create(detector_name=detector_name)
        if not created:
            obj.detection_count = F('detection_count') + 1
        else:
            obj.detection_count = 1
        if is_false_positive:
            obj.false_positive_count = F('false_positive_count') + 1
        obj.last_detection = timezone.now()
        obj.save(update_fields=['detection_count', 'false_positive_count', 'last_detection'])

    def __str__(self) -> str:
        return f'{self.detector_name} ({self.detection_count} detections)'