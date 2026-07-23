"""
Custom logging formatters for the WAF logging system.

Two formatters are provided:
- WafTextFormatter: human-readable, used for waf.log / access.log
- AttackJSONFormatter: one JSON object per line, used for attacks.log
  so attack records stay machine-parseable (e.g. for later ingestion
  into a SIEM, or ad-hoc grep/jq analysis) without losing structure.
"""

import json
import logging
from datetime import datetime, timezone as dt_timezone


class WafTextFormatter(logging.Formatter):
    """Plain, readable formatter for general WAF component logs."""

    def format(self, record: logging.LogRecord) -> str:
        record.asctime = datetime.fromtimestamp(
            record.created, tz=dt_timezone.utc
        ).strftime('%Y-%m-%d %H:%M:%S UTC')
        return f'[{record.asctime}] {record.levelname} {record.name}: {record.getMessage()}'


class AttackJSONFormatter(logging.Formatter):
    """
    Formats attack log records as a single JSON object per line.

    Expects the log call to pass structured attack data via the
    `extra=` kwarg (see attack_logger.log_attack), e.g.:

        logger.info('attack_detected', extra={'attack_data': {...}})

    Falls back to a plain message field if `attack_data` isn't present,
    so this formatter never raises on an unexpected log call.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload = getattr(record, 'attack_data', None)
        entry = {
            'timestamp': datetime.fromtimestamp(
                record.created, tz=dt_timezone.utc
            ).isoformat(),
            'level': record.levelname,
        }
        if payload is not None:
            entry.update(payload)
        else:
            entry['message'] = record.getMessage()
        return json.dumps(entry, default=str)