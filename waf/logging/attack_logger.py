"""
attack_logger.py

The single public entry point the detection/decision engine (and
middleware) call once an attack has been identified. This is the
"seam" between their modules and mine: they hand over a plain dict,
and everything downstream — DB write, log file, rule/detector
counters, IP blocking — happens here.

Usage (from middleware or the decision engine):

    from waf.logging.attack_logger import log_attack

    log_attack({
        'ip_address': request.META.get('REMOTE_ADDR'),
        'url': request.path,
        'method': request.method,
        'payload': dict(request.POST) or dict(request.GET),
        'headers': dict(request.headers),
        'attack_type': 'sql_injection',
        'severity': 'high',
        'risk_score': 90,
        'rule_triggered': 'SQLI-001',
        'detector_name': 'sqli_detector',
        'user_agent': request.META.get('HTTP_USER_AGENT', ''),
        'blocked': True,
        'response_code': 403,
    })

Only ip_address, url, method, and attack_type are required. Everything
else has a safe default. This function never raises — a failure to
log must never take down the request/response cycle it's protecting.
"""

from typing import Optional

from django.utils import timezone

from waf.models import AttackLog, BlockedIP, RuleStats, DetectorStats
from waf.logging.logger import get_logger

logger = get_logger('waf.attacks')
_error_logger = get_logger('waf')

REQUIRED_FIELDS = ('ip_address', 'url', 'method', 'attack_type')


def log_attack(event: dict) -> Optional[AttackLog]:
    """
    Record a detected attack: writes to the database, the attacks.log
    file, and updates rule/detector counters and IP block status.

    Args:
        event: dict describing the attack. See module docstring for
            the expected shape.

    Returns:
        The created AttackLog instance, or None if logging failed
        (the failure itself is written to waf.log, not raised).
    """
    missing = [f for f in REQUIRED_FIELDS if not event.get(f)]
    if missing:
        _error_logger.error(f'log_attack called with missing required fields: {missing}')
        return None

    try:
        attack = AttackLog.objects.create(
            ip_address=event['ip_address'],
            url=event['url'],
            method=event['method'],
            timestamp=event.get('timestamp', timezone.now()),
            payload=event.get('payload'),
            headers=event.get('headers'),
            attack_type=event['attack_type'],
            severity=event.get('severity', 'low'),
            risk_score=event.get('risk_score', 0),
            rule_triggered=event.get('rule_triggered', ''),
            detector_name=event.get('detector_name', ''),
            user_agent=event.get('user_agent', ''),
            blocked=event.get('blocked', False),
            response_code=event.get('response_code'),
            country=event.get('country', ''),
            city=event.get('city', ''),
            latitude=event.get('latitude'),
            longitude=event.get('longitude'),
        )
    except Exception as exc:
        _error_logger.error(f'Failed to save AttackLog: {exc}', exc_info=True)
        return None

    # Update aggregate counters — failures here shouldn't roll back
    # the AttackLog row itself, so each step is wrapped independently.
    try:
        if attack.rule_triggered:
            RuleStats.record_trigger(attack.rule_triggered)
        if attack.detector_name:
            DetectorStats.record_detection(
                attack.detector_name,
                is_false_positive=event.get('is_false_positive', False),
            )
    except Exception as exc:
        _error_logger.error(f'Failed to update rule/detector stats: {exc}', exc_info=True)

    # Auto-block only after multiple blocked attacks from the same IP.
    AUTO_BLOCK_THRESHOLD = 3

    if attack.blocked and event.get('auto_block', True):
        try:
            blocked_count = AttackLog.objects.filter(
                 ip_address=attack.ip_address,
                blocked=True,
             ).count()

            if blocked_count >= AUTO_BLOCK_THRESHOLD:
             BlockedIP.block(
                 attack.ip_address,
                 reason=(
                       f'{blocked_count} blocked attacks '
                      f'(latest: {attack.attack_type} via rule {attack.rule_triggered or "unknown"})'
                    ),
             )
        except Exception as exc:
            _error_logger.error(f'Failed to update BlockedIP: {exc}', exc_info=True)

    # Write the structured line to attacks.log
    try:
        logger.info(
            'attack_detected',
            extra={'attack_data': {
                'ip_address': attack.ip_address,
                'url': attack.url,
                'method': attack.method,
                'attack_type': attack.attack_type,
                'severity': attack.severity,
                'risk_score': attack.risk_score,
                'rule_triggered': attack.rule_triggered,
                'detector_name': attack.detector_name,
                'blocked': attack.blocked,
                'response_code': attack.response_code,
            }},
        )
    except Exception as exc:
        _error_logger.error(f'Failed to write attacks.log entry: {exc}', exc_info=True)

    return attack


def log_access(ip_address: str, url: str, method: str, status_code: Optional[int] = None) -> None:
    """
    Lightweight access-log helper for middleware to call on every
    request (not just attacks). Kept separate from log_attack since
    most requests are not attacks.
    """
    access_logger = get_logger('waf.access')
    try:
        access_logger.info(f'{method} {url} from {ip_address} -> {status_code}')
    except Exception as exc:
        _error_logger.error(f'Failed to write access.log entry: {exc}', exc_info=True)