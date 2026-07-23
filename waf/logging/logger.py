"""
Reusable logger factory for WAF components.

Any module in the WAF pipeline (middleware, normalizers, detectors,
decision engine) can call get_logger(__name__) to get a correctly
namespaced logger that routes into waf.log via the LOGGING config in
settings.py, without needing to know about handlers, formatters, or
file paths.
"""

import logging


def get_logger(name: str = 'waf') -> logging.Logger:
    """
    Return a logger under the 'waf' namespace.

    Passing __name__ from a module like `waf.dashboard.views` yields
    'waf.dashboard.views', which still routes through the 'waf' logger
    config (handlers: waf_file, console) unless a more specific logger
    name (e.g. 'waf.attacks', 'waf.access') is configured in
    settings.LOGGING.
    """
    if name == 'waf' or name.startswith('waf.'):
        return logging.getLogger(name)
    return logging.getLogger(f'waf.{name}')


# Convenience shortcuts for quick, simple calls from anywhere in the
# WAF pipeline, e.g.: from waf.logging.logger import log_info
_default_logger = get_logger('waf')


def log_debug(message: str, *args, **kwargs) -> None:
    _default_logger.debug(message, *args, **kwargs)


def log_info(message: str, *args, **kwargs) -> None:
    _default_logger.info(message, *args, **kwargs)


def log_warning(message: str, *args, **kwargs) -> None:
    _default_logger.warning(message, *args, **kwargs)


def log_error(message: str, *args, **kwargs) -> None:
    _default_logger.error(message, *args, **kwargs)