"""
constants.py

Central location for constants used throughout the standalone WAF
core. Identical to the original waf/constants.py — this module has
no framework dependencies and was moved here unchanged.
"""

# ==========================================================
# WAF Actions
# ==========================================================

ALLOW = "allow"
BLOCK = "block"


# ==========================================================
# Severity Levels
# ==========================================================

LOW = "low"
MEDIUM = "medium"
HIGH = "high"
CRITICAL = "critical"

SEVERITY_LEVELS = (
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL,
)


# ==========================================================
# HTTP Status Codes
# ==========================================================

HTTP_OK = 200
HTTP_FORBIDDEN = 403
HTTP_BAD_REQUEST = 400
HTTP_UNAUTHORIZED = 401
HTTP_NOT_FOUND = 404
HTTP_INTERNAL_SERVER_ERROR = 500


# ==========================================================
# Risk Scoring
# ==========================================================

MIN_RISK_SCORE = 0
MAX_RISK_SCORE = 100

DEFAULT_BLOCK_THRESHOLD = 70


# ==========================================================
# Default Response Messages
# ==========================================================

BLOCK_MESSAGE = (
    "Request blocked by Web Application Firewall."
)

ALLOW_MESSAGE = (
    "Request allowed."
)


# ==========================================================
# Detector Defaults
# ==========================================================

UNKNOWN_ATTACK = "unknown"
UNKNOWN_RULE = "UNKNOWN"
UNKNOWN_DETECTOR = "unknown_detector"

DEFAULT_ATTACK_SCORE = 0
DEFAULT_SEVERITY = LOW


# ==========================================================
# Common Attack Types
# ==========================================================

SQL_INJECTION = "sql_injection"
XSS = "cross_site_scripting"
COMMAND_INJECTION = "command_injection"
PATH_TRAVERSAL = "path_traversal"
FILE_INCLUSION = "file_inclusion"
MALICIOUS_UPLOAD = "malicious_upload"
BAD_USER_AGENT = "bad_user_agent"
RATE_LIMIT = "rate_limit"
OTHER = "other"


# ==========================================================
# HTTP Methods
# ==========================================================

HTTP_GET = "GET"
HTTP_POST = "POST"
HTTP_PUT = "PUT"
HTTP_PATCH = "PATCH"
HTTP_DELETE = "DELETE"
HTTP_OPTIONS = "OPTIONS"
HTTP_HEAD = "HEAD"


# ==========================================================
# Logging
# ==========================================================

ACCESS_LOGGER = "waf.access"
ATTACK_LOGGER = "waf.attacks"
SYSTEM_LOGGER = "waf"


# ==========================================================
# Default Header Names
# ==========================================================

HEADER_USER_AGENT = "User-Agent"
HEADER_REFERER = "Referer"
HEADER_HOST = "Host"
HEADER_COOKIE = "Cookie"
HEADER_CONTENT_TYPE = "Content-Type"


# ==========================================================
# Miscellaneous
# ==========================================================

UNKNOWN_IP = "unknown"

DEFAULT_ENCODING = "utf-8"

VERSION = "1.0"
