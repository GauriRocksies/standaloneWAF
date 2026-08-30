"""
base_detector.py

Backward-compatibility shim. The real implementation now lives in
waf_core/base_detector.py (framework-independent, single source of
truth). This module re-exports it so any existing
`from waf.detectors.base_detector import ...` keeps working
unchanged.
"""

from waf_core.base_detector import (
    normalize,
    get_query_params,
    get_post_data,
    get_json_body,
    get_cookies,
    get_headers,
    get_files,
    get_all_text_values,
    match_ruleset,
    scan_values,
    match_all,
    build_result,
    result_from_rule,
    report,
    safe_detect,
)

__all__ = [
    "normalize",
    "get_query_params",
    "get_post_data",
    "get_json_body",
    "get_cookies",
    "get_headers",
    "get_files",
    "get_all_text_values",
    "match_ruleset",
    "scan_values",
    "match_all",
    "build_result",
    "result_from_rule",
    "report",
    "safe_detect",
]
