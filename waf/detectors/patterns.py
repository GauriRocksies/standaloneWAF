"""
patterns.py

Shared, precompiled regex registry for the detector pipeline.

This is the single source of truth for attack signatures. Detectors
do NOT keep their own copies of SQLi/XSS/path-traversal/command
patterns — they call match_ruleset() against this registry. That is
what lets cookie_validator.py, header_validator.py, and
payload_validator.py reuse the exact same SQLi/XSS checks that
sql_injection.py and xss.py use, without duplicating a single regex.

Patterns are grouped by attack_type (matching waf.models.AttackType
values) and compiled once at import time — never per-request.

Scoring convention (0-100):
    80-100  high-confidence, rarely appears in benign traffic
    50-79   strong signal, occasionally benign
    20-49   weak signal alone; common in benign traffic too
             (kept for breadth of coverage / future score-aggregation
             by a decision engine, not meant to trigger alone)

Severity is intentionally lowercase to match waf.models.Severity
('low', 'medium', 'high', 'critical') exactly — the model's TextField
choices are not enforced at the DB level, but sending mismatched case
means rows won't get a friendly admin label and dashboard filters by
severity will silently miss them.
"""

import re
from dataclasses import dataclass
from typing import Dict, List, Tuple


@dataclass(frozen=True)
class Rule:
    """A single compiled detection rule."""
    pattern: "re.Pattern[str]"
    rule_id: str
    attack_type: str
    score: int
    severity: str
    description: str


def severity_for_score(score: int) -> str:
    """
    Map a 0-100 score to a Severity choice. Public so individual
    detectors can recompute severity after adjusting a score (e.g.
    bumping it when multiple independent rules match the same
    request), without duplicating the threshold table.
    """
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


# Internal alias kept for readability at the definition site below.
_severity_for = severity_for_score


# Raw pattern definitions: (regex, rule_id, attack_type, score, description)
# Severity is derived from score via _severity_for unless noted otherwise.
_RAW_RULES: List[Tuple[str, str, str, int, str]] = [
    # ---- SQL injection ------------------------------------------------
    (r"union\s+select", "SQLI-001", "sql_injection", 80, "UNION-based injection"),
    (r"select\s+\*\s+from", "SQLI-002", "sql_injection", 30, "generic SELECT (weak alone)"),
    (r"drop\s+table", "SQLI-003", "sql_injection", 95, "destructive DDL"),
    (r"insert\s+into", "SQLI-004", "sql_injection", 50, "INSERT statement"),
    (r"update\s+\w+\s+set", "SQLI-005", "sql_injection", 50, "UPDATE statement"),
    (r"delete\s+from", "SQLI-006", "sql_injection", 60, "DELETE statement"),
    (r"\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?", "SQLI-007", "sql_injection", 45, "OR tautology (e.g. OR 1=1)"),
    (r"\band\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?", "SQLI-008", "sql_injection", 40, "AND tautology (e.g. AND 1=1)"),
    (r"information_schema", "SQLI-009", "sql_injection", 70, "schema enumeration"),
    (r"sleep\s*\(\s*\d+\s*\)", "SQLI-010", "sql_injection", 65, "MySQL time-based blind (sleep)"),
    (r"benchmark\s*\(", "SQLI-011", "sql_injection", 65, "MySQL time-based blind (benchmark)"),
    (r"load_file\s*\(", "SQLI-012", "sql_injection", 85, "MySQL file read"),
    (r"into\s+outfile", "SQLI-013", "sql_injection", 85, "MySQL file write"),
    (r"xp_cmdshell", "SQLI-014", "sql_injection", 95, "MSSQL OS command execution"),
    (r"exec(?:ute)?\s*\(", "SQLI-015", "sql_injection", 55, "dynamic execution call"),
    (r"concat\s*\(", "SQLI-016", "sql_injection", 20, "string concat (weak alone)"),
    (r"char\s*\(\s*\d+", "SQLI-017", "sql_injection", 20, "char()-encoded literal (weak alone)"),
    (r"0x[0-9a-f]{4,}", "SQLI-018", "sql_injection", 25, "hex-encoded literal (weak alone)"),
    (r"(--|#|/\*)", "SQLI-019", "sql_injection", 15, "SQL comment marker (weak alone)"),
    (r"pg_sleep\s*\(", "SQLI-020", "sql_injection", 65, "PostgreSQL time-based blind"),
    (r"sqlite_master", "SQLI-021", "sql_injection", 60, "SQLite schema table"),
    (r"waitfor\s+delay", "SQLI-022", "sql_injection", 65, "MSSQL time-based blind"),
    (r"utl_http|dbms_\w+", "SQLI-023", "sql_injection", 60, "Oracle PL/SQL package abuse"),

    # ---- XSS ------------------------------------------------------------
    (r"<script", "XSS-001", "xss", 90, "inline script tag"),
    (r"javascript\s*:", "XSS-002", "xss", 70, "javascript: URI scheme"),
    (r"on(error|load|click|mouseover)\s*=", "XSS-003", "xss", 75, "inline event handler"),
    (r"<iframe", "XSS-004", "xss", 60, "iframe injection"),
    (r"<svg", "XSS-005", "xss", 40, "svg tag (common onload vector)"),
    (r"document\.cookie", "XSS-006", "xss", 80, "cookie theft attempt"),
    (r"(alert|prompt|confirm)\s*\(", "XSS-007", "xss", 50, "JS dialog call (common PoC)"),
    (r"eval\s*\(", "XSS-008", "xss", 60, "eval() call"),
    (r"fetch\s*\(", "XSS-009", "xss", 25, "fetch() call (weak alone)"),
    (r"location\.href", "XSS-010", "xss", 35, "location redirect (weak alone)"),
    (r"innerHTML", "XSS-011", "xss", 40, "DOM sink assignment"),
    (r"srcdoc\s*=", "XSS-012", "xss", 55, "iframe srcdoc injection"),

    # ---- Path traversal ---------------------------------------------
    (r"\.\.[/\\]", "PATH-001", "path_traversal", 70, "directory traversal sequence"),
    (r"%2e%2e", "PATH-002", "path_traversal", 50, "URL-encoded traversal (raw, undecoded)"),
    (r"%252e%252e", "PATH-003", "path_traversal", 60, "double URL-encoded traversal (evasion attempt)"),
    (r"/etc/passwd", "PATH-004", "path_traversal", 90, "Unix password file"),
    (r"boot\.ini", "PATH-005", "path_traversal", 85, "Windows boot config"),
    (r"windows[/\\]system32", "PATH-006", "path_traversal", 80, "Windows system directory"),
    (r"proc/self", "PATH-007", "path_traversal", 70, "Linux procfs introspection"),
    (r"etc[/\\]shadow", "PATH-008", "path_traversal", 85, "Unix shadow password file"),
    (r"etc[/\\]hosts", "PATH-009", "path_traversal", 55, "hosts file"),

    # ---- Command injection -------------------------------------------
    (r"[;&|`]|\$\(", "CMD-001", "command_injection", 40, "shell metacharacter (weak alone)"),
    (r"cmd\.exe", "CMD-002", "command_injection", 85, "Windows command shell"),
    (r"powershell", "CMD-003", "command_injection", 75, "PowerShell invocation"),
    (r"\bbash\b|\bsh\s+-c\b", "CMD-004", "command_injection", 45, "shell invocation"),
    (r"\b(wget|curl)\b", "CMD-005", "command_injection", 40, "remote fetch utility (weak alone)"),
    (r"\bnc\b|\bnetcat\b", "CMD-006", "command_injection", 55, "netcat (reverse shell tool)"),
    (r"\bwhoami\b", "CMD-007", "command_injection", 60, "identity enumeration"),
    (r"\b(cat|ls|dir)\b", "CMD-008", "command_injection", 20, "file listing/read command (weak alone)"),
    (r"\bping\b", "CMD-009", "command_injection", 25, "network probe (weak alone)"),
    (r"\bsleep\s+\d+\b", "CMD-010", "command_injection", 50, "shell-level time delay"),
]

# Compile once, grouped by attack_type, sorted by descending score so
# match_ruleset() returns the strongest signal first.
REGISTRY: Dict[str, List[Rule]] = {}
for _pattern, _rule_id, _attack_type, _score, _desc in _RAW_RULES:
    rule = Rule(
        pattern=re.compile(_pattern, re.IGNORECASE),
        rule_id=_rule_id,
        attack_type=_attack_type,
        score=_score,
        severity=_severity_for(_score),
        description=_desc,
    )
    REGISTRY.setdefault(_attack_type, []).append(rule)

for _rules in REGISTRY.values():
    _rules.sort(key=lambda r: r.score, reverse=True)
