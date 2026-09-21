"""
evaluate_waf.py
================
Research/evaluation harness for the standalone WAF repository.

What it measures for the paper's Section V:
  A. Detection performance: precision, recall, F1
  B. False-positive analysis
  C. Evasion resistance
  D. Latency overhead (optional live HTTP test)
  E. Cross-framework portability (optional live HTTP test)

Core measurements need only the Python standard library + this repo.
Live HTTP measurements also use urllib from the standard library.

Run from the repository root:

    python evaluate_waf.py
    python evaluate_waf.py --live \
        --proxy-url http://127.0.0.1:8080 \
        --origin-url http://127.0.0.1:8000

Cross-framework comparison requires two reachable proxy endpoints:
    python evaluate_waf.py --cross-framework \
        --django-proxy-url http://127.0.0.1:8080 \
        --flask-proxy-url http://127.0.0.1:8081

The script writes:
    evaluation_results.json
    evaluation_report.txt

IMPORTANT FOR LIVE BENCHMARKING:
The Django integration can auto-block an IP after repeated attacks.
For latency benchmarks, disable auto-block temporarily:
    WAF_AUTO_BLOCK=False
Otherwise later malicious requests may be short-circuited by the blocklist,
which would measure blocklist lookup latency rather than detector latency.
"""

from __future__ import annotations

import argparse
import html
import json
import math
import statistics
import sys
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlencode, quote, urlsplit, urlunsplit
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from waf_core import WAFEngine, WAFRequest
from waf_core.constants import ALLOW, BLOCK


REPO_ROOT = Path(__file__).resolve().parent
RESULTS_JSON = REPO_ROOT / "evaluation_results.json"
REPORT_TXT = REPO_ROOT / "evaluation_report.txt"

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36"
)


@dataclass(frozen=True)
class EvaluationCase:
    case_id: str
    label: str  # "benign" or attack type such as "sql_injection"
    request: WAFRequest
    family: str = ""
    variant: str = ""


def req(
    case_id: str,
    label: str,
    *,
    path: str = "/",
    method: str = "GET",
    query_params: Optional[Dict[str, str]] = None,
    form_data: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    files: Optional[Dict[str, Any]] = None,
    body: str | bytes = b"",
    family: str = "",
    variant: str = "",
    ip_suffix: str = "",
) -> EvaluationCase:
    base_headers = {"User-Agent": BROWSER_UA}
    base_headers.update(headers or {})
    meta = {"REMOTE_ADDR": f"10.250.0.{ip_suffix or '1'}"}
    return EvaluationCase(
        case_id=case_id,
        label=label,
        request=WAFRequest(
            path=path,
            method=method,
            query_params=query_params,
            form_data=form_data,
            headers=base_headers,
            cookies=cookies,
            files=files,
            body=body,
            meta=meta,
        ),
        family=family,
        variant=variant,
    )


def build_benign_cases() -> List[EvaluationCase]:
    return [
        req("B01", "benign", path="/", ip_suffix="11"),
        req("B02", "benign", path="/products", query_params={"id": "123"}, ip_suffix="12"),
        req(
            "B03",
            "benign",
            path="/search",
            query_params={"q": "wireless headphones under 3000"},
            ip_suffix="13",
        ),
        req(
            "B04",
            "benign",
            path="/login",
            method="POST",
            form_data={"username": "alice", "password": "hunter2"},
            ip_suffix="14",
        ),
        req(
            "B05",
            "benign",
            path="/comment",
            method="POST",
            form_data={"body": "I really liked this article."},
            ip_suffix="15",
        ),
        req(
            "B06",
            "benign",
            path="/search",
            query_params={"q": "OR 1=1 is a SQL example in a tutorial"},
            ip_suffix="16",
        ),
        req(
            "B07",
            "benign",
            path="/profile",
            cookies={"theme": "dark", "sessionid": "abc123"},
            ip_suffix="17",
        ),
        req(
            "B08",
            "benign",
            path="/api/items",
            method="POST",
            headers={"Content-Type": "application/json"},
            body='{"name":"keyboard","quantity":2}',
            ip_suffix="18",
        ),
        req(
            "B09",
            "benign",
            path="/download",
            query_params={"file": "report_2026.pdf"},
            ip_suffix="19",
        ),
        req(
            "B10",
            "benign",
            path="/",
            headers={
                "Referer": "https://example.com/articles/waf-testing",
                "Accept": "text/html,application/xhtml+xml",
            },
            ip_suffix="20",
        ),
        req(
            "B11",
            "benign",
            path="/products",
            method="OPTIONS",
            ip_suffix="21",
        ),
        req(
            "B12",
            "benign",
            path="/comment",
            method="POST",
            form_data={"body": "Use <b>bold</b> text in the comment."},
            ip_suffix="22",
        ),
    ]


def build_malicious_cases() -> List[EvaluationCase]:
    # These are representative test strings for a lab/demo WAF.
    # They are sent to the WAF as data, not executed by this script.
    return [
        # SQL injection
        req(
            "SQL01", "sql_injection",
            path="/login", method="POST",
            form_data={"username": "admin' OR '1'='1", "password": "x"},
            family="sqli", variant="tautology", ip_suffix="31",
        ),
        req(
            "SQL02", "sql_injection",
            path="/search",
            query_params={"id": "1 UNION SELECT username, password FROM users"},
            family="sqli", variant="union-select", ip_suffix="32",
        ),
        req(
            "SQL03", "sql_injection",
            path="/search",
            query_params={"q": "'; DROP TABLE users;--"},
            family="sqli", variant="drop-table", ip_suffix="33",
        ),
        req(
            "SQL04", "sql_injection",
            path="/search",
            query_params={"id": "1' AND 1=1 --"},
            family="sqli", variant="and-tautology", ip_suffix="34",
        ),
        req(
            "SQL05", "sql_injection",
            path="/search",
            query_params={"id": "1; SELECT * FROM users"},
            family="sqli", variant="select-from", ip_suffix="35",
        ),

        # XSS
        req(
            "XSS01", "xss",
            path="/search",
            query_params={"q": "<script>alert(1)</script>"},
            family="xss", variant="script-tag", ip_suffix="41",
        ),
        req(
            "XSS02", "xss",
            path="/comment", method="POST",
            form_data={"body": "<img src=x onerror=alert(1)>"},
            family="xss", variant="event-handler", ip_suffix="42",
        ),
        req(
            "XSS03", "xss",
            path="/comment", method="POST",
            form_data={"body": '<iframe src="javascript:alert(1)"></iframe>'},
            family="xss", variant="iframe-javascript", ip_suffix="43",
        ),
        req(
            "XSS04", "xss",
            path="/profile",
            cookies={"theme": "<script>document.cookie</script>"},
            family="xss", variant="cookie-script", ip_suffix="44",
        ),
        req(
            "XSS05", "xss",
            path="/",
            headers={"Referer": "<script>document.cookie</script>"},
            family="xss", variant="header-script", ip_suffix="45",
        ),

        # Command injection
        req(
            "CMD01", "command_injection",
            path="/run",
            query_params={"cmd": ";cat /etc/passwd"},
            family="command", variant="semicolon-cat", ip_suffix="51",
        ),
        req(
            "CMD02", "command_injection",
            path="/run",
            query_params={"cmd": "id && whoami"},
            family="command", variant="and-whoami", ip_suffix="52",
        ),
        req(
            "CMD03", "command_injection",
            path="/run",
            query_params={"cmd": "powershell -c whoami"},
            family="command", variant="powershell", ip_suffix="53",
        ),
        req(
            "CMD04", "command_injection",
            path="/run",
            query_params={"cmd": "$(id)"},
            family="command", variant="command-substitution", ip_suffix="54",
        ),

        # Path traversal
        req(
            "PATH01", "path_traversal",
            path="/download",
            query_params={"file": "../../etc/passwd"},
            family="path", variant="dot-dot", ip_suffix="61",
        ),
        req(
            "PATH02", "path_traversal",
            path="/download",
            query_params={"file": "../" * 3 + "etc/passwd"},
            family="path", variant="unix-passwd", ip_suffix="62",
        ),
        req(
            "PATH03", "path_traversal",
            path="/download",
            query_params={"file": "..%2f..%2f..%2fetc%2fpasswd"},
            family="path", variant="url-encoded", ip_suffix="63",
        ),
    ]


def build_evasion_cases() -> List[EvaluationCase]:
    # Every case belongs to the same attack family as its plaintext
    # equivalent, but is represented in a different encoding/obfuscation.
    return [
        req(
            "EV01", "xss",
            path="/search",
            query_params={"q": "%3Cscript%3Ealert(1)%3C/script%3E"},
            family="xss", variant="url-encoded-once", ip_suffix="71",
        ),
        req(
            "EV02", "xss",
            path="/search",
            query_params={"q": "%253Cscript%253Ealert(1)%253C/script%253E"},
            family="xss", variant="url-encoded-twice", ip_suffix="72",
        ),
        req(
            "EV03", "xss",
            path="/comment", method="POST",
            form_data={"body": "&lt;script&gt;alert(1)&lt;/script&gt;"},
            family="xss", variant="html-entity", ip_suffix="73",
        ),
        req(
            "EV04", "sql_injection",
            path="/search",
            query_params={"id": "1%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--"},
            family="sqli", variant="url-encoded-union", ip_suffix="74",
        ),
        req(
            "EV05", "path_traversal",
            path="/download",
            query_params={"file": "..%2f..%2f..%2fetc%2fpasswd"},
            family="path", variant="url-encoded-traversal", ip_suffix="75",
        ),
        req(
            "EV06", "path_traversal",
            path="/download",
            query_params={"file": "%252e%252e%252f%252e%252e%252fetc%252fpasswd"},
            family="path", variant="double-encoded-traversal", ip_suffix="76",
        ),
    ]


def distinct_attack_labels(cases: Iterable[EvaluationCase]) -> List[str]:
    return sorted({c.label for c in cases if c.label != "benign"})


def run_core_case(engine: WAFEngine, case: EvaluationCase) -> Dict[str, Any]:
    decision = engine.inspect(case.request)
    predicted = sorted({
        str(d.get("attack"))
        for d in decision.detections
        if d.get("attack")
    })
    predicted_detectors = sorted({
        str(d.get("detector"))
        for d in decision.detections
        if d.get("detector")
    })
    return {
        "case_id": case.case_id,
        "label": case.label,
        "family": case.family,
        "variant": case.variant,
        "action": decision.action,
        "risk_score": decision.risk_score,
        "predicted_attacks": predicted,
        "detectors": predicted_detectors,
        "rules": list(decision.rules),
        "reasons": list(decision.reasons),
    }


def run_core_evaluation(
    benign_cases: Sequence[EvaluationCase],
    malicious_cases: Sequence[EvaluationCase],
    evasion_cases: Sequence[EvaluationCase],
) -> Dict[str, Any]:
    # Fresh engine per evaluation group avoids state leaking across groups.
    perf_engine = WAFEngine()
    benign_results = [run_core_case(perf_engine, c) for c in benign_cases]
    malicious_results = [run_core_case(perf_engine, c) for c in malicious_cases]

    # Evasion uses another fresh engine, with unique REMOTE_ADDR values.
    evasion_engine = WAFEngine()
    evasion_results = [run_core_case(evasion_engine, c) for c in evasion_cases]

    labels = distinct_attack_labels(malicious_cases)

    # One-vs-rest over the whole labeled evaluation set:
    #   actual positive = case.label == class
    #   predicted positive = class appears in predicted_attacks
    combined = benign_results + malicious_results
    performance = []
    overall_tp = overall_fp = overall_fn = overall_tn = 0

    for cls in labels:
        tp = fp = fn = tn = 0
        for row in combined:
            actual_positive = row["label"] == cls
            predicted_positive = cls in row["predicted_attacks"]
            if actual_positive and predicted_positive:
                tp += 1
            elif not actual_positive and predicted_positive:
                fp += 1
            elif actual_positive and not predicted_positive:
                fn += 1
            else:
                tn += 1

        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall)
            else 0.0
        )
        performance.append({
            "attack_class": cls,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": precision,
            "recall": recall,
            "f1": f1,
        })
        overall_tp += tp
        overall_fp += fp
        overall_fn += fn
        overall_tn += tn

    macro_precision = statistics.mean(r["precision"] for r in performance) if performance else 0
    macro_recall = statistics.mean(r["recall"] for r in performance) if performance else 0
    macro_f1 = statistics.mean(r["f1"] for r in performance) if performance else 0

    # False positives: request-level and detector-level.
    benign_blocked = [r for r in benign_results if r["action"] == BLOCK]
    detector_fp_counts = Counter()
    detector_fp_cases: Dict[str, List[str]] = defaultdict(list)

    for row in benign_results:
        for detector in row["detectors"]:
            detector_fp_counts[detector] += 1
            detector_fp_cases[detector].append(row["case_id"])

    benign_total = len(benign_results)
    aggregate_fpr = len(benign_blocked) / benign_total if benign_total else 0.0

    detector_fp_table = []
    all_detectors = sorted({
        detector
        for row in benign_results
        for detector in row["detectors"]
    })
    for detector in all_detectors:
        count = detector_fp_counts[detector]
        detector_fp_table.append({
            "detector": detector,
            "false_alarm_cases": count,
            "false_alarm_rate": count / benign_total if benign_total else 0.0,
            "cases": detector_fp_cases[detector],
        })

    # Evasion resistance.
    evasion_rows = []
    for row in evasion_results:
        caught_as_expected = row["label"] in row["predicted_attacks"]
        evasion_rows.append({
            "case_id": row["case_id"],
            "family": row["family"],
            "variant": row["variant"],
            "expected": row["label"],
            "caught_as_expected": caught_as_expected,
            "action": row["action"],
            "risk_score": row["risk_score"],
            "predicted_attacks": row["predicted_attacks"],
            "rules": row["rules"],
        })
    evasion_rate = (
        sum(1 for r in evasion_rows if r["caught_as_expected"]) / len(evasion_rows)
        if evasion_rows else 0.0
    )

    return {
        "detection_performance": {
            "n_benign": benign_total,
            "n_malicious": len(malicious_results),
            "n_total": len(combined),
            "classes": performance,
            "macro_precision": macro_precision,
            "macro_recall": macro_recall,
            "macro_f1": macro_f1,
            "micro_tp": overall_tp,
            "micro_fp": overall_fp,
            "micro_fn": overall_fn,
            "micro_tn": overall_tn,
        },
        "false_positive_analysis": {
            "n_benign": benign_total,
            "n_benign_blocked": len(benign_blocked),
            "aggregate_false_positive_rate": aggregate_fpr,
            "blocked_case_ids": [r["case_id"] for r in benign_blocked],
            "per_detector": detector_fp_table,
        },
        "evasion_resistance": {
            "n_cases": len(evasion_rows),
            "caught_as_expected": sum(1 for r in evasion_rows if r["caught_as_expected"]),
            "detection_rate": evasion_rate,
            "cases": evasion_rows,
        },
        "raw": {
            "benign": benign_results,
            "malicious": malicious_results,
            "evasion": evasion_results,
        },
    }


def percentile(values: Sequence[float], p: float) -> float:
    if not values:
        return float("nan")
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * p
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return ordered[low]
    weight = rank - low
    return ordered[low] * (1 - weight) + ordered[high] * weight


def stats(values: Sequence[float]) -> Dict[str, float]:
    if not values:
        return {}
    return {
        "n": len(values),
        "mean_ms": statistics.mean(values) * 1000,
        "median_ms": statistics.median(values) * 1000,
        "p95_ms": percentile(values, 0.95) * 1000,
        "p99_ms": percentile(values, 0.99) * 1000,
        "min_ms": min(values) * 1000,
        "max_ms": max(values) * 1000,
    }


def make_url(base_url: str, case: EvaluationCase) -> str:
    parts = urlsplit(base_url.rstrip("/") + "/")
    path = case.request.path
    query = dict(case.request.GET)
    if case.request.method == "GET":
        # For live tests, query params are sent as URL parameters.
        encoded_query = urlencode(query)
        return urlunsplit((parts.scheme, parts.netloc, path, encoded_query, ""))
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def http_request(
    url: str,
    case: EvaluationCase,
    timeout: float = 10.0,
) -> Tuple[int, float, str]:
    headers = {
        "User-Agent": BROWSER_UA,
        "Accept": "*/*",
    }
    headers.update(dict(case.request.headers.items()))

    data = None
    if case.request.method != "GET":
        data = case.request.body or None
        if not data and case.request.POST:
            data = urlencode(case.request.POST).encode("utf-8")
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

    request = Request(
        url,
        method=case.request.method,
        headers=headers,
        data=data,
    )

    started = time.perf_counter()
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read(512)
            status = int(response.status)
    except HTTPError as exc:
        # HTTP errors are still valid latency observations.
        body = exc.read(512) if hasattr(exc, "read") else b""
        status = int(exc.code)
    except (URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"HTTP request failed for {url}: {exc}") from exc
    elapsed = time.perf_counter() - started
    return status, elapsed, body.decode("utf-8", errors="replace")


def measure_live_latency(
    proxy_url: str,
    origin_url: str,
    *,
    benign_iterations: int = 20,
    malicious_iterations: int = 10,
) -> Dict[str, Any]:
    benign_case = req(
        "LAT-BENIGN", "benign",
        path="/",
        ip_suffix="91",
    )
    malicious_case = req(
        "LAT-MALICIOUS", "sql_injection",
        path="/",
        query_params={"id": "1 UNION SELECT username, password FROM users"},
        ip_suffix="92",
    )

    direct_times: List[float] = []
    proxy_benign_times: List[float] = []
    proxy_malicious_times: List[float] = []

    direct_statuses = Counter()
    proxy_benign_statuses = Counter()
    proxy_malicious_statuses = Counter()

    # Direct origin: benign
    for _ in range(benign_iterations):
        status, elapsed, _ = http_request(
            make_url(origin_url, benign_case),
            benign_case,
        )
        direct_times.append(elapsed)
        direct_statuses[status] += 1

    # Proxy: benign
    for _ in range(benign_iterations):
        status, elapsed, _ = http_request(
            make_url(proxy_url, benign_case),
            benign_case,
        )
        proxy_benign_times.append(elapsed)
        proxy_benign_statuses[status] += 1

    # Proxy: malicious. Use the same request, because the attack is
    # supposed to be representative and the timing should be measured
    # at the actual proxy boundary.
    for _ in range(malicious_iterations):
        status, elapsed, _ = http_request(
            make_url(proxy_url, malicious_case),
            malicious_case,
        )
        proxy_malicious_times.append(elapsed)
        proxy_malicious_statuses[status] += 1

    direct = stats(direct_times)
    proxy_benign = stats(proxy_benign_times)
    proxy_malicious = stats(proxy_malicious_times)

    mean_overhead_ms = proxy_benign["mean_ms"] - direct["mean_ms"]
    relative_overhead = (
        mean_overhead_ms / direct["mean_ms"]
        if direct["mean_ms"]
        else float("nan")
    )

    return {
        "proxy_url": proxy_url,
        "origin_url": origin_url,
        "direct_origin_benign": direct | {"statuses": dict(direct_statuses)},
        "proxy_benign": proxy_benign | {"statuses": dict(proxy_benign_statuses)},
        "proxy_malicious": proxy_malicious | {"statuses": dict(proxy_malicious_statuses)},
        "benign_mean_overhead_ms": mean_overhead_ms,
        "benign_relative_overhead": relative_overhead,
    }


def compare_frameworks(
    django_proxy_url: str,
    flask_proxy_url: str,
    cases: Sequence[EvaluationCase],
) -> Dict[str, Any]:
    rows = []
    exact = 0

    for case in cases:
        django_status, _, _ = http_request(
            make_url(django_proxy_url, case), case
        )
        flask_status, _, _ = http_request(
            make_url(flask_proxy_url, case), case
        )

        django_blocked = django_status == 403
        flask_blocked = flask_status == 403
        same = django_blocked == flask_blocked
        exact += int(same)

        rows.append({
            "case_id": case.case_id,
            "expected_label": case.label,
            "django_status": django_status,
            "flask_status": flask_status,
            "django_blocked": django_blocked,
            "flask_blocked": flask_blocked,
            "same_verdict": same,
        })

    consistency = exact / len(rows) if rows else 0.0
    return {
        "n_cases": len(rows),
        "matching_verdicts": exact,
        "consistency_rate": consistency,
        "cases": rows,
    }


def fmt_pct(value: float) -> str:
    return f"{value * 100:.2f}%"


def fmt_ms(value: float) -> str:
    return f"{value:.3f} ms"


def make_report(results: Dict[str, Any]) -> str:
    lines: List[str] = []
    perf = results["detection_performance"]
    fp = results["false_positive_analysis"]
    ev = results["evasion_resistance"]

    lines.append("WAF EVALUATION REPORT")
    lines.append("=" * 80)
    lines.append("")

    lines.append("V-A. Detection Performance")
    lines.append("-" * 80)
    lines.append(
        f"Evaluation corpus: {perf['n_total']} requests "
        f"({perf['n_malicious']} malicious, {perf['n_benign']} benign)."
    )
    lines.append("")
    lines.append(
        f"{'Class':<22}{'TP':>5}{'FP':>5}{'FN':>5}"
        f"{'Precision':>12}{'Recall':>12}{'F1':>12}"
    )
    for row in perf["classes"]:
        lines.append(
            f"{row['attack_class']:<22}{row['tp']:>5}{row['fp']:>5}{row['fn']:>5}"
            f"{fmt_pct(row['precision']):>12}{fmt_pct(row['recall']):>12}"
            f"{fmt_pct(row['f1']):>12}"
        )
    lines.append("")
    lines.append(
        "Macro-average: "
        f"precision={fmt_pct(perf['macro_precision'])}, "
        f"recall={fmt_pct(perf['macro_recall'])}, "
        f"F1={fmt_pct(perf['macro_f1'])}."
    )
    lines.append("")

    lines.append("V-B. False-Positive Analysis")
    lines.append("-" * 80)
    lines.append(
        f"Benign requests incorrectly blocked: "
        f"{fp['n_benign_blocked']}/{fp['n_benign']} "
        f"({fmt_pct(fp['aggregate_false_positive_rate'])})."
    )
    if fp["blocked_case_ids"]:
        lines.append("Blocked benign case IDs: " + ", ".join(fp["blocked_case_ids"]))
    else:
        lines.append("No benign case was blocked.")
    lines.append("")
    if fp["per_detector"]:
        lines.append(f"{'Detector':<30}{'False alarms':>15}{'Rate':>12}")
        for row in fp["per_detector"]:
            lines.append(
                f"{row['detector']:<30}{row['false_alarm_cases']:>15}"
                f"{fmt_pct(row['false_alarm_rate']):>12}"
            )
    else:
        lines.append("No detector generated an alert on the benign corpus.")
    lines.append("")

    lines.append("V-C. Evasion Resistance")
    lines.append("-" * 80)
    lines.append(
        f"Encoded/obfuscated cases caught with the expected class: "
        f"{ev['caught_as_expected']}/{ev['n_cases']} "
        f"({fmt_pct(ev['detection_rate'])})."
    )
    lines.append("")
    lines.append(
        f"{'Case':<8}{'Family':<10}{'Variant':<28}{'Caught':>10}{'Action':>10}"
    )
    for row in ev["cases"]:
        lines.append(
            f"{row['case_id']:<8}{row['family']:<10}{row['variant']:<28}"
            f"{str(row['caught_as_expected']):>10}{row['action']:>10}"
        )
    lines.append("")

    latency = results.get("latency")
    if latency:
        lines.append("V-D. Latency Overhead")
        lines.append("-" * 80)
        for name, key in [
            ("Direct origin, benign", "direct_origin_benign"),
            ("Nginx + WAF, benign", "proxy_benign"),
            ("Nginx + WAF, malicious", "proxy_malicious"),
        ]:
            row = latency[key]
            lines.append(
                f"{name}: mean={fmt_ms(row['mean_ms'])}, "
                f"median={fmt_ms(row['median_ms'])}, "
                f"p95={fmt_ms(row['p95_ms'])}, "
                f"p99={fmt_ms(row['p99_ms'])} "
                f"(n={row['n']})."
            )
        lines.append(
            f"Mean benign overhead: {fmt_ms(latency['benign_mean_overhead_ms'])} "
            f"({fmt_pct(latency['benign_relative_overhead'])} relative to direct origin)."
        )
        lines.append("")
    else:
        lines.append("V-D. Latency Overhead")
        lines.append("-" * 80)
        lines.append("Not run. Supply --live, --proxy-url, and --origin-url.")
        lines.append("")

    cross = results.get("cross_framework")
    if cross:
        lines.append("V-E. Cross-Framework Portability")
        lines.append("-" * 80)
        lines.append(
            f"Identical request set: {cross['n_cases']} cases. "
            f"Matching block/allow verdicts: {cross['matching_verdicts']}/"
            f"{cross['n_cases']} ({fmt_pct(cross['consistency_rate'])})."
        )
        mismatches = [r for r in cross["cases"] if not r["same_verdict"]]
        if mismatches:
            lines.append("Mismatches:")
            for row in mismatches:
                lines.append(
                    f"  {row['case_id']}: "
                    f"Django={row['django_status']}, Flask={row['flask_status']}"
                )
        else:
            lines.append("No verdict mismatches were observed.")
        lines.append("")
    else:
        lines.append("V-E. Cross-Framework Portability")
        lines.append("-" * 80)
        lines.append(
            "Not run. Supply --cross-framework with both proxy URLs "
            "to exercise Django and Flask origins."
        )
        lines.append("")

    lines.append("PAPER-READY PARAGRAPHS")
    lines.append("=" * 80)
    lines.append("")
    lines.append(
        "Detection Performance: "
        f"The evaluation corpus contained {perf['n_total']} labeled requests, "
        f"including {perf['n_malicious']} malicious and {perf['n_benign']} benign requests. "
        f"Across the evaluated attack classes, the macro-averaged precision was "
        f"{fmt_pct(perf['macro_precision'])}, recall was {fmt_pct(perf['macro_recall'])}, "
        f"and F1-score was {fmt_pct(perf['macro_f1'])}."
    )
    lines.append(
        "False-Positive Analysis: "
        f"The WAF incorrectly blocked {fp['n_benign_blocked']} of {fp['n_benign']} "
        f"benign requests, giving an aggregate false-positive rate of "
        f"{fmt_pct(fp['aggregate_false_positive_rate'])}."
    )
    lines.append(
        "Evasion Resistance: "
        f"The encoded/obfuscated test set contained {ev['n_cases']} cases, "
        f"of which {ev['caught_as_expected']} were detected with the expected "
        f"attack class, corresponding to a detection rate of {fmt_pct(ev['detection_rate'])}."
    )
    if latency:
        lines.append(
            "Latency Overhead: "
            f"For benign traffic, the direct-origin mean latency was "
            f"{fmt_ms(latency['direct_origin_benign']['mean_ms'])}, compared with "
            f"{fmt_ms(latency['proxy_benign']['mean_ms'])} through Nginx and the WAF, "
            f"for a mean overhead of {fmt_ms(latency['benign_mean_overhead_ms'])}. "
            f"Malicious requests through the WAF had mean latency "
            f"{fmt_ms(latency['proxy_malicious']['mean_ms'])}."
        )
    if cross:
        lines.append(
            "Cross-Framework Portability: "
            f"The same {cross['n_cases']}-request corpus produced matching "
            f"allow/block verdicts for the Django and Flask origins in "
            f"{cross['matching_verdicts']} cases "
            f"({fmt_pct(cross['consistency_rate'])})."
        )

    lines.append("")
    lines.append(
        "Do not change the Results sections to claim measurements that the "
        "script did not actually run. Human beings invented papers; apparently "
        "we also invented the ancient ritual of typing [to be inserted] and "
        "hoping for the best."
    )

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Measure the standalone WAF for paper Section V."
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Run live HTTP latency measurement.",
    )
    parser.add_argument(
        "--proxy-url",
        default="http://127.0.0.1:8080",
        help="WAF/Nginx URL for live testing.",
    )
    parser.add_argument(
        "--origin-url",
        default="http://127.0.0.1:8000",
        help="Direct origin URL for latency comparison.",
    )
    parser.add_argument(
        "--benign-iterations",
        type=int,
        default=20,
        help="Number of benign timing requests per configuration.",
    )
    parser.add_argument(
        "--malicious-iterations",
        type=int,
        default=10,
        help="Number of malicious timing requests through the proxy.",
    )
    parser.add_argument(
        "--cross-framework",
        action="store_true",
        help="Compare two proxy endpoints protecting different origins.",
    )
    parser.add_argument(
        "--django-proxy-url",
        default="http://127.0.0.1:8080",
        help="Proxy URL whose upstream is Django.",
    )
    parser.add_argument(
        "--flask-proxy-url",
        default="http://127.0.0.1:8081",
        help="Second proxy URL whose upstream is Flask.",
    )
    parser.add_argument(
        "--cross-cases",
        type=int,
        default=0,
        help="Number of labeled core cases to send in cross-framework test. "
             "0 means all benign + malicious cases.",
    )
    args = parser.parse_args()

    benign_cases = build_benign_cases()
    malicious_cases = build_malicious_cases()
    evasion_cases = build_evasion_cases()

    results = run_core_evaluation(
        benign_cases,
        malicious_cases,
        evasion_cases,
    )

    if args.live:
        print("Running live latency benchmark...")
        results["latency"] = measure_live_latency(
            args.proxy_url,
            args.origin_url,
            benign_iterations=args.benign_iterations,
            malicious_iterations=args.malicious_iterations,
        )

    if args.cross_framework:
        cross_cases = benign_cases + malicious_cases
        if args.cross_cases > 0:
            cross_cases = cross_cases[:args.cross_cases]
        print("Running cross-framework portability benchmark...")
        results["cross_framework"] = compare_frameworks(
            args.django_proxy_url,
            args.flask_proxy_url,
            cross_cases,
        )

    report = make_report(results)

    RESULTS_JSON.write_text(
        json.dumps(results, indent=2, default=str),
        encoding="utf-8",
    )
    REPORT_TXT.write_text(report, encoding="utf-8")

    print("")
    print(report)
    print("")
    print(f"Saved machine-readable results to: {RESULTS_JSON}")
    print(f"Saved paper-ready report to:       {REPORT_TXT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
