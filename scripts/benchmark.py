"""
Benchmarks detector throughput - how many requests/sec the current
DETECTOR_REGISTRY can process. Gives Member 1 real numbers to reason
about middleware overhead and blocking thresholds.

Run with: python manage.py shell < scripts/benchmark.py
"""
import time
import statistics

from django.test import RequestFactory

from waf.detectors import DETECTOR_REGISTRY

rf = RequestFactory()


def build_mixed_requests(n: int = 200):
    """Alternates clean and malicious requests, similar to real traffic."""
    requests = []
    for i in range(n):
        if i % 3 == 0:
            requests.append(rf.get("/blog/search/", {"q": "1 UNION SELECT * FROM users"}))
        elif i % 3 == 1:
            requests.append(rf.get("/blog/comment/", {"text": "<script>alert(1)</script>"}))
        else:
            requests.append(rf.get("/blog/", {"page": str(i)}))
    return requests


def run_benchmark(n: int = 200):
    requests = build_mixed_requests(n)
    durations = []

    start_total = time.perf_counter()
    for request in requests:
        start = time.perf_counter()
        for detect in DETECTOR_REGISTRY:
            detect(request)
        durations.append(time.perf_counter() - start)
    total_time = time.perf_counter() - start_total

    durations_ms = [d * 1000 for d in durations]
    print(f"Requests processed: {n}")
    print(f"Total time: {total_time:.3f}s")
    print(f"Requests/sec: {n / total_time:.1f}")
    print(f"Avg per-request latency: {statistics.mean(durations_ms):.2f} ms")
    print(f"p95 latency: {sorted(durations_ms)[int(n * 0.95)]:.2f} ms")
    print(f"Max latency: {max(durations_ms):.2f} ms")


if __name__ == "__main__":
    run_benchmark()