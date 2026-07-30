"""
Generates fake attack requests (using Django's RequestFactory, same
pattern Member 2 used in their manual verification) and runs them
through Member 2's DETECTOR_REGISTRY. Useful for:
  - smoke-testing detectors end-to-end without needing middleware
  - feeding realistic traffic into the throttling/rate limiter
  - populating the dashboard with sample data for demos

Run with: python manage.py shell < scripts/fake_attack_generator.py
(or adapt into a management command).
"""
from django.test import RequestFactory

from waf.detectors import DETECTOR_REGISTRY

rf = RequestFactory()

SAMPLE_ATTACKS = [
    ("GET", "/blog/search/", {"q": "1 UNION SELECT username,password FROM auth_user"}),
    ("GET", "/blog/post/", {"id": "1 OR 1=1"}),
    ("GET", "/blog/comment/", {"text": "<script>alert(document.cookie)</script>"}),
    ("GET", "/blog/comment/", {"text": "<img src=x onerror=alert(1)>"}),
    ("GET", "/files/", {"path": "../../../../etc/passwd"}),
    ("GET", "/files/", {"path": "%2e%2e%2f%2e%2e%2fetc%2fpasswd"}),
    ("GET", "/tools/ping/", {"host": "127.0.0.1; cat /etc/passwd"}),
    ("GET", "/tools/ping/", {"host": "127.0.0.1 && whoami"}),
]


def generate_and_run(count_per_type: int = 1):
    results = []
    for method, path, params in SAMPLE_ATTACKS:
        for _ in range(count_per_type):
            request = rf.get(path, params) if method == "GET" else rf.post(path, params)
            for detect in DETECTOR_REGISTRY:
                result = detect(request)
                if result:
                    results.append({"path": path, "params": params, "result": result})
    return results


if __name__ == "__main__":
    hits = generate_and_run()
    print(f"Generated attacks, {len(hits)} detector hits:")
    for h in hits:
        print(f"  [{h['result']['detector']}] {h['result']['rule']} -> {h['path']} {h['params']}")