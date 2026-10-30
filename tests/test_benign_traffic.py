"""
test_benign_traffic.py

False-positive guard. A WAF that blocks everything would pass every
attack test, so this file checks that realistic legitimate traffic is
allowed AND stays comfortably under the block threshold.
"""

import unittest

from waf_core.constants import ALLOW, DEFAULT_BLOCK_THRESHOLD

from tests.helpers import add_cases, inspect

JSON = {"Content-Type": "application/json"}

# (case_id, request kwargs)
BENIGN_REQUESTS = [
    ("home_page", dict(path="/")),
    ("product_listing_with_paging", dict(path="/products", query_params={"page": "2", "sort": "price", "dir": "asc"})),
    ("search_with_apostrophe", dict(path="/search", query_params={"q": "O'Brien's bakery"})),
    ("search_with_ampersand", dict(path="/search", query_params={"q": "Tom & Jerry"})),
    ("search_with_sql_words_in_prose", dict(path="/search", query_params={"q": "please select a size from the list"})),
    ("search_with_union_word", dict(path="/search", query_params={"q": "european union members"})),
    ("email_with_plus_tag", dict(path="/signup", method="POST", form_data={"email": "alice+news@example.com"})),
    ("redirect_url_parameter", dict(path="/login", query_params={"next": "https://example.com/a/b?c=d&e=f"})),
    ("unicode_names", dict(path="/profile", method="POST", form_data={"name": "Zo\u00eb M\u00fcller \u65e5\u672c\u8a9e"})),
    ("long_free_text", dict(path="/comment", method="POST", form_data={"body": "Lorem ipsum dolor sit amet. " * 150})),
    ("date_range_with_dashes", dict(path="/report", query_params={"range": "2024-05-01 -- 2024-06-01"})),
    ("math_expression_text", dict(path="/calc", query_params={"expr": "3 < 5 and 7 > 2"})),
    ("json_post_nested", dict(path="/api/posts", method="POST", headers=JSON, body='{"title": "Hello", "tags": ["a", "b"], "meta": {"draft": false}}')),
    ("json_post_with_quotes_and_unicode", dict(path="/api/posts", method="POST", headers=JSON, body='{"title": "She said \\"hi\\" \\u2014 ok"}')),
    ("session_cookies", dict(path="/dashboard", cookies={"sessionid": "9f8e7d6c5b4a", "csrftoken": "Qq1Ww2Ee3", "theme": "dark"})),
    ("base64_cookie", dict(path="/", cookies={"token": "dGVzdC10b2tlbi12YWx1ZQ=="})),
    ("typical_browser_headers", dict(path="/", headers={
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Referer": "https://example.com/products?id=5",
    })),
    ("static_asset_path", dict(path="/static/js/app.min.js")),
    ("versioned_api_path", dict(path="/api/v2/users/42/orders")),
    ("png_upload", dict(path="/upload", method="POST", files={"photo": {"name": "cat.png", "content_type": "image/png"}})),
    ("put_request", dict(path="/api/items/3", method="PUT", headers=JSON, body='{"qty": 2}')),
    ("delete_request", dict(path="/api/items/3", method="DELETE")),
    ("options_preflight", dict(path="/api/items", method="OPTIONS", headers={"Origin": "https://app.example.com"})),
    ("head_request", dict(path="/", method="HEAD")),
    ("code_discussion_text", dict(path="/forum", method="POST", form_data={"body": "In Python use a or b; in shell a || b."})),
]


def _benign(self, kwargs):
    decision = inspect(**kwargs)
    self.assertEqual(decision.action, ALLOW, msg=f"{decision.rules} {decision.reasons}")
    self.assertLess(decision.risk_score, DEFAULT_BLOCK_THRESHOLD)


class TestBenignTraffic(unittest.TestCase):
    pass


add_cases(TestBenignTraffic, "test_allows", BENIGN_REQUESTS, _benign)


class TestBenignBurst(unittest.TestCase):
    def test_hundred_distinct_clean_requests_all_pass(self):
        blocked = [
            i for i in range(100)
            if inspect(path=f"/items/{i}", query_params={"n": str(i)}).action != ALLOW
        ]
        self.assertEqual(blocked, [])


if __name__ == "__main__":
    unittest.main()
