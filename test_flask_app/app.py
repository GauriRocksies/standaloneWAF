"""
test_flask_app/app.py

Deliberately tiny. Exists only to prove:

    WAF -> Flask

works exactly like

    WAF -> Django

without touching the WAF's detection logic — i.e. the WAF is
framework-independent. Every request that reaches this app is logged
loudly so it's obvious, in the test output, whether a "blocked"
request actually got here (it shouldn't).
"""

import logging

from flask import Flask, request

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("test_flask_app")

app = Flask(__name__)


@app.route("/", methods=["GET"])
def index():
    logger.info("FLASK RECEIVED REQUEST: GET /")
    return "Hello from Flask origin.\n"


@app.route("/submit", methods=["POST"])
def submit():
    logger.info("FLASK RECEIVED REQUEST: POST /submit body=%r", request.get_data())
    return "Flask received your POST.\n"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)