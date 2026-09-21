from flask import Flask, request

app = Flask(__name__)


# Accept basically every path and the HTTP methods used by our evaluation
# corpus. The endpoint itself deliberately does almost nothing because we're
# testing the WAF's verdict, not Flask's application logic.
@app.route(
    "/",
    defaults={"path": ""},
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
)
@app.route(
    "/<path:path>",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
)
def catch_all(path):
    return {
        "status": "ok",
        "framework": "flask",
        "path": request.path
    }, 200


if __name__ == "__main__":
    # Django already occupies port 8000, so Flask gets its own origin port.
    app.run(host="127.0.0.1", port=5000, debug=False)