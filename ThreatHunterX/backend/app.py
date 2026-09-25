import os

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request

from cache import TTLCache
from detect import detect_input_type
from normalize import NORMALIZERS
from ratelimit import SlidingWindowLimiter
from vt_client import VTError, fetch_domain, fetch_file, fetch_ip, fetch_url

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BACKEND_DIR)

load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

API_KEY = os.environ.get("VT_API_KEY", "").strip()

app = Flask(
    __name__,
    template_folder=os.path.join(PROJECT_ROOT, "frontend", "templates"),
    static_folder=os.path.join(PROJECT_ROOT, "frontend", "static"),
)

cache = TTLCache(ttl_seconds=300)
limiter = SlidingWindowLimiter(max_calls=4, period_seconds=60)

FETCHERS = {
    "ip": fetch_ip,
    "domain": fetch_domain,
    "url": fetch_url,
    "file": fetch_file,
}

MAX_QUERY_LENGTH = 2048


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/lookup", methods=["POST"])
def lookup():
    if not API_KEY:
        return jsonify(error="Server is missing VT_API_KEY. Add it to your .env file and restart."), 500

    payload = request.get_json(silent=True) or {}
    raw_query = payload.get("query")
    if not isinstance(raw_query, str):
        return jsonify(error="Missing 'query' field."), 400
    raw_query = raw_query[:MAX_QUERY_LENGTH]

    kind, value = detect_input_type(raw_query)
    if kind is None:
        return (
            jsonify(
                error="Input doesn't match a URL, IP address, domain, or file hash (MD5/SHA-1/SHA-256)."
            ),
            400,
        )

    cache_key = f"{kind}:{value}"
    cached = cache.get(cache_key)
    if cached is not None:
        return jsonify(type=kind, id=value, data=cached, cached=True)

    allowed, retry_after = limiter.allow()
    if not allowed:
        return (
            jsonify(
                error=f"Local rate limit reached (VirusTotal free tier: 4 requests/min). Try again in {retry_after}s."
            ),
            429,
        )

    try:
        raw = FETCHERS[kind](API_KEY, value)
    except VTError as exc:
        return jsonify(error=exc.message), exc.status_code

    normalized = NORMALIZERS[kind](raw)
    cache.set(cache_key, normalized)
    return jsonify(type=kind, id=value, data=normalized, cached=False)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
