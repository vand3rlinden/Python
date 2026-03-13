import os
import requests
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
IPINFO_API_KEY = os.getenv("IPINFO_API_KEY", "")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan-url", methods=["POST"])
def scan_url():
    data = request.get_json()
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400
    if not VIRUSTOTAL_API_KEY:
        return jsonify({"error": "VirusTotal API key not configured"}), 500

    api_url = "https://www.virustotal.com/vtapi/v2/url/report"
    params = {"apikey": VIRUSTOTAL_API_KEY, "resource": url}
    try:
        response = requests.get(api_url, params=params, timeout=15)
        if response.status_code == 200:
            return jsonify({"ok": True, "data": response.json()})
        return jsonify({"error": f"VirusTotal returned {response.status_code}: {response.text}"}), response.status_code
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan-hash", methods=["POST"])
def scan_hash():
    data = request.get_json()
    file_hash = data.get("hash", "").strip()
    if not file_hash:
        return jsonify({"error": "File hash is required"}), 400
    if not VIRUSTOTAL_API_KEY:
        return jsonify({"error": "VirusTotal API key not configured"}), 500

    api_url = "https://www.virustotal.com/vtapi/v2/file/report"
    params = {"apikey": VIRUSTOTAL_API_KEY, "resource": file_hash}
    try:
        response = requests.get(api_url, params=params, timeout=15)
        if response.status_code == 200:
            return jsonify({"ok": True, "data": response.json()})
        return jsonify({"error": f"VirusTotal returned {response.status_code}: {response.text}"}), response.status_code
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan-ip-abuse", methods=["POST"])
def scan_ip_abuse():
    data = request.get_json()
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "IP address is required"}), 400
    if not ABUSEIPDB_API_KEY:
        return jsonify({"error": "AbuseIPDB API key not configured"}), 500

    api_url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        response = requests.get(api_url, headers=headers, params=params, timeout=15)
        if response.status_code == 200:
            return jsonify({"ok": True, "data": response.json().get("data", {})})
        return jsonify({"error": f"AbuseIPDB returned {response.status_code}: {response.text}"}), response.status_code
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan-ip-ipinfo", methods=["POST"])
def scan_ip_ipinfo():
    data = request.get_json()
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "IP address is required"}), 400
    if not IPINFO_API_KEY:
        return jsonify({"error": "IPInfo API key not configured"}), 500

    api_url = f"https://api.ipinfo.io/lite/{ip}"
    params = {"token": IPINFO_API_KEY}
    try:
        response = requests.get(api_url, params=params, timeout=15)
        if response.status_code == 200:
            return jsonify({"ok": True, "data": response.json()})
        return jsonify({"error": f"IPInfo returned {response.status_code}: {response.text}"}), response.status_code
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True, port=5000)
