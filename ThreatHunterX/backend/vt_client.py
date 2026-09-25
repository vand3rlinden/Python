"""Thin client for the VirusTotal v3 API. Only used server-side; the key
never leaves this module's callers."""

import base64

import requests

VT_BASE = "https://www.virustotal.com/api/v3"
TIMEOUT_SECONDS = 15


class VTError(Exception):
    def __init__(self, status_code, message):
        super().__init__(message)
        self.status_code = status_code
        self.message = message


def _headers(api_key):
    return {"x-apikey": api_key, "Accept": "application/json"}


def _get(endpoint, api_key):
    url = f"{VT_BASE}{endpoint}"
    try:
        resp = requests.get(url, headers=_headers(api_key), timeout=TIMEOUT_SECONDS)
    except requests.RequestException as exc:
        raise VTError(502, f"Could not reach VirusTotal: {exc}") from exc

    if resp.status_code == 200:
        try:
            return resp.json()
        except ValueError as exc:
            raise VTError(502, "VirusTotal returned an unreadable response.") from exc

    if resp.status_code == 404:
        raise VTError(404, "No results found for this indicator on VirusTotal.")
    if resp.status_code == 401:
        raise VTError(401, "VirusTotal rejected the API key. Check VT_API_KEY in your .env file.")
    if resp.status_code == 429:
        raise VTError(429, "VirusTotal rate limit reached (free tier: 4 requests/min). Wait a minute and try again.")

    raise VTError(resp.status_code, f"VirusTotal returned an unexpected error ({resp.status_code}).")


def url_id(url):
    """VT v3 requires the base64url encoding of the URL, without padding."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").strip("=")


def fetch_ip(api_key, ip):
    return _get(f"/ip_addresses/{ip}", api_key)


def fetch_domain(api_key, domain):
    return _get(f"/domains/{domain}", api_key)


def fetch_url(api_key, url):
    return _get(f"/urls/{url_id(url)}", api_key)


def fetch_file(api_key, file_hash):
    return _get(f"/files/{file_hash}", api_key)
