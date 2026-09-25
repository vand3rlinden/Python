"""Detects whether a raw search string is a file hash, IP address, URL, or domain."""

import ipaddress
import re
from urllib.parse import urlparse

_MD5_RE = re.compile(r"^[A-Fa-f0-9]{32}$")
_SHA1_RE = re.compile(r"^[A-Fa-f0-9]{40}$")
_SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)


def detect_input_type(raw):
    """Returns (kind, normalized_value) where kind is one of
    'file', 'ip', 'url', 'domain', or (None, None) if nothing matches."""
    value = (raw or "").strip()
    if not value:
        return None, None

    if _MD5_RE.match(value) or _SHA1_RE.match(value) or _SHA256_RE.match(value):
        return "file", value.lower()

    try:
        ipaddress.ip_address(value)
        return "ip", value
    except ValueError:
        pass

    if value.lower().startswith(("http://", "https://")):
        parsed = urlparse(value)
        if parsed.netloc:
            return "url", value
        return None, None

    candidate = value.rstrip(".").lower()
    if "." in candidate and _DOMAIN_RE.match(candidate):
        return "domain", candidate

    return None, None
