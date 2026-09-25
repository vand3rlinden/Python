"""Reduces raw VirusTotal JSON down to a fixed, known-safe set of fields.

Everything VirusTotal returns is treated as untrusted: values are coerced to
plain str/int/float/bool/list/dict of those, and strings are length-capped.
Nothing here is HTML-escaped because the frontend never uses innerHTML for
this data - it only ever assigns it via textContent.
"""

MAX_ENGINES = 200
MAX_TAGS = 30
MAX_CATEGORIES = 30
MAX_NAMES = 20
MAX_STR = 300


def _s(value, max_len=MAX_STR):
    if value is None:
        return None
    return str(value)[:max_len]


def _int(value, default=0):
    return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else default


def _ts(value):
    return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _stats(attrs):
    stats = attrs.get("last_analysis_stats") or {}
    if not isinstance(stats, dict):
        stats = {}
    return {
        "malicious": _int(stats.get("malicious")),
        "suspicious": _int(stats.get("suspicious")),
        "harmless": _int(stats.get("harmless")),
        "undetected": _int(stats.get("undetected")),
        "timeout": _int(stats.get("timeout")),
    }


def _engine_results(attrs):
    results = attrs.get("last_analysis_results") or {}
    if not isinstance(results, dict):
        return []

    out = []
    for engine, info in list(results.items())[:MAX_ENGINES]:
        if not isinstance(info, dict):
            continue
        out.append(
            {
                "engine": _s(engine, 100) or "unknown",
                "category": _s(info.get("category"), 50) or "unknown",
                "result": _s(info.get("result"), 150),
                "method": _s(info.get("method"), 50),
            }
        )

    priority = {"malicious": 0, "suspicious": 1}
    out.sort(key=lambda r: (priority.get(r["category"], 2), r["engine"].lower()))
    return out


def _tags(attrs):
    tags = attrs.get("tags") or []
    if not isinstance(tags, list):
        return []
    return [_s(t, 60) for t in tags[:MAX_TAGS] if isinstance(t, (str, int, float))]


def _categories(attrs):
    cats = attrs.get("categories") or {}
    if not isinstance(cats, dict):
        return {}
    return {_s(k, 60): _s(v, 150) for k, v in list(cats.items())[:MAX_CATEGORIES]}


def _common(attrs):
    return {
        "stats": _stats(attrs),
        "reputation": _int(attrs.get("reputation")),
        "last_analysis_date": _ts(attrs.get("last_analysis_date")),
        "engines": _engine_results(attrs),
        "tags": _tags(attrs),
        "categories": _categories(attrs),
    }


def normalize_ip(raw):
    attrs = (raw.get("data") or {}).get("attributes") or {}
    out = _common(attrs)
    out.update(
        {
            "country": _s(attrs.get("country"), 100),
            "continent": _s(attrs.get("continent"), 50),
            "asn": _int(attrs.get("asn"), None) if attrs.get("asn") is not None else None,
            "as_owner": _s(attrs.get("as_owner"), 200),
            "network": _s(attrs.get("network"), 100),
            "regional_internet_registry": _s(attrs.get("regional_internet_registry"), 20),
        }
    )
    return out


def normalize_domain(raw):
    attrs = (raw.get("data") or {}).get("attributes") or {}
    out = _common(attrs)

    records = attrs.get("last_dns_records") or []
    dns = {"A": [], "MX": [], "NS": [], "TXT": []}
    if isinstance(records, list):
        for rec in records:
            if not isinstance(rec, dict):
                continue
            rtype = rec.get("type")
            if rtype in dns:
                dns[rtype].append(_s(rec.get("value"), 300) or "")

    whois_raw = attrs.get("whois")
    whois_summary = None
    if isinstance(whois_raw, str) and whois_raw:
        whois_summary = whois_raw[:1500] + ("… (truncated)" if len(whois_raw) > 1500 else "")

    out.update(
        {
            "registrar": _s(attrs.get("registrar"), 150),
            "creation_date": _ts(attrs.get("creation_date")),
            "last_update_date": _ts(attrs.get("last_update_date")),
            "whois_summary": whois_summary,
            "dns_records": dns,
        }
    )
    return out


def normalize_url(raw):
    attrs = (raw.get("data") or {}).get("attributes") or {}
    out = _common(attrs)
    out.update(
        {
            "final_url": _s(attrs.get("last_final_url") or attrs.get("url"), 2048),
            "http_response_code": _int(attrs.get("last_http_response_code"), None)
            if attrs.get("last_http_response_code") is not None
            else None,
            "title": _s(attrs.get("title"), 300),
        }
    )
    return out


def normalize_file(raw):
    attrs = (raw.get("data") or {}).get("attributes") or {}
    out = _common(attrs)

    names = attrs.get("names") or []
    clean_names = [_s(n, 200) for n in names[:MAX_NAMES]] if isinstance(names, list) else []

    out.update(
        {
            "type_description": _s(attrs.get("type_description"), 150),
            "size": _int(attrs.get("size"), None) if attrs.get("size") is not None else None,
            "names": clean_names,
            "md5": _s(attrs.get("md5"), 32),
            "sha1": _s(attrs.get("sha1"), 40),
            "sha256": _s(attrs.get("sha256"), 64),
            "first_submission_date": _ts(attrs.get("first_submission_date")),
            "last_submission_date": _ts(attrs.get("last_submission_date")),
        }
    )
    return out


NORMALIZERS = {
    "ip": normalize_ip,
    "domain": normalize_domain,
    "url": normalize_url,
    "file": normalize_file,
}
