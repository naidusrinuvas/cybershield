"""
Website Security Checker
Checks HTTP status, HTTPS usage, security headers, server info, robots.txt, sitemap.xml.
"""

import requests

SECURITY_HEADERS = {
    "Content-Security-Policy": "CSP",
    "Strict-Transport-Security": "HSTS",
    "X-Frame-Options": "X-Frame-Options",
    "X-XSS-Protection": "X-XSS-Protection",
    "X-Content-Type-Options": "X-Content-Type-Options",
    "Referrer-Policy": "Referrer-Policy",
}


def _normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def check_website(url: str) -> dict:
    url = _normalize_url(url)
    result = {
        "url": url,
        "reachable": False,
        "https": url.startswith("https://"),
        "status_code": None,
        "server": "unknown",
        "headers_present": {},
        "headers_missing": [],
        "robots_txt": False,
        "sitemap_xml": False,
        "error": None,
    }

    try:
        resp = requests.get(url, timeout=8, allow_redirects=True)
        result["reachable"] = True
        result["status_code"] = resp.status_code
        result["server"] = resp.headers.get("Server", "unknown")

        for header, label in SECURITY_HEADERS.items():
            if header in resp.headers:
                result["headers_present"][label] = resp.headers[header]
            else:
                result["headers_missing"].append(label)

        base = url.split("://")[0] + "://" + url.split("://")[1].split("/")[0]
        try:
            robots = requests.get(base + "/robots.txt", timeout=5)
            result["robots_txt"] = robots.status_code == 200
        except requests.RequestException:
            pass
        try:
            sitemap = requests.get(base + "/sitemap.xml", timeout=5)
            result["sitemap_xml"] = sitemap.status_code == 200
        except requests.RequestException:
            pass

    except requests.RequestException as e:
        result["error"] = str(e)

    return result


def calculate_risk(result: dict) -> str:
    if not result["reachable"]:
        return "High"
    score = 0
    if not result["https"]:
        score += 2
    score += len(result["headers_missing"])
    if score >= 5:
        return "High"
    if score >= 2:
        return "Medium"
    return "Low"
