"""
SQL Injection Detector
Basic payload testing against URL parameters and HTML forms.
Uses error-based detection: injects common SQLi payloads and checks the
response for known database error signatures.

IMPORTANT: Only scan URLs/applications you own or have explicit permission
to test (e.g. a locally running DVWA or OWASP Juice Shop instance).
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup

SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR '1'='1' -- ",
    "\" OR \"1\"=\"1",
    "') OR ('1'='1",
]

# Signatures that commonly appear in raw DB error messages
ERROR_SIGNATURES = [
    "sql syntax", "mysql_fetch", "you have an error in your sql syntax",
    "unclosed quotation mark", "quoted string not properly terminated",
    "sqlite3.OperationalError", "sqlite3.programmingerror",
    "psycopg2", "ora-01756", "odbc sql server driver",
    "syntax error", "unterminated string",
]


def _contains_error_signature(text: str) -> str | None:
    lower = text.lower()
    for sig in ERROR_SIGNATURES:
        if sig.lower() in lower:
            return sig
    return None


def scan_url_params(url: str) -> list:
    """Test each GET parameter in the URL with SQLi payloads."""
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return findings

    try:
        baseline = requests.get(url, timeout=8)
        baseline_len = len(baseline.text)
    except requests.RequestException as e:
        return [{"type": "error", "detail": f"Could not reach target: {e}"}]

    for param in params:
        for payload in SQLI_PAYLOADS:
            test_params = params.copy()
            test_params[param] = [payload]
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                resp = requests.get(test_url, timeout=8)
            except requests.RequestException:
                continue

            sig = _contains_error_signature(resp.text)
            if sig:
                findings.append({
                    "type": "GET parameter",
                    "parameter": param,
                    "payload": payload,
                    "evidence": sig,
                    "risk": "High",
                })
                break  # one confirmed finding per parameter is enough

    return findings


def scan_forms(url: str) -> list:
    """Find HTML forms on the page and test each input field with SQLi payloads."""
    findings = []
    try:
        page = requests.get(url, timeout=8)
    except requests.RequestException as e:
        return [{"type": "error", "detail": f"Could not reach target: {e}"}]

    soup = BeautifulSoup(page.text, "html.parser")
    forms = soup.find_all("form")

    for form in forms:
        action = form.get("action") or url
        method = form.get("method", "get").lower()
        inputs = form.find_all(["input", "textarea"])
        field_names = [i.get("name") for i in inputs if i.get("name")]

        if not field_names:
            continue

        target_url = action if action.startswith("http") else url.rsplit("/", 1)[0] + "/" + action.lstrip("/")

        for field in field_names:
            for payload in SQLI_PAYLOADS[:3]:  # keep form testing lighter
                data = {f: payload for f in field_names}
                try:
                    if method == "post":
                        resp = requests.post(target_url, data=data, timeout=8)
                    else:
                        resp = requests.get(target_url, params=data, timeout=8)
                except requests.RequestException:
                    continue

                sig = _contains_error_signature(resp.text)
                if sig:
                    findings.append({
                        "type": f"Form field ({method.upper()})",
                        "parameter": field,
                        "payload": payload,
                        "evidence": sig,
                        "risk": "High",
                    })
                    break

    return findings


def detect_sql_injection(url: str) -> dict:
    param_findings = scan_url_params(url)
    form_findings = scan_forms(url)
    all_findings = param_findings + form_findings

    errors = [f for f in all_findings if f.get("type") == "error"]
    real_findings = [f for f in all_findings if f.get("type") != "error"]

    if errors and not real_findings:
        risk_level = "Unknown"
    elif real_findings:
        risk_level = "High"
    else:
        risk_level = "Low"

    return {"url": url, "findings": real_findings, "errors": errors, "risk_level": risk_level}
