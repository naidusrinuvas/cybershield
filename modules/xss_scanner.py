"""
XSS Scanner
Tests URL parameters and HTML forms for reflected XSS by injecting a
unique marker payload and checking whether it appears unescaped in the
response HTML.

IMPORTANT: Only scan URLs/applications you own or have explicit permission
to test (e.g. a locally running DVWA or OWASP Juice Shop instance).
"""

import uuid
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup


def _make_payload() -> tuple:
    """Return (payload, marker) where marker is a unique string to search for."""
    marker = f"xss{uuid.uuid4().hex[:8]}"
    payload = f"<script>alert('{marker}')</script>"
    return payload, marker


def scan_url_params(url: str) -> list:
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return findings

    for param in params:
        payload, marker = _make_payload()
        test_params = params.copy()
        test_params[param] = [payload]
        new_query = urlencode(test_params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))

        try:
            resp = requests.get(test_url, timeout=8)
        except requests.RequestException:
            continue

        # Reflected & unescaped if the raw <script> tag with our marker appears verbatim
        if f"<script>alert('{marker}')</script>" in resp.text:
            findings.append({
                "type": "Reflected XSS (GET parameter)",
                "parameter": param,
                "payload": payload,
                "risk": "High",
            })

    return findings


def scan_forms(url: str) -> list:
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
            payload, marker = _make_payload()
            data = {f: (payload if f == field else "test") for f in field_names}
            try:
                if method == "post":
                    resp = requests.post(target_url, data=data, timeout=8)
                else:
                    resp = requests.get(target_url, params=data, timeout=8)
            except requests.RequestException:
                continue

            if f"<script>alert('{marker}')</script>" in resp.text:
                findings.append({
                    "type": f"Reflected XSS (Form, {method.upper()})",
                    "parameter": field,
                    "payload": payload,
                    "risk": "High",
                })

    return findings


def detect_xss(url: str) -> dict:
    param_findings = scan_url_params(url)
    form_findings = scan_forms(url)
    all_findings = param_findings + form_findings

    errors = [f for f in all_findings if f.get("type") == "error"]
    real_findings = [f for f in all_findings if f.get("type") != "error"]

    risk_level = "High" if real_findings else "Low"
    return {"url": url, "findings": real_findings, "errors": errors, "risk_level": risk_level}
