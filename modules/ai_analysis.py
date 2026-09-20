"""
AI Security Analysis
Takes a scan result and generates a plain-English summary, risk explanation,
and remediation recommendations.

Two modes:
1. Real AI mode (used when ANTHROPIC_API_KEY is set as an environment
   variable): calls the Anthropic API to generate genuinely AI-written
   analysis. This is what justifies the "AI-Powered" name in the project.
2. Rule-based fallback (used when no API key is configured, or if the API
   call fails): produces a templated but still useful analysis so the
   feature works out of the box with no setup.

To enable real AI mode, set an environment variable before running the app:
    Windows (PowerShell):  $env:ANTHROPIC_API_KEY="sk-ant-..."
    Mac/Linux:             export ANTHROPIC_API_KEY="sk-ant-..."
Get a key from https://console.anthropic.com/
"""

import os
import json
import requests

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-3-5-haiku-20241022")


def _build_prompt(scan_type: str, target: str, result: str, risk_level: str) -> str:
    return f"""You are a cybersecurity analyst assistant embedded in a student security toolkit.
Given this scan result, respond ONLY with valid JSON (no markdown, no preamble) matching this shape:
{{
  "summary": "1-2 sentence plain-English summary of what was found",
  "risk_explanation": "1-2 sentences explaining why this risk level was assigned",
  "recommendations": ["short actionable step 1", "short actionable step 2", "short actionable step 3"]
}}

Scan type: {scan_type}
Target: {target}
Result: {result}
Risk level: {risk_level}
"""


def _call_anthropic_api(scan_type: str, target: str, result: str, risk_level: str) -> dict | None:
    if not ANTHROPIC_API_KEY:
        return None

    try:
        response = requests.post(
            ANTHROPIC_URL,
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": ANTHROPIC_MODEL,
                "max_tokens": 400,
                "messages": [{"role": "user", "content": _build_prompt(scan_type, target, result, risk_level)}],
            },
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()
        text = "".join(block.get("text", "") for block in data.get("content", []))
        text = text.strip().strip("`").lstrip("json").strip()
        parsed = json.loads(text)
        parsed["source"] = "ai"
        return parsed
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Rule-based fallback (no API key required)
# ---------------------------------------------------------------------------
RECOMMENDATIONS_BY_TYPE = {
    "Password Strength Check": [
        "Use a passphrase of 12+ characters mixing case, numbers, and symbols.",
        "Avoid dictionary words and common substitutions (e.g. '@' for 'a').",
        "Use a password manager to generate and store unique passwords per account.",
    ],
    "Port Scan": [
        "Close or firewall any open ports not required for the service to function.",
        "Restrict management ports (SSH, RDP) to specific trusted IP ranges.",
        "Keep services bound to open ports patched and up to date.",
    ],
    "Packet Capture": [
        "Use encrypted protocols (HTTPS, SSH, TLS) instead of plaintext ones where possible.",
        "Segment sensitive traffic onto a separate VLAN.",
        "Monitor for unexpected traffic patterns that could indicate a compromise.",
    ],
    "Website Security Check": [
        "Add missing security headers (CSP, HSTS, X-Frame-Options) to the web server config.",
        "Enforce HTTPS site-wide with a valid TLS certificate.",
        "Avoid exposing detailed server/version info in response headers.",
    ],
    "SSL Certificate Check": [
        "Renew the certificate before it expires to avoid browser warnings and downtime.",
        "Enable automatic renewal (e.g. Let's Encrypt + certbot) to prevent future lapses.",
        "Use a certificate from a trusted, well-known Certificate Authority.",
    ],
    "Subdomain Scan": [
        "Audit all discovered subdomains and decommission any that are unused.",
        "Ensure staging/dev/test subdomains are not publicly accessible or are behind auth.",
        "Keep DNS records up to date and remove stale entries pointing to old infrastructure.",
    ],
    "Directory Scan": [
        "Remove or restrict access to sensitive directories (admin, backup, config) via server config.",
        "Never expose backup files or config files in a web-accessible directory.",
        "Use authentication for any administrative interface.",
    ],
    "SQL Injection Scan": [
        "Use parameterized queries / prepared statements instead of string concatenation.",
        "Apply the principle of least privilege to the database user the app connects with.",
        "Add input validation and a web application firewall (WAF) as defense in depth.",
    ],
    "XSS Scan": [
        "Escape all user input before rendering it in HTML (use your framework's auto-escaping).",
        "Implement a Content-Security-Policy header to restrict inline script execution.",
        "Validate and sanitize input on both client and server side.",
    ],
    "AES Encryption": [
        "Store the encryption password separately from the encrypted file, never alongside it.",
        "Use a strong, unique password for each file you encrypt.",
    ],
    "AES Decryption": [
        "Verify file integrity after decryption if the file is sensitive.",
    ],
    "RSA Key Generation": [
        "Never share your private key; only distribute the public key.",
        "Store the private key encrypted at rest if saving it to disk.",
    ],
}

RISK_EXPLANATIONS = {
    "High": "This finding indicates a significant, exploitable weakness that should be addressed as a priority.",
    "Medium": "This finding indicates a moderate weakness that should be reviewed and remediated soon.",
    "Low": "No significant issues were found, or the target is already following good security practices.",
    "Unknown": "The scan could not be completed or reach the target, so risk could not be conclusively determined.",
}


def _rule_based_analysis(scan_type: str, target: str, result: str, risk_level: str) -> dict:
    recommendations = RECOMMENDATIONS_BY_TYPE.get(
        scan_type, ["Review the finding manually and apply standard security hardening for this asset type."]
    )
    return {
        "summary": f"{scan_type} on '{target}' completed with result: {result}.",
        "risk_explanation": RISK_EXPLANATIONS.get(risk_level, RISK_EXPLANATIONS["Unknown"]),
        "recommendations": recommendations,
        "source": "rule-based",
    }


def generate_ai_analysis(scan_type: str, target: str, result: str, risk_level: str) -> dict:
    """
    Returns dict: {summary, risk_explanation, recommendations: [...], source: "ai"|"rule-based"}
    Tries the real Anthropic API first (if configured), falls back to rule-based templates.
    """
    ai_result = _call_anthropic_api(scan_type, target, result, risk_level)
    if ai_result:
        return ai_result
    return _rule_based_analysis(scan_type, target, result, risk_level)
