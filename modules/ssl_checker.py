"""
SSL Certificate Checker
Connects to a host on port 443 and inspects its TLS certificate.
"""

import ssl
import socket
from datetime import datetime


def check_ssl_certificate(hostname: str, port: int = 443) -> dict:
    hostname = hostname.replace("https://", "").replace("http://", "").split("/")[0]

    result = {
        "hostname": hostname,
        "valid": False,
        "issuer": None,
        "subject": None,
        "start_date": None,
        "expiry_date": None,
        "days_remaining": None,
        "error": None,
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))

        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_remaining = (not_after - datetime.utcnow()).days

        result.update({
            "valid": days_remaining > 0,
            "issuer": issuer.get("organizationName", issuer.get("commonName", "unknown")),
            "subject": subject.get("commonName", hostname),
            "start_date": not_before.strftime("%Y-%m-%d"),
            "expiry_date": not_after.strftime("%Y-%m-%d"),
            "days_remaining": days_remaining,
        })

    except (socket.gaierror, socket.timeout) as e:
        result["error"] = f"Could not connect: {e}"
    except ssl.SSLError as e:
        result["error"] = f"SSL error: {e}"
    except Exception as e:
        result["error"] = f"Unexpected error: {e}"

    return result
