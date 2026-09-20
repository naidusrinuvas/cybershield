"""
Subdomain Scanner
Checks a list of common subdomains for DNS resolution against a base domain.
"""

import socket
import concurrent.futures

COMMON_SUBDOMAINS = ["www", "mail", "ftp", "api", "admin", "blog", "dev", "test", "shop"]


def _clean_domain(domain: str) -> str:
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    # Strip a leading "www." if present so we scan the bare domain plus www itself
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def scan_subdomains(domain: str) -> list:
    domain = _clean_domain(domain)
    found = []

    def check(sub):
        full = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(full)
            return {"subdomain": full, "ip": ip, "found": True}
        except socket.gaierror:
            return {"subdomain": full, "ip": None, "found": False}

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(check, COMMON_SUBDOMAINS))

    found = [r for r in results if r["found"]]
    return found
