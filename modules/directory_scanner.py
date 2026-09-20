"""
Directory Scanner
Checks a list of common directory/file paths for accessibility on a target website.
"""

import requests
import concurrent.futures

COMMON_DIRECTORIES = [
    "admin", "login", "backup", "uploads", "images", "assets", "config",
]


def _normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def scan_directories(base_url: str) -> list:
    base_url = _normalize_url(base_url)

    def check(path):
        full_url = f"{base_url}/{path}/"
        try:
            resp = requests.get(full_url, timeout=6, allow_redirects=False)
            return {"path": path, "url": full_url, "status_code": resp.status_code,
                    "accessible": resp.status_code in (200, 301, 302, 403)}
        except requests.RequestException:
            return {"path": path, "url": full_url, "status_code": None, "accessible": False}

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(check, COMMON_DIRECTORIES))

    return results
