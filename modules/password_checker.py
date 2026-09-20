"""
Password Strength Checker
Rule-based scoring: length, uppercase, lowercase, numbers, symbols.
"""

import re


def check_password_strength(password: str) -> dict:
    """Return a dict with score, label, and which checks passed."""
    checks = {
        "length": len(password) >= 8,
        "long_length": len(password) >= 12,
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "lowercase": bool(re.search(r"[a-z]", password)),
        "numbers": bool(re.search(r"\d", password)),
        "symbols": bool(re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=~`\[\]\\/;']", password)),
    }

    # Common weak passwords / patterns
    common_passwords = {
        "password", "123456", "12345678", "qwerty", "abc123",
        "password1", "111111", "123456789", "letmein", "admin",
    }
    is_common = password.lower() in common_passwords

    score = sum([
        checks["length"],
        checks["long_length"],
        checks["uppercase"],
        checks["lowercase"],
        checks["numbers"],
        checks["symbols"],
    ])

    if is_common or len(password) == 0:
        label = "Weak"
    elif score <= 2:
        label = "Weak"
    elif score <= 4:
        label = "Medium"
    else:
        label = "Strong"

    return {
        "password_length": len(password),
        "score": score,
        "max_score": 6,
        "label": label,
        "is_common": is_common,
        "checks": checks,
    }
