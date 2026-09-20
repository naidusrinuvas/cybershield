"""
Password Generator
Uses the `secrets` module for cryptographically secure randomness.
"""

import secrets
import string


def generate_password(length: int = 16, use_upper: bool = True,
                       use_numbers: bool = True, use_symbols: bool = True) -> str:
    length = max(4, min(length, 128))  # sane bounds

    pool = string.ascii_lowercase
    required = [secrets.choice(string.ascii_lowercase)]

    if use_upper:
        pool += string.ascii_uppercase
        required.append(secrets.choice(string.ascii_uppercase))
    if use_numbers:
        pool += string.digits
        required.append(secrets.choice(string.digits))
    if use_symbols:
        symbols = "!@#$%^&*()-_=+[]{}"
        pool += symbols
        required.append(secrets.choice(symbols))

    remaining_length = max(0, length - len(required))
    body = [secrets.choice(pool) for _ in range(remaining_length)]

    password_chars = required + body
    # Shuffle securely (Fisher-Yates using secrets)
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return "".join(password_chars)
