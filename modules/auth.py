"""
Authentication logic: register, login, password hashing, session helpers.
"""

import re
import sqlite3

from werkzeug.security import generate_password_hash, check_password_hash

from utils.db import get_db


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_registration(username: str, email: str, password: str) -> str | None:
    """Return an error message, or None if valid."""
    if not username or len(username) < 3:
        return "Username must be at least 3 characters."
    if not email or not EMAIL_RE.match(email):
        return "Please enter a valid email address."
    if not password or len(password) < 8:
        return "Password must be at least 8 characters."
    return None


def register_user(username: str, email: str, password: str) -> tuple[bool, str]:
    error = validate_registration(username, email, password)
    if error:
        return False, error

    hashed = generate_password_hash(password)
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
            (username, email, hashed),
        )
        conn.commit()
        return True, "Account created successfully."
    except sqlite3.IntegrityError:
        return False, "Username or email is already taken."
    finally:
        conn.close()


def authenticate_user(username_or_email: str, password: str):
    """Return the user row if credentials are valid, else None."""
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ? OR email = ?",
        (username_or_email, username_or_email),
    ).fetchone()
    conn.close()

    if user and check_password_hash(user["password"], password):
        return user
    return None


def change_password(user_id: int, old_password: str, new_password: str) -> tuple[bool, str]:
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    if not user or not check_password_hash(user["password"], old_password):
        conn.close()
        return False, "Current password is incorrect."
    if len(new_password) < 8:
        conn.close()
        return False, "New password must be at least 8 characters."

    conn.execute(
        "UPDATE users SET password = ? WHERE id = ?",
        (generate_password_hash(new_password), user_id),
    )
    conn.commit()
    conn.close()
    return True, "Password updated successfully."
