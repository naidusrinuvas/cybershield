"""
Database setup for CyberShield.
Creates all tables defined in the project scope: users, scan_history,
reports, logs. Uses plain sqlite3 (no ORM) to keep things simple for
a final-year project.
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "database.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            scan_type TEXT NOT NULL,
            target TEXT,
            result TEXT,
            risk_level TEXT,
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            report_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            report_name TEXT NOT NULL,
            file_path TEXT NOT NULL,
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            activity TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
        )
    """)

    conn.commit()
    conn.close()


def log_activity(user_id, activity: str):
    """Write a row to the logs table. user_id can be None for anonymous events."""
    conn = get_db()
    conn.execute(
        "INSERT INTO logs (user_id, activity) VALUES (?, ?)",
        (user_id, activity),
    )
    conn.commit()
    conn.close()


def add_scan_history(user_id, scan_type, target, result, risk_level):
    conn = get_db()
    conn.execute(
        """INSERT INTO scan_history (user_id, scan_type, target, result, risk_level)
           VALUES (?, ?, ?, ?, ?)""",
        (user_id, scan_type, target, result, risk_level),
    )
    conn.commit()
    conn.close()
