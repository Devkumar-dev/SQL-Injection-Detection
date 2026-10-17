"""
Database Module for SQL Injection Detection and Mitigation Lab
=============================================================
Manages SQLite database initialization, dummy account seeding,
and secure parameterized authentication using cryptographic password hashing.

Educational Lab Safety Notice:
- Operates locally on an isolated SQLite database file.
- Contains only fictional dummy test accounts.
"""

import os
import sqlite3
from typing import Optional, Dict, Any, List
from werkzeug.security import generate_password_hash, check_password_hash

DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), "sql_lab.db")

# Seeded dummy accounts with non-sensitive fictional credentials
DUMMY_USERS = [
    {
        "username": "alice",
        "password": "AlicePassword123!",
        "full_name": "Alice Vance",
        "role": "Security Analyst",
    },
    {
        "username": "bob",
        "password": "BobPassword456!",
        "full_name": "Bob Miller",
        "role": "Compliance Auditor",
    },
    {
        "username": "admin_demo",
        "password": "AdminLabDemo789!",
        "full_name": "Educational Admin",
        "role": "System Administrator",
    },
]


def get_db_connection(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Establish a connection to the SQLite database with Row factory."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    """
    Initialize the database schema and seed dummy test accounts.
    Uses PBKDF2:SHA256 password hashing.
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    # Create users table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    # Seed dummy accounts if table is empty
    cursor.execute("SELECT COUNT(*) AS count FROM users")
    count = cursor.fetchone()["count"]

    if count == 0:
        for user in DUMMY_USERS:
            # Generate cryptographically salted hash
            hashed_pw = generate_password_hash(
                user["password"], method="pbkdf2:sha256", salt_length=16
            )
            cursor.execute(
                """
                INSERT INTO users (username, password_hash, full_name, role)
                VALUES (?, ?, ?, ?)
                """,
                (user["username"], hashed_pw, user["full_name"], user["role"]),
            )
        conn.commit()

    conn.close()


def authenticate_secure(
    username: str, password: str, db_path: str = DEFAULT_DB_PATH
) -> Optional[Dict[str, Any]]:
    """
    Authenticate a user using parameterized queries and secure password hash verification.

    Mitigation Details:
    1. Uses parameterized query ('?' placeholder):
       Input is treated strictly as literal data by the SQLite engine,
       preventing any interpretation as SQL syntax.
    2. Secure password hashing:
       Uses check_password_hash to verify against stored salted hashes.
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    # Parameterized query: inputs are bounded parameters, NOT concatenated
    query = "SELECT id, username, password_hash, full_name, role FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    user_dict = dict(row)
    if check_password_hash(user_dict["password_hash"], password):
        # Authentication successful: strip password_hash before returning
        del user_dict["password_hash"]
        return user_dict

    return None


def get_public_dummy_accounts() -> List[Dict[str, str]]:
    """Return public list of dummy accounts for educational lab display."""
    return [
        {
            "username": u["username"],
            "full_name": u["full_name"],
            "role": u["role"],
            "sample_password": u["password"],
        }
        for u in DUMMY_USERS
    ]


if __name__ == "__main__":
    init_db()
    print("Database initialized and dummy accounts seeded successfully.")
