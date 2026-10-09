import sqlite3

from flask import current_app

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    role TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    total REAL NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""

USERS = [
    (1, "alice", "alice@example.com", "admin"),
    (2, "bob", "bob@example.com", "customer"),
    (3, "carol", "carol@example.com", "customer"),
    (4, "dave", "dave@example.com", "customer"),
]

ORDERS = [
    (1, 2, 120.0, "paid", "2026-09-01"),
    (2, 3, 45.5, "refunded", "2026-09-02"),
    (3, 2, 300.0, "paid", "2026-09-03"),
    (4, 4, 80.0, "refunded", "2026-09-04"),
    (5, 3, 15.0, "paid", "2026-09-05"),
]


def init_db(path):
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        conn.executemany("INSERT INTO users VALUES (?, ?, ?, ?)", USERS)
        conn.executemany("INSERT INTO orders VALUES (?, ?, ?, ?, ?)", ORDERS)
    conn.commit()
    conn.close()


def get_conn():
    conn = sqlite3.connect(current_app.config["DB_PATH"])
    conn.row_factory = sqlite3.Row
    return conn
