import re
import sqlite3


def suppressed(conn, name):
    # `semgrep --test` honours the nosemgrep below, so it can't see this one; Trust Issues scans
    # with --disable-nosem, and tests/test_ai_rules.py checks it does catch it.
    # todoruleid: ai-patch-scanner-suppression
    return conn.execute(f"SELECT * FROM users WHERE name = '{name}'")  # nosemgrep


def suppressed_bandit(conn, name):
    # ruleid: ai-patch-scanner-suppression
    return conn.execute("SELECT * FROM users WHERE name = '" + name + "'")  # nosec B608


def mentions_the_word(conn):
    # ok: ai-patch-scanner-suppression
    return conn.execute("SELECT 1")  # explains why we never use nosemgrep here


def escaped_by_hand(conn, name):
    # ruleid: ai-patch-handrolled-sql-escaping
    safe = name.replace("'", "''")
    return conn.execute(f"SELECT * FROM users WHERE name = '{safe}'")


def stripped(conn, sort):
    # ruleid: ai-patch-handrolled-sql-escaping
    sort = sort.replace(";", "")
    return conn.execute("SELECT * FROM orders ORDER BY " + sort)


def regex_scrubbed(conn, name):
    # ruleid: ai-patch-handrolled-sql-escaping
    name = re.sub(r"[^a-z]", "", name)
    return conn.execute(f"SELECT * FROM users WHERE name = '{name}'")


def parameterized(conn, name):
    # ok: ai-patch-handrolled-sql-escaping
    return conn.execute("SELECT * FROM users WHERE name = ?", (name,))


def unrelated_replace(text):
    # ok: ai-patch-handrolled-sql-escaping
    return text.replace("-", "_")


def swallowed(conn, name):
    # ruleid: ai-patch-swallowed-db-error
    try:
        rows = conn.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall()
    except Exception:
        rows = []
    return rows


def swallowed_bare(conn):
    # ruleid: ai-patch-swallowed-db-error
    try:
        conn.execute("DELETE FROM sessions")
    except:
        pass


def reraised(conn):
    # ok: ai-patch-swallowed-db-error
    try:
        conn.execute("DELETE FROM sessions")
    except Exception:
        conn.rollback()
        raise


def specific(conn):
    # ok: ai-patch-swallowed-db-error
    try:
        conn.execute("DELETE FROM sessions")
    except sqlite3.OperationalError:
        return None
