from flask import Blueprint, jsonify, request

from .db import get_conn

bp = Blueprint("users", __name__)


@bp.route("/users/search")
def search_users():
    name = request.args.get("name", "")
    conn = get_conn()
    rows = conn.execute(
        "SELECT id, name, email FROM users WHERE name = ?", (name,)
    ).fetchall()
    return jsonify([dict(r) for r in rows])
