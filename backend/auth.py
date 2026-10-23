"""Xaxglog authentication + RBAC.

Straight-through workflow: an analyst logs in once, the dashboard holds a JWT,
and every subsequent request flows without friction. Authorization and the
audit trail are enforced server-side and recorded silently in the background.

Roles:
  admin   — manage users/cases, run every module
  analyst — run every module, create/edit cases, attach evidence
  viewer  — read-only
"""
import datetime
import functools

try:
    import jwt  # PyJWT
except Exception:  # pragma: no cover
    jwt = None

from werkzeug.security import check_password_hash, generate_password_hash

import config as C
import db

ALGO = "HS256"
TOKEN_TTL_HOURS = 12


def _secret():
    return C.FLASK_SECRET_KEY or "xaxglog-dev-change-me"


def create_user(username, password, role="analyst"):
    if role not in ("admin", "analyst", "viewer"):
        raise ValueError("invalid role")
    c = db.get_db()
    h = generate_password_hash(password)
    try:
        cur = c.execute(
            "INSERT INTO users (username,password_hash,role,created_at) VALUES (?,?,?,?)",
            (username, h, role, db.utcnow()),
        )
        c.commit()
        return cur.lastrowid
    except Exception as e:
        if "UNIQUE" in str(e):
            raise ValueError("username already exists")
        raise


def authenticate(username, password):
    c = db.get_db()
    row = c.execute(
        "SELECT * FROM users WHERE username=? AND active=1", (username,)
    ).fetchone()
    if not row or not check_password_hash(row["password_hash"], password):
        return None
    return {"username": row["username"], "role": row["role"]}


def issue_token(user):
    if not jwt:
        return None
    payload = {
        "sub": user["username"],
        "role": user["role"],
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=TOKEN_TTL_HOURS),
    }
    return jwt.encode(payload, _secret(), algorithm=ALGO)


def decode_token(token):
    if not jwt:
        return None
    try:
        return jwt.decode(token, _secret(), algorithms=[ALGO])
    except Exception:
        return None


def current_user(request):
    """Extract the authenticated user from the Authorization header."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    payload = decode_token(auth[7:].strip())
    if not payload:
        return None
    return {"username": payload.get("sub"), "role": payload.get("role")}


def require(min_role="viewer"):
    """Decorator enforcing authentication + a minimum role, logging access."""
    order = {"viewer": 0, "analyst": 1, "admin": 2}

    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            from flask import jsonify, request

            user = current_user(request)
            if not user:
                return jsonify({"error": "authentication required"}), 401
            if order.get(user["role"], 0) < order.get(min_role, 0):
                db.audit(user["username"], "authz.deny", request.path,
                         f"role={user['role']} need>={min_role}", request.remote_addr)
                return jsonify({"error": f"insufficient role (need {min_role})"}), 403
            request.xuser = user  # available to the route
            return fn(*args, **kwargs)

        return wrapper

    return deco
