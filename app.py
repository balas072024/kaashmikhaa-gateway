"""
Kaashmikhaa Gateway - API Gateway for Arivu Maiyam
A Flask-based API gateway that routes requests to backend microservices,
handles authentication, and provides unified API access.
"""

import os
import sys
import time
import sqlite3
import json
import datetime
import functools
import threading
from contextlib import contextmanager

import jwt
import bcrypt
import requests as http_requests
from flask import Flask, request, jsonify, g, render_template, Response
from flask_cors import CORS

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

app = Flask(__name__)
CORS(app)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "kaashmikhaa-secret-key-change-in-production")
app.config["DATABASE"] = os.environ.get("DATABASE", os.path.join(os.path.dirname(os.path.abspath(__file__)), "gateway.db"))
app.config["JWT_EXPIRY_HOURS"] = int(os.environ.get("JWT_EXPIRY_HOURS", "24"))
app.config["RATE_LIMIT_PER_MINUTE"] = int(os.environ.get("RATE_LIMIT_PER_MINUTE", "60"))
app.config["PROXY_TIMEOUT"] = int(os.environ.get("PROXY_TIMEOUT", "30"))

PORT = int(os.environ.get("PORT", "5013"))

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    """Get a database connection for the current request context."""
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Initialise the SQLite database with required tables."""
    db_path = app.config["DATABASE"]
    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            url TEXT NOT NULL,
            prefix TEXT UNIQUE NOT NULL,
            description TEXT DEFAULT '',
            health_endpoint TEXT DEFAULT '/health',
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS request_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            service_name TEXT,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            status_code INTEGER,
            latency_ms REAL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            response_size INTEGER DEFAULT 0,
            error_message TEXT DEFAULT ''
        );

        CREATE INDEX IF NOT EXISTS idx_request_logs_timestamp ON request_logs(request_timestamp);
        CREATE INDEX IF NOT EXISTS idx_request_logs_service ON request_logs(service_name);
        CREATE INDEX IF NOT EXISTS idx_request_logs_user ON request_logs(user_id);
    """)
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# JWT Authentication helpers
# ---------------------------------------------------------------------------

def create_token(user_id, username, role):
    """Create a JWT token for the given user."""
    payload = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=app.config["JWT_EXPIRY_HOURS"]),
        "iat": datetime.datetime.utcnow(),
    }
    return jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")


def decode_token(token):
    """Decode and validate a JWT token."""
    return jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])


def token_required(f):
    """Decorator that requires a valid JWT token."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
        if not token:
            token = request.args.get("token")
        if not token:
            return jsonify({"error": "Authentication token is missing"}), 401
        try:
            data = decode_token(token)
            g.current_user = data
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Decorator that requires the user to have the admin role."""
    @functools.wraps(f)
    @token_required
    def decorated(*args, **kwargs):
        if g.current_user.get("role") != "admin":
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Rate Limiting
# ---------------------------------------------------------------------------

# In-memory store: { user_id: [ timestamp, ... ] }
_rate_limit_store: dict[int, list[float]] = {}
_rate_limit_lock = threading.Lock()


def check_rate_limit(user_id: int) -> bool:
    """Return True if the request is allowed, False if rate-limited."""
    now = time.time()
    window = 60.0  # 1 minute
    limit = app.config["RATE_LIMIT_PER_MINUTE"]

    with _rate_limit_lock:
        timestamps = _rate_limit_store.get(user_id, [])
        # Prune old entries
        timestamps = [t for t in timestamps if now - t < window]
        if len(timestamps) >= limit:
            _rate_limit_store[user_id] = timestamps
            return False
        timestamps.append(now)
        _rate_limit_store[user_id] = timestamps
        return True


# ---------------------------------------------------------------------------
# Request logging helper
# ---------------------------------------------------------------------------

def log_request(user_id, service_name, method, path, status_code, latency_ms, response_size=0, error_message=""):
    """Log a proxied request to the database."""
    try:
        db = get_db()
        db.execute(
            """INSERT INTO request_logs
               (user_id, service_name, method, path, status_code, latency_ms, response_size, error_message)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (user_id, service_name, method, path, status_code, latency_ms, response_size, error_message),
        )
        db.commit()
    except Exception:
        pass  # Logging should never break the main flow


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------

@app.route("/api/auth/register", methods=["POST"])
def register():
    """Register a new user."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    role = data.get("role", "user")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    if role not in ("user", "admin"):
        return jsonify({"error": "Role must be 'user' or 'admin'"}), 400

    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    db = get_db()
    try:
        cursor = db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, password_hash, role),
        )
        db.commit()
        user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409

    token = create_token(user_id, username, role)
    return jsonify({"message": "User registered successfully", "token": token, "user_id": user_id, "username": username, "role": role}), 201


@app.route("/api/auth/login", methods=["POST"])
def login():
    """Authenticate a user and return a JWT token."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    if not bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
        return jsonify({"error": "Invalid credentials"}), 401

    token = create_token(user["id"], user["username"], user["role"])
    return jsonify({"message": "Login successful", "token": token, "user_id": user["id"], "username": user["username"], "role": user["role"]}), 200


@app.route("/api/auth/me", methods=["GET"])
@token_required
def auth_me():
    """Return the current user information from the token."""
    return jsonify({"user": g.current_user}), 200


# ---------------------------------------------------------------------------
# Service Registry endpoints
# ---------------------------------------------------------------------------

@app.route("/api/services", methods=["GET"])
@token_required
def list_services():
    """List all registered services."""
    db = get_db()
    rows = db.execute("SELECT * FROM services ORDER BY name").fetchall()
    services = [dict(r) for r in rows]
    return jsonify({"services": services}), 200


@app.route("/api/services", methods=["POST"])
@admin_required
def add_service():
    """Register a new backend service."""
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    url = data.get("url", "").strip().rstrip("/")
    prefix = data.get("prefix", "").strip()
    description = data.get("description", "")
    health_endpoint = data.get("health_endpoint", "/health")

    if not name or not url or not prefix:
        return jsonify({"error": "name, url, and prefix are required"}), 400
    if not prefix.startswith("/"):
        prefix = "/" + prefix

    db = get_db()
    try:
        cursor = db.execute(
            """INSERT INTO services (name, url, prefix, description, health_endpoint)
               VALUES (?, ?, ?, ?, ?)""",
            (name, url, prefix, description, health_endpoint),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Service name or prefix already exists"}), 409

    return jsonify({"message": f"Service '{name}' registered", "service_id": cursor.lastrowid}), 201


@app.route("/api/services/<int:service_id>", methods=["PUT"])
@admin_required
def update_service(service_id):
    """Update a registered service."""
    data = request.get_json(silent=True) or {}
    db = get_db()
    service = db.execute("SELECT * FROM services WHERE id = ?", (service_id,)).fetchone()
    if not service:
        return jsonify({"error": "Service not found"}), 404

    name = data.get("name", service["name"])
    url = data.get("url", service["url"]).rstrip("/")
    prefix = data.get("prefix", service["prefix"])
    description = data.get("description", service["description"])
    health_endpoint = data.get("health_endpoint", service["health_endpoint"])
    is_active = data.get("is_active", service["is_active"])

    if not prefix.startswith("/"):
        prefix = "/" + prefix

    try:
        db.execute(
            """UPDATE services SET name=?, url=?, prefix=?, description=?, health_endpoint=?, is_active=?
               WHERE id=?""",
            (name, url, prefix, description, health_endpoint, int(is_active), service_id),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Service name or prefix conflict"}), 409

    return jsonify({"message": f"Service '{name}' updated"}), 200


@app.route("/api/services/<int:service_id>", methods=["DELETE"])
@admin_required
def remove_service(service_id):
    """Remove a registered service."""
    db = get_db()
    service = db.execute("SELECT * FROM services WHERE id = ?", (service_id,)).fetchone()
    if not service:
        return jsonify({"error": "Service not found"}), 404

    db.execute("DELETE FROM services WHERE id = ?", (service_id,))
    db.commit()
    return jsonify({"message": f"Service '{service['name']}' removed"}), 200


# ---------------------------------------------------------------------------
# API Gateway - Proxy routes
# ---------------------------------------------------------------------------

@app.route("/gateway/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
@token_required
def gateway_proxy(path):
    """Proxy requests to the appropriate backend service based on prefix matching."""
    user_id = g.current_user.get("user_id")

    # Rate limiting
    if not check_rate_limit(user_id):
        return jsonify({"error": "Rate limit exceeded. Try again later."}), 429

    # Find matching service
    db = get_db()
    services = db.execute("SELECT * FROM services WHERE is_active = 1").fetchall()

    target_service = None
    remaining_path = path
    for svc in services:
        prefix = svc["prefix"].strip("/")
        if path == prefix or path.startswith(prefix + "/"):
            target_service = svc
            remaining_path = path[len(prefix):].lstrip("/")
            break

    if not target_service:
        return jsonify({"error": f"No service matched for path: /{path}"}), 404

    # Build target URL
    target_url = f"{target_service['url']}/{remaining_path}".rstrip("/")

    # Forward the request
    start_time = time.time()
    try:
        headers = {k: v for k, v in request.headers if k.lower() not in ("host", "authorization", "content-length")}
        headers["X-Forwarded-For"] = request.headers.get('CF-Connecting-IP') or request.headers.get('X-Forwarded-For', '').split(',')[0].strip() or request.remote_addr or "unknown"
        headers["X-Gateway-User"] = str(user_id)

        resp = http_requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            params=request.args,
            data=request.get_data(),
            timeout=app.config["PROXY_TIMEOUT"],
            allow_redirects=False,
        )
        latency_ms = (time.time() - start_time) * 1000

        log_request(user_id, target_service["name"], request.method, f"/{path}", resp.status_code, latency_ms, len(resp.content))

        # Build response
        excluded_headers = {"content-encoding", "transfer-encoding", "content-length", "connection"}
        response_headers = {k: v for k, v in resp.headers.items() if k.lower() not in excluded_headers}
        return Response(resp.content, status=resp.status_code, headers=response_headers)

    except http_requests.Timeout:
        latency_ms = (time.time() - start_time) * 1000
        log_request(user_id, target_service["name"], request.method, f"/{path}", 504, latency_ms, error_message="Gateway timeout")
        return jsonify({"error": "Gateway timeout - backend service did not respond in time"}), 504

    except http_requests.ConnectionError:
        latency_ms = (time.time() - start_time) * 1000
        log_request(user_id, target_service["name"], request.method, f"/{path}", 502, latency_ms, error_message="Connection error")
        return jsonify({"error": "Bad gateway - could not connect to backend service"}), 502

    except Exception as exc:
        latency_ms = (time.time() - start_time) * 1000
        log_request(user_id, target_service["name"], request.method, f"/{path}", 500, latency_ms, error_message=str(exc))
        return jsonify({"error": f"Gateway error: {str(exc)}"}), 500


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.route("/api/health", methods=["GET"])
@app.route("/health", methods=["GET"])
def health():
    """Health check for the gateway itself."""
    return jsonify({"status": "healthy", "service": "kaashmikhaa-gateway", "timestamp": datetime.datetime.utcnow().isoformat()}), 200


@app.route("/api/health/services", methods=["GET"])
@token_required
def health_services():
    """Aggregate health status of all registered services."""
    db = get_db()
    services = db.execute("SELECT * FROM services WHERE is_active = 1").fetchall()
    results = []

    for svc in services:
        health_url = f"{svc['url']}{svc['health_endpoint']}"
        entry = {"name": svc["name"], "url": svc["url"], "health_url": health_url}
        try:
            start = time.time()
            resp = http_requests.get(health_url, timeout=5)
            latency = (time.time() - start) * 1000
            entry["status"] = "healthy" if resp.status_code == 200 else "unhealthy"
            entry["status_code"] = resp.status_code
            entry["latency_ms"] = round(latency, 2)
        except Exception as exc:
            entry["status"] = "unreachable"
            entry["status_code"] = None
            entry["latency_ms"] = None
            entry["error"] = str(exc)
        results.append(entry)

    all_healthy = all(r["status"] == "healthy" for r in results) if results else True
    return jsonify({"gateway": "healthy", "services": results, "all_healthy": all_healthy}), 200


# ---------------------------------------------------------------------------
# Request logs
# ---------------------------------------------------------------------------

@app.route("/api/logs", methods=["GET"])
@token_required
def get_logs():
    """Return recent request logs."""
    limit = min(int(request.args.get("limit", 100)), 1000)
    offset = int(request.args.get("offset", 0))
    service = request.args.get("service")

    db = get_db()
    if service:
        rows = db.execute(
            "SELECT * FROM request_logs WHERE service_name = ? ORDER BY request_timestamp DESC LIMIT ? OFFSET ?",
            (service, limit, offset),
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM request_logs ORDER BY request_timestamp DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()

    logs = [dict(r) for r in rows]
    return jsonify({"logs": logs, "count": len(logs)}), 200


@app.route("/api/logs/export", methods=["GET"])
@token_required
def export_logs():
    """Export all request logs as JSON for download."""
    db = get_db()
    rows = db.execute(
        "SELECT * FROM request_logs ORDER BY request_timestamp DESC"
    ).fetchall()
    logs = [dict(r) for r in rows]
    response = jsonify({"logs": logs, "count": len(logs), "exported_at": datetime.datetime.utcnow().isoformat()})
    response.headers["Content-Disposition"] = "attachment; filename=request_logs.json"
    return response, 200


@app.route("/api/logs/clear", methods=["DELETE"])
@admin_required
def clear_old_logs():
    """Clear request logs older than 7 days. Admin only."""
    db = get_db()
    cutoff = (datetime.datetime.utcnow() - datetime.timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
    cursor = db.execute(
        "DELETE FROM request_logs WHERE request_timestamp < ?", (cutoff,)
    )
    db.commit()
    deleted_count = cursor.rowcount
    return jsonify({"message": f"Cleared {deleted_count} old log entries", "deleted_count": deleted_count}), 200


# ---------------------------------------------------------------------------
# Analytics
# ---------------------------------------------------------------------------

@app.route("/api/analytics", methods=["GET"])
@token_required
def analytics():
    """Return analytics: request counts per service, avg latency, error rates."""
    db = get_db()

    # Per-service stats
    per_service = db.execute("""
        SELECT
            service_name,
            COUNT(*) as total_requests,
            ROUND(AVG(latency_ms), 2) as avg_latency_ms,
            ROUND(MIN(latency_ms), 2) as min_latency_ms,
            ROUND(MAX(latency_ms), 2) as max_latency_ms,
            SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) as error_count,
            ROUND(100.0 * SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) / COUNT(*), 2) as error_rate
        FROM request_logs
        WHERE service_name IS NOT NULL
        GROUP BY service_name
        ORDER BY total_requests DESC
    """).fetchall()

    # Overall stats
    overall = db.execute("""
        SELECT
            COUNT(*) as total_requests,
            ROUND(AVG(latency_ms), 2) as avg_latency_ms,
            SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) as error_count
        FROM request_logs
    """).fetchone()

    # Requests per hour (last 24 hours)
    hourly = db.execute("""
        SELECT
            strftime('%Y-%m-%d %H:00', request_timestamp) as hour,
            COUNT(*) as count
        FROM request_logs
        WHERE request_timestamp >= datetime('now', '-24 hours')
        GROUP BY hour
        ORDER BY hour
    """).fetchall()

    # Top methods
    methods = db.execute("""
        SELECT method, COUNT(*) as count
        FROM request_logs
        GROUP BY method
        ORDER BY count DESC
    """).fetchall()

    return jsonify({
        "per_service": [dict(r) for r in per_service],
        "overall": dict(overall) if overall else {},
        "hourly": [dict(r) for r in hourly],
        "methods": [dict(r) for r in methods],
    }), 200


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.route("/")
def landing():
    """Serve the public arivumaiyam.com landing page."""
    return render_template("landing.html")


@app.route("/admin")
def dashboard():
    """Serve the gateway admin dashboard."""
    return render_template("index.html")


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/") or request.path.startswith("/gateway/"):
        return jsonify({"error": "Not found"}), 404
    return render_template("landing.html"), 200


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405


@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error"}), 500


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

with app.app_context():
    init_db()


if __name__ == "__main__":
    print(f"Kaashmikhaa Gateway starting on port {PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true')
