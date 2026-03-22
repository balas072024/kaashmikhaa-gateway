"""
Tests for Kaashmikhaa Gateway API.
Run with: pytest tests/test_api.py -v
"""

import os
import sys
import json
import tempfile
import pytest

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, init_db


@pytest.fixture
def client():
    """Create a test client with a fresh temporary database."""
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    app.config["DATABASE"] = db_path
    app.config["TESTING"] = True
    app.config["RATE_LIMIT_PER_MINUTE"] = 1000  # generous for tests

    with app.app_context():
        init_db()

    with app.test_client() as client:
        yield client

    os.close(db_fd)
    os.unlink(db_path)


def register_user(client, username="testuser", password="testpass123", role="admin"):
    """Helper to register a user and return the response."""
    return client.post("/api/auth/register", json={
        "username": username,
        "password": password,
        "role": role,
    })


def get_token(client, username="testuser", password="testpass123", role="admin"):
    """Helper to register a user and return the JWT token."""
    resp = register_user(client, username, password, role)
    return json.loads(resp.data)["token"]


def auth_headers(token):
    """Return Authorization headers for a given token."""
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


# ---- Auth Tests ----

def test_register_success(client):
    resp = register_user(client)
    data = json.loads(resp.data)
    assert resp.status_code == 201
    assert "token" in data
    assert data["username"] == "testuser"
    assert data["role"] == "admin"


def test_register_duplicate_username(client):
    register_user(client)
    resp = register_user(client)
    assert resp.status_code == 409
    assert "already exists" in json.loads(resp.data)["error"]


def test_register_missing_fields(client):
    resp = client.post("/api/auth/register", json={"username": "", "password": ""})
    assert resp.status_code == 400


def test_register_short_password(client):
    resp = client.post("/api/auth/register", json={"username": "user1", "password": "12345"})
    assert resp.status_code == 400
    assert "at least 6" in json.loads(resp.data)["error"]


def test_register_invalid_role(client):
    resp = client.post("/api/auth/register", json={
        "username": "badrole", "password": "password123", "role": "superadmin",
    })
    assert resp.status_code == 400
    assert "Role" in json.loads(resp.data)["error"]


def test_login_missing_fields(client):
    resp = client.post("/api/auth/login", json={})
    assert resp.status_code == 400
    assert "required" in json.loads(resp.data)["error"].lower()


def test_login_success(client):
    register_user(client)
    resp = client.post("/api/auth/login", json={"username": "testuser", "password": "testpass123"})
    data = json.loads(resp.data)
    assert resp.status_code == 200
    assert "token" in data
    assert data["username"] == "testuser"


def test_login_invalid_password(client):
    register_user(client)
    resp = client.post("/api/auth/login", json={"username": "testuser", "password": "wrongpassword"})
    assert resp.status_code == 401
    assert "Invalid credentials" in json.loads(resp.data)["error"]


def test_login_nonexistent_user(client):
    resp = client.post("/api/auth/login", json={"username": "ghost", "password": "password123"})
    assert resp.status_code == 401


def test_auth_me(client):
    token = get_token(client)
    resp = client.get("/api/auth/me", headers=auth_headers(token))
    data = json.loads(resp.data)
    assert resp.status_code == 200
    assert data["user"]["username"] == "testuser"


def test_auth_no_token(client):
    resp = client.get("/api/auth/me")
    assert resp.status_code == 401


def test_auth_invalid_token(client):
    resp = client.get("/api/auth/me", headers={"Authorization": "Bearer invalid.token.here"})
    assert resp.status_code == 401


# ---- Service Registry Tests ----

def test_add_service(client):
    token = get_token(client)
    resp = client.post("/api/services", headers=auth_headers(token), json={
        "name": "user-service",
        "url": "http://localhost:5001",
        "prefix": "/users",
        "description": "User management",
    })
    data = json.loads(resp.data)
    assert resp.status_code == 201
    assert "service_id" in data


def test_list_services(client):
    token = get_token(client)
    client.post("/api/services", headers=auth_headers(token), json={
        "name": "svc-a", "url": "http://localhost:5001", "prefix": "/a",
    })
    client.post("/api/services", headers=auth_headers(token), json={
        "name": "svc-b", "url": "http://localhost:5002", "prefix": "/b",
    })
    resp = client.get("/api/services", headers=auth_headers(token))
    data = json.loads(resp.data)
    assert resp.status_code == 200
    assert len(data["services"]) == 2


def test_add_service_duplicate(client):
    token = get_token(client)
    payload = {"name": "dup-service", "url": "http://localhost:5001", "prefix": "/dup"}
    client.post("/api/services", headers=auth_headers(token), json=payload)
    resp = client.post("/api/services", headers=auth_headers(token), json=payload)
    assert resp.status_code == 409


def test_remove_service(client):
    token = get_token(client)
    resp = client.post("/api/services", headers=auth_headers(token), json={
        "name": "removable", "url": "http://localhost:5001", "prefix": "/rm",
    })
    sid = json.loads(resp.data)["service_id"]
    resp = client.delete(f"/api/services/{sid}", headers=auth_headers(token))
    assert resp.status_code == 200
    # Verify it's gone
    resp = client.get("/api/services", headers=auth_headers(token))
    names = [s["name"] for s in json.loads(resp.data)["services"]]
    assert "removable" not in names


def test_remove_nonexistent_service(client):
    token = get_token(client)
    resp = client.delete("/api/services/9999", headers=auth_headers(token))
    assert resp.status_code == 404


def test_non_admin_cannot_add_service(client):
    token = get_token(client, username="regular", password="testpass123", role="user")
    resp = client.post("/api/services", headers=auth_headers(token), json={
        "name": "forbidden", "url": "http://localhost:5001", "prefix": "/nope",
    })
    assert resp.status_code == 403


def test_add_service_missing_fields(client):
    token = get_token(client)
    resp = client.post("/api/services", headers=auth_headers(token), json={
        "name": "incomplete",
    })
    assert resp.status_code == 400
    assert "required" in json.loads(resp.data)["error"]


# ---- Health Check Tests ----

def test_gateway_health(client):
    resp = client.get("/api/health")
    data = json.loads(resp.data)
    assert resp.status_code == 200
    assert data["status"] == "healthy"
    assert data["service"] == "kaashmikhaa-gateway"


def test_health_services_empty(client):
    token = get_token(client)
    resp = client.get("/api/health/services", headers=auth_headers(token))
    data = json.loads(resp.data)
    assert resp.status_code == 200
    assert data["all_healthy"] is True
    assert len(data["services"]) == 0


# ---- Analytics & Logs Tests ----

def test_analytics_empty(client):
    token = get_token(client)
    resp = client.get("/api/analytics", headers=auth_headers(token))
    data = json.loads(resp.data)
    assert resp.status_code == 200
    assert "per_service" in data
    assert "overall" in data


def test_logs_empty(client):
    token = get_token(client)
    resp = client.get("/api/logs", headers=auth_headers(token))
    data = json.loads(resp.data)
    assert resp.status_code == 200
    assert data["logs"] == []


def test_logs_requires_auth(client):
    resp = client.get("/api/logs")
    assert resp.status_code == 401


def test_analytics_requires_auth(client):
    resp = client.get("/api/analytics")
    assert resp.status_code == 401


# ---- Gateway Proxy Tests ----

def test_gateway_no_matching_service(client):
    token = get_token(client)
    resp = client.get("/gateway/nonexistent/path", headers=auth_headers(token))
    assert resp.status_code == 404
    assert "No service matched" in json.loads(resp.data)["error"]


# ---- Dashboard Test ----

def test_dashboard_returns_html(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Kaashmikhaa" in resp.data
    assert b"Gateway" in resp.data


# ---- Update Service Test ----

def test_update_service(client):
    token = get_token(client)
    resp = client.post("/api/services", headers=auth_headers(token), json={
        "name": "updatable", "url": "http://localhost:5001", "prefix": "/upd",
    })
    sid = json.loads(resp.data)["service_id"]
    resp = client.put(f"/api/services/{sid}", headers=auth_headers(token), json={
        "description": "Updated description",
    })
    assert resp.status_code == 200
    # Verify update
    resp = client.get("/api/services", headers=auth_headers(token))
    svc = [s for s in json.loads(resp.data)["services"] if s["name"] == "updatable"][0]
    assert svc["description"] == "Updated description"
