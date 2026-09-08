import os
import sys
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Set environment variables for testing before importing modules
os.environ.setdefault("POSTGRES_PASSWORD", "test_password")
os.environ.setdefault("JWT_SECRET_KEY", "test_jwt_secret_key_at_least_32_bytes_long")

from auth import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from database import Base, get_db
from main import app
from models import User


@pytest.fixture
def db_session():
    """Create an in-memory SQLite database session fixture for testing."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestingSessionLocal = sessionmaker(
        autocommit=False, autoflush=False, bind=engine
    )
    session = TestingSessionLocal()

    # Create admin user
    admin_user = User(
        email="admin@example.com",
        password_hash=hash_password("adminpass"),
        role="admin",
    )
    # Create normal user
    normal_user = User(
        email="user@example.com",
        password_hash=hash_password("userpass"),
        role="user",
    )
    session.add_all([admin_user, normal_user])
    session.commit()

    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client(db_session):
    """Provide a TestClient with database session override."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    test_client = TestClient(app)
    yield test_client
    app.dependency_overrides.clear()


def test_password_hashing():
    """Test hashing and verifying passwords."""
    password = "MySecurePassword123"
    hashed = hash_password(password)

    assert hashed != password
    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword", hashed) is False


def test_jwt_token_generation_and_decoding():
    """Test creating and decoding JWT access tokens."""
    payload_data = {"sub": "test@example.com", "role": "admin"}
    token = create_access_token(payload_data)

    decoded = decode_access_token(token)
    assert decoded["sub"] == "test@example.com"
    assert decoded["role"] == "admin"


def test_missing_jwt_secret_key(monkeypatch):
    """Test that missing JWT_SECRET_KEY raises a startup ValueError."""
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    import importlib
    import auth

    with pytest.raises(ValueError, match="JWT_SECRET_KEY environment variable must be set"):
        importlib.reload(auth)

    # Restore JWT_SECRET_KEY environment variable and reload auth module
    monkeypatch.setenv("JWT_SECRET_KEY", "test_jwt_secret_key_at_least_32_bytes_long")
    importlib.reload(auth)


def test_login_success(client):
    """Test successful login with correct credentials."""
    response = client.post(
        "/auth/login",
        json={"email": "admin@example.com", "password": "adminpass"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_login_invalid_password(client):
    """Test login failure with incorrect password."""
    response = client.post(
        "/auth/login",
        json={"email": "admin@example.com", "password": "wrongpassword"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password"


def test_login_nonexistent_user(client):
    """Test login failure with unknown email."""
    response = client.post(
        "/auth/login",
        json={"email": "unknown@example.com", "password": "somepassword"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password"


def test_unauthenticated_requests_rejected(client):
    """Test that unauthenticated requests to protected endpoints return 401."""
    response_get = client.get("/targets")
    assert response_get.status_code == 401

    response_post = client.post(
        "/targets",
        json={"hostname_or_ip": "192.168.1.1", "label": "Test Host"},
    )
    assert response_post.status_code == 401


def test_non_admin_cannot_post_target(client):
    """Test that a non-admin user cannot POST /targets (403 Forbidden)."""
    # Login as normal user
    login_resp = client.post(
        "/auth/login",
        json={"email": "user@example.com", "password": "userpass"},
    )
    token = login_resp.json()["access_token"]

    headers = {"Authorization": f"Bearer {token}"}
    response = client.post(
        "/targets",
        json={"hostname_or_ip": "192.168.1.10", "label": "Web Server"},
        headers=headers,
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Admin access required"


def test_admin_can_post_target_and_user_can_get_targets(client):
    """Test that admin can add targets and non-admin can list targets."""
    # Login as admin
    admin_login = client.post(
        "/auth/login",
        json={"email": "admin@example.com", "password": "adminpass"},
    )
    admin_token = admin_login.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Admin creates target
    create_resp = client.post(
        "/targets",
        json={"hostname_or_ip": "10.0.0.5", "label": "Database Host"},
        headers=admin_headers,
    )
    assert create_resp.status_code == 201
    created_target = create_resp.json()
    assert created_target["hostname_or_ip"] == "10.0.0.5"
    assert created_target["label"] == "Database Host"

    # Normal user logs in and lists targets
    user_login = client.post(
        "/auth/login",
        json={"email": "user@example.com", "password": "userpass"},
    )
    user_token = user_login.json()["access_token"]
    user_headers = {"Authorization": f"Bearer {user_token}"}

    get_resp = client.get("/targets", headers=user_headers)
    assert get_resp.status_code == 200
    targets_list = get_resp.json()
    assert len(targets_list) == 1
    assert targets_list[0]["hostname_or_ip"] == "10.0.0.5"
