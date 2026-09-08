import os
import sys
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Set environment variables for testing
os.environ.setdefault("POSTGRES_PASSWORD", "change_me_password")
os.environ.setdefault("JWT_SECRET_KEY", "test_jwt_secret_key_1234567890")

from auth import hash_password
from database import Base, get_db
from main import app
from models import User

engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    """Override database session dependency using shared in-memory SQLite for tests."""
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_database():
    """Fixture resetting database schema before each test function."""
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        # Seed test admin and user
        admin = User(
            email="admin@test.com",
            password_hash=hash_password("adminpass"),
            role="admin",
        )
        user = User(
            email="user@test.com",
            password_hash=hash_password("userpass"),
            role="user",
        )
        db.add_all([admin, user])
        db.commit()
    finally:
        db.close()
    yield
    Base.metadata.drop_all(bind=engine)


def test_missing_jwt_secret_raises_error():
    """Verify that backend/auth.py raises ValueError if JWT_SECRET_KEY is missing."""
    old_val = os.environ.get("JWT_SECRET_KEY")
    try:
        if "JWT_SECRET_KEY" in os.environ:
            del os.environ["JWT_SECRET_KEY"]
        with pytest.raises(
            ValueError, match="JWT_SECRET_KEY environment variable must be set"
        ):
            import importlib
            import auth

            importlib.reload(auth)
    finally:
        if old_val:
            os.environ["JWT_SECRET_KEY"] = old_val


def test_login_success():
    """Verify POST /auth/login returns a valid JWT token on correct credentials."""
    response = client.post(
        "/auth/login",
        json={"email": "admin@test.com", "password": "adminpass"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_login_invalid_credentials():
    """Verify POST /auth/login returns 401 Unauthorized on wrong password or email."""
    response = client.post(
        "/auth/login",
        json={"email": "admin@test.com", "password": "wrongpassword"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect email or password"


def test_unauthenticated_request_rejected():
    """Verify unauthenticated GET /targets request is rejected with HTTP 401."""
    response = client.get("/targets")
    assert response.status_code == 401


def test_authenticated_user_can_get_targets():
    """Verify authenticated non-admin user can access GET /targets."""
    login_resp = client.post(
        "/auth/login",
        json={"email": "user@test.com", "password": "userpass"},
    )
    token = login_resp.json()["access_token"]

    response = client.get(
        "/targets",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_non_admin_cannot_post_targets():
    """Verify non-admin user receives HTTP 403 Forbidden when attempting POST /targets."""
    login_resp = client.post(
        "/auth/login",
        json={"email": "user@test.com", "password": "userpass"},
    )
    token = login_resp.json()["access_token"]

    response = client.post(
        "/targets",
        headers={"Authorization": f"Bearer {token}"},
        json={"hostname_or_ip": "192.168.1.50", "label": "Test Host"},
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Admin privileges required"


def test_admin_can_post_and_get_targets():
    """Verify admin user can POST /targets to add an allow-listed target host."""
    login_resp = client.post(
        "/auth/login",
        json={"email": "admin@test.com", "password": "adminpass"},
    )
    token = login_resp.json()["access_token"]

    post_resp = client.post(
        "/targets",
        headers={"Authorization": f"Bearer {token}"},
        json={"hostname_or_ip": "10.0.0.100", "label": "Production DB"},
    )
    assert post_resp.status_code == 201
    data = post_resp.json()
    assert data["hostname_or_ip"] == "10.0.0.100"
    assert data["label"] == "Production DB"

    get_resp = client.get(
        "/targets",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert get_resp.status_code == 200
    targets = get_resp.json()
    assert len(targets) == 1
    assert targets[0]["hostname_or_ip"] == "10.0.0.100"
