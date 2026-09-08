import os
import sys
from datetime import datetime, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Set environment variables for testing
os.environ.setdefault("POSTGRES_PASSWORD", "test_password")
os.environ.setdefault("JWT_SECRET_KEY", "test_jwt_secret_key_at_least_32_bytes_long")

from database import Base
from models import AllowedTarget, Check, Policy, Scan, ScanResult, User
from scripts.seed_dev_data import seed_data


@pytest.fixture
def db_session():
    """Create an in-memory SQLite database session fixture for testing."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()


def test_create_user(db_session):
    """Test creating a User model instance in the database."""
    user = User(
        email="testuser@example.com",
        password_hash="hashed_secret",
        role="user",
    )
    db_session.add(user)
    db_session.commit()

    saved_user = db_session.query(User).filter_by(email="testuser@example.com").first()
    assert saved_user is not None
    assert saved_user.id is not None
    assert saved_user.role == "user"


def test_create_allowed_target(db_session):
    """Test creating an AllowedTarget linked to a User."""
    user = User(
        email="admin@example.com",
        password_hash="hashed_secret",
        role="admin",
    )
    db_session.add(user)
    db_session.commit()

    target = AllowedTarget(
        hostname_or_ip="10.0.0.1",
        label="Test Host",
        added_by_user_id=user.id,
    )
    db_session.add(target)
    db_session.commit()

    saved_target = db_session.query(AllowedTarget).filter_by(hostname_or_ip="10.0.0.1").first()
    assert saved_target is not None
    assert saved_target.added_by_user.email == "admin@example.com"


def test_policy_and_checks(db_session):
    """Test creating Policy and Check models with relationship."""
    policy = Policy(
        name="Test Policy",
        description="Policy description",
        source="NIST-800-53",
        version="1.0",
    )
    db_session.add(policy)
    db_session.commit()

    check = Check(
        policy_id=policy.id,
        check_type="openscap_rule",
        expected_state="pass",
        risk_level="high",
        remediation_text="Fix settings",
    )
    db_session.add(check)
    db_session.commit()

    assert len(policy.checks) == 1
    assert policy.checks[0].check_type == "openscap_rule"


def test_scan_and_scan_results(db_session):
    """Test creating Scan and ScanResult models."""
    user = User(email="usr@example.com", password_hash="hash", role="user")
    db_session.add(user)
    db_session.commit()

    target = AllowedTarget(hostname_or_ip="192.168.1.1", label="Web", added_by_user_id=user.id)
    db_session.add(target)
    db_session.commit()

    policy = Policy(name="P1", description="D1", source="S1", version="1")
    db_session.add(policy)
    db_session.commit()

    check = Check(
        policy_id=policy.id,
        check_type="port_exposure",
        expected_state="closed",
        risk_level="low",
        remediation_text="Close port",
    )
    db_session.add(check)
    db_session.commit()

    now = datetime.now(timezone.utc)
    scan = Scan(
        target_id=target.id,
        requested_by_user_id=user.id,
        status="completed",
        queued_at=now,
    )
    db_session.add(scan)
    db_session.commit()

    scan_result = ScanResult(
        scan_id=scan.id,
        check_id=check.id,
        raw_output="raw",
        status="compliant",
        severity="low",
    )
    db_session.add(scan_result)
    db_session.commit()

    assert scan_result.scan.status == "completed"
    assert scan_result.check.check_type == "port_exposure"


def test_seed_dev_data_script(db_session):
    """Test executing the seed_dev_data function against database session."""
    seed_data(db=db_session)

    users_count = db_session.query(User).count()
    targets_count = db_session.query(AllowedTarget).count()
    policies_count = db_session.query(Policy).count()
    checks_count = db_session.query(Check).count()
    scans_count = db_session.query(Scan).count()
    results_count = db_session.query(ScanResult).count()

    assert users_count == 2
    assert targets_count == 2
    assert policies_count == 2
    assert checks_count == 2
    assert scans_count == 1
    assert results_count == 2
