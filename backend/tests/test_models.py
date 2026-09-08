import os
import sys
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add parent directory to python path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database import Base
from models import AllowedTarget, Check, Policy, Scan, ScanResult, User
from scripts.seed_dev_data import seed_data


@pytest.fixture(scope="function")
def db_session():
    """Fixture providing an in-memory SQLite database session for model testing."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


def test_create_user_and_target(db_session):
    """Test creating a User and an associated AllowedTarget."""
    user = User(email="test@example.com", password_hash="hash123", role="admin")
    db_session.add(user)
    db_session.commit()

    target = AllowedTarget(
        hostname_or_ip="127.0.0.1", label="Localhost", added_by_user_id=user.id
    )
    db_session.add(target)
    db_session.commit()

    assert user.id is not None
    assert target.id is not None
    assert target.added_by_user.email == "test@example.com"
    assert len(user.allowed_targets) == 1


def test_policy_and_checks_relationships(db_session):
    """Test creating a Policy and linking multiple Check entries."""
    policy = Policy(
        name="Test Policy",
        description="Policy description",
        source="TEST-SRC",
        version="1.0",
    )
    db_session.add(policy)
    db_session.commit()

    check = Check(
        policy_id=policy.id,
        check_type="openscap_rule",
        expected_state="pass",
        risk_level="high",
        remediation_text="Fix issue",
    )
    db_session.add(check)
    db_session.commit()

    assert check.policy.name == "Test Policy"
    assert len(policy.checks) == 1


def test_scan_and_scan_results(db_session):
    """Test creating a Scan and linking ScanResult entries."""
    user = User(email="user@example.com", password_hash="hash", role="user")
    policy = Policy(name="Pol", description="Desc", source="SRC", version="1.0")
    db_session.add_all([user, policy])
    db_session.commit()

    target = AllowedTarget(
        hostname_or_ip="10.0.0.1", label="Target", added_by_user_id=user.id
    )
    check = Check(
        policy_id=policy.id,
        check_type="port_exposure",
        expected_state="closed",
        risk_level="low",
        remediation_text="Remediate",
    )
    db_session.add_all([target, check])
    db_session.commit()

    scan = Scan(
        target_id=target.id,
        requested_by_user_id=user.id,
        status="completed",
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


def test_seed_dev_data_script():
    """Test executing the seed_dev_data function against PostgreSQL."""
    seed_data()
    from database import SessionLocal

    session = SessionLocal()
    try:
        users_count = session.query(User).count()
        targets_count = session.query(AllowedTarget).count()
        policies_count = session.query(Policy).count()
        checks_count = session.query(Check).count()
        scans_count = session.query(Scan).count()
        results_count = session.query(ScanResult).count()

        assert users_count == 2
        assert targets_count == 2
        assert policies_count == 2
        assert checks_count == 2
        assert scans_count == 1
        assert results_count == 2
    finally:
        session.close()
