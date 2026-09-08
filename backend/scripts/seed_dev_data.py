import os
import sys
from datetime import datetime, timezone

# Add parent directory to python path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database import SessionLocal
from models import AllowedTarget, Check, Policy, Scan, ScanResult, User


def seed_data() -> None:
    """Populate the database with realistic dev-only initial test data.

    Clears existing records in reverse dependency order and inserts
    sample entries for users, allowed targets, policies, checks, scans,
    and scan results.
    """
    db = SessionLocal()
    try:
        # Clear existing data for clean seed execution
        db.query(ScanResult).delete()
        db.query(Scan).delete()
        db.query(Check).delete()
        db.query(Policy).delete()
        db.query(AllowedTarget).delete()
        db.query(User).delete()
        db.commit()

        # 1. Users
        admin_user = User(
            email="admin@example.com",
            password_hash="$2b$12$e86R0...fake_admin_hash",
            role="admin",
        )
        normal_user = User(
            email="user@example.com",
            password_hash="$2b$12$f97S1...fake_user_hash",
            role="user",
        )
        db.add_all([admin_user, normal_user])
        db.commit()

        # 2. Allowed Targets
        target1 = AllowedTarget(
            hostname_or_ip="192.168.1.100",
            label="Internal Web Server",
            added_by_user_id=admin_user.id,
        )
        target2 = AllowedTarget(
            hostname_or_ip="10.0.0.50",
            label="Database Host",
            added_by_user_id=admin_user.id,
        )
        db.add_all([target1, target2])
        db.commit()

        # 3. Policies
        policy1 = Policy(
            name="NIST SP 800-53 AC-2 Account Management",
            description="Controls governing account management, authorization, and lifecycle.",
            source="NIST-800-53-AC2",
            version="1.0",
        )
        policy2 = Policy(
            name="CIS Benchmark Level 1 Server Baseline",
            description="General baseline configuration for hardened Linux servers.",
            source="CIS-Benchmark-v8",
            version="2.0",
        )
        db.add_all([policy1, policy2])
        db.commit()

        # 4. Checks
        check1 = Check(
            policy_id=policy1.id,
            check_type="openscap_rule",
            expected_state="pass",
            risk_level="high",
            remediation_text="Ensure inactive accounts are disabled after 90 days in /etc/default/useradd.",
        )
        check2 = Check(
            policy_id=policy2.id,
            check_type="port_exposure",
            expected_state="closed",
            risk_level="medium",
            remediation_text="Close port 21/tcp (FTP) or replace with SFTP/SSH.",
        )
        db.add_all([check1, check2])
        db.commit()

        # 5. Scans
        now = datetime.now(timezone.utc)
        scan1 = Scan(
            target_id=target1.id,
            requested_by_user_id=normal_user.id,
            status="completed",
            queued_at=now,
            started_at=now,
            completed_at=now,
        )
        db.add(scan1)
        db.commit()

        # 6. Scan Results
        res1 = ScanResult(
            scan_id=scan1.id,
            check_id=check1.id,
            raw_output="Rule xccdf_org.ssgproject.content_rule_account_disable_post_pw_expiration: Pass",
            status="compliant",
            severity="high",
            evaluated_at=now,
        )
        res2 = ScanResult(
            scan_id=scan1.id,
            check_id=check2.id,
            raw_output="Port 21/tcp filtered or open",
            status="non_compliant",
            severity="medium",
            evaluated_at=now,
        )
        db.add_all([res1, res2])
        db.commit()

        print("Dev test data successfully seeded.")
    except Exception as e:
        db.rollback()
        print(f"Error seeding database: {e}")
        raise e
    finally:
        db.close()


if __name__ == "__main__":
    seed_data()
