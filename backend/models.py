from datetime import datetime
from typing import List, Optional
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


class User(Base):
    """User account model for system access and role tracking.

    Attributes:
        id: Primary key integer.
        email: Unique user email address.
        password_hash: Hashed password string.
        role: User access role (e.g., 'admin', 'user').
        created_at: Timestamp of account creation.
    """

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    allowed_targets: Mapped[List["AllowedTarget"]] = relationship(
        "AllowedTarget", back_populates="added_by_user"
    )
    scans: Mapped[List["Scan"]] = relationship("Scan", back_populates="requested_by_user")


class AllowedTarget(Base):
    """Allow-listed host target eligible for scanning.

    Attributes:
        id: Primary key integer.
        hostname_or_ip: Hostname or IP address of the target host.
        label: Descriptive label for the target host.
        added_by_user_id: Foreign key linking to the creating user.
        created_at: Timestamp when target was added.
    """

    __tablename__ = "allowed_targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    hostname_or_ip: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    added_by_user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    added_by_user: Mapped["User"] = relationship("User", back_populates="allowed_targets")
    scans: Mapped[List["Scan"]] = relationship("Scan", back_populates="target")


class Policy(Base):
    """Security compliance policy definition.

    Attributes:
        id: Primary key integer.
        name: Name of the policy.
        description: Detailed summary of policy objectives.
        source: Source baseline identifier (e.g. NIST-800-53-AC2, CIS-Benchmark-v8).
        version: Policy revision/version string.
        created_at: Timestamp of policy creation.
    """

    __tablename__ = "policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(50), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    checks: Mapped[List["Check"]] = relationship("Check", back_populates="policy")


class Check(Base):
    """Individual security rule or check item associated with a policy.

    Attributes:
        id: Primary key integer.
        policy_id: Foreign key linking to the parent policy.
        check_type: Category of check (openscap_rule | port_exposure | service_check).
        expected_state: Target state requirement.
        risk_level: Risk classification.
        remediation_text: Instructions to remediate non-compliance.
    """

    __tablename__ = "checks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    policy_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("policies.id", ondelete="CASCADE"), nullable=False
    )
    check_type: Mapped[str] = mapped_column(String(50), nullable=False)
    expected_state: Mapped[str] = mapped_column(Text, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(50), nullable=False)
    remediation_text: Mapped[str] = mapped_column(Text, nullable=False)

    policy: Mapped["Policy"] = relationship("Policy", back_populates="checks")
    scan_results: Mapped[List["ScanResult"]] = relationship("ScanResult", back_populates="check")


class Scan(Base):
    """Scan job execution record.

    Attributes:
        id: Primary key integer.
        target_id: Foreign key linking to the target host.
        requested_by_user_id: Foreign key linking to requesting user.
        status: Execution status (queued | running | completed | failed).
        queued_at: Timestamp when scan was enqueued.
        started_at: Timestamp when scan execution began.
        completed_at: Timestamp when scan finished.
    """

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    target_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("allowed_targets.id", ondelete="CASCADE"), nullable=False
    )
    requested_by_user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    queued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    target: Mapped["AllowedTarget"] = relationship("AllowedTarget", back_populates="scans")
    requested_by_user: Mapped["User"] = relationship("User", back_populates="scans")
    scan_results: Mapped[List["ScanResult"]] = relationship("ScanResult", back_populates="scan")


class ScanResult(Base):
    """Compliance result entry for a specific check within a scan.

    Attributes:
        id: Primary key integer.
        scan_id: Foreign key linking to the scan job.
        check_id: Foreign key linking to the evaluated check.
        raw_output: Raw output returned by scanner engine.
        status: Compliance state (compliant | non_compliant | warning | error).
        severity: Result severity string.
        evaluated_at: Timestamp when check result was evaluated.
    """

    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    check_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("checks.id", ondelete="CASCADE"), nullable=False
    )
    raw_output: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(50), nullable=False)
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="scan_results")
    check: Mapped["Check"] = relationship("Check", back_populates="scan_results")
