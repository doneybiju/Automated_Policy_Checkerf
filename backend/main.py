from typing import List

from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from auth import (
    create_access_token,
    get_current_user,
    require_admin,
    verify_password,
)
from database import get_db
from models import AllowedTarget, User
from schemas import (
    LoginRequest,
    TargetCreate,
    TargetResponse,
    TokenResponse,
)

app = FastAPI(title="Automated Security Policy Compliance Checker API")


class HealthResponse(BaseModel):
    """Schema for the health check endpoint response."""

    status: str


@app.get("/health", response_model=HealthResponse)
def health_check() -> HealthResponse:
    """Check the health status of the API backend service.

    Returns:
        HealthResponse: A Pydantic model containing the status string "ok".
    """
    return HealthResponse(status="ok")


@app.post("/auth/login", response_model=TokenResponse)
def login(
    login_data: LoginRequest, db: Session = Depends(get_db)
) -> TokenResponse:
    """Authenticate a user and issue a JWT access token.

    Args:
        login_data: Pydantic model containing user email and password.
        db: SQLAlchemy database session.

    Returns:
        TokenResponse: Access token string and token type.

    Raises:
        HTTPException: 401 Unauthorized if email or password is invalid.
    """
    user = db.query(User).filter(User.email == login_data.email).first()
    if not user or not verify_password(login_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(data={"sub": user.email, "role": user.role})
    return TokenResponse(access_token=access_token, token_type="bearer")


@app.get("/targets", response_model=List[TargetResponse])
def get_targets(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> List[TargetResponse]:
    """Retrieve all allow-listed targets available for scanning.

    Args:
        db: SQLAlchemy database session.
        current_user: Authenticated User object.

    Returns:
        List[TargetResponse]: List of allow-listed target records.
    """
    targets = db.query(AllowedTarget).all()
    return targets


@app.post(
    "/targets",
    response_model=TargetResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_target(
    target_data: TargetCreate,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_admin),
) -> TargetResponse:
    """Add a new target host to the allow-list (Admin only).

    Args:
        target_data: Pydantic model containing target hostname/IP and label.
        db: SQLAlchemy database session.
        admin_user: Authenticated User object with admin role.

    Returns:
        TargetResponse: Created target record details.
    """
    new_target = AllowedTarget(
        hostname_or_ip=target_data.hostname_or_ip,
        label=target_data.label,
        added_by_user_id=admin_user.id,
    )
    db.add(new_target)
    db.commit()
    db.refresh(new_target)
    return new_target
