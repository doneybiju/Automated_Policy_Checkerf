from typing import List

from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from auth import create_access_token, get_current_user, require_admin, verify_password
from database import get_db
from models import AllowedTarget, User
from schemas import LoginRequest, TargetCreate, TargetResponse, TokenResponse

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
def login(request: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    """Authenticate user credentials and issue a JWT access token.

    Args:
        request: Login payload containing email and password.
        db: Database session.

    Returns:
        TokenResponse: Access token string and bearer token type.

    Raises:
        HTTPException: If user is not found or password is invalid.
    """
    user = db.query(User).filter(User.email == request.email).first()
    if user is None or not verify_password(request.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )

    access_token = create_access_token(data={"sub": str(user.id), "role": user.role})
    return TokenResponse(access_token=access_token, token_type="bearer")


@app.get("/targets", response_model=List[TargetResponse])
def list_targets(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> List[TargetResponse]:
    """Retrieve all allow-listed targets. Accessible to any authenticated user.

    Args:
        db: Database session.
        current_user: Authenticated user model.

    Returns:
        List[TargetResponse]: List of target host records.
    """
    targets = db.query(AllowedTarget).all()
    return [TargetResponse.model_validate(t) for t in targets]


@app.post(
    "/targets",
    response_model=TargetResponse,
    status_code=status.HTTP_201_CREATED,
)
def add_target(
    request: TargetCreate,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_admin),
) -> TargetResponse:
    """Add a new target host to the allow-list. Restricted to admin users only.

    Args:
        request: Target creation payload with hostname_or_ip and label.
        db: Database session.
        admin_user: Authenticated admin user model.

    Returns:
        TargetResponse: Created target host record.
    """
    target = AllowedTarget(
        hostname_or_ip=request.hostname_or_ip,
        label=request.label,
        added_by_user_id=admin_user.id,
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    return TargetResponse.model_validate(target)
