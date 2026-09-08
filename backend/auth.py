import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from database import get_db
from models import User

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security_scheme = HTTPBearer(auto_error=False)


def get_jwt_secret_key() -> str:
    """Retrieve and validate the JWT secret key from environment variables.

    Returns:
        str: Validated secret key string.

    Raises:
        ValueError: If JWT_SECRET_KEY is not set or empty in environment.
    """
    secret = os.getenv("JWT_SECRET_KEY")
    if not secret:
        raise ValueError("JWT_SECRET_KEY environment variable must be set")
    return secret


# Initial startup check to ensure fail-fast behavior if JWT_SECRET_KEY is missing
get_jwt_secret_key()


def hash_password(password: str) -> str:
    """Hash a plaintext password string using bcrypt.

    Args:
        password: Plaintext password.

    Returns:
        str: Bcrypt hashed password string.
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a stored bcrypt hash.

    Args:
        plain_password: Plaintext candidate password.
        hashed_password: Stored password hash.

    Returns:
        bool: True if candidate matches hash, False otherwise.
    """
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(
    data: Dict[str, Any], expires_delta: Optional[timedelta] = None
) -> str:
    """Create a signed JWT access token.

    Args:
        data: Claims dictionary to encode in token payload.
        expires_delta: Optional expiration duration override.

    Returns:
        str: Encoded JWT token string.
    """
    secret_key = get_jwt_secret_key()
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, secret_key, algorithm=ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decode and validate a JWT access token.

    Args:
        token: Encoded JWT string.

    Returns:
        Dict[str, Any]: Decoded payload dictionary.

    Raises:
        HTTPException: If token is invalid or expired.
    """
    secret_key = get_jwt_secret_key()
    try:
        payload = jwt.decode(token, secret_key, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    db: Session = Depends(get_db),
) -> User:
    """FastAPI dependency extracting and validating the authenticated user.

    Args:
        credentials: Bearer token header credentials.
        db: Database session.

    Returns:
        User: Authenticated User model instance.

    Raises:
        HTTPException: If unauthenticated, token invalid, or user not found.
    """
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(credentials.credentials)
    user_id: Optional[int] = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(User).filter(User.id == int(user_id)).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """FastAPI dependency enforcing admin role access.

    Args:
        current_user: Currently authenticated user.

    Returns:
        User: Admin user instance.

    Raises:
        HTTPException: If current user role is not 'admin'.
    """
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return current_user
