from datetime import datetime
from pydantic import BaseModel, EmailStr, ConfigDict


class LoginRequest(BaseModel):
    """Schema for authentication login request body."""

    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    """Schema for JWT authentication token response."""

    access_token: str
    token_type: str = "bearer"


class TargetCreate(BaseModel):
    """Schema for adding a new target host to the allow-list."""

    hostname_or_ip: str
    label: str


class TargetResponse(BaseModel):
    """Schema for target host API responses."""

    id: int
    hostname_or_ip: str
    label: str
    added_by_user_id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
