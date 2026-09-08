from datetime import datetime
from pydantic import BaseModel, ConfigDict, EmailStr


class LoginRequest(BaseModel):
    """Schema for authentication login request payload."""

    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    """Schema for JWT authentication token response."""

    access_token: str
    token_type: str = "bearer"


class TargetCreate(BaseModel):
    """Schema for creating a new allow-listed target."""

    hostname_or_ip: str
    label: str


class TargetResponse(BaseModel):
    """Schema for returning allow-listed target information."""

    id: int
    hostname_or_ip: str
    label: str
    added_by_user_id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserResponse(BaseModel):
    """Schema for user response output."""

    id: int
    email: EmailStr
    role: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
