from fastapi import FastAPI
from pydantic import BaseModel

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
