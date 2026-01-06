"""API Endpoints module."""

from app.api.v1.endpoints import (
    credentials,
    assets,
    logs,
    vulnerabilities,
    compliance,
    risks,
    dashboard,
    integrations,
)

__all__ = [
    "credentials",
    "assets",
    "logs",
    "vulnerabilities",
    "compliance",
    "risks",
    "dashboard",
    "integrations",
]
