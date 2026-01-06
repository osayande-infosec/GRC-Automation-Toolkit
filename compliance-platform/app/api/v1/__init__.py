"""
API v1 Router - Aggregates all endpoint routers
"""

from fastapi import APIRouter

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

router = APIRouter()

# Include all endpoint routers
router.include_router(credentials.router, prefix="/credentials", tags=["Credential Auditing"])
router.include_router(assets.router, prefix="/assets", tags=["Asset Management"])
router.include_router(logs.router, prefix="/logs", tags=["Security Logs"])
router.include_router(vulnerabilities.router, prefix="/vulnerabilities", tags=["Vulnerability Management"])
router.include_router(compliance.router, prefix="/compliance", tags=["Compliance Tracking"])
router.include_router(risks.router, prefix="/risks", tags=["Risk Management"])
router.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard"])
router.include_router(integrations.router, prefix="/integrations", tags=["Integrations"])
