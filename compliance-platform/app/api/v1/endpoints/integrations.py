"""
Integrations API Endpoints
--------------------------
Third-party service integrations (AWS, Okta, GitHub, etc.)
"""

from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from enum import Enum

from app.core.security import get_current_user, require_role, TokenData

router = APIRouter()


class IntegrationProvider(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    OKTA = "okta"
    AZURE_AD = "azure_ad"
    GITHUB = "github"
    GITLAB = "gitlab"
    JIRA = "jira"
    SLACK = "slack"
    QUALYS = "qualys"
    TENABLE = "tenable"
    CROWDSTRIKE = "crowdstrike"


class IntegrationStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    PENDING = "pending"


class IntegrationCreate(BaseModel):
    """Create integration request."""
    provider: IntegrationProvider
    name: str
    credentials: dict  # Provider-specific credentials
    settings: dict = {}


class IntegrationResponse(BaseModel):
    """Integration response."""
    id: str
    provider: IntegrationProvider
    name: str
    status: IntegrationStatus
    last_sync: Optional[datetime]
    next_sync: Optional[datetime]
    sync_frequency_hours: int
    error_message: Optional[str]
    evidence_collected: int
    created_at: datetime


class EvidenceCollection(BaseModel):
    """Evidence collection result."""
    integration_id: str
    provider: str
    collected_at: datetime
    controls_updated: int
    evidence_items: List[dict]
    errors: List[str]


# In-memory storage
_integrations_db: dict = {}


# Provider configurations
PROVIDER_CONFIGS = {
    IntegrationProvider.AWS: {
        "name": "Amazon Web Services",
        "category": "cloud",
        "required_credentials": ["access_key_id", "secret_access_key", "region"],
        "evidence_types": ["s3_encryption", "iam_mfa", "cloudtrail_enabled", "vpc_flow_logs"],
        "docs_url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
    },
    IntegrationProvider.OKTA: {
        "name": "Okta",
        "category": "identity",
        "required_credentials": ["domain", "api_token"],
        "evidence_types": ["mfa_enrollment", "password_policy", "user_status", "app_assignments"],
        "docs_url": "https://developer.okta.com/docs/guides/create-an-api-token/",
    },
    IntegrationProvider.GITHUB: {
        "name": "GitHub",
        "category": "devops",
        "required_credentials": ["token", "organization"],
        "evidence_types": ["branch_protection", "security_advisories", "dependabot_alerts", "code_scanning"],
        "docs_url": "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens",
    },
    IntegrationProvider.AZURE: {
        "name": "Microsoft Azure",
        "category": "cloud",
        "required_credentials": ["tenant_id", "client_id", "client_secret", "subscription_id"],
        "evidence_types": ["storage_encryption", "key_vault", "network_security_groups", "defender_status"],
        "docs_url": "https://learn.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal",
    },
}


@router.get("/providers")
async def list_providers():
    """List available integration providers."""
    providers = []
    for provider, config in PROVIDER_CONFIGS.items():
        providers.append({
            "id": provider.value,
            "name": config["name"],
            "category": config["category"],
            "evidence_types": config["evidence_types"],
            "docs_url": config["docs_url"],
        })
    return {"providers": providers}


@router.post("/", response_model=IntegrationResponse)
async def create_integration(
    integration: IntegrationCreate,
    current_user: TokenData = Depends(require_role(["admin"])),
):
    """
    Create a new integration.
    
    Requires admin role.
    """
    # Validate provider
    if integration.provider not in PROVIDER_CONFIGS:
        raise HTTPException(status_code=400, detail="Unsupported provider")
    
    config = PROVIDER_CONFIGS[integration.provider]
    
    # Validate required credentials
    for cred in config["required_credentials"]:
        if cred not in integration.credentials:
            raise HTTPException(
                status_code=400,
                detail=f"Missing required credential: {cred}"
            )
    
    # Create integration
    int_id = f"{integration.provider.value}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    now = datetime.utcnow()
    
    int_dict = {
        "id": int_id,
        "provider": integration.provider,
        "name": integration.name,
        "status": IntegrationStatus.PENDING,
        "credentials": integration.credentials,  # Should be encrypted in production
        "settings": integration.settings,
        "last_sync": None,
        "next_sync": now,
        "sync_frequency_hours": 24,
        "error_message": None,
        "evidence_collected": 0,
        "created_at": now,
    }
    
    _integrations_db[int_id] = int_dict
    
    # Return without credentials
    response = IntegrationResponse(**{k: v for k, v in int_dict.items() if k != "credentials"})
    return response


@router.get("/", response_model=List[IntegrationResponse])
async def list_integrations(
    provider: Optional[IntegrationProvider] = None,
    status: Optional[IntegrationStatus] = None,
    current_user: TokenData = Depends(get_current_user),
):
    """List configured integrations."""
    integrations = list(_integrations_db.values())
    
    if provider:
        integrations = [i for i in integrations if i.get("provider") == provider]
    if status:
        integrations = [i for i in integrations if i.get("status") == status]
    
    # Return without credentials
    return [
        IntegrationResponse(**{k: v for k, v in i.items() if k != "credentials"})
        for i in integrations
    ]


@router.post("/{integration_id}/sync", response_model=EvidenceCollection)
async def sync_integration(
    integration_id: str,
    current_user: TokenData = Depends(get_current_user),
):
    """
    Trigger manual sync for an integration.
    
    Collects evidence from the connected service.
    """
    if integration_id not in _integrations_db:
        raise HTTPException(status_code=404, detail="Integration not found")
    
    integration = _integrations_db[integration_id]
    provider = integration["provider"]
    
    # Simulate evidence collection (in production, this would call actual APIs)
    evidence_items = []
    errors = []
    
    if provider == IntegrationProvider.AWS:
        evidence_items = [
            {"control": "PR.DS-1", "type": "s3_encryption", "status": "pass", "details": "All S3 buckets encrypted"},
            {"control": "PR.AC-1", "type": "iam_mfa", "status": "partial", "details": "3 users without MFA"},
            {"control": "DE.CM-1", "type": "cloudtrail_enabled", "status": "pass", "details": "CloudTrail active"},
        ]
    elif provider == IntegrationProvider.OKTA:
        evidence_items = [
            {"control": "PR.AC-7", "type": "mfa_enrollment", "status": "partial", "details": "96% MFA enrolled"},
            {"control": "PR.AC-1", "type": "password_policy", "status": "pass", "details": "NIST-compliant policy"},
        ]
    elif provider == IntegrationProvider.GITHUB:
        evidence_items = [
            {"control": "PR.IP-1", "type": "branch_protection", "status": "pass", "details": "All repos protected"},
            {"control": "ID.RA-1", "type": "dependabot_alerts", "status": "partial", "details": "5 open alerts"},
        ]
    
    # Update integration status
    now = datetime.utcnow()
    integration["last_sync"] = now
    integration["next_sync"] = now.replace(hour=now.hour + integration["sync_frequency_hours"])
    integration["status"] = IntegrationStatus.ACTIVE
    integration["evidence_collected"] = len(evidence_items)
    
    return EvidenceCollection(
        integration_id=integration_id,
        provider=provider.value,
        collected_at=now,
        controls_updated=len(evidence_items),
        evidence_items=evidence_items,
        errors=errors,
    )


@router.delete("/{integration_id}")
async def delete_integration(
    integration_id: str,
    current_user: TokenData = Depends(require_role(["admin"])),
):
    """Delete an integration. Requires admin role."""
    if integration_id not in _integrations_db:
        raise HTTPException(status_code=404, detail="Integration not found")
    
    del _integrations_db[integration_id]
    return {"message": "Integration deleted", "id": integration_id}


@router.get("/{integration_id}/test")
async def test_integration(
    integration_id: str,
    current_user: TokenData = Depends(get_current_user),
):
    """Test integration connectivity."""
    if integration_id not in _integrations_db:
        raise HTTPException(status_code=404, detail="Integration not found")
    
    integration = _integrations_db[integration_id]
    
    # Simulate connection test
    return {
        "integration_id": integration_id,
        "provider": integration["provider"].value,
        "status": "success",
        "message": "Connection successful",
        "latency_ms": 142,
        "tested_at": datetime.utcnow().isoformat(),
    }
