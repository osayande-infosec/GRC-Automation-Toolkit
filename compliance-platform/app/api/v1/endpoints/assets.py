"""
Asset Management API Endpoints
------------------------------
IT asset lifecycle tracking and compliance monitoring.
"""

from typing import List, Optional
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from enum import Enum

from app.core.security import get_current_user, TokenData

router = APIRouter()


class AssetType(str, Enum):
    SERVER = "server"
    WORKSTATION = "workstation"
    NETWORK = "network"
    CLOUD = "cloud"
    APPLICATION = "application"
    DATABASE = "database"
    IOT = "iot"


class Criticality(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AssetCreate(BaseModel):
    """Create asset request."""
    asset_id: str = Field(..., description="Unique asset identifier (e.g., SRV-PRD-WEB-001)")
    name: str
    asset_type: AssetType
    owner: Optional[str] = None
    location: Optional[str] = None
    ip_address: Optional[str] = None
    os_version: Optional[str] = None
    criticality: Criticality = Criticality.MEDIUM
    end_of_life: Optional[datetime] = None
    metadata: Optional[dict] = {}


class AssetResponse(BaseModel):
    """Asset response model."""
    id: str
    asset_id: str
    name: str
    asset_type: AssetType
    owner: Optional[str]
    location: Optional[str]
    ip_address: Optional[str]
    os_version: Optional[str]
    criticality: Criticality
    status: str
    compliant: bool
    end_of_life: Optional[datetime]
    last_scanned: Optional[datetime]
    days_until_eol: Optional[int]
    compliance_issues: List[str]


class AssetInventorySummary(BaseModel):
    """Asset inventory summary."""
    total_assets: int
    compliance_rate: float
    by_type: dict
    by_criticality: dict
    by_status: dict
    alerts: List[str]
    eol_upcoming: int
    non_compliant: int
    not_scanned_90_days: int


# In-memory storage (replace with database in production)
_assets_db: dict = {}


def check_asset_compliance(asset: dict) -> tuple[bool, List[str]]:
    """Check asset compliance and return issues."""
    issues = []
    
    # Check EOL
    if asset.get("end_of_life"):
        eol = asset["end_of_life"]
        if isinstance(eol, str):
            eol = datetime.fromisoformat(eol.replace("Z", "+00:00"))
        if eol < datetime.now(eol.tzinfo if eol.tzinfo else None):
            issues.append("Asset is past end-of-life")
    
    # Check last scan
    if asset.get("last_scanned"):
        last_scan = asset["last_scanned"]
        if isinstance(last_scan, str):
            last_scan = datetime.fromisoformat(last_scan.replace("Z", "+00:00"))
        if datetime.now(last_scan.tzinfo if last_scan.tzinfo else None) - last_scan > timedelta(days=90):
            issues.append("Not scanned in 90+ days")
    else:
        issues.append("Never scanned")
    
    # Check owner
    if not asset.get("owner"):
        issues.append("No owner assigned")
    
    return len(issues) == 0, issues


@router.post("/", response_model=AssetResponse)
async def create_asset(
    asset: AssetCreate,
    current_user: TokenData = Depends(get_current_user),
):
    """Create a new asset in the inventory."""
    if asset.asset_id in _assets_db:
        raise HTTPException(status_code=400, detail="Asset ID already exists")
    
    asset_dict = asset.model_dump()
    asset_dict["id"] = asset.asset_id
    asset_dict["status"] = "active"
    asset_dict["last_scanned"] = None
    asset_dict["created_at"] = datetime.utcnow().isoformat()
    
    compliant, issues = check_asset_compliance(asset_dict)
    asset_dict["compliant"] = compliant
    
    _assets_db[asset.asset_id] = asset_dict
    
    # Calculate days until EOL
    days_until_eol = None
    if asset.end_of_life:
        delta = asset.end_of_life - datetime.now(asset.end_of_life.tzinfo if asset.end_of_life.tzinfo else None)
        days_until_eol = delta.days
    
    return AssetResponse(
        **asset_dict,
        days_until_eol=days_until_eol,
        compliance_issues=issues,
    )


@router.get("/", response_model=List[AssetResponse])
async def list_assets(
    asset_type: Optional[AssetType] = None,
    criticality: Optional[Criticality] = None,
    compliant: Optional[bool] = None,
    limit: int = Query(100, le=1000),
    offset: int = 0,
    current_user: TokenData = Depends(get_current_user),
):
    """List assets with optional filtering."""
    assets = list(_assets_db.values())
    
    # Apply filters
    if asset_type:
        assets = [a for a in assets if a.get("asset_type") == asset_type]
    if criticality:
        assets = [a for a in assets if a.get("criticality") == criticality]
    if compliant is not None:
        assets = [a for a in assets if a.get("compliant") == compliant]
    
    # Pagination
    assets = assets[offset:offset + limit]
    
    # Build response
    results = []
    for a in assets:
        _, issues = check_asset_compliance(a)
        days_until_eol = None
        if a.get("end_of_life"):
            eol = a["end_of_life"]
            if isinstance(eol, str):
                eol = datetime.fromisoformat(eol.replace("Z", "+00:00"))
            delta = eol - datetime.now(eol.tzinfo if eol.tzinfo else None)
            days_until_eol = delta.days
        
        results.append(AssetResponse(
            **a,
            days_until_eol=days_until_eol,
            compliance_issues=issues,
        ))
    
    return results


@router.get("/summary", response_model=AssetInventorySummary)
async def get_inventory_summary(
    current_user: TokenData = Depends(get_current_user),
):
    """Get asset inventory summary and compliance metrics."""
    assets = list(_assets_db.values())
    
    if not assets:
        return AssetInventorySummary(
            total_assets=0,
            compliance_rate=0,
            by_type={},
            by_criticality={},
            by_status={},
            alerts=[],
            eol_upcoming=0,
            non_compliant=0,
            not_scanned_90_days=0,
        )
    
    # Calculate metrics
    by_type = {}
    by_criticality = {}
    by_status = {}
    non_compliant = 0
    eol_upcoming = 0
    not_scanned = 0
    alerts = []
    
    for asset in assets:
        # By type
        atype = asset.get("asset_type", "unknown")
        by_type[atype] = by_type.get(atype, 0) + 1
        
        # By criticality
        crit = asset.get("criticality", "medium")
        by_criticality[crit] = by_criticality.get(crit, 0) + 1
        
        # By status
        status = asset.get("status", "unknown")
        by_status[status] = by_status.get(status, 0) + 1
        
        # Compliance check
        compliant, _ = check_asset_compliance(asset)
        if not compliant:
            non_compliant += 1
        
        # EOL check
        if asset.get("end_of_life"):
            eol = asset["end_of_life"]
            if isinstance(eol, str):
                eol = datetime.fromisoformat(eol.replace("Z", "+00:00"))
            days_left = (eol - datetime.now(eol.tzinfo if eol.tzinfo else None)).days
            if days_left <= 90:
                eol_upcoming += 1
        
        # Scan check
        if not asset.get("last_scanned"):
            not_scanned += 1
    
    # Generate alerts
    if non_compliant > 0:
        alerts.append(f"🚨 {non_compliant} non-compliant asset(s)")
    if eol_upcoming > 0:
        alerts.append(f"⚠️ {eol_upcoming} asset(s) approaching end-of-life")
    if not_scanned > 0:
        alerts.append(f"⚠️ {not_scanned} asset(s) not scanned in 90+ days")
    
    compliance_rate = round((len(assets) - non_compliant) / len(assets) * 100, 1)
    
    return AssetInventorySummary(
        total_assets=len(assets),
        compliance_rate=compliance_rate,
        by_type=by_type,
        by_criticality=by_criticality,
        by_status=by_status,
        alerts=alerts,
        eol_upcoming=eol_upcoming,
        non_compliant=non_compliant,
        not_scanned_90_days=not_scanned,
    )


@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(
    asset_id: str,
    current_user: TokenData = Depends(get_current_user),
):
    """Get a specific asset by ID."""
    if asset_id not in _assets_db:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    asset = _assets_db[asset_id]
    _, issues = check_asset_compliance(asset)
    
    days_until_eol = None
    if asset.get("end_of_life"):
        eol = asset["end_of_life"]
        if isinstance(eol, str):
            eol = datetime.fromisoformat(eol.replace("Z", "+00:00"))
        delta = eol - datetime.now(eol.tzinfo if eol.tzinfo else None)
        days_until_eol = delta.days
    
    return AssetResponse(
        **asset,
        days_until_eol=days_until_eol,
        compliance_issues=issues,
    )


@router.delete("/{asset_id}")
async def delete_asset(
    asset_id: str,
    current_user: TokenData = Depends(get_current_user),
):
    """Delete an asset from inventory."""
    if asset_id not in _assets_db:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    del _assets_db[asset_id]
    return {"message": "Asset deleted", "asset_id": asset_id}
