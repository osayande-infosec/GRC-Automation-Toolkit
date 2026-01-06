"""
Vulnerability Management API Endpoints
--------------------------------------
CVSS-based prioritization and remediation tracking.
"""

from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from enum import Enum

from app.core.security import get_current_user, TokenData

router = APIRouter()


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false_positive"


class VulnerabilityCreate(BaseModel):
    """Create vulnerability request."""
    vuln_id: str
    title: str
    description: Optional[str] = None
    severity: Severity
    cvss_score: float = Field(..., ge=0, le=10)
    cve_ids: List[str] = []
    asset_id: str
    port: Optional[str] = None
    protocol: Optional[str] = None
    solution: Optional[str] = None


class VulnerabilityResponse(BaseModel):
    """Vulnerability response."""
    id: str
    vuln_id: str
    title: str
    description: Optional[str]
    severity: Severity
    cvss_score: float
    cve_ids: List[str]
    asset_id: str
    port: Optional[str]
    protocol: Optional[str]
    solution: Optional[str]
    status: VulnStatus
    risk_score: float
    priority_rank: int
    first_seen: datetime
    last_seen: datetime
    sla_days: int
    sla_status: str


class VulnSummary(BaseModel):
    """Vulnerability summary."""
    total: int
    by_severity: dict
    by_status: dict
    overall_risk_score: float
    critical_count: int
    overdue_count: int
    mean_time_to_remediate: Optional[float]
    top_cves: List[dict]
    affected_assets: int


class ScanImport(BaseModel):
    """Import vulnerabilities from scan."""
    scanner: str  # openvas, nessus, qualys
    scan_date: datetime
    findings: List[VulnerabilityCreate]


# SLA definitions (days to remediate by severity)
SLA_DAYS = {
    Severity.CRITICAL: 7,
    Severity.HIGH: 30,
    Severity.MEDIUM: 90,
    Severity.LOW: 180,
    Severity.INFO: 365,
}

# In-memory storage
_vulns_db: dict = {}


def calculate_risk_score(vuln: dict) -> float:
    """Calculate risk score based on CVSS and asset criticality."""
    cvss = vuln.get("cvss_score", 0)
    # Could factor in asset criticality here
    return round(cvss * 10, 1)  # 0-100 scale


def get_sla_status(vuln: dict) -> str:
    """Check SLA compliance."""
    severity = Severity(vuln.get("severity", "medium"))
    first_seen = vuln.get("first_seen")
    
    if isinstance(first_seen, str):
        first_seen = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
    
    if not first_seen:
        return "unknown"
    
    days_open = (datetime.utcnow() - first_seen.replace(tzinfo=None)).days
    sla_days = SLA_DAYS.get(severity, 90)
    
    if vuln.get("status") in (VulnStatus.RESOLVED, VulnStatus.ACCEPTED, VulnStatus.FALSE_POSITIVE):
        return "closed"
    elif days_open > sla_days:
        return "overdue"
    elif days_open > sla_days * 0.8:
        return "at_risk"
    else:
        return "on_track"


@router.post("/", response_model=VulnerabilityResponse)
async def create_vulnerability(
    vuln: VulnerabilityCreate,
    current_user: TokenData = Depends(get_current_user),
):
    """Create a new vulnerability finding."""
    now = datetime.utcnow()
    
    vuln_dict = vuln.model_dump()
    vuln_dict["id"] = vuln.vuln_id
    vuln_dict["status"] = VulnStatus.OPEN
    vuln_dict["first_seen"] = now
    vuln_dict["last_seen"] = now
    
    _vulns_db[vuln.vuln_id] = vuln_dict
    
    risk_score = calculate_risk_score(vuln_dict)
    sla_status = get_sla_status(vuln_dict)
    
    return VulnerabilityResponse(
        **vuln_dict,
        risk_score=risk_score,
        priority_rank=1,
        sla_days=SLA_DAYS.get(vuln.severity, 90),
        sla_status=sla_status,
    )


@router.get("/", response_model=List[VulnerabilityResponse])
async def list_vulnerabilities(
    severity: Optional[Severity] = None,
    status: Optional[VulnStatus] = None,
    asset_id: Optional[str] = None,
    cve: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    current_user: TokenData = Depends(get_current_user),
):
    """List vulnerabilities with filtering."""
    vulns = list(_vulns_db.values())
    
    # Apply filters
    if severity:
        vulns = [v for v in vulns if v.get("severity") == severity]
    if status:
        vulns = [v for v in vulns if v.get("status") == status]
    if asset_id:
        vulns = [v for v in vulns if v.get("asset_id") == asset_id]
    if cve:
        vulns = [v for v in vulns if cve in v.get("cve_ids", [])]
    
    # Sort by CVSS score (highest first)
    vulns.sort(key=lambda x: x.get("cvss_score", 0), reverse=True)
    
    # Pagination
    vulns = vulns[offset:offset + limit]
    
    # Build response with calculated fields
    results = []
    for i, v in enumerate(vulns):
        risk_score = calculate_risk_score(v)
        sla_status = get_sla_status(v)
        severity_enum = Severity(v.get("severity", "medium"))
        
        results.append(VulnerabilityResponse(
            **v,
            risk_score=risk_score,
            priority_rank=i + 1 + offset,
            sla_days=SLA_DAYS.get(severity_enum, 90),
            sla_status=sla_status,
        ))
    
    return results


@router.get("/summary", response_model=VulnSummary)
async def get_vulnerability_summary(
    current_user: TokenData = Depends(get_current_user),
):
    """Get vulnerability summary and metrics."""
    vulns = list(_vulns_db.values())
    
    if not vulns:
        return VulnSummary(
            total=0,
            by_severity={},
            by_status={},
            overall_risk_score=0,
            critical_count=0,
            overdue_count=0,
            mean_time_to_remediate=None,
            top_cves=[],
            affected_assets=0,
        )
    
    # By severity
    by_severity = {}
    for v in vulns:
        sev = v.get("severity", "unknown")
        by_severity[sev] = by_severity.get(sev, 0) + 1
    
    # By status
    by_status = {}
    for v in vulns:
        status = v.get("status", "unknown")
        by_status[status] = by_status.get(status, 0) + 1
    
    # Critical count
    critical_count = by_severity.get(Severity.CRITICAL, 0)
    
    # Overdue count
    overdue_count = sum(1 for v in vulns if get_sla_status(v) == "overdue")
    
    # Overall risk score (average of top 10 by CVSS)
    sorted_vulns = sorted(vulns, key=lambda x: x.get("cvss_score", 0), reverse=True)
    top_10 = sorted_vulns[:10]
    overall_risk = sum(calculate_risk_score(v) for v in top_10) / len(top_10) if top_10 else 0
    
    # Top CVEs
    cve_counts = {}
    for v in vulns:
        for cve in v.get("cve_ids", []):
            cve_counts[cve] = cve_counts.get(cve, 0) + 1
    top_cves = sorted(cve_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    
    # Affected assets
    affected_assets = len(set(v.get("asset_id") for v in vulns))
    
    return VulnSummary(
        total=len(vulns),
        by_severity=by_severity,
        by_status=by_status,
        overall_risk_score=round(overall_risk, 1),
        critical_count=critical_count,
        overdue_count=overdue_count,
        mean_time_to_remediate=None,  # Would calculate from resolved vulns
        top_cves=[{"cve": c, "count": n} for c, n in top_cves],
        affected_assets=affected_assets,
    )


@router.patch("/{vuln_id}/status")
async def update_vulnerability_status(
    vuln_id: str,
    status: VulnStatus,
    notes: Optional[str] = None,
    current_user: TokenData = Depends(get_current_user),
):
    """Update vulnerability status."""
    if vuln_id not in _vulns_db:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    _vulns_db[vuln_id]["status"] = status
    if status in (VulnStatus.RESOLVED, VulnStatus.FALSE_POSITIVE):
        _vulns_db[vuln_id]["resolved_at"] = datetime.utcnow().isoformat()
    
    return {"message": "Status updated", "vuln_id": vuln_id, "status": status}


@router.post("/import", response_model=dict)
async def import_scan_results(
    scan: ScanImport,
    current_user: TokenData = Depends(get_current_user),
):
    """Import vulnerabilities from a scanner."""
    imported = 0
    updated = 0
    
    for finding in scan.findings:
        if finding.vuln_id in _vulns_db:
            # Update existing
            _vulns_db[finding.vuln_id]["last_seen"] = scan.scan_date
            updated += 1
        else:
            # Create new
            vuln_dict = finding.model_dump()
            vuln_dict["id"] = finding.vuln_id
            vuln_dict["status"] = VulnStatus.OPEN
            vuln_dict["first_seen"] = scan.scan_date
            vuln_dict["last_seen"] = scan.scan_date
            _vulns_db[finding.vuln_id] = vuln_dict
            imported += 1
    
    return {
        "scanner": scan.scanner,
        "scan_date": scan.scan_date,
        "imported": imported,
        "updated": updated,
        "total": len(scan.findings),
    }


@router.get("/sla")
async def get_sla_policy():
    """Get SLA policy for vulnerability remediation."""
    return {
        "policy": "Vulnerability Remediation SLA",
        "framework": "CVSS 3.1",
        "sla_by_severity": {
            "critical": {"days": 7, "description": "CVSS 9.0-10.0"},
            "high": {"days": 30, "description": "CVSS 7.0-8.9"},
            "medium": {"days": 90, "description": "CVSS 4.0-6.9"},
            "low": {"days": 180, "description": "CVSS 0.1-3.9"},
            "info": {"days": 365, "description": "CVSS 0.0 / Informational"},
        },
    }
