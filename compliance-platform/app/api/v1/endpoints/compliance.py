"""
Compliance Tracking API Endpoints
---------------------------------
Multi-framework control status and gap analysis.
"""

from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from enum import Enum

from app.core.security import get_current_user, TokenData

router = APIRouter()


class Framework(str, Enum):
    NIST_CSF = "nist_csf"
    ISO_27001 = "iso_27001"
    SOC2 = "soc2"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    GDPR = "gdpr"
    CIS = "cis"


class ControlStatus(str, Enum):
    IMPLEMENTED = "implemented"
    PARTIAL = "partial"
    NOT_IMPLEMENTED = "not_implemented"
    NOT_APPLICABLE = "not_applicable"


class ControlCreate(BaseModel):
    """Create control request."""
    control_id: str = Field(..., description="e.g., PR.AC-1, CC6.1, A.9.4.2")
    framework: Framework
    title: str
    description: Optional[str] = None
    family: Optional[str] = None  # e.g., "Protect", "Access Control"
    status: ControlStatus = ControlStatus.NOT_IMPLEMENTED
    owner: Optional[str] = None
    priority: str = "medium"
    evidence: Optional[str] = None
    notes: Optional[str] = None


class ControlResponse(BaseModel):
    """Control response."""
    id: str
    control_id: str
    framework: Framework
    title: str
    description: Optional[str]
    family: Optional[str]
    status: ControlStatus
    owner: Optional[str]
    priority: str
    evidence: Optional[str]
    notes: Optional[str]
    last_assessed: Optional[datetime]
    mappings: dict  # Cross-framework mappings


class ComplianceScore(BaseModel):
    """Compliance score for a framework."""
    framework: Framework
    score: float
    status: str  # compliant, partial, non_compliant
    total_controls: int
    implemented: int
    partial: int
    not_implemented: int
    not_applicable: int
    by_family: dict
    gaps: List[dict]
    recommendations: List[str]


class ComplianceDashboard(BaseModel):
    """Multi-framework compliance dashboard."""
    overall_score: float
    frameworks: List[ComplianceScore]
    total_controls: int
    critical_gaps: List[dict]
    upcoming_reviews: List[dict]


# Cross-framework control mappings
CONTROL_MAPPINGS = {
    # Access Control mappings
    "PR.AC-1": {"iso_27001": "A.9.2.1", "soc2": "CC6.1", "hipaa": "164.312(a)(1)"},
    "PR.AC-4": {"iso_27001": "A.9.2.3", "soc2": "CC6.2", "hipaa": "164.312(a)(1)"},
    "CC6.1": {"nist_csf": "PR.AC-1", "iso_27001": "A.9.2.1", "hipaa": "164.312(a)(1)"},
    # Data Protection mappings
    "PR.DS-1": {"iso_27001": "A.8.2.3", "soc2": "CC6.7", "pci_dss": "3.4"},
    "PR.DS-2": {"iso_27001": "A.13.2.1", "soc2": "CC6.7", "pci_dss": "4.1"},
}

# In-memory storage
_controls_db: dict = {}


def calculate_compliance_score(controls: List[dict]) -> tuple[float, dict]:
    """Calculate compliance score and breakdown."""
    if not controls:
        return 0.0, {}
    
    # Filter out N/A
    applicable = [c for c in controls if c.get("status") != ControlStatus.NOT_APPLICABLE]
    
    if not applicable:
        return 100.0, {}
    
    # Score: Implemented = 1.0, Partial = 0.5, Not Implemented = 0
    score = 0
    for control in applicable:
        status = control.get("status")
        if status == ControlStatus.IMPLEMENTED:
            score += 1.0
        elif status == ControlStatus.PARTIAL:
            score += 0.5
    
    percentage = round(score / len(applicable) * 100, 1)
    
    # By family breakdown
    by_family = {}
    for control in controls:
        family = control.get("family", "Other")
        if family not in by_family:
            by_family[family] = {"total": 0, "implemented": 0}
        by_family[family]["total"] += 1
        if control.get("status") == ControlStatus.IMPLEMENTED:
            by_family[family]["implemented"] += 1
    
    return percentage, by_family


@router.post("/controls", response_model=ControlResponse)
async def create_control(
    control: ControlCreate,
    current_user: TokenData = Depends(get_current_user),
):
    """Create a new compliance control."""
    key = f"{control.framework}:{control.control_id}"
    
    control_dict = control.model_dump()
    control_dict["id"] = key
    control_dict["last_assessed"] = datetime.utcnow()
    control_dict["mappings"] = CONTROL_MAPPINGS.get(control.control_id, {})
    
    _controls_db[key] = control_dict
    
    return ControlResponse(**control_dict)


@router.get("/controls", response_model=List[ControlResponse])
async def list_controls(
    framework: Optional[Framework] = None,
    status: Optional[ControlStatus] = None,
    family: Optional[str] = None,
    owner: Optional[str] = None,
    current_user: TokenData = Depends(get_current_user),
):
    """List compliance controls with filtering."""
    controls = list(_controls_db.values())
    
    if framework:
        controls = [c for c in controls if c.get("framework") == framework]
    if status:
        controls = [c for c in controls if c.get("status") == status]
    if family:
        controls = [c for c in controls if c.get("family") == family]
    if owner:
        controls = [c for c in controls if c.get("owner") == owner]
    
    return [ControlResponse(**c) for c in controls]


@router.get("/score/{framework}", response_model=ComplianceScore)
async def get_framework_score(
    framework: Framework,
    current_user: TokenData = Depends(get_current_user),
):
    """Get compliance score for a specific framework."""
    controls = [c for c in _controls_db.values() if c.get("framework") == framework]
    
    if not controls:
        return ComplianceScore(
            framework=framework,
            score=0,
            status="not_assessed",
            total_controls=0,
            implemented=0,
            partial=0,
            not_implemented=0,
            not_applicable=0,
            by_family={},
            gaps=[],
            recommendations=[],
        )
    
    # Count by status
    implemented = sum(1 for c in controls if c.get("status") == ControlStatus.IMPLEMENTED)
    partial = sum(1 for c in controls if c.get("status") == ControlStatus.PARTIAL)
    not_impl = sum(1 for c in controls if c.get("status") == ControlStatus.NOT_IMPLEMENTED)
    not_app = sum(1 for c in controls if c.get("status") == ControlStatus.NOT_APPLICABLE)
    
    score, by_family = calculate_compliance_score(controls)
    
    # Determine status
    if score >= 90:
        status = "compliant"
    elif score >= 70:
        status = "partial_compliance"
    else:
        status = "non_compliant"
    
    # Find gaps (not implemented or partial, high priority)
    gaps = [
        {"control_id": c.get("control_id"), "title": c.get("title"), "owner": c.get("owner")}
        for c in controls
        if c.get("status") in (ControlStatus.NOT_IMPLEMENTED, ControlStatus.PARTIAL)
        and c.get("priority") in ("critical", "high")
    ]
    
    # Generate recommendations
    recommendations = []
    if not_impl > 0:
        recommendations.append(f"URGENT: {not_impl} control(s) not implemented. Address high-priority gaps first.")
    if partial > 0:
        recommendations.append(f"{partial} control(s) partially implemented. Complete documentation and evidence.")
    
    # Family-specific recommendations
    for family, data in by_family.items():
        if data["total"] > 0:
            rate = data["implemented"] / data["total"] * 100
            if rate < 50:
                recommendations.append(f"Focus on '{family}' family ({rate:.0f}% implemented)")
    
    return ComplianceScore(
        framework=framework,
        score=score,
        status=status,
        total_controls=len(controls),
        implemented=implemented,
        partial=partial,
        not_implemented=not_impl,
        not_applicable=not_app,
        by_family={f: f"{d['implemented']}/{d['total']}" for f, d in by_family.items()},
        gaps=gaps[:10],
        recommendations=recommendations[:5],
    )


@router.get("/dashboard", response_model=ComplianceDashboard)
async def get_compliance_dashboard(
    current_user: TokenData = Depends(get_current_user),
):
    """Get multi-framework compliance dashboard."""
    # Get all unique frameworks in use
    frameworks_in_use = set(c.get("framework") for c in _controls_db.values())
    
    framework_scores = []
    total_controls = 0
    critical_gaps = []
    
    for fw in frameworks_in_use:
        score_data = await get_framework_score(fw, current_user)
        framework_scores.append(score_data)
        total_controls += score_data.total_controls
        critical_gaps.extend(score_data.gaps[:3])
    
    # Overall score (average of framework scores)
    if framework_scores:
        overall = sum(f.score for f in framework_scores) / len(framework_scores)
    else:
        overall = 0
    
    return ComplianceDashboard(
        overall_score=round(overall, 1),
        frameworks=framework_scores,
        total_controls=total_controls,
        critical_gaps=critical_gaps[:10],
        upcoming_reviews=[],  # Would come from next_review dates
    )


@router.patch("/controls/{control_id}/status")
async def update_control_status(
    control_id: str,
    framework: Framework,
    status: ControlStatus,
    evidence: Optional[str] = None,
    notes: Optional[str] = None,
    current_user: TokenData = Depends(get_current_user),
):
    """Update control status with evidence."""
    key = f"{framework}:{control_id}"
    
    if key not in _controls_db:
        raise HTTPException(status_code=404, detail="Control not found")
    
    _controls_db[key]["status"] = status
    _controls_db[key]["last_assessed"] = datetime.utcnow()
    
    if evidence:
        _controls_db[key]["evidence"] = evidence
    if notes:
        _controls_db[key]["notes"] = notes
    
    return {"message": "Control updated", "control_id": control_id, "status": status}


@router.get("/frameworks")
async def list_frameworks():
    """List supported compliance frameworks."""
    return {
        "frameworks": [
            {
                "id": "nist_csf",
                "name": "NIST Cybersecurity Framework",
                "version": "1.1",
                "families": ["Identify", "Protect", "Detect", "Respond", "Recover"],
            },
            {
                "id": "iso_27001",
                "name": "ISO/IEC 27001:2022",
                "version": "2022",
                "families": ["A.5-A.8 (Organizational)", "A.9-A.14 (Technical)"],
            },
            {
                "id": "soc2",
                "name": "SOC 2 Type II",
                "version": "2017",
                "families": ["CC1-CC9 (Common Criteria)", "Availability", "Confidentiality"],
            },
            {
                "id": "hipaa",
                "name": "HIPAA Security Rule",
                "version": "2013",
                "families": ["Administrative", "Physical", "Technical"],
            },
            {
                "id": "pci_dss",
                "name": "PCI DSS",
                "version": "4.0",
                "families": ["Build & Maintain", "Protect Data", "Vulnerability Management"],
            },
        ]
    }


@router.get("/mappings/{control_id}")
async def get_control_mappings(
    control_id: str,
):
    """Get cross-framework mappings for a control."""
    mappings = CONTROL_MAPPINGS.get(control_id, {})
    
    if not mappings:
        return {"control_id": control_id, "mappings": {}, "message": "No mappings found"}
    
    return {
        "control_id": control_id,
        "mappings": mappings,
        "mapped_frameworks": list(mappings.keys()),
    }
