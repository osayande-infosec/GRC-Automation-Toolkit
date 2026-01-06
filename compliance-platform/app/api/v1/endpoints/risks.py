"""
Risk Management API Endpoints
-----------------------------
Enterprise risk register and treatment tracking.
"""

from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from enum import Enum

from app.core.security import get_current_user, TokenData

router = APIRouter()


class RiskCategory(str, Enum):
    TECHNICAL = "technical"
    OPERATIONAL = "operational"
    COMPLIANCE = "compliance"
    FINANCIAL = "financial"
    REPUTATIONAL = "reputational"
    STRATEGIC = "strategic"


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Treatment(str, Enum):
    ACCEPT = "accept"
    MITIGATE = "mitigate"
    TRANSFER = "transfer"
    AVOID = "avoid"


class RiskStatus(str, Enum):
    OPEN = "open"
    IN_TREATMENT = "in_treatment"
    CLOSED = "closed"
    ACCEPTED = "accepted"


class RiskCreate(BaseModel):
    """Create risk request."""
    risk_id: str = Field(..., description="e.g., RISK-001")
    title: str
    description: Optional[str] = None
    category: RiskCategory
    likelihood: int = Field(..., ge=1, le=5, description="1=Rare, 5=Almost Certain")
    impact: int = Field(..., ge=1, le=5, description="1=Negligible, 5=Catastrophic")
    controls: List[str] = []  # Existing controls
    residual_likelihood: Optional[int] = Field(None, ge=1, le=5)
    residual_impact: Optional[int] = Field(None, ge=1, le=5)
    owner: Optional[str] = None
    treatment: Treatment = Treatment.MITIGATE
    due_date: Optional[datetime] = None
    notes: Optional[str] = None


class RiskResponse(BaseModel):
    """Risk response."""
    id: str
    risk_id: str
    title: str
    description: Optional[str]
    category: RiskCategory
    likelihood: int
    impact: int
    inherent_score: float
    inherent_level: RiskLevel
    controls: List[str]
    residual_likelihood: int
    residual_impact: int
    residual_score: float
    residual_level: RiskLevel
    risk_reduction: float
    owner: Optional[str]
    treatment: Treatment
    status: RiskStatus
    due_date: Optional[datetime]
    notes: Optional[str]
    created_at: datetime
    updated_at: Optional[datetime]


class RiskSummary(BaseModel):
    """Risk register summary."""
    total_risks: int
    average_inherent_score: float
    average_residual_score: float
    risk_reduction_percentage: float
    by_level: dict
    by_category: dict
    by_treatment: dict
    critical_risks: List[dict]
    overdue_risks: int
    recommendations: List[str]


class RiskMatrix(BaseModel):
    """Risk matrix visualization data."""
    matrix: List[List[int]]  # 5x5 grid with risk counts
    risks_by_cell: dict  # {"1,1": ["RISK-001"], ...}


# In-memory storage
_risks_db: dict = {}


def calculate_risk_level(score: float) -> RiskLevel:
    """Determine risk level from score (1-25)."""
    if score >= 20:
        return RiskLevel.CRITICAL
    elif score >= 12:
        return RiskLevel.HIGH
    elif score >= 6:
        return RiskLevel.MEDIUM
    else:
        return RiskLevel.LOW


@router.post("/", response_model=RiskResponse)
async def create_risk(
    risk: RiskCreate,
    current_user: TokenData = Depends(get_current_user),
):
    """Create a new risk entry."""
    if risk.risk_id in _risks_db:
        raise HTTPException(status_code=400, detail="Risk ID already exists")
    
    now = datetime.utcnow()
    
    # Calculate scores
    inherent_score = risk.likelihood * risk.impact
    residual_likelihood = risk.residual_likelihood or risk.likelihood
    residual_impact = risk.residual_impact or risk.impact
    residual_score = residual_likelihood * residual_impact
    
    risk_reduction = 0
    if inherent_score > 0:
        risk_reduction = round((1 - residual_score / inherent_score) * 100, 1)
    
    risk_dict = risk.model_dump()
    risk_dict["id"] = risk.risk_id
    risk_dict["inherent_score"] = inherent_score
    risk_dict["inherent_level"] = calculate_risk_level(inherent_score)
    risk_dict["residual_likelihood"] = residual_likelihood
    risk_dict["residual_impact"] = residual_impact
    risk_dict["residual_score"] = residual_score
    risk_dict["residual_level"] = calculate_risk_level(residual_score)
    risk_dict["risk_reduction"] = risk_reduction
    risk_dict["status"] = RiskStatus.OPEN
    risk_dict["created_at"] = now
    risk_dict["updated_at"] = None
    
    _risks_db[risk.risk_id] = risk_dict
    
    return RiskResponse(**risk_dict)


@router.get("/", response_model=List[RiskResponse])
async def list_risks(
    category: Optional[RiskCategory] = None,
    level: Optional[RiskLevel] = None,
    status: Optional[RiskStatus] = None,
    treatment: Optional[Treatment] = None,
    owner: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    current_user: TokenData = Depends(get_current_user),
):
    """List risks with filtering."""
    risks = list(_risks_db.values())
    
    if category:
        risks = [r for r in risks if r.get("category") == category]
    if level:
        risks = [r for r in risks if r.get("residual_level") == level]
    if status:
        risks = [r for r in risks if r.get("status") == status]
    if treatment:
        risks = [r for r in risks if r.get("treatment") == treatment]
    if owner:
        risks = [r for r in risks if r.get("owner") == owner]
    
    # Sort by residual score (highest first)
    risks.sort(key=lambda x: x.get("residual_score", 0), reverse=True)
    
    # Pagination
    risks = risks[offset:offset + limit]
    
    return [RiskResponse(**r) for r in risks]


@router.get("/summary", response_model=RiskSummary)
async def get_risk_summary(
    current_user: TokenData = Depends(get_current_user),
):
    """Get risk register summary and metrics."""
    risks = list(_risks_db.values())
    
    if not risks:
        return RiskSummary(
            total_risks=0,
            average_inherent_score=0,
            average_residual_score=0,
            risk_reduction_percentage=0,
            by_level={},
            by_category={},
            by_treatment={},
            critical_risks=[],
            overdue_risks=0,
            recommendations=[],
        )
    
    # Calculate averages
    avg_inherent = sum(r.get("inherent_score", 0) for r in risks) / len(risks)
    avg_residual = sum(r.get("residual_score", 0) for r in risks) / len(risks)
    risk_reduction = round((1 - avg_residual / avg_inherent) * 100, 1) if avg_inherent > 0 else 0
    
    # By level
    by_level = {}
    for r in risks:
        level = r.get("residual_level", "unknown")
        by_level[level] = by_level.get(level, 0) + 1
    
    # By category
    by_category = {}
    for r in risks:
        cat = r.get("category", "unknown")
        by_category[cat] = by_category.get(cat, 0) + 1
    
    # By treatment
    by_treatment = {}
    for r in risks:
        treat = r.get("treatment", "unknown")
        by_treatment[treat] = by_treatment.get(treat, 0) + 1
    
    # Critical risks
    critical = [
        {"risk_id": r.get("risk_id"), "title": r.get("title"), "score": r.get("residual_score"), "owner": r.get("owner")}
        for r in risks
        if r.get("residual_level") == RiskLevel.CRITICAL
    ]
    
    # Overdue risks
    now = datetime.utcnow()
    overdue = sum(
        1 for r in risks
        if r.get("due_date") and r.get("due_date") < now and r.get("status") not in (RiskStatus.CLOSED, RiskStatus.ACCEPTED)
    )
    
    # Recommendations
    recommendations = []
    if by_level.get(RiskLevel.CRITICAL, 0) > 0:
        recommendations.append(f"URGENT: {by_level[RiskLevel.CRITICAL]} critical risk(s) require immediate executive attention.")
    
    # Find category with most high-severity risks
    high_severity_by_cat = {}
    for r in risks:
        if r.get("residual_level") in (RiskLevel.CRITICAL, RiskLevel.HIGH):
            cat = r.get("category")
            high_severity_by_cat[cat] = high_severity_by_cat.get(cat, 0) + 1
    
    if high_severity_by_cat:
        top_cat = max(high_severity_by_cat, key=high_severity_by_cat.get)
        recommendations.append(f"'{top_cat}' category has {high_severity_by_cat[top_cat]} high-severity risks. Consider focused remediation.")
    
    if overdue > 0:
        recommendations.append(f"{overdue} risk(s) past due date. Review and update treatment plans.")
    
    return RiskSummary(
        total_risks=len(risks),
        average_inherent_score=round(avg_inherent, 1),
        average_residual_score=round(avg_residual, 1),
        risk_reduction_percentage=risk_reduction,
        by_level=by_level,
        by_category=by_category,
        by_treatment=by_treatment,
        critical_risks=critical[:5],
        overdue_risks=overdue,
        recommendations=recommendations[:5],
    )


@router.get("/matrix", response_model=RiskMatrix)
async def get_risk_matrix(
    current_user: TokenData = Depends(get_current_user),
):
    """Get 5x5 risk matrix data for visualization."""
    # Initialize 5x5 matrix (likelihood x impact)
    matrix = [[0 for _ in range(5)] for _ in range(5)]
    risks_by_cell = {}
    
    for risk in _risks_db.values():
        likelihood = risk.get("residual_likelihood", 1) - 1  # 0-indexed
        impact = risk.get("residual_impact", 1) - 1
        
        matrix[likelihood][impact] += 1
        
        cell_key = f"{likelihood},{impact}"
        if cell_key not in risks_by_cell:
            risks_by_cell[cell_key] = []
        risks_by_cell[cell_key].append(risk.get("risk_id"))
    
    return RiskMatrix(matrix=matrix, risks_by_cell=risks_by_cell)


@router.patch("/{risk_id}")
async def update_risk(
    risk_id: str,
    status: Optional[RiskStatus] = None,
    treatment: Optional[Treatment] = None,
    residual_likelihood: Optional[int] = None,
    residual_impact: Optional[int] = None,
    notes: Optional[str] = None,
    current_user: TokenData = Depends(get_current_user),
):
    """Update risk status, treatment, or residual scores."""
    if risk_id not in _risks_db:
        raise HTTPException(status_code=404, detail="Risk not found")
    
    risk = _risks_db[risk_id]
    
    if status:
        risk["status"] = status
    if treatment:
        risk["treatment"] = treatment
    if residual_likelihood:
        risk["residual_likelihood"] = residual_likelihood
    if residual_impact:
        risk["residual_impact"] = residual_impact
    if notes:
        risk["notes"] = notes
    
    # Recalculate residual score
    risk["residual_score"] = risk["residual_likelihood"] * risk["residual_impact"]
    risk["residual_level"] = calculate_risk_level(risk["residual_score"])
    
    if risk["inherent_score"] > 0:
        risk["risk_reduction"] = round((1 - risk["residual_score"] / risk["inherent_score"]) * 100, 1)
    
    risk["updated_at"] = datetime.utcnow()
    
    return {"message": "Risk updated", "risk_id": risk_id}


@router.get("/treatments")
async def get_treatment_options():
    """Get risk treatment options and guidance."""
    return {
        "treatments": [
            {
                "id": "accept",
                "name": "Accept",
                "description": "Acknowledge the risk without taking action. Document acceptance rationale.",
                "when_to_use": "Risk is within appetite, cost of treatment exceeds benefit",
            },
            {
                "id": "mitigate",
                "name": "Mitigate",
                "description": "Implement controls to reduce likelihood or impact.",
                "when_to_use": "Risk exceeds appetite and can be reduced cost-effectively",
            },
            {
                "id": "transfer",
                "name": "Transfer",
                "description": "Shift risk to third party (insurance, outsourcing, contracts).",
                "when_to_use": "Risk cannot be reduced internally, financial impact is primary concern",
            },
            {
                "id": "avoid",
                "name": "Avoid",
                "description": "Eliminate the risk by not engaging in the activity.",
                "when_to_use": "Risk exceeds appetite and no effective treatment exists",
            },
        ],
        "framework": "ISO 31000:2018",
    }


@router.get("/scoring")
async def get_scoring_criteria():
    """Get risk scoring criteria (Likelihood x Impact)."""
    return {
        "likelihood": {
            "1": {"name": "Rare", "description": "< 5% chance of occurrence"},
            "2": {"name": "Unlikely", "description": "5-20% chance"},
            "3": {"name": "Possible", "description": "20-50% chance"},
            "4": {"name": "Likely", "description": "50-80% chance"},
            "5": {"name": "Almost Certain", "description": "> 80% chance"},
        },
        "impact": {
            "1": {"name": "Negligible", "description": "Minimal business impact"},
            "2": {"name": "Minor", "description": "Limited impact, easily recoverable"},
            "3": {"name": "Moderate", "description": "Significant but manageable impact"},
            "4": {"name": "Major", "description": "Serious impact, difficult recovery"},
            "5": {"name": "Catastrophic", "description": "Existential threat to organization"},
        },
        "risk_levels": {
            "critical": {"range": "20-25", "color": "#dc3545"},
            "high": {"range": "12-19", "color": "#fd7e14"},
            "medium": {"range": "6-11", "color": "#ffc107"},
            "low": {"range": "1-5", "color": "#28a745"},
        },
    }
