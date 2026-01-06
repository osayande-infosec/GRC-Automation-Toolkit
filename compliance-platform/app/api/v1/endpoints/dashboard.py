"""
Dashboard API Endpoints
-----------------------
Executive dashboard and reporting.
"""

from typing import List, Optional
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.core.security import get_current_user, TokenData

router = APIRouter()


class DashboardMetrics(BaseModel):
    """Executive dashboard metrics."""
    compliance_score: float
    risk_score: float
    vulnerability_score: float
    asset_compliance_rate: float
    security_alerts_24h: int
    critical_findings: int
    overdue_items: int
    trends: dict


class ExecutiveSummary(BaseModel):
    """Executive summary for board reporting."""
    generated_at: datetime
    period: str
    overall_security_posture: str  # Strong, Moderate, Weak
    compliance_status: dict
    top_risks: List[dict]
    key_metrics: dict
    recommendations: List[str]
    upcoming_milestones: List[dict]


class TrendData(BaseModel):
    """Historical trend data."""
    metric: str
    period: str
    data_points: List[dict]  # [{"date": "2026-01-01", "value": 85}, ...]


@router.get("/overview", response_model=DashboardMetrics)
async def get_dashboard_overview(
    current_user: TokenData = Depends(get_current_user),
):
    """
    Get executive dashboard overview with key metrics.
    
    This aggregates data from all modules for at-a-glance visibility.
    """
    # In production, these would come from actual data stores
    return DashboardMetrics(
        compliance_score=71.9,
        risk_score=12.1,  # Average residual risk (lower is better)
        vulnerability_score=85.0,  # Based on % resolved
        asset_compliance_rate=80.0,
        security_alerts_24h=7,
        critical_findings=2,
        overdue_items=3,
        trends={
            "compliance": "+5.2%",  # vs last month
            "risk": "-12.0%",
            "vulnerabilities": "-8 resolved",
        },
    )


@router.get("/executive-summary", response_model=ExecutiveSummary)
async def get_executive_summary(
    current_user: TokenData = Depends(get_current_user),
):
    """
    Generate executive summary for board/leadership reporting.
    """
    return ExecutiveSummary(
        generated_at=datetime.utcnow(),
        period="Q4 2025",
        overall_security_posture="Moderate",
        compliance_status={
            "nist_csf": {"score": 71.9, "status": "partial"},
            "iso_27001": {"score": 68.5, "status": "partial"},
            "soc2": {"score": 75.2, "status": "partial"},
        },
        top_risks=[
            {"id": "RISK-001", "title": "Ransomware Attack", "level": "critical", "trend": "stable"},
            {"id": "RISK-003", "title": "Legacy System Compromise", "level": "critical", "trend": "improving"},
            {"id": "RISK-002", "title": "Data Breach via Phishing", "level": "high", "trend": "stable"},
        ],
        key_metrics={
            "mean_time_to_detect": "4.2 hours",
            "mean_time_to_respond": "2.1 hours",
            "patch_compliance": "92%",
            "mfa_adoption": "96%",
            "security_training_completion": "88%",
        },
        recommendations=[
            "Complete MFA rollout for remaining 4% of users",
            "Address 2 critical vulnerabilities within SLA",
            "Finalize incident response playbooks for Respond/Recover controls",
            "Schedule penetration test for Q1 2026",
        ],
        upcoming_milestones=[
            {"date": "2026-01-15", "item": "SOC 2 Type II audit begins"},
            {"date": "2026-02-01", "item": "Legacy ERP migration deadline"},
            {"date": "2026-03-01", "item": "Security awareness training refresh"},
        ],
    )


@router.get("/trends/{metric}", response_model=TrendData)
async def get_metric_trend(
    metric: str,
    days: int = 30,
    current_user: TokenData = Depends(get_current_user),
):
    """
    Get historical trend data for a specific metric.
    
    Metrics: compliance_score, risk_score, vulnerability_count, alert_count
    """
    # Generate sample trend data
    data_points = []
    base_date = datetime.utcnow()
    
    # Sample values for different metrics
    base_values = {
        "compliance_score": 65,
        "risk_score": 15,
        "vulnerability_count": 25,
        "alert_count": 10,
    }
    
    base = base_values.get(metric, 50)
    
    for i in range(days, -1, -1):
        date = base_date - timedelta(days=i)
        # Simulate gradual improvement
        value = base + (days - i) * 0.2 + (i % 3)  # Some variance
        data_points.append({
            "date": date.strftime("%Y-%m-%d"),
            "value": round(value, 1),
        })
    
    return TrendData(
        metric=metric,
        period=f"Last {days} days",
        data_points=data_points,
    )


@router.get("/alerts")
async def get_active_alerts(
    current_user: TokenData = Depends(get_current_user),
):
    """Get active security and compliance alerts."""
    return {
        "alerts": [
            {
                "id": "ALERT-001",
                "severity": "critical",
                "type": "vulnerability",
                "title": "Critical CVE detected on production server",
                "created_at": datetime.utcnow().isoformat(),
                "source": "vulnerability_scanner",
            },
            {
                "id": "ALERT-002",
                "severity": "high",
                "type": "security",
                "title": "Brute force attack detected from 203.0.113.45",
                "created_at": datetime.utcnow().isoformat(),
                "source": "log_analyzer",
            },
            {
                "id": "ALERT-003",
                "severity": "medium",
                "type": "compliance",
                "title": "3 controls approaching review deadline",
                "created_at": datetime.utcnow().isoformat(),
                "source": "compliance_tracker",
            },
            {
                "id": "ALERT-004",
                "severity": "medium",
                "type": "asset",
                "title": "2 assets past end-of-life date",
                "created_at": datetime.utcnow().isoformat(),
                "source": "asset_manager",
            },
        ],
        "summary": {
            "critical": 1,
            "high": 1,
            "medium": 2,
            "low": 0,
        },
    }


@router.get("/widgets")
async def get_dashboard_widgets(
    current_user: TokenData = Depends(get_current_user),
):
    """Get data for dashboard widgets."""
    return {
        "compliance_gauge": {
            "value": 71.9,
            "target": 85,
            "status": "partial",
        },
        "risk_heatmap": {
            "critical": 2,
            "high": 7,
            "medium": 6,
            "low": 0,
        },
        "vulnerability_funnel": {
            "open": 10,
            "in_progress": 5,
            "resolved_30d": 15,
        },
        "asset_donut": {
            "compliant": 20,
            "non_compliant": 5,
        },
        "recent_activity": [
            {"action": "Control updated", "item": "PR.AC-1", "user": "analyst@acme.com", "time": "2 min ago"},
            {"action": "Risk closed", "item": "RISK-009", "user": "ciso@acme.com", "time": "1 hour ago"},
            {"action": "Vuln resolved", "item": "VULN-005", "user": "security@acme.com", "time": "3 hours ago"},
        ],
    }
