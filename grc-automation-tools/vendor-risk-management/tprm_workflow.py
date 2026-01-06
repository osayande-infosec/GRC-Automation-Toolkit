#!/usr/bin/env python3
"""
Third-Party Risk Management (TPRM) Workflow
============================================

A scalable vendor risk assessment tool utilizing NIST SP 800-161
(Cybersecurity Supply Chain Risk Management) standards to categorize
vendors by data sensitivity and criticality.

Features:
- Vendor tiering based on data access and business criticality
- NIST SP 800-161 aligned risk assessment
- Due diligence questionnaire scoring
- Continuous monitoring recommendations
- Contract security requirements generation

Author: Osayande (CISSP)
Framework: NIST SP 800-161, ISO 27001 Annex A.15
"""

import json
import csv
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
import sys


class VendorTier(Enum):
    """Vendor classification tiers based on risk exposure."""
    CRITICAL = "Critical"      # Tier 1: Direct access to sensitive data/systems
    HIGH = "High"              # Tier 2: Indirect access, significant impact
    MODERATE = "Moderate"      # Tier 3: Limited access, moderate impact
    LOW = "Low"                # Tier 4: No data access, minimal impact


class DataClassification(Enum):
    """Data sensitivity classification levels."""
    PUBLIC = "Public"
    INTERNAL = "Internal"
    CONFIDENTIAL = "Confidential"
    RESTRICTED = "Restricted"        # PII, PHI, Financial
    HIGHLY_RESTRICTED = "Highly Restricted"  # Regulated data, trade secrets


class AssessmentStatus(Enum):
    """Vendor assessment lifecycle status."""
    PENDING = "Pending"
    IN_PROGRESS = "In Progress"
    UNDER_REVIEW = "Under Review"
    APPROVED = "Approved"
    CONDITIONAL = "Conditionally Approved"
    REJECTED = "Rejected"
    EXPIRED = "Expired"


@dataclass
class SecurityControl:
    """Security control requirement for vendor assessment."""
    control_id: str
    domain: str
    requirement: str
    weight: float  # 1.0 to 5.0
    mandatory: bool = False
    evidence_required: List[str] = field(default_factory=list)


@dataclass
class VendorProfile:
    """Comprehensive vendor profile for risk assessment."""
    vendor_id: str
    vendor_name: str
    vendor_type: str  # SaaS, IaaS, Consultant, Contractor, etc.
    primary_contact: str
    contract_owner: str
    
    # Data handling
    data_classification: DataClassification
    data_types: List[str]  # PII, PHI, Financial, IP, etc.
    data_volume: str  # Low, Medium, High, Very High
    data_location: List[str]  # Countries/regions
    
    # Access scope
    has_network_access: bool = False
    has_system_access: bool = False
    has_physical_access: bool = False
    has_data_processing: bool = True
    
    # Business context
    business_criticality: str = "Medium"  # Low, Medium, High, Critical
    service_description: str = ""
    annual_spend: float = 0.0
    contract_start: str = ""
    contract_end: str = ""
    
    # Assessment results
    tier: Optional[VendorTier] = None
    inherent_risk_score: float = 0.0
    residual_risk_score: float = 0.0
    assessment_status: AssessmentStatus = AssessmentStatus.PENDING
    last_assessment: str = ""
    next_assessment: str = ""


@dataclass
class AssessmentResponse:
    """Vendor's response to a security control assessment."""
    control_id: str
    implemented: bool
    maturity_level: int  # 1-5 (Initial, Repeatable, Defined, Managed, Optimized)
    evidence_provided: List[str]
    notes: str = ""
    compensating_controls: str = ""


class TPRMWorkflow:
    """
    Third-Party Risk Management workflow engine.
    
    Implements NIST SP 800-161 aligned vendor risk assessment
    with tiering, scoring, and continuous monitoring.
    """
    
    # NIST SP 800-161 aligned security control domains
    CONTROL_DOMAINS = {
        "governance": "Supply Chain Risk Governance",
        "access": "Access Control & Identity Management",
        "data": "Data Protection & Privacy",
        "security": "Security Operations",
        "incident": "Incident Response & Recovery",
        "compliance": "Regulatory Compliance",
        "business": "Business Continuity",
    }
    
    # Standard security controls for vendor assessment
    SECURITY_CONTROLS: List[SecurityControl] = [
        # Governance Domain
        SecurityControl("GOV-01", "governance", "Information Security Policy", 4.0, True,
                       ["Security policy document", "Annual review evidence"]),
        SecurityControl("GOV-02", "governance", "Risk Management Program", 4.0, True,
                       ["Risk assessment methodology", "Risk register"]),
        SecurityControl("GOV-03", "governance", "Security Awareness Training", 3.0, True,
                       ["Training completion records", "Phishing test results"]),
        SecurityControl("GOV-04", "governance", "Third-Party Management", 3.0, False,
                       ["Subcontractor list", "Subcontractor assessments"]),
        
        # Access Control Domain
        SecurityControl("ACC-01", "access", "Multi-Factor Authentication", 5.0, True,
                       ["MFA configuration evidence", "User access list"]),
        SecurityControl("ACC-02", "access", "Privileged Access Management", 4.0, True,
                       ["PAM solution documentation", "Privileged user inventory"]),
        SecurityControl("ACC-03", "access", "Access Review Process", 3.0, True,
                       ["Access review reports", "Termination procedures"]),
        SecurityControl("ACC-04", "access", "SSO Integration", 2.0, False,
                       ["SSO configuration", "SAML/OIDC documentation"]),
        
        # Data Protection Domain
        SecurityControl("DAT-01", "data", "Data Encryption at Rest", 5.0, True,
                       ["Encryption standards", "Key management procedures"]),
        SecurityControl("DAT-02", "data", "Data Encryption in Transit", 5.0, True,
                       ["TLS configuration", "Certificate management"]),
        SecurityControl("DAT-03", "data", "Data Loss Prevention", 4.0, False,
                       ["DLP policy", "DLP tool documentation"]),
        SecurityControl("DAT-04", "data", "Data Retention & Disposal", 3.0, True,
                       ["Retention policy", "Disposal certificates"]),
        SecurityControl("DAT-05", "data", "Privacy Program (GDPR/CCPA)", 4.0, False,
                       ["Privacy policy", "DPIA documentation"]),
        
        # Security Operations Domain
        SecurityControl("SEC-01", "security", "Vulnerability Management", 4.0, True,
                       ["Vulnerability scan reports", "Patch management SLAs"]),
        SecurityControl("SEC-02", "security", "Penetration Testing", 4.0, True,
                       ["Annual pentest report", "Remediation evidence"]),
        SecurityControl("SEC-03", "security", "Security Monitoring (SIEM)", 4.0, True,
                       ["SIEM architecture", "Alerting procedures"]),
        SecurityControl("SEC-04", "security", "Endpoint Protection", 3.0, True,
                       ["EDR/AV solution details", "Coverage metrics"]),
        
        # Incident Response Domain
        SecurityControl("INC-01", "incident", "Incident Response Plan", 5.0, True,
                       ["IR plan document", "Contact procedures"]),
        SecurityControl("INC-02", "incident", "Breach Notification Process", 5.0, True,
                       ["Notification timeline SLA", "Communication templates"]),
        SecurityControl("INC-03", "incident", "Tabletop Exercises", 3.0, False,
                       ["Exercise reports", "Lessons learned"]),
        
        # Compliance Domain
        SecurityControl("CMP-01", "compliance", "SOC 2 Type II Report", 5.0, False,
                       ["Current SOC 2 report", "Bridge letter if needed"]),
        SecurityControl("CMP-02", "compliance", "ISO 27001 Certification", 4.0, False,
                       ["ISO certificate", "Statement of Applicability"]),
        SecurityControl("CMP-03", "compliance", "Industry Certifications", 3.0, False,
                       ["HIPAA attestation", "PCI-DSS AOC", "FedRAMP"]),
        
        # Business Continuity Domain
        SecurityControl("BCP-01", "business", "Business Continuity Plan", 4.0, True,
                       ["BCP document", "Recovery objectives"]),
        SecurityControl("BCP-02", "business", "Disaster Recovery Testing", 4.0, True,
                       ["DR test results", "RTO/RPO metrics"]),
        SecurityControl("BCP-03", "business", "Geographic Redundancy", 3.0, False,
                       ["Data center locations", "Failover procedures"]),
    ]
    
    # Tier classification matrix
    TIER_MATRIX = {
        # (data_classification, business_criticality) -> VendorTier
        (DataClassification.HIGHLY_RESTRICTED, "Critical"): VendorTier.CRITICAL,
        (DataClassification.HIGHLY_RESTRICTED, "High"): VendorTier.CRITICAL,
        (DataClassification.HIGHLY_RESTRICTED, "Medium"): VendorTier.HIGH,
        (DataClassification.HIGHLY_RESTRICTED, "Low"): VendorTier.HIGH,
        
        (DataClassification.RESTRICTED, "Critical"): VendorTier.CRITICAL,
        (DataClassification.RESTRICTED, "High"): VendorTier.HIGH,
        (DataClassification.RESTRICTED, "Medium"): VendorTier.HIGH,
        (DataClassification.RESTRICTED, "Low"): VendorTier.MODERATE,
        
        (DataClassification.CONFIDENTIAL, "Critical"): VendorTier.HIGH,
        (DataClassification.CONFIDENTIAL, "High"): VendorTier.HIGH,
        (DataClassification.CONFIDENTIAL, "Medium"): VendorTier.MODERATE,
        (DataClassification.CONFIDENTIAL, "Low"): VendorTier.MODERATE,
        
        (DataClassification.INTERNAL, "Critical"): VendorTier.HIGH,
        (DataClassification.INTERNAL, "High"): VendorTier.MODERATE,
        (DataClassification.INTERNAL, "Medium"): VendorTier.MODERATE,
        (DataClassification.INTERNAL, "Low"): VendorTier.LOW,
        
        (DataClassification.PUBLIC, "Critical"): VendorTier.MODERATE,
        (DataClassification.PUBLIC, "High"): VendorTier.MODERATE,
        (DataClassification.PUBLIC, "Medium"): VendorTier.LOW,
        (DataClassification.PUBLIC, "Low"): VendorTier.LOW,
    }
    
    # Assessment frequency by tier (in days)
    ASSESSMENT_FREQUENCY = {
        VendorTier.CRITICAL: 365,    # Annual
        VendorTier.HIGH: 365,        # Annual
        VendorTier.MODERATE: 730,    # Biennial
        VendorTier.LOW: 1095,        # Every 3 years
    }
    
    def __init__(self):
        """Initialize the TPRM workflow engine."""
        self.vendors: Dict[str, VendorProfile] = {}
        self.assessments: Dict[str, List[AssessmentResponse]] = {}
    
    def classify_vendor_tier(self, vendor: VendorProfile) -> VendorTier:
        """
        Classify vendor into risk tier based on NIST SP 800-161 criteria.
        
        Considers:
        - Data classification level
        - Business criticality
        - Access scope (network, system, physical)
        """
        # Get base tier from matrix
        base_tier = self.TIER_MATRIX.get(
            (vendor.data_classification, vendor.business_criticality),
            VendorTier.MODERATE
        )
        
        # Elevate tier if vendor has elevated access
        access_factors = sum([
            vendor.has_network_access,
            vendor.has_system_access,
            vendor.has_physical_access,
        ])
        
        if access_factors >= 2 and base_tier != VendorTier.CRITICAL:
            # Elevate by one tier
            tier_order = [VendorTier.LOW, VendorTier.MODERATE, VendorTier.HIGH, VendorTier.CRITICAL]
            current_idx = tier_order.index(base_tier)
            base_tier = tier_order[min(current_idx + 1, 3)]
        
        return base_tier
    
    def calculate_inherent_risk(self, vendor: VendorProfile) -> float:
        """
        Calculate inherent risk score (before controls) on 1-100 scale.
        
        Based on NIST SP 800-161 supply chain risk factors.
        """
        score = 0.0
        
        # Data classification factor (0-30 points)
        data_scores = {
            DataClassification.PUBLIC: 5,
            DataClassification.INTERNAL: 10,
            DataClassification.CONFIDENTIAL: 18,
            DataClassification.RESTRICTED: 25,
            DataClassification.HIGHLY_RESTRICTED: 30,
        }
        score += data_scores.get(vendor.data_classification, 15)
        
        # Business criticality factor (0-25 points)
        criticality_scores = {"Low": 5, "Medium": 12, "High": 20, "Critical": 25}
        score += criticality_scores.get(vendor.business_criticality, 12)
        
        # Access scope factor (0-25 points)
        if vendor.has_network_access:
            score += 8
        if vendor.has_system_access:
            score += 10
        if vendor.has_physical_access:
            score += 7
        
        # Data volume factor (0-10 points)
        volume_scores = {"Low": 2, "Medium": 5, "High": 8, "Very High": 10}
        score += volume_scores.get(vendor.data_volume, 5)
        
        # Geographic factor (0-10 points)
        high_risk_regions = ["China", "Russia", "Iran", "North Korea"]
        if any(loc in high_risk_regions for loc in vendor.data_location):
            score += 10
        elif len(vendor.data_location) > 2:
            score += 5  # Multi-region adds complexity
        
        return min(score, 100)
    
    def calculate_control_score(
        self,
        vendor: VendorProfile,
        responses: List[AssessmentResponse]
    ) -> Tuple[float, List[Dict]]:
        """
        Calculate security control effectiveness score.
        
        Returns:
            Tuple of (score 0-100, list of gaps)
        """
        total_weight = 0.0
        achieved_weight = 0.0
        gaps = []
        
        # Get applicable controls based on tier
        applicable_controls = self._get_applicable_controls(vendor.tier)
        
        response_map = {r.control_id: r for r in responses}
        
        for control in applicable_controls:
            total_weight += control.weight
            
            response = response_map.get(control.control_id)
            
            if response and response.implemented:
                # Score based on maturity level (1-5 scale)
                maturity_factor = response.maturity_level / 5.0
                achieved_weight += control.weight * maturity_factor
            else:
                # Record gap
                gap = {
                    "control_id": control.control_id,
                    "domain": control.domain,
                    "requirement": control.requirement,
                    "mandatory": control.mandatory,
                    "weight": control.weight,
                    "evidence_required": control.evidence_required,
                }
                if response and response.compensating_controls:
                    gap["compensating_controls"] = response.compensating_controls
                    # Partial credit for compensating controls
                    achieved_weight += control.weight * 0.5
                gaps.append(gap)
        
        score = (achieved_weight / total_weight * 100) if total_weight > 0 else 0
        return round(score, 1), gaps
    
    def _get_applicable_controls(self, tier: VendorTier) -> List[SecurityControl]:
        """Get controls applicable to vendor tier."""
        if tier == VendorTier.CRITICAL:
            return self.SECURITY_CONTROLS  # All controls
        elif tier == VendorTier.HIGH:
            # All mandatory + high-weight optional
            return [c for c in self.SECURITY_CONTROLS if c.mandatory or c.weight >= 4.0]
        elif tier == VendorTier.MODERATE:
            # Mandatory only
            return [c for c in self.SECURITY_CONTROLS if c.mandatory]
        else:  # LOW
            # Core mandatory only
            return [c for c in self.SECURITY_CONTROLS 
                    if c.mandatory and c.weight >= 4.0]
    
    def calculate_residual_risk(
        self,
        inherent_risk: float,
        control_score: float
    ) -> float:
        """
        Calculate residual risk after control effectiveness.
        
        Formula: Residual = Inherent × (1 - Control Effectiveness)
        """
        control_effectiveness = control_score / 100
        residual = inherent_risk * (1 - control_effectiveness * 0.8)  # Max 80% reduction
        return round(residual, 1)
    
    def determine_assessment_status(
        self,
        vendor: VendorProfile,
        control_score: float,
        gaps: List[Dict]
    ) -> AssessmentStatus:
        """Determine vendor assessment status based on results."""
        mandatory_gaps = [g for g in gaps if g.get("mandatory")]
        
        if mandatory_gaps:
            if len(mandatory_gaps) > 3:
                return AssessmentStatus.REJECTED
            else:
                return AssessmentStatus.CONDITIONAL
        
        if control_score >= 80:
            return AssessmentStatus.APPROVED
        elif control_score >= 60:
            return AssessmentStatus.CONDITIONAL
        else:
            return AssessmentStatus.REJECTED
    
    def generate_contract_requirements(
        self,
        vendor: VendorProfile,
        gaps: List[Dict]
    ) -> Dict:
        """
        Generate security requirements for vendor contract.
        
        Based on NIST SP 800-161 supply chain security provisions.
        """
        requirements = {
            "vendor_name": vendor.vendor_name,
            "tier": vendor.tier.value if vendor.tier else "Unknown",
            "generated_date": datetime.now().strftime("%Y-%m-%d"),
            "mandatory_clauses": [],
            "recommended_clauses": [],
            "gap_remediation": [],
            "sla_requirements": {},
        }
        
        # Standard mandatory clauses for all vendors
        requirements["mandatory_clauses"] = [
            "Right to audit security controls annually",
            "Security incident notification within 24 hours",
            "Data return/destruction upon contract termination",
            "Compliance with applicable privacy regulations",
            "Background checks for personnel with data access",
        ]
        
        # Tier-specific requirements
        if vendor.tier in [VendorTier.CRITICAL, VendorTier.HIGH]:
            requirements["mandatory_clauses"].extend([
                "Annual SOC 2 Type II or equivalent report",
                "Penetration test results sharing",
                "Business continuity/DR plan documentation",
                "Cyber insurance minimum $5M coverage",
                "Subcontractor approval requirements",
            ])
            requirements["sla_requirements"] = {
                "security_incident_notification": "24 hours",
                "vulnerability_remediation_critical": "72 hours",
                "vulnerability_remediation_high": "30 days",
                "access_review_frequency": "Quarterly",
                "compliance_reporting": "Annual",
            }
        elif vendor.tier == VendorTier.MODERATE:
            requirements["mandatory_clauses"].extend([
                "Annual security attestation",
                "Vulnerability management evidence",
            ])
            requirements["sla_requirements"] = {
                "security_incident_notification": "48 hours",
                "vulnerability_remediation_critical": "7 days",
                "compliance_reporting": "Annual",
            }
        
        # Gap-specific remediation requirements
        for gap in gaps:
            if gap.get("mandatory"):
                requirements["gap_remediation"].append({
                    "control": gap["requirement"],
                    "timeline": "90 days" if vendor.tier == VendorTier.CRITICAL else "180 days",
                    "evidence_required": gap.get("evidence_required", []),
                })
        
        return requirements
    
    def assess_vendor(
        self,
        vendor: VendorProfile,
        responses: List[AssessmentResponse]
    ) -> Dict:
        """
        Perform complete vendor risk assessment.
        
        Returns comprehensive assessment report.
        """
        # Classify tier
        vendor.tier = self.classify_vendor_tier(vendor)
        
        # Calculate risks
        vendor.inherent_risk_score = self.calculate_inherent_risk(vendor)
        control_score, gaps = self.calculate_control_score(vendor, responses)
        vendor.residual_risk_score = self.calculate_residual_risk(
            vendor.inherent_risk_score, control_score
        )
        
        # Determine status
        vendor.assessment_status = self.determine_assessment_status(
            vendor, control_score, gaps
        )
        
        # Set assessment dates
        vendor.last_assessment = datetime.now().strftime("%Y-%m-%d")
        next_date = datetime.now() + timedelta(
            days=self.ASSESSMENT_FREQUENCY.get(vendor.tier, 365)
        )
        vendor.next_assessment = next_date.strftime("%Y-%m-%d")
        
        # Generate contract requirements
        contract_requirements = self.generate_contract_requirements(vendor, gaps)
        
        # Build assessment report
        report = {
            "assessment_date": vendor.last_assessment,
            "vendor_profile": {
                "vendor_id": vendor.vendor_id,
                "vendor_name": vendor.vendor_name,
                "vendor_type": vendor.vendor_type,
                "tier": vendor.tier.value,
                "data_classification": vendor.data_classification.value,
            },
            "risk_scores": {
                "inherent_risk": vendor.inherent_risk_score,
                "control_effectiveness": control_score,
                "residual_risk": vendor.residual_risk_score,
                "risk_rating": self._get_risk_rating(vendor.residual_risk_score),
            },
            "assessment_result": {
                "status": vendor.assessment_status.value,
                "total_controls_assessed": len(self._get_applicable_controls(vendor.tier)),
                "gaps_identified": len(gaps),
                "mandatory_gaps": len([g for g in gaps if g.get("mandatory")]),
            },
            "gaps": gaps,
            "contract_requirements": contract_requirements,
            "next_assessment_due": vendor.next_assessment,
            "recommendations": self._generate_recommendations(vendor, gaps),
        }
        
        return report
    
    def _get_risk_rating(self, residual_risk: float) -> str:
        """Convert residual risk score to rating."""
        if residual_risk >= 75:
            return "Critical"
        elif residual_risk >= 50:
            return "High"
        elif residual_risk >= 25:
            return "Medium"
        else:
            return "Low"
    
    def _generate_recommendations(
        self,
        vendor: VendorProfile,
        gaps: List[Dict]
    ) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []
        
        if vendor.assessment_status == AssessmentStatus.REJECTED:
            recommendations.append(
                "⛔ Do not proceed with vendor engagement until critical gaps are addressed"
            )
        elif vendor.assessment_status == AssessmentStatus.CONDITIONAL:
            recommendations.append(
                "⚠️ Conditional approval - implement remediation plan before go-live"
            )
        
        # Gap-specific recommendations
        mandatory_gaps = [g for g in gaps if g.get("mandatory")]
        if mandatory_gaps:
            recommendations.append(
                f"🔴 Address {len(mandatory_gaps)} mandatory control gaps within 90 days"
            )
        
        # Domain-specific recommendations
        gap_domains = set(g["domain"] for g in gaps)
        if "data" in gap_domains:
            recommendations.append(
                "📊 Prioritize data protection controls - request encryption evidence"
            )
        if "incident" in gap_domains:
            recommendations.append(
                "🚨 Establish clear incident response SLAs in contract"
            )
        
        # Monitoring recommendations
        if vendor.tier == VendorTier.CRITICAL:
            recommendations.append(
                "👁️ Implement continuous monitoring with quarterly check-ins"
            )
        
        return recommendations


def create_sample_assessment() -> Tuple[VendorProfile, List[AssessmentResponse]]:
    """Create sample vendor and assessment data for demonstration."""
    
    # Sample cloud SaaS vendor
    vendor = VendorProfile(
        vendor_id="VND-2024-001",
        vendor_name="CloudPayroll Solutions Inc.",
        vendor_type="SaaS",
        primary_contact="security@cloudpayroll.example.com",
        contract_owner="John Smith (HR)",
        data_classification=DataClassification.RESTRICTED,
        data_types=["PII", "Financial", "Tax Information"],
        data_volume="High",
        data_location=["United States", "Canada"],
        has_network_access=False,
        has_system_access=True,  # API integration
        has_physical_access=False,
        has_data_processing=True,
        business_criticality="High",
        service_description="Cloud-based payroll processing and tax filing",
        annual_spend=150000.00,
        contract_start="2024-01-15",
        contract_end="2027-01-14",
    )
    
    # Sample assessment responses
    responses = [
        # Implemented controls
        AssessmentResponse("GOV-01", True, 4, ["Security policy v2.3"], "Annual review completed Dec 2023"),
        AssessmentResponse("GOV-02", True, 4, ["Risk assessment report Q4 2023"], ""),
        AssessmentResponse("GOV-03", True, 3, ["Training records 2023"], "95% completion rate"),
        AssessmentResponse("ACC-01", True, 5, ["Okta MFA configuration"], "All users MFA enforced"),
        AssessmentResponse("ACC-02", True, 4, ["CyberArk PAM deployment"], ""),
        AssessmentResponse("ACC-03", True, 3, ["Q3 2023 access review"], "Quarterly reviews"),
        AssessmentResponse("DAT-01", True, 5, ["AES-256 encryption"], "All data at rest encrypted"),
        AssessmentResponse("DAT-02", True, 5, ["TLS 1.3 configuration"], ""),
        AssessmentResponse("DAT-04", True, 3, ["Retention policy document"], "7-year retention"),
        AssessmentResponse("SEC-01", True, 4, ["Qualys scan reports"], "Monthly scanning"),
        AssessmentResponse("SEC-02", True, 4, ["2023 pentest report"], "Critical findings remediated"),
        AssessmentResponse("SEC-03", True, 4, ["Splunk SIEM architecture"], "24/7 monitoring"),
        AssessmentResponse("SEC-04", True, 4, ["CrowdStrike EDR"], "100% endpoint coverage"),
        AssessmentResponse("INC-01", True, 4, ["IR plan v3.0"], "Updated Nov 2023"),
        AssessmentResponse("INC-02", True, 5, ["Notification SLA"], "24-hour notification commitment"),
        AssessmentResponse("CMP-01", True, 5, ["SOC 2 Type II 2023"], "Unqualified opinion"),
        AssessmentResponse("BCP-01", True, 4, ["BCP document"], "RTO: 4 hours, RPO: 1 hour"),
        AssessmentResponse("BCP-02", True, 3, ["DR test Nov 2023"], ""),
        
        # Gaps / Not implemented
        AssessmentResponse("GOV-04", False, 0, [], "", "Subcontractor list available on request"),
        AssessmentResponse("ACC-04", False, 0, [], "", "SAML SSO on roadmap Q2 2024"),
        AssessmentResponse("DAT-03", True, 2, ["Basic DLP"], "Limited DLP capability"),
        AssessmentResponse("DAT-05", True, 3, ["Privacy policy"], "GDPR compliant"),
        AssessmentResponse("INC-03", False, 0, [], "", "Planning tabletop for Q1 2024"),
        AssessmentResponse("CMP-02", False, 0, [], "", "ISO 27001 certification in progress"),
        AssessmentResponse("CMP-03", False, 0, [], "", "SOC 2 serves as primary attestation"),
        AssessmentResponse("BCP-03", True, 3, ["AWS multi-region"], "US-East-1 and US-West-2"),
    ]
    
    return vendor, responses


def print_assessment_report(report: Dict) -> None:
    """Print formatted assessment report."""
    print("\n" + "=" * 70)
    print("         THIRD-PARTY RISK MANAGEMENT ASSESSMENT REPORT")
    print("              NIST SP 800-161 Aligned Evaluation")
    print("=" * 70)
    
    # Vendor Profile
    profile = report["vendor_profile"]
    print(f"\n📋 VENDOR PROFILE")
    print("-" * 40)
    print(f"  Vendor ID:          {profile['vendor_id']}")
    print(f"  Vendor Name:        {profile['vendor_name']}")
    print(f"  Vendor Type:        {profile['vendor_type']}")
    print(f"  Risk Tier:          {profile['tier']}")
    print(f"  Data Classification: {profile['data_classification']}")
    
    # Risk Scores
    scores = report["risk_scores"]
    print(f"\n📊 RISK ASSESSMENT SCORES")
    print("-" * 40)
    print(f"  Inherent Risk:        {scores['inherent_risk']:.1f}/100")
    print(f"  Control Effectiveness: {scores['control_effectiveness']:.1f}%")
    print(f"  Residual Risk:        {scores['residual_risk']:.1f}/100")
    print(f"  Risk Rating:          {scores['risk_rating']}")
    
    # Visual risk meter
    residual = scores['residual_risk']
    meter_len = 30
    filled = int(residual / 100 * meter_len)
    meter = "█" * filled + "░" * (meter_len - filled)
    if residual >= 75:
        color = "🔴"
    elif residual >= 50:
        color = "🟠"
    elif residual >= 25:
        color = "🟡"
    else:
        color = "🟢"
    print(f"  Risk Meter: {color} [{meter}] {residual:.0f}%")
    
    # Assessment Result
    result = report["assessment_result"]
    print(f"\n✅ ASSESSMENT RESULT")
    print("-" * 40)
    status_icons = {
        "Approved": "✅",
        "Conditionally Approved": "⚠️",
        "Rejected": "❌",
        "Pending": "⏳",
    }
    status_icon = status_icons.get(result['status'], "📋")
    print(f"  Status:           {status_icon} {result['status']}")
    print(f"  Controls Assessed: {result['total_controls_assessed']}")
    print(f"  Gaps Identified:   {result['gaps_identified']}")
    print(f"  Mandatory Gaps:    {result['mandatory_gaps']}")
    
    # Gaps Summary
    if report["gaps"]:
        print(f"\n🔴 CONTROL GAPS ({len(report['gaps'])} identified)")
        print("-" * 40)
        for i, gap in enumerate(report["gaps"][:5], 1):  # Show first 5
            mandatory = " [MANDATORY]" if gap.get("mandatory") else ""
            print(f"  {i}. {gap['requirement']}{mandatory}")
            print(f"     Domain: {gap['domain'].upper()}, Weight: {gap['weight']}")
        if len(report["gaps"]) > 5:
            print(f"  ... and {len(report['gaps']) - 5} more gaps")
    
    # Contract Requirements Summary
    contract = report["contract_requirements"]
    print(f"\n📝 CONTRACT SECURITY REQUIREMENTS")
    print("-" * 40)
    print(f"  Mandatory Clauses: {len(contract['mandatory_clauses'])}")
    if contract["gap_remediation"]:
        print(f"  Gap Remediation Items: {len(contract['gap_remediation'])}")
    if contract["sla_requirements"]:
        print("  Key SLAs:")
        for sla, value in list(contract["sla_requirements"].items())[:3]:
            print(f"    - {sla.replace('_', ' ').title()}: {value}")
    
    # Recommendations
    print(f"\n💡 RECOMMENDATIONS")
    print("-" * 40)
    for rec in report["recommendations"]:
        print(f"  {rec}")
    
    # Next Steps
    print(f"\n📅 NEXT ASSESSMENT DUE: {report['next_assessment_due']}")
    
    print("\n" + "=" * 70)
    print(f"  Assessment Date: {report['assessment_date']}")
    print(f"  Framework: NIST SP 800-161 (Supply Chain Risk Management)")
    print("=" * 70 + "\n")


def main():
    """Main execution for TPRM workflow demonstration."""
    print("\n" + "=" * 70)
    print("     THIRD-PARTY RISK MANAGEMENT (TPRM) WORKFLOW ENGINE")
    print("           NIST SP 800-161 Aligned Assessment Tool")
    print("=" * 70)
    
    # Initialize workflow engine
    tprm = TPRMWorkflow()
    
    # Load sample data
    print("\n📂 Loading sample vendor data...")
    vendor, responses = create_sample_assessment()
    
    print(f"  Vendor: {vendor.vendor_name}")
    print(f"  Type: {vendor.vendor_type}")
    print(f"  Data Types: {', '.join(vendor.data_types)}")
    print(f"  Business Criticality: {vendor.business_criticality}")
    
    # Perform assessment
    print("\n🔍 Performing risk assessment...")
    report = tprm.assess_vendor(vendor, responses)
    
    # Print report
    print_assessment_report(report)
    
    # Export options
    print("📤 EXPORT OPTIONS")
    print("-" * 40)
    print("  1. JSON Report: tprm_assessment_report.json")
    print("  2. Contract Requirements: vendor_contract_requirements.json")
    
    # Save JSON report
    with open("sample_data/tprm_assessment_report.json", "w") as f:
        # Convert enums to strings for JSON serialization
        json_report = json.loads(json.dumps(report, default=str))
        json.dump(json_report, f, indent=2)
    print("\n✅ Assessment report exported to sample_data/tprm_assessment_report.json")
    
    return report


if __name__ == "__main__":
    main()
