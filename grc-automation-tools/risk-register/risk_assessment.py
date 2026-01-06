#!/usr/bin/env python3
"""
Risk Assessment Module
----------------------
GRC Automation Toolkit - Module 06

Performs quantitative and qualitative risk assessments:
- Risk scoring (Likelihood × Impact)
- Risk matrix visualization
- Treatment recommendations
- Risk register management
- Trend analysis support

Based on NIST SP 800-30 and ISO 31000 methodologies.

Author: osayande-infosec
License: MIT
"""

from __future__ import annotations

import argparse
import csv
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, date
from pathlib import Path
from typing import List, Dict, Optional, Tuple


# Risk matrix definitions
LIKELIHOOD_LEVELS = {
    1: ("Rare", "< 5% chance"),
    2: ("Unlikely", "5-25% chance"),
    3: ("Possible", "25-50% chance"),
    4: ("Likely", "50-75% chance"),
    5: ("Almost Certain", "> 75% chance"),
}

IMPACT_LEVELS = {
    1: ("Negligible", "Minimal business impact"),
    2: ("Minor", "Limited impact, easily recoverable"),
    3: ("Moderate", "Noticeable impact, requires effort to recover"),
    4: ("Major", "Significant impact, substantial recovery needed"),
    5: ("Catastrophic", "Severe/existential threat to business"),
}

# Risk rating thresholds
def get_risk_rating(score: int) -> Tuple[str, str]:
    """Get risk rating and color based on score."""
    if score >= 20:
        return ("Critical", "🔴")
    elif score >= 12:
        return ("High", "🟠")
    elif score >= 6:
        return ("Medium", "🟡")
    elif score >= 2:
        return ("Low", "🔵")
    return ("Minimal", "⚪")


@dataclass
class Risk:
    """Represents a risk entry."""
    risk_id: str
    title: str
    description: str
    category: str  # operational, technical, compliance, financial, strategic
    likelihood: int  # 1-5
    impact: int  # 1-5
    inherent_score: int = 0
    controls: List[str] = field(default_factory=list)
    residual_likelihood: Optional[int] = None
    residual_impact: Optional[int] = None
    residual_score: int = 0
    owner: str = ""
    treatment: str = ""  # accept, mitigate, transfer, avoid
    status: str = "open"  # open, in_treatment, closed, accepted
    due_date: Optional[date] = None
    notes: str = ""


@dataclass
class RiskReport:
    """Risk assessment report."""
    total_risks: int
    by_rating: Dict[str, int]
    by_category: Dict[str, int]
    by_status: Dict[str, int]
    critical_risks: List[Risk]
    high_risks: List[Risk]
    overdue_risks: List[Risk]
    average_inherent: float
    average_residual: float
    risk_reduction: float  # Percentage reduction from controls
    treatment_summary: Dict[str, int]
    recommendations: List[str]


def parse_date(date_str: str) -> Optional[date]:
    """Parse date string."""
    if not date_str or date_str.lower() in ("", "n/a", "none", "-"):
        return None
    for fmt in ["%Y-%m-%d", "%m/%d/%Y", "%d/%m/%Y"]:
        try:
            return datetime.strptime(date_str.strip(), fmt).date()
        except ValueError:
            continue
    return None


def parse_int(value: str, default: int = 3) -> int:
    """Parse integer with default."""
    try:
        val = int(value)
        return max(1, min(5, val))  # Clamp to 1-5
    except (ValueError, TypeError):
        return default


def load_risks(csv_path: Path) -> List[Risk]:
    """Load risks from CSV file."""
    risks = []
    
    with csv_path.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Normalize keys
            row = {k.lower().strip().replace(" ", "_"): v.strip() 
                   for k, v in row.items()}
            
            likelihood = parse_int(row.get("likelihood", "3"))
            impact = parse_int(row.get("impact", "3"))
            inherent_score = likelihood * impact
            
            # Residual values (after controls)
            res_likelihood = row.get("residual_likelihood", "")
            res_impact = row.get("residual_impact", "")
            
            if res_likelihood and res_impact:
                residual_likelihood = parse_int(res_likelihood)
                residual_impact = parse_int(res_impact)
                residual_score = residual_likelihood * residual_impact
            else:
                residual_likelihood = None
                residual_impact = None
                residual_score = inherent_score  # Same as inherent if no controls
            
            # Parse controls (comma-separated)
            controls_str = row.get("controls", row.get("mitigations", ""))
            controls = [c.strip() for c in controls_str.split(",") if c.strip()]
            
            risk = Risk(
                risk_id=row.get("risk_id", row.get("id", "")),
                title=row.get("title", row.get("risk", row.get("name", "Unknown"))),
                description=row.get("description", ""),
                category=row.get("category", row.get("type", "operational")).lower(),
                likelihood=likelihood,
                impact=impact,
                inherent_score=inherent_score,
                controls=controls,
                residual_likelihood=residual_likelihood,
                residual_impact=residual_impact,
                residual_score=residual_score,
                owner=row.get("owner", row.get("risk_owner", "")),
                treatment=row.get("treatment", row.get("response", "mitigate")).lower(),
                status=row.get("status", "open").lower(),
                due_date=parse_date(row.get("due_date", "")),
                notes=row.get("notes", ""),
            )
            risks.append(risk)
    
    return risks


def generate_recommendations(risks: List[Risk]) -> List[str]:
    """Generate risk management recommendations."""
    recommendations = []
    
    critical = [r for r in risks if get_risk_rating(r.inherent_score)[0] == "Critical"]
    high = [r for r in risks if get_risk_rating(r.inherent_score)[0] == "High"]
    no_treatment = [r for r in risks if not r.treatment or r.treatment == "none"]
    no_controls = [r for r in risks if not r.controls and r.inherent_score >= 12]
    
    if critical:
        recommendations.append(
            f"URGENT: {len(critical)} critical risk(s) identified. "
            "Immediate executive attention and resource allocation required."
        )
    
    if no_treatment:
        recommendations.append(
            f"{len(no_treatment)} risk(s) lack defined treatment strategies. "
            "Document risk response for each identified risk."
        )
    
    if no_controls:
        recommendations.append(
            f"{len(no_controls)} high-scoring risk(s) have no documented controls. "
            "Implement compensating controls to reduce exposure."
        )
    
    # Category concentration
    categories = Counter(r.category for r in risks if r.inherent_score >= 12)
    if categories:
        top_category = categories.most_common(1)[0]
        recommendations.append(
            f"'{top_category[0].title()}' category has {top_category[1]} high-severity risks. "
            "Consider focused risk reduction initiatives in this area."
        )
    
    # Overdue items
    today = date.today()
    overdue = [r for r in risks if r.due_date and r.due_date < today and r.status != "closed"]
    if overdue:
        recommendations.append(
            f"{len(overdue)} risk treatment(s) are past due date. "
            "Review and update treatment plans."
        )
    
    if not recommendations:
        recommendations.append("Risk posture is well-managed. Continue regular assessments.")
    
    return recommendations


def analyze_risks(risks: List[Risk]) -> RiskReport:
    """Analyze risks and generate report."""
    # Rating distribution (based on inherent score)
    by_rating = Counter(get_risk_rating(r.inherent_score)[0] for r in risks)
    by_category = Counter(r.category for r in risks)
    by_status = Counter(r.status for r in risks)
    
    # Critical and high risks
    critical = [r for r in risks if get_risk_rating(r.inherent_score)[0] == "Critical"]
    high = [r for r in risks if get_risk_rating(r.inherent_score)[0] == "High"]
    
    # Sort by score descending
    critical.sort(key=lambda r: r.inherent_score, reverse=True)
    high.sort(key=lambda r: r.inherent_score, reverse=True)
    
    # Overdue risks
    today = date.today()
    overdue = [r for r in risks if r.due_date and r.due_date < today and r.status not in ("closed", "accepted")]
    
    # Calculate averages
    avg_inherent = sum(r.inherent_score for r in risks) / len(risks) if risks else 0
    avg_residual = sum(r.residual_score for r in risks) / len(risks) if risks else 0
    
    # Risk reduction percentage
    if avg_inherent > 0:
        risk_reduction = ((avg_inherent - avg_residual) / avg_inherent) * 100
    else:
        risk_reduction = 0
    
    # Treatment summary
    treatment_summary = Counter(r.treatment for r in risks if r.treatment)
    
    return RiskReport(
        total_risks=len(risks),
        by_rating=dict(by_rating),
        by_category=dict(by_category),
        by_status=dict(by_status),
        critical_risks=critical,
        high_risks=high,
        overdue_risks=overdue,
        average_inherent=round(avg_inherent, 1),
        average_residual=round(avg_residual, 1),
        risk_reduction=round(risk_reduction, 1),
        treatment_summary=dict(treatment_summary),
        recommendations=generate_recommendations(risks),
    )


def print_risk_matrix() -> None:
    """Print the risk matrix legend."""
    print("\n📊 RISK MATRIX (Likelihood × Impact)")
    print("     Impact →   1     2     3     4     5")
    print("  Likelihood ↓")
    
    for l in range(5, 0, -1):
        row = f"       {l}      "
        for i in range(1, 6):
            score = l * i
            rating, icon = get_risk_rating(score)
            row += f" {icon}  "
        print(row)
    print()


def print_report(report: RiskReport, verbose: bool = False) -> None:
    """Print risk assessment report."""
    print("\n" + "=" * 60)
    print("RISK ASSESSMENT REPORT")
    print("=" * 60)
    
    # Overall metrics
    print(f"\n📈 RISK METRICS")
    print(f"   Total Risks: {report.total_risks}")
    print(f"   Average Inherent Score: {report.average_inherent}/25")
    print(f"   Average Residual Score: {report.average_residual}/25")
    print(f"   Risk Reduction: {report.risk_reduction}%")
    
    # Rating distribution
    print(f"\n🎯 RISK DISTRIBUTION")
    rating_order = ["Critical", "High", "Medium", "Low", "Minimal"]
    for rating in rating_order:
        count = report.by_rating.get(rating, 0)
        if count > 0:
            _, icon = get_risk_rating({"Critical": 25, "High": 15, "Medium": 8, "Low": 3, "Minimal": 1}[rating])
            pct = count / report.total_risks * 100
            print(f"   {icon} {rating}: {count} ({pct:.1f}%)")
    
    # Critical risks (always show)
    if report.critical_risks:
        print(f"\n🚨 CRITICAL RISKS ({len(report.critical_risks)})")
        for r in report.critical_risks[:5]:
            print(f"   • [{r.risk_id}] {r.title}")
            print(f"     Score: {r.inherent_score} → {r.residual_score} | Owner: {r.owner or 'Unassigned'}")
    
    # Treatment summary
    print(f"\n📋 TREATMENT STRATEGIES")
    treatment_icons = {"mitigate": "🛡️", "accept": "✔️", "transfer": "↪️", "avoid": "🚫"}
    for treatment, count in sorted(report.treatment_summary.items()):
        icon = treatment_icons.get(treatment, "❓")
        print(f"   {icon} {treatment.title()}: {count}")
    
    # Overdue alerts
    if report.overdue_risks:
        print(f"\n⏰ OVERDUE TREATMENTS ({len(report.overdue_risks)})")
        for r in report.overdue_risks[:3]:
            days_overdue = (date.today() - r.due_date).days
            print(f"   • [{r.risk_id}] {r.title} - {days_overdue} days overdue")
    
    # Recommendations
    print(f"\n💡 RECOMMENDATIONS")
    for i, rec in enumerate(report.recommendations, 1):
        print(f"   {i}. {rec}")
    
    if verbose:
        print_risk_matrix()
        
        print(f"\n📁 BY CATEGORY")
        for cat, count in sorted(report.by_category.items(), key=lambda x: -x[1]):
            print(f"   • {cat.title()}: {count}")
        
        if report.high_risks:
            print(f"\n🟠 HIGH RISKS ({len(report.high_risks)})")
            for r in report.high_risks[:5]:
                controls_str = ", ".join(r.controls[:2]) if r.controls else "None"
                print(f"   • [{r.risk_id}] {r.title}")
                print(f"     Controls: {controls_str}")
    
    print("\n" + "=" * 60 + "\n")


def export_risk_register(risks: List[Risk], output_path: Path) -> None:
    """Export full risk register to CSV."""
    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Risk ID", "Title", "Category", "Likelihood", "Impact", 
            "Inherent Score", "Rating", "Controls", "Residual Score",
            "Treatment", "Owner", "Status", "Due Date"
        ])
        
        for r in sorted(risks, key=lambda x: x.inherent_score, reverse=True):
            rating, _ = get_risk_rating(r.inherent_score)
            writer.writerow([
                r.risk_id,
                r.title,
                r.category,
                r.likelihood,
                r.impact,
                r.inherent_score,
                rating,
                "; ".join(r.controls),
                r.residual_score,
                r.treatment,
                r.owner,
                r.status,
                r.due_date or "",
            ])
    
    print(f"Risk register exported to {output_path}")


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Perform risk assessment and generate reports.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python risk_assessment.py --csv risks.csv
  python risk_assessment.py --csv risk_register.csv --verbose --export report.csv
        """
    )
    parser.add_argument(
        "--csv", "-c",
        required=True,
        type=Path,
        help="Path to CSV risk file"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed output including risk matrix"
    )
    parser.add_argument(
        "--export", "-e",
        type=Path,
        help="Export risk register to CSV"
    )
    
    args = parser.parse_args()
    
    if not args.csv.exists():
        raise SystemExit(f"File not found: {args.csv}")
    
    risks = load_risks(args.csv)
    
    if not risks:
        raise SystemExit("No risks found in file.")
    
    report = analyze_risks(risks)
    print_report(report, verbose=args.verbose)
    
    if args.export:
        export_risk_register(risks, args.export)


if __name__ == "__main__":
    main()
