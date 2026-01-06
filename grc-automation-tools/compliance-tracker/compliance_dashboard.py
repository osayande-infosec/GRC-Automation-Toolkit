#!/usr/bin/env python3
"""
Compliance Dashboard Module
---------------------------
GRC Automation Toolkit - Module 05

Generates compliance status dashboards from control assessments:
- Framework coverage (NIST, ISO 27001, SOC 2, HIPAA, PCI-DSS)
- Control implementation status tracking
- Gap analysis and recommendations
- Trend visualization data

Author: osayande-infosec
License: MIT
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional


# Common compliance frameworks with control families
FRAMEWORKS = {
    "nist_csf": {
        "name": "NIST Cybersecurity Framework",
        "families": ["Identify", "Protect", "Detect", "Respond", "Recover"],
    },
    "iso27001": {
        "name": "ISO 27001:2022",
        "families": ["A.5", "A.6", "A.7", "A.8"],  # Simplified
    },
    "soc2": {
        "name": "SOC 2",
        "families": ["Security", "Availability", "Processing Integrity", 
                     "Confidentiality", "Privacy"],
    },
    "hipaa": {
        "name": "HIPAA",
        "families": ["Administrative", "Physical", "Technical"],
    },
    "pci_dss": {
        "name": "PCI DSS 4.0",
        "families": ["Network Security", "Data Protection", "Vulnerability Management",
                     "Access Control", "Monitoring", "Security Policy"],
    },
}


@dataclass
class Control:
    """Represents a compliance control."""
    control_id: str
    title: str
    description: str
    framework: str
    family: str
    status: str  # implemented, partial, not_implemented, not_applicable
    owner: str
    evidence: str
    last_assessed: Optional[datetime] = None
    notes: str = ""
    priority: str = "medium"


@dataclass
class ComplianceReport:
    """Compliance assessment report."""
    total_controls: int
    framework: str
    framework_name: str
    overall_score: float  # 0-100
    by_status: Dict[str, int]
    by_family: Dict[str, Dict[str, int]]
    gaps: List[Control]  # Not implemented controls
    partial: List[Control]
    recent_changes: List[Control]
    recommendations: List[str]


def parse_datetime(dt_str: str) -> Optional[datetime]:
    """Parse datetime string."""
    if not dt_str:
        return None
    for fmt in ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%m/%d/%Y"]:
        try:
            return datetime.strptime(dt_str.strip(), fmt)
        except ValueError:
            continue
    return None


def normalize_status(status: str) -> str:
    """Normalize control status."""
    status = status.lower().strip()
    
    status_map = {
        "implemented": "implemented",
        "complete": "implemented",
        "compliant": "implemented",
        "yes": "implemented",
        "pass": "implemented",
        "partial": "partial",
        "in_progress": "partial",
        "in progress": "partial",
        "not_implemented": "not_implemented",
        "not implemented": "not_implemented",
        "no": "not_implemented",
        "fail": "not_implemented",
        "gap": "not_implemented",
        "not_applicable": "not_applicable",
        "n/a": "not_applicable",
        "na": "not_applicable",
    }
    
    return status_map.get(status, "not_implemented")


def load_controls(json_path: Path) -> List[Control]:
    """Load controls from JSON file."""
    with json_path.open(encoding="utf-8") as f:
        data = json.load(f)
    
    controls_data = data if isinstance(data, list) else data.get("controls", data.get("findings", []))
    
    controls = []
    for item in controls_data:
        control = Control(
            control_id=str(item.get("id", item.get("control_id", ""))),
            title=item.get("title", item.get("name", item.get("control", "Unknown"))),
            description=item.get("description", ""),
            framework=item.get("framework", "custom").lower(),
            family=item.get("family", item.get("category", item.get("domain", "General"))),
            status=normalize_status(item.get("status", item.get("state", ""))),
            owner=item.get("owner", item.get("responsible", "")),
            evidence=item.get("evidence", item.get("artifacts", "")),
            last_assessed=parse_datetime(item.get("last_assessed", item.get("assessed_date", ""))),
            notes=item.get("notes", item.get("comments", "")),
            priority=item.get("priority", "medium").lower(),
        )
        controls.append(control)
    
    return controls


def calculate_compliance_score(controls: List[Control]) -> float:
    """Calculate overall compliance score."""
    if not controls:
        return 0.0
    
    # Exclude N/A controls
    applicable = [c for c in controls if c.status != "not_applicable"]
    if not applicable:
        return 100.0
    
    # Weight by status
    implemented = sum(1 for c in applicable if c.status == "implemented")
    partial = sum(1 for c in applicable if c.status == "partial")
    
    # Partial counts as 50%
    score = ((implemented + partial * 0.5) / len(applicable)) * 100
    return round(score, 1)


def generate_recommendations(controls: List[Control]) -> List[str]:
    """Generate remediation recommendations."""
    recommendations = []
    
    gaps = [c for c in controls if c.status == "not_implemented"]
    partial = [c for c in controls if c.status == "partial"]
    
    # Priority-based recommendations
    critical_gaps = [c for c in gaps if c.priority == "critical" or c.priority == "high"]
    
    if critical_gaps:
        recommendations.append(
            f"URGENT: {len(critical_gaps)} high-priority control(s) not implemented. "
            "Address these first to reduce risk exposure."
        )
    
    if len(gaps) > len(controls) * 0.3:
        recommendations.append(
            "Significant compliance gaps detected (>30%). Consider a phased "
            "implementation approach with executive sponsorship."
        )
    
    if partial:
        recommendations.append(
            f"{len(partial)} control(s) partially implemented. "
            "Complete documentation and evidence collection to achieve full compliance."
        )
    
    # Framework-specific recommendations
    frameworks_in_use = set(c.framework for c in controls)
    if len(frameworks_in_use) > 1:
        recommendations.append(
            "Multiple frameworks detected. Consider control mapping to reduce "
            "duplicate compliance efforts."
        )
    
    # Evidence gaps
    no_evidence = [c for c in controls if c.status == "implemented" and not c.evidence]
    if no_evidence:
        recommendations.append(
            f"{len(no_evidence)} implemented control(s) lack documented evidence. "
            "Gather artifacts to support audit readiness."
        )
    
    if not recommendations:
        recommendations.append("Compliance posture is strong. Maintain regular assessments.")
    
    return recommendations


def analyze_compliance(controls: List[Control]) -> ComplianceReport:
    """Analyze controls and generate compliance report."""
    by_status = Counter(c.status for c in controls)
    
    # Group by family
    by_family = defaultdict(lambda: defaultdict(int))
    for c in controls:
        by_family[c.family][c.status] += 1
    
    # Identify gaps and partial
    gaps = [c for c in controls if c.status == "not_implemented"]
    partial = [c for c in controls if c.status == "partial"]
    
    # Sort gaps by priority
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    gaps.sort(key=lambda c: priority_order.get(c.priority, 99))
    
    # Recent changes (assessed in last 30 days)
    now = datetime.now()
    recent = [
        c for c in controls 
        if c.last_assessed and (now - c.last_assessed).days <= 30
    ]
    
    # Determine primary framework
    framework_counts = Counter(c.framework for c in controls)
    primary_framework = framework_counts.most_common(1)[0][0] if framework_counts else "custom"
    framework_info = FRAMEWORKS.get(primary_framework, {"name": "Custom Framework"})
    
    return ComplianceReport(
        total_controls=len(controls),
        framework=primary_framework,
        framework_name=framework_info["name"],
        overall_score=calculate_compliance_score(controls),
        by_status=dict(by_status),
        by_family={k: dict(v) for k, v in by_family.items()},
        gaps=gaps,
        partial=partial,
        recent_changes=recent,
        recommendations=generate_recommendations(controls),
    )


def print_dashboard(report: ComplianceReport, verbose: bool = False) -> None:
    """Print compliance dashboard."""
    print("\n" + "=" * 60)
    print("COMPLIANCE DASHBOARD")
    print(f"Framework: {report.framework_name}")
    print("=" * 60)
    
    # Score banner with visual indicator
    score = report.overall_score
    if score >= 80:
        indicator = "🟢"
        status = "COMPLIANT"
    elif score >= 60:
        indicator = "🟡"
        status = "PARTIAL COMPLIANCE"
    else:
        indicator = "🔴"
        status = "NON-COMPLIANT"
    
    print(f"\n{indicator} COMPLIANCE SCORE: {score}% - {status}")
    
    # Progress bar
    filled = int(score / 5)
    bar = "█" * filled + "░" * (20 - filled)
    print(f"   [{bar}]")
    
    print(f"\n📊 CONTROL STATUS SUMMARY")
    status_icons = {
        "implemented": "✅",
        "partial": "🔶",
        "not_implemented": "❌",
        "not_applicable": "➖",
    }
    total = report.total_controls
    for status, count in sorted(report.by_status.items()):
        pct = count / total * 100 if total else 0
        icon = status_icons.get(status, "❓")
        print(f"   {icon} {status.replace('_', ' ').title()}: {count} ({pct:.1f}%)")
    
    # Family breakdown
    print(f"\n📁 BY CONTROL FAMILY")
    for family, statuses in sorted(report.by_family.items()):
        total_family = sum(statuses.values())
        impl = statuses.get("implemented", 0)
        family_score = (impl / total_family * 100) if total_family else 0
        print(f"   • {family}: {impl}/{total_family} implemented ({family_score:.0f}%)")
    
    # Gaps summary
    if report.gaps:
        print(f"\n⚠️  COMPLIANCE GAPS ({len(report.gaps)})")
        for gap in report.gaps[:5]:
            priority_icon = "🔴" if gap.priority in ("critical", "high") else "🟡"
            print(f"   {priority_icon} [{gap.control_id}] {gap.title}")
            if gap.owner:
                print(f"      Owner: {gap.owner}")
    
    # Recommendations
    print(f"\n💡 RECOMMENDATIONS")
    for i, rec in enumerate(report.recommendations, 1):
        print(f"   {i}. {rec}")
    
    if verbose:
        if report.partial:
            print(f"\n🔶 PARTIAL IMPLEMENTATIONS ({len(report.partial)})")
            for ctrl in report.partial[:5]:
                print(f"   • [{ctrl.control_id}] {ctrl.title}")
                if ctrl.notes:
                    print(f"     Notes: {ctrl.notes[:60]}...")
        
        if report.recent_changes:
            print(f"\n📅 RECENTLY ASSESSED ({len(report.recent_changes)})")
            for ctrl in report.recent_changes[:5]:
                print(f"   • [{ctrl.control_id}] {ctrl.title} - {ctrl.status}")
    
    print("\n" + "=" * 60 + "\n")


def export_gap_analysis(report: ComplianceReport, output_path: Path) -> None:
    """Export gap analysis to CSV."""
    import csv
    
    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Control ID", "Title", "Family", "Priority", "Status", "Owner", "Notes"])
        
        for ctrl in report.gaps + report.partial:
            writer.writerow([
                ctrl.control_id,
                ctrl.title,
                ctrl.family,
                ctrl.priority,
                ctrl.status,
                ctrl.owner,
                ctrl.notes,
            ])
    
    print(f"Gap analysis exported to {output_path}")


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Generate compliance dashboard from control assessments.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python compliance_dashboard.py --json controls.json
  python compliance_dashboard.py --json assessment.json --verbose --export gaps.csv
        """
    )
    parser.add_argument(
        "--json", "-j",
        required=True,
        type=Path,
        help="Path to JSON controls file"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed output"
    )
    parser.add_argument(
        "--export", "-e",
        type=Path,
        help="Export gap analysis to CSV"
    )
    
    args = parser.parse_args()
    
    if not args.json.exists():
        raise SystemExit(f"File not found: {args.json}")
    
    controls = load_controls(args.json)
    
    if not controls:
        raise SystemExit("No controls found in file.")
    
    report = analyze_compliance(controls)
    print_dashboard(report, verbose=args.verbose)
    
    if args.export:
        export_gap_analysis(report, args.export)


if __name__ == "__main__":
    main()
