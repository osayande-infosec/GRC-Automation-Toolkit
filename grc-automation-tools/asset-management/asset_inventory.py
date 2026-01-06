#!/usr/bin/env python3
"""
Asset Inventory Module
----------------------
GRC Automation Toolkit - Module 02

Parses and analyzes IT asset inventory from CSV files.
Provides insights for compliance and risk management:
- Asset categorization and statistics
- End-of-life/support tracking
- Compliance status summary
- Risk-based prioritization

Author: osayande-infosec
License: MIT
"""

from __future__ import annotations

import argparse
import csv
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, date
from pathlib import Path
from typing import List, Dict, Optional


@dataclass
class Asset:
    """Represents an IT asset."""
    asset_id: str
    name: str
    asset_type: str  # server, workstation, network, cloud, etc.
    owner: str
    department: str
    os: str
    criticality: str  # critical, high, medium, low
    status: str  # active, inactive, retired
    last_updated: Optional[date] = None
    eol_date: Optional[date] = None
    compliance_status: str = "unknown"
    location: str = ""
    ip_address: str = ""


@dataclass
class InventoryReport:
    """Summary report of asset inventory."""
    total_assets: int
    by_type: Dict[str, int]
    by_criticality: Dict[str, int]
    by_status: Dict[str, int]
    by_department: Dict[str, int]
    eol_assets: List[Asset]
    stale_assets: List[Asset]  # Not updated in 90+ days
    non_compliant: List[Asset]
    compliance_rate: float


def parse_date(date_str: str) -> Optional[date]:
    """Parse date string in various formats."""
    if not date_str or date_str.lower() in ("", "n/a", "none", "-"):
        return None
    
    formats = ["%Y-%m-%d", "%m/%d/%Y", "%d/%m/%Y", "%Y/%m/%d"]
    for fmt in formats:
        try:
            return datetime.strptime(date_str.strip(), fmt).date()
        except ValueError:
            continue
    return None


def load_inventory(csv_path: Path) -> List[Asset]:
    """Load asset inventory from CSV file."""
    assets = []
    
    with csv_path.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Normalize column names (lowercase, strip whitespace)
            row = {k.lower().strip().replace(" ", "_"): v.strip() 
                   for k, v in row.items()}
            
            asset = Asset(
                asset_id=row.get("asset_id", row.get("id", "")),
                name=row.get("name", row.get("hostname", "")),
                asset_type=row.get("asset_type", row.get("type", "unknown")),
                owner=row.get("owner", row.get("assigned_to", "")),
                department=row.get("department", row.get("dept", "")),
                os=row.get("os", row.get("operating_system", "")),
                criticality=row.get("criticality", row.get("priority", "medium")),
                status=row.get("status", "active"),
                last_updated=parse_date(row.get("last_updated", "")),
                eol_date=parse_date(row.get("eol_date", row.get("end_of_life", ""))),
                compliance_status=row.get("compliance_status", row.get("compliant", "unknown")),
                location=row.get("location", ""),
                ip_address=row.get("ip_address", row.get("ip", "")),
            )
            assets.append(asset)
    
    return assets


def analyze_inventory(assets: List[Asset]) -> InventoryReport:
    """Analyze asset inventory and generate report."""
    today = date.today()
    stale_threshold = 90  # days
    
    by_type = Counter(a.asset_type.lower() for a in assets)
    by_criticality = Counter(a.criticality.lower() for a in assets)
    by_status = Counter(a.status.lower() for a in assets)
    by_department = Counter(a.department for a in assets if a.department)
    
    # Find EOL assets
    eol_assets = [
        a for a in assets 
        if a.eol_date and a.eol_date <= today and a.status.lower() == "active"
    ]
    
    # Find stale assets (not updated recently)
    stale_assets = []
    for a in assets:
        if a.last_updated and a.status.lower() == "active":
            days_since_update = (today - a.last_updated).days
            if days_since_update > stale_threshold:
                stale_assets.append(a)
    
    # Find non-compliant assets
    non_compliant = [
        a for a in assets 
        if a.compliance_status.lower() in ("non-compliant", "failed", "no", "false")
    ]
    
    # Calculate compliance rate
    compliant_count = sum(
        1 for a in assets 
        if a.compliance_status.lower() in ("compliant", "passed", "yes", "true")
    )
    compliance_rate = (compliant_count / len(assets) * 100) if assets else 0
    
    return InventoryReport(
        total_assets=len(assets),
        by_type=dict(by_type),
        by_criticality=dict(by_criticality),
        by_status=dict(by_status),
        by_department=dict(by_department),
        eol_assets=eol_assets,
        stale_assets=stale_assets,
        non_compliant=non_compliant,
        compliance_rate=compliance_rate,
    )


def print_report(report: InventoryReport, verbose: bool = False) -> None:
    """Print formatted inventory report."""
    print("\n" + "=" * 60)
    print("ASSET INVENTORY REPORT")
    print("=" * 60)
    
    print(f"\n📊 SUMMARY")
    print(f"   Total Assets: {report.total_assets}")
    print(f"   Compliance Rate: {report.compliance_rate:.1f}%")
    
    print(f"\n📁 BY TYPE:")
    for asset_type, count in sorted(report.by_type.items(), key=lambda x: -x[1]):
        print(f"   • {asset_type.capitalize()}: {count}")
    
    print(f"\n🎯 BY CRITICALITY:")
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for crit, count in sorted(report.by_criticality.items(), 
                               key=lambda x: order.get(x[0], 99)):
        print(f"   • {crit.capitalize()}: {count}")
    
    print(f"\n📍 BY STATUS:")
    for status, count in report.by_status.items():
        print(f"   • {status.capitalize()}: {count}")
    
    # Alerts section
    alerts = []
    if report.eol_assets:
        alerts.append(f"⚠️  {len(report.eol_assets)} asset(s) past end-of-life")
    if report.stale_assets:
        alerts.append(f"⚠️  {len(report.stale_assets)} asset(s) not updated in 90+ days")
    if report.non_compliant:
        alerts.append(f"🚨 {len(report.non_compliant)} non-compliant asset(s)")
    
    if alerts:
        print(f"\n🔔 ALERTS:")
        for alert in alerts:
            print(f"   {alert}")
    
    if verbose:
        if report.eol_assets:
            print(f"\n📋 EOL ASSETS:")
            for a in report.eol_assets:
                print(f"   • {a.asset_id}: {a.name} ({a.asset_type}) - EOL: {a.eol_date}")
        
        if report.non_compliant:
            print(f"\n📋 NON-COMPLIANT ASSETS:")
            for a in report.non_compliant:
                print(f"   • {a.asset_id}: {a.name} ({a.criticality} criticality)")
    
    print("\n" + "=" * 60 + "\n")


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Analyze IT asset inventory for GRC insights.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python asset_inventory.py --csv inventory.csv
  python asset_inventory.py --csv assets.csv --verbose
        """
    )
    parser.add_argument(
        "--csv", "-c",
        required=True,
        type=Path,
        help="Path to CSV inventory file"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed asset lists"
    )
    
    args = parser.parse_args()
    
    if not args.csv.exists():
        raise SystemExit(f"File not found: {args.csv}")
    
    assets = load_inventory(args.csv)
    report = analyze_inventory(assets)
    print_report(report, verbose=args.verbose)


if __name__ == "__main__":
    main()
